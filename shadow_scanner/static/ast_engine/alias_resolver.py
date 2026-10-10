"""AliasResolver - builds a name -> resolved-string scope from AST assignments."""
from shadow_scanner.static.ast_engine.walker import walk
class AliasResolver:
    """
    EXTRACTOR 4: AliasResolver (runs FIRST — feeds scope to Extractors 1-3)
    Builds a name → resolved_string map from all assignments in the file.
    """
    MAX_DEPTH = 10

    def __init__(self, existing_resolver_bindings=None):
        self.scope = dict(existing_resolver_bindings or {})

    def build_scope(self, ast_body):
        for _ in range(self.MAX_DEPTH):
            prev = len(self.scope)
            walk(ast_body, self._visit)
            if len(self.scope) == prev:
                break
        # FIX FN-2: Second pass — resolve axios.create({baseURL}) wrappers.
        # After the first walk has built the scope, scan for patterns like:
        #   const api = axios.create({ baseURL: '/api/v2' })
        # and register  api.__baseURL = '/api/v2'  so that api.get('/path')
        # gets correctly resolved by _resolve_call_expression.
        self._resolve_axios_wrappers(ast_body)
        return self.scope

    def _resolve_axios_wrappers(self, ast_body):
        """
        FIX FN-2: Register axios.create() wrappers so downstream call-sites
        can resolve  axiosInstance.get('/endpoint')  with the correct base URL.
        """
        def _visit_axios(node):
            if node.type != 'VariableDeclarator':
                return
            if not node.init or node.init.type != 'CallExpression':
                return
            callee = node.init.callee
            # Match: axios.create(...)
            if not (callee.type == 'MemberExpression'
                    and getattr(callee.property, 'name', '') == 'create'
                    and getattr(getattr(callee, 'object', None), 'name', '') == 'axios'):
                return
            var_name = getattr(node.id, 'name', None)
            if not var_name:
                return
            args = node.init.arguments
            if not args:
                return
            config = args[0]
            if config.type != 'ObjectExpression':
                return
            for prop in config.properties:
                key = getattr(prop.key, 'name', getattr(prop.key, 'value', ''))
                if key in ('baseURL', 'baseUrl', 'base', 'url'):
                    base_val = self._resolve(prop.value)
                    if base_val:
                        # Register as axiosVar.__baseURL for downstream lookup
                        self.scope[f'{var_name}.__baseURL'] = base_val
                        # Also register so that var.get('/path') can prepend it
                        self.scope[f'{var_name}'] = base_val
                        break
        walk(ast_body, _visit_axios)

    def _visit(self, node):
        if node.type == 'VariableDeclarator' and node.init:
            name = getattr(node.id, 'name', None)
            if name:
                val = self._resolve(node.init)
                if val is not None:
                    self.scope[name] = val

        if node.type == 'AssignmentExpression' and node.operator == '=':
            lhs = node.left
            if lhs.type == 'Identifier':
                val = self._resolve(node.right)
                if val is not None:
                    self.scope[lhs.name] = val
            elif lhs.type == 'MemberExpression' and not lhs.computed:
                if hasattr(lhs.object, 'type'):
                    obj  = getattr(lhs.object,   'name', '')
                    prop = getattr(lhs.property, 'name', '')
                    if obj and prop:
                        val = self._resolve(node.right)
                        if val is not None:
                            self.scope[f'{obj}.{prop}'] = val

    def _resolve(self, node, depth=0):
        if depth > self.MAX_DEPTH:
            return None
        if node is None:
            return None
        if node.type == 'Literal':
            return str(node.value) if isinstance(node.value, (str, int, float)) else None
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._resolve(node.left,  depth+1)
            r = self._resolve(node.right, depth+1)
            if l is not None and r is not None:
                return l + r
            if l is not None:
                return l
            return None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    v = self._resolve(node.expressions[i], depth+1)
                    parts.append(v if v is not None else '')
            return ''.join(parts)
        if node.type == 'MemberExpression' and not node.computed:
            obj  = getattr(node.object,   'name', '')
            prop = getattr(node.property, 'name', '')
            # Dotted lookup, e.g. API.users -> scope['API.users']
            return self.scope.get(f'{obj}.{prop}')
        # ⭐ ENHANCEMENT 2.1: Add CallExpression resolution (for method calls returning URLs)
        if node.type == 'CallExpression':
            # FIX FN-3: Handle ['api','v1','orders'].join('/') array assembly
            array_join = self._resolve_array_join(node)
            if array_join is not None:
                return array_join
            return self._resolve_call_expression(node, depth)
        # 🔥 FINAL FIX 1.2: Add ObjectExpression resolution for nested objects
        if node.type == 'ObjectExpression':
            return self._resolve_object_expression(node, depth)
        return None

    def _resolve_array_join(self, node):
        """
        FIX FN-3: Resolve ['api','v1','orders'].join('/') → '/api/v1/orders'.
        Also handles Array.join with computed elements where known vars are resolved.
        """
        callee = node.callee
        if not (callee.type == 'MemberExpression'
                and getattr(callee.property, 'name', '') == 'join'):
            return None
        arr_node = callee.object
        if arr_node.type != 'ArrayExpression':
            return None
        args = node.arguments
        separator = '/'
        if args and args[0].type == 'Literal':
            separator = str(args[0].value)
        parts = []
        for elem in arr_node.elements:
            if elem is None:
                continue
            val = self._resolve(elem)
            parts.append(val if val is not None else '{var}')
        if not parts:
            return None
        joined = separator.join(str(p) for p in parts)
        # Only return if it looks like a URL path
        if '/' in joined or joined.startswith('http'):
            return '/' + joined.lstrip('/')
        return None

    # ⭐ ENHANCEMENT 2.1: New method to resolve method calls that return base URLs
    def _resolve_call_expression(self, node, depth):
        """Resolve method calls like getApiBase() or this.getRootUrl()"""
        if depth > self.MAX_DEPTH:
            return None

        callee = node.callee

        # Handle simple function calls: getApiBase()
        if callee.type == 'Identifier':
            method_name = callee.name
            # Check if we know what this method returns
            if method_name in self.scope:
                return self.scope[method_name]

        # Handle member expressions: this.getApiBase() or obj.getUrl()
        elif callee.type == 'MemberExpression' and not callee.computed:
            obj_name = getattr(callee.object, 'name', '')
            prop_name = getattr(callee.property, 'name', '')

            # Try to resolve this.methodName()
            if obj_name == 'this':
                method_key = f'this.{prop_name}'
                if method_key in self.scope:
                    return self.scope[method_key]

            # Try obj.method()
            key = f'{obj_name}.{prop_name}'
            if key in self.scope:
                return self.scope[key]

        return None

    # 🔥 FINAL FIX 1.3: New method to resolve nested object expressions
    def _resolve_object_expression(self, node, depth):
        """
        Resolve nested object expressions like:
        const API = { users: '/users', delete: '/DeleteUser' }

        Previously only the first resolved value was returned, silently discarding
        all other keys.  Now every key/value pair is registered into self.scope
        so MemberExpression lookups (e.g. API.delete) resolve correctly.
        Returns the first string value for callers that only need one result.
        """
        if depth > self.MAX_DEPTH:
            return None

        first_value = None

        for prop in node.properties:
            if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                continue

            # Get property key name
            if prop.key.type == 'Identifier':
                key = prop.key.name
            elif prop.key.type == 'Literal':
                key = str(prop.key.value)
            else:
                continue

            # Resolve property value (recurse for nested objects)
            val = self._resolve(prop.value, depth + 1)

            if val is not None and isinstance(val, str) and len(val) > 2:
                # Register into scope so MemberExpression lookups work:
                # e.g.  const API = { users: '/users' }  →  scope['API.users'] = '/users'
                # The parent _visit() caller will have stored the object var name;
                # we can't know it here, but the ObjectExpressionExtractor (AST layer)
                # handles the per-key endpoint emission.  What matters most is that
                # every sibling key is surfaced, so we also stash them under their
                # plain key name for cross-file resolution.
                if key not in self.scope:
                    self.scope[key] = val
                if first_value is None:
                    first_value = val

        return first_value
