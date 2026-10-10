"""
Single-pass AST extractors (each walks the tree once and emits endpoint dicts).

* ComputedPropertyExtractor - obj["/path"], api["get"]("/path"), api[m]("/path")
* TemplateLiteralExtractor  - `${base}/path` inside HTTP calls / declarations
* BranchLogicExtractor      - ternaries, switch/case and if/else URL branches
* ObjectExpressionExtractor - URL values inside object literals
"""
import re

from shadow_scanner.static.ast_engine.walker import walk
class ComputedPropertyExtractor:
    """
    EXTRACTOR 1: ComputedPropertyExtractor
    Finds endpoints constructed via obj[expr] syntax AND api["get"]("/path") calls.

    T08 depth fix: also resolves dynamic HTTP method calls like:
      client["get"]("/api/users")
      api["post"]("/api/orders", body)
    """
    _HTTP_METHODS = {'get', 'post', 'put', 'delete', 'patch', 'request', 'head', 'options'}

    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        # ── Pattern A: endpoint stored in computed key ─────────────────────
        if node.type == 'MemberExpression' and node.computed:
            prop = node.property
            if prop.type == 'Literal' and isinstance(prop.value, str):
                candidate = prop.value
                if self._looks_like_path(candidate):
                    self._emit(candidate, 'GET', 'computed_literal_key')
            elif prop.type == 'Identifier':
                resolved = self.scope.get(prop.name)
                if resolved and self._looks_like_path(resolved):
                    self._emit(resolved, 'GET', 'computed_scope_key', prop.name)
            elif prop.type == 'BinaryExpression' and prop.operator == '+':
                parts = self._flatten_binary(prop)
                combined = ''.join(p for p in parts if isinstance(p, str))
                if combined and self._looks_like_path(combined):
                    self._emit(combined, 'GET', 'computed_concat_key')

        # ── Pattern B: api["get"]("/path") or api[m]("/path") — computed method call ──
        # Covers: client["post"]("/api/orders"), api[variable]("/path"), api[obj.prop]("/path")
        if node.type == 'CallExpression':
            callee = node.callee
            if callee.type == 'MemberExpression' and callee.computed:
                prop_node   = callee.property
                method_str  = None

                if prop_node.type == 'Literal':
                    # api["get"](...) — direct literal
                    method_str = str(prop_node.value).lower()
                elif prop_node.type == 'Identifier':
                    # api[m](...) where m is a variable — look it up in scope
                    resolved = self.scope.get(prop_node.name)
                    if resolved:
                        method_str = str(resolved).lower()
                elif prop_node.type == 'MemberExpression' and not prop_node.computed:
                    # api[cfg.method](...) or api[METHODS.read](...)
                    obj_n  = getattr(prop_node.object,   'name', '')
                    prop_n = getattr(prop_node.property, 'name', '')
                    if obj_n and prop_n:
                        resolved = self.scope.get(f'{obj_n}.{prop_n}')
                        if resolved:
                            method_str = str(resolved).lower()

                if method_str and method_str in self._HTTP_METHODS and node.arguments:
                    first_arg = node.arguments[0]
                    url_val = self._resolve_arg(first_arg)
                    if url_val and self._looks_like_path(url_val):
                        self._emit(url_val, method_str.upper(), 'computed_method_call')

    def _resolve_arg(self, node):
        if node.type == 'Literal' and isinstance(node.value, str):
            return node.value
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    v = self.scope.get(getattr(node.expressions[i], 'name', ''), '')
                    parts.append(v or '{param}')
            return ''.join(parts)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._resolve_arg(node.left)  or ''
            r = self._resolve_arg(node.right) or ''
            return l + r
        return None

    def _flatten_binary(self, node, depth=0):
        if depth > 12:
            return []
        if node.type == 'Literal':
            return [node.value if isinstance(node.value, str) else None]
        if node.type == 'Identifier':
            return [self.scope.get(node.name)]
        if node.type == 'BinaryExpression' and node.operator == '+':
            return (self._flatten_binary(node.left, depth+1) +
                    self._flatten_binary(node.right, depth+1))
        return [None]

    def _looks_like_path(self, s):
        if not isinstance(s, str) or len(s) < 2:
            return False
        return s.startswith('/') or '/api' in s or '/v' in s

    def _emit(self, path, method='GET', source='', alias=None):
        self.found.append({
            'method':     method,
            'endpoint':   path,
            'type':       'AST_COMPUTED_KEY',
            'classification': 'BACKEND_API',
            'source':     source,
            'alias_name': alias,
            'ast_extracted': True,
            'confidence_bonus': 1,
        })

class TemplateLiteralExtractor:
    """
    EXTRACTOR 2: TemplateLiteralExtractor
    Resolves multi-line and nested template strings.
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        if node.type == 'CallExpression':
            if self._is_http_call(node):
                for arg in node.arguments:
                    if arg.type == 'TemplateLiteral':
                        result = self._resolve_template(arg)
                        if result:
                            method = self._infer_method(node)
                            self._emit(result, method, 'template_in_http_call')

        if node.type == 'VariableDeclarator' and node.init:
            if node.init.type == 'TemplateLiteral':
                result = self._resolve_template(node.init)
                if result and self._looks_like_path(result):
                    self.scope[node.id.name] = result
                    self._emit(result, 'GET', 'template_variable')

    def _resolve_template(self, node):
        parts = []
        quasis = node.quasis
        exprs  = node.expressions

        for i, quasi in enumerate(quasis):
            parts.append(quasi.value.cooked or '')
            if i < len(exprs):
                expr = exprs[i]
                resolved = self._resolve_expr(expr)
                parts.append(resolved if resolved else '{var}')

        result = ''.join(str(p) for p in parts)
        return result if len(result) > 2 else None

    def _resolve_expr(self, node):
        if node.type == 'Identifier':
            return self.scope.get(node.name, '')
        if node.type == 'Literal':
            return str(node.value)
        if node.type == 'MemberExpression' and not node.computed:
            obj  = node.object.name  if node.object.type  == 'Identifier' else ''
            prop = node.property.name if node.property.type == 'Identifier' else ''
            key  = f'{obj}.{prop}'
            return self.scope.get(key, '')
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._resolve_expr(node.left)  or ''
            r = self._resolve_expr(node.right) or ''
            return l + r
        return ''

    def _is_http_call(self, node):
        callee = node.callee
        HTTP_FNS = {'fetch', 'get', 'post', 'put', 'delete', 'patch',
                    'request', 'head', 'options'}
        if callee.type == 'Identifier' and callee.name in HTTP_FNS:
            return True
        if callee.type == 'MemberExpression':
            if hasattr(callee.property,'name') and callee.property.name in HTTP_FNS:
                return True
        return False

    def _infer_method(self, node):
        if node.callee.type == 'MemberExpression':
            name = getattr(node.callee.property, 'name', '').upper()
            if name in ('POST','PUT','DELETE','PATCH','GET','HEAD'):
                return name
        return 'GET'

    def _looks_like_path(self, s):
        return isinstance(s, str) and (s.startswith('/') or '/api' in s)

    def _emit(self, path, method, source):
        self.found.append({
            'method':     method,
            'endpoint':   path,
            'type':       'AST_TEMPLATE_LITERAL',
            'classification': 'BACKEND_API',
            'source':     source,
            'ast_extracted': True,
            'confidence_bonus': 2,
        })

class BranchLogicExtractor:
    """
    EXTRACTOR 3: BranchLogicExtractor
    Handles ternary operators, switch/case, and if/else logic.

    FIX FP-3 / FN-6: Require API-level path (must contain /api/, /vN, /graphql,
    /rest/, /service, or start with http).  Bare component-name paths like
    /ProductCard or /CheckoutForm are frontend routes, not API endpoints, and
    should never be emitted here.  When a resolved base URL is available the
    fragment is prepended to it (fixing FN-6 feature-flag branches).
    """
    # API indicator patterns that must be present in a path for it to qualify
    _API_RE = re.compile(
        r'(?:/api[/_]|/v\d+[/_/]|/graphql|/gql|/rest[/_/]|/odata|/rpc|'
        r'/auth[/_/]|/login|/token|/logout|/user[s/]|/admin[/_/]|/internal|'
        r'\.json$|wss?://|^https?://)',
        re.IGNORECASE
    )

    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        # ── Ternary: flag ? "/api/v1/..." : "/api/v2/..." ──────────────────
        if node.type == 'ConditionalExpression':
            for branch in (node.consequent, node.alternate):
                val = self._try_extract_string(branch)
                if val and self._looks_like_api_path(val):
                    self._emit(val, 'GET', 'ternary_branch')

        # ── Switch/case return values ───────────────────────────────────────
        if node.type == 'SwitchStatement':
            for case in node.cases:
                for stmt in case.consequent:
                    self._scan_for_paths_in_stmt(stmt)

        # ── if/else return values ───────────────────────────────────────────
        if node.type == 'IfStatement':
            for branch in filter(None, [node.consequent, node.alternate]):
                self._scan_for_paths_in_stmt(branch)

    def _scan_for_paths_in_stmt(self, node):
        if node is None:
            return
        if node.type == 'ReturnStatement' and node.argument:
            val = self._try_extract_string(node.argument)
            if val and self._looks_like_api_path(val):
                self._emit(val, 'GET', 'branch_return')
        if node.type == 'ExpressionStatement':
            expr = node.expression
            if expr.type == 'AssignmentExpression':
                val = self._try_extract_string(expr.right)
                if val and self._looks_like_api_path(val):
                    self._emit(val, 'GET', 'branch_assignment')
        if node.type == 'BlockStatement':
            for stmt in node.body:
                self._scan_for_paths_in_stmt(stmt)

    def _try_extract_string(self, node):
        if node is None:
            return None
        if node.type == 'Literal' and isinstance(node.value, str):
            return node.value
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._try_extract_string(node.left)  or ''
            r = self._try_extract_string(node.right) or ''
            combined = l + r
            return combined if combined else None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    parts.append(self._try_extract_string(node.expressions[i]) or '')
            return ''.join(parts)
        return None

    def _looks_like_api_path(self, s):
        """Strict check: path must have real API indicators, not just start with /."""
        if not isinstance(s, str) or len(s) < 4:
            return False
        # Full http/ws URLs always qualify
        if s.startswith(('http://', 'https://', 'ws://', 'wss://')):
            return True
        # Fragment-only paths need an API indicator
        if s.startswith('/') or s.startswith('#/'):
            return bool(self._API_RE.search(s))
        return False

    def _emit(self, path, method, source):
        self.found.append({
            'method':     method,
            'endpoint':   path,
            'type':       'AST_BRANCH_LOGIC',
            'classification': 'BACKEND_API',
            'source':     source,
            'ast_extracted': True,
            'confidence_bonus': 1,
        })

# ⭐ ENHANCEMENT 2.2: New extractor for object property access patterns
class ObjectExpressionExtractor:
    """
    EXTRACTOR 4: ObjectExpressionExtractor
    Handles patterns like: service["DeleteUser"], obj[key], endpoints.users
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        # Handle object literals with URL values
        if node.type == 'ObjectExpression':
            for prop in node.properties:
                if hasattr(prop, 'value'):
                    val = self._try_extract_value(prop.value)
                    if val and self._looks_like_path(val):
                        key_name = self._get_property_key(prop)
                        self._emit(val, 'GET', 'object_property', key_name)

        # Handle variable declarations with object assignments
        if node.type == 'VariableDeclarator' and node.init:
            if node.init.type == 'ObjectExpression':
                for prop in node.init.properties:
                    if hasattr(prop, 'value'):
                        val = self._try_extract_value(prop.value)
                        if val and self._looks_like_path(val):
                            key_name = self._get_property_key(prop)
                            self._emit(val, 'GET', 'object_var_property', key_name)

    def _get_property_key(self, prop):
        """Extract the property key name"""
        if hasattr(prop, 'key'):
            if prop.key.type == 'Identifier':
                return prop.key.name
            elif prop.key.type == 'Literal':
                return str(prop.key.value)
        return None

    def _try_extract_value(self, node):
        """Try to extract a string value from various node types"""
        if node.type == 'Literal' and isinstance(node.value, str):
            return node.value
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._try_extract_value(node.left) or ''
            r = self._try_extract_value(node.right) or ''
            return l + r if (l or r) else None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    expr_val = self._try_extract_value(node.expressions[i])
                    parts.append(expr_val if expr_val else '{var}')
            return ''.join(parts)
        return None

    def _looks_like_path(self, s):
        if not isinstance(s, str) or len(s) < 2:
            return False
        # '/api' must be an anchored prefix, not a substring anywhere in s
        # to avoid matching docs/configs/error messages that contain '/api' mid-string
        return (s.startswith('/')
                or s.startswith('http')
                or s.startswith('/api')
                or (s.startswith('#/') and len(s) > 3))

    def _emit(self, path, method, source, key_name=None):
        self.found.append({
            'method': method,
            'endpoint': path,
            'type': 'AST_OBJECT_PROPERTY',
            'classification': 'BACKEND_API',
            'source': source,
            'key_name': key_name,
            'ast_extracted': True,
            'confidence_bonus': 2,
        })
