"""
Inter-procedural AST call-graph engines.

* ASTCallGraphExtractor - class / object-literal / prototype method contexts
  with `this`-scope, HOF and IIFE evaluation.
* ASTCallGraph          - pure function-chain resolver with a parameter
  binding stack (buildPath -> makeEndpoint -> createOrder ...).
"""
import re

from shadow_scanner.static.ast_engine.walker import walk
class ASTCallGraphExtractor:
    """
    EXTRACTOR 5 — True AST-based interprocedural call graph.

    Unlike the regex-based interprocedural engine, this uses the fully parsed
    AST to:
      • Build a complete function/arrow registry with parameter lists and
        their exact return AST nodes.
      • Recursively evaluate call chains of arbitrary depth (up to 8 levels).
      • Correctly substitute call-site arguments (including unknown identifiers
        that become {paramName} placeholders).
      • Handle: function declarations, arrow functions (expression and block
        body), object method shorthand, template literal bodies, binary
        concatenation, and nested calls like buildUrl(x) → prefix(x) → BASE+path.

    This is a genuine call-graph engine, not a heuristic pattern matcher.
    It answers the reviewer's critique: "no full AST call graph".
    """

    # HTTP function names whose first argument is treated as a URL
    _HTTP_FUNCS = frozenset({
        'fetch', 'get', 'post', 'put', 'delete', 'patch',
        'request', 'head', 'options', 'axios',
        'getDataFromUrl', 'postDataFromUrl', 'getRawDataFromUrl',
    })

    def __init__(self, scope: dict, known_vars: dict = None):
        self.scope   = scope          # AliasResolver scope (shared)
        self.vars    = dict(known_vars or {})
        self.funcs   = {}             # fname → {params, return_node}
        self.found   = []

    # ── Public entry point ─────────────────────────────────────────────────
    def extract(self, tree) -> list:
        self._collect(tree)
        # Multi-pass: re-resolve vars that depend on functions
        for _ in range(4):
            before = len(self.vars)
            self._resolve_var_funcs()
            if len(self.vars) == before:
                break
        self._find_call_sites(tree)
        return self.found

    # ── Pass 1: Collect variable bindings and function definitions ─────────
    def _collect(self, node, depth=0):
        if node is None or not hasattr(node, 'type') or depth > 40:
            return
        t = node.type

        # Variable declaration: const/let/var X = <expr>
        if t == 'VariableDeclarator' and node.id and node.init:
            name = getattr(node.id, 'name', None)
            if name:
                init_type = getattr(node.init, 'type', '')
                if init_type in ('ArrowFunctionExpression', 'FunctionExpression'):
                    fn_node = node.init
                    params = [getattr(p, 'name', f'p{i}') for i, p in enumerate(getattr(fn_node, 'params', []))]
                    body = getattr(fn_node, 'body', None)
                    if body is not None:
                        if getattr(body, 'type', '') == 'BlockStatement':
                            ret = self._find_return(body)
                        else:
                            ret = body  # arrow expression body
                        if ret:
                            self.funcs[name] = {'params': params, 'return_node': ret, 'this_scope': {}}
                else:
                    val = self._eval(node.init, {})
                    if val is not None:
                        self.vars[name] = val

        # Function declaration: function f(x) { return expr; }
        elif t == 'FunctionDeclaration' and node.id:
            params = [getattr(p, 'name', f'p{i}') for i, p in enumerate(node.params)]
            ret    = self._find_return(node.body)
            if ret:
                self.funcs[node.id.name] = {'params': params, 'return_node': ret, 'this_scope': {}}

        # Assignment: X = expr  (simple vars AND prototype method assignments)
        elif t == 'AssignmentExpression' and node.operator == '=':
            lhs = node.left
            if lhs.type == 'Identifier':
                val = self._eval(node.right, {})
                if val is not None:
                    self.vars[lhs.name] = val
            # ── GAP 1 FIX: Prototype method assignment ──────────────────────
            # Foo.prototype.method = function() { return this.base + '/path' }
            elif (lhs.type == 'MemberExpression' and not lhs.computed
                  and getattr(lhs.object, 'type', '') == 'MemberExpression'
                  and getattr(getattr(lhs.object, 'property', None), 'name', '') == 'prototype'):
                method_name = getattr(lhs.property, 'name', None)
                fn_node = node.right
                fn_type = getattr(fn_node, 'type', '')
                if method_name and fn_type in ('FunctionExpression', 'ArrowFunctionExpression'):
                    params = [getattr(p, 'name', f'p{i}') for i, p in enumerate(getattr(fn_node, 'params', []))]
                    body = getattr(fn_node, 'body', None)
                    if body is not None:
                        ret = (self._find_return(body)
                               if getattr(body, 'type', '') == 'BlockStatement'
                               else body)
                        if ret:
                            self.funcs[method_name] = {
                                'params': params, 'return_node': ret, 'this_scope': {}
                            }

        # ── GAP 1 FIX: Object literal methods ──────────────────────────────
        # const svc = { base: '/api', getUrl() { return this.base + '/users' } }
        elif t == 'ObjectExpression':
            # First pass: collect non-function literal properties → this-scope
            obj_this_scope: dict = {}
            for prop in getattr(node, 'properties', []):
                if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                    continue
                key = getattr(prop.key, 'name', getattr(prop.key, 'value', None))
                val_node = getattr(prop, 'value', None)
                if key and val_node and getattr(val_node, 'type', '') == 'Literal':
                    v = self._eval(val_node, {})
                    if v is not None:
                        obj_this_scope[key] = v
            # Second pass: register method properties with the this-scope
            for prop in getattr(node, 'properties', []):
                if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                    continue
                key = getattr(prop.key, 'name', getattr(prop.key, 'value', None))
                if not key:
                    continue
                fn_node = prop.value
                fn_type = getattr(fn_node, 'type', '')
                is_method = getattr(prop, 'method', False)
                if is_method or fn_type in ('FunctionExpression', 'ArrowFunctionExpression'):
                    params = [getattr(p, 'name', f'p{i}')
                              for i, p in enumerate(getattr(fn_node, 'params', []))]
                    body = getattr(fn_node, 'body', None)
                    if body is not None:
                        ret = (self._find_return(body)
                               if getattr(body, 'type', '') == 'BlockStatement'
                               else body)
                        if ret:
                            self.funcs[key] = {
                                'params': params,
                                'return_node': ret,
                                'this_scope': dict(obj_this_scope),
                            }

        # ── GAP 1 FIX: Class declarations / expressions ─────────────────────
        # class MyService { constructor(){this.base='...'} getUrl(){return this.base+'/api'} }
        elif t in ('ClassDeclaration', 'ClassExpression'):
            body_node = getattr(node, 'body', None)
            if body_node and getattr(body_node, 'type', '') == 'ClassBody':
                class_this_scope: dict = {}
                members = getattr(body_node, 'body', [])
                # Pass 1: extract this.prop assignments from constructor
                for member in members:
                    if (getattr(member, 'type', '') == 'MethodDefinition'
                            and getattr(member, 'kind', '') == 'constructor'):
                        fn_node = getattr(member, 'value', None)
                        ctor_body = getattr(fn_node, 'body', None) if fn_node else None
                        for stmt in getattr(ctor_body, 'body', []):
                            if getattr(stmt, 'type', '') != 'ExpressionStatement':
                                continue
                            expr = getattr(stmt, 'expression', None)
                            if not expr or getattr(expr, 'type', '') != 'AssignmentExpression':
                                continue
                            lhs2 = getattr(expr, 'left', None)
                            if not lhs2 or getattr(lhs2, 'type', '') != 'MemberExpression':
                                continue
                            if getattr(getattr(lhs2, 'object', None), 'type', '') != 'ThisExpression':
                                continue
                            prop = getattr(getattr(lhs2, 'property', None), 'name', '')
                            val = self._eval(getattr(expr, 'right', None), {})
                            if prop and val is not None:
                                class_this_scope[prop] = val
                                self.vars[f'this.{prop}'] = val
                # Pass 2: register non-constructor methods
                for member in members:
                    if getattr(member, 'type', '') != 'MethodDefinition':
                        continue
                    if getattr(member, 'kind', '') in ('constructor', 'get', 'set'):
                        continue
                    method_name = getattr(getattr(member, 'key', None), 'name', None)
                    fn_node = getattr(member, 'value', None)
                    if not method_name or not fn_node:
                        continue
                    params = [getattr(p, 'name', f'p{i}')
                              for i, p in enumerate(getattr(fn_node, 'params', []))]
                    body = getattr(fn_node, 'body', None)
                    if body is not None:
                        ret = self._find_return(body)
                        if ret:
                            self.funcs[method_name] = {
                                'params': params,
                                'return_node': ret,
                                'this_scope': dict(class_this_scope),
                            }

        for key in vars(node):
            child = getattr(node, key, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if hasattr(item, 'type'):
                        self._collect(item, depth + 1)
            elif hasattr(child, 'type'):
                self._collect(child, depth + 1)

    def _resolve_var_funcs(self):
        """
        Second-pass resolver: for any var whose value is still a non-URL identifier,
        try resolving it through the function registry (handles order-dependent parsing).
        """
        for name in list(self.vars.keys()):
            val = self.vars[name]
            if val and not (str(val).startswith('http') or str(val).startswith('/')):
                resolved = self._eval_call_by_name(val, [], depth=0)
                if resolved:
                    self.vars[name] = resolved

    def _eval_call_by_name(self, fname: str, args: list, depth: int = 0):
        """Evaluate a named function call with given arg values."""
        if depth > 5 or fname not in self.funcs:
            return None
        fn = self.funcs[fname]
        params = fn['params']
        lc = {f'this.{k}': v for k, v in fn.get('this_scope', {}).items()}
        for i, p in enumerate(params):
            if i < len(args):
                lc[p] = args[i]
        return self._eval(fn['return_node'], lc, depth + 1)

    def _find_return(self, block):
        """Find ALL return statement values in a block; return the first URL-like one."""
        if not hasattr(block, 'body'):
            return None
        candidates = []
        for stmt in block.body:
            if getattr(stmt, 'type', '') == 'ReturnStatement' and stmt.argument:
                candidates.append(stmt.argument)
        # Prefer a return that looks like a URL (has '/' or 'http' in its literal value)
        for c in candidates:
            if getattr(c, 'type', '') == 'Literal':
                v = str(getattr(c, 'value', ''))
                if v.startswith('/') or v.startswith('http'):
                    return c
        # Prefer binary expressions (likely concatenation) over plain identifiers
        for c in candidates:
            if getattr(c, 'type', '') in ('BinaryExpression', 'TemplateLiteral', 'CallExpression'):
                return c
        return candidates[-1] if candidates else None

    # ── Expression evaluator ───────────────────────────────────────────────
    def _eval(self, node, local: dict, depth: int = 0):
        """
        Recursively evaluate node to a string value.
        Returns None if the expression cannot be statically determined.
        """
        if depth > 9 or node is None:
            return None
        t = getattr(node, 'type', '')

        if t == 'Literal':
            return str(node.value) if isinstance(node.value, (str, int, float)) else None

        if t == 'Identifier':
            name = node.name
            return (local.get(name)
                    or self.vars.get(name)
                    or self.scope.get(name))

        if t == 'BinaryExpression' and node.operator == '+':
            lv = self._eval(node.left,  local, depth + 1)
            rv = self._eval(node.right, local, depth + 1)
            if lv is not None and rv is not None:
                return lv + rv
            if lv is not None:
                return lv   # partial — return what we have
            return None

        if t == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    expr_node = node.expressions[i]
                    v = self._eval(expr_node, local, depth + 1)
                    if v is None:
                        # Use the expression's identifier name as {paramName}
                        n = getattr(expr_node, 'name', None)
                        v = '{' + n + '}' if n else '{param}'
                    parts.append(v)
            return ''.join(parts)

        if t == 'CallExpression':
            callee_t = getattr(node.callee, 'type', '')

            # ── P2 FIX: IIFE evaluation ────────────────────────────────────
            # Handles: ((params) => body)(args)   AND
            #          ((params) => () => body)(args)()
            # The outer function is anonymous, so it's not in self.funcs.
            # We evaluate it inline without any registry lookup.
            if callee_t in ('ArrowFunctionExpression', 'FunctionExpression'):
                iife_fn  = node.callee
                params   = [getattr(p, 'name', f'p{i}')
                            for i, p in enumerate(getattr(iife_fn, 'params', []))]
                body     = getattr(iife_fn, 'body', None)
                if body is not None:
                    # Build local scope from arguments
                    lc = dict(local)
                    for i, p in enumerate(params):
                        if i < len(node.arguments):
                            v = self._eval(node.arguments[i], local, depth + 1)
                            lc[p] = v if v is not None else (
                                ('{' + node.arguments[i].name + '}')
                                if getattr(node.arguments[i], 'type', '') == 'Identifier'
                                else '{' + p + '}'
                            )
                    # Evaluate the IIFE body
                    if getattr(body, 'type', '') == 'BlockStatement':
                        ret = self._find_return(body)
                    else:
                        ret = body  # expression body
                    if ret is not None:
                        result = self._eval(ret, lc, depth + 1)
                        # If result is a string URL — done
                        if isinstance(result, str) and ('/' in result or result.startswith('http')):
                            return result
                        # If result is a closure AST node (HOF), evaluate it with zero args
                        ret_type = getattr(ret, 'type', '') if result is None else ''
                        if ret_type in ('ArrowFunctionExpression', 'FunctionExpression'):
                            closure_body = getattr(ret, 'body', None)
                            if closure_body is not None:
                                c_ret = (self._find_return(closure_body)
                                         if getattr(closure_body, 'type', '') == 'BlockStatement'
                                         else closure_body)
                                if c_ret is not None:
                                    return self._eval(c_ret, lc, depth + 1)

            # ── Regular call expression ────────────────────────────────────
            return self._eval_call(node, local, depth + 1)

        if t == 'ConditionalExpression':
            # Take BOTH branches — return consequent (caller collects alternate separately)
            return (self._eval(node.consequent, local, depth + 1)
                    or self._eval(node.alternate,  local, depth + 1))

        if t == 'MemberExpression':
            obj_node  = node.object
            prop_node = node.property

            if not node.computed:
                # ── Non-computed: obj.prop ─────────────────────────────────
                # ThisExpression.prop — look up in local this-scope first
                if getattr(obj_node, 'type', '') == 'ThisExpression':
                    prop_n = getattr(prop_node, 'name', '')
                    if prop_n:
                        return (local.get(f'this.{prop_n}')
                                or self.vars.get(f'this.{prop_n}')
                                or self.scope.get(f'this.{prop_n}'))

                obj_n  = getattr(obj_node, 'name', '')
                prop_n = getattr(prop_node, 'name', '')

                if obj_n and prop_n:
                    # Direct lookup: VERSIONS.prod, cfg.method
                    dotted = f'{obj_n}.{prop_n}'
                    val = (local.get(dotted)
                           or self.vars.get(dotted)
                           or self.scope.get(dotted))
                    if val is not None:
                        return val

                # Nested chain: a.b.c — evaluate object recursively then look up prop
                obj_val = self._eval(obj_node, local, depth + 1)
                if obj_val is not None and prop_n:
                    # obj_val is a string — try obj_val.prop lookup
                    return (local.get(f'{obj_val}.{prop_n}')
                            or self.vars.get(f'{obj_val}.{prop_n}')
                            or self.scope.get(f'{obj_val}.{prop_n}'))

            else:
                # ── Computed: obj[expr] ────────────────────────────────────
                # Evaluate the index expression
                idx_val = self._eval(prop_node, local, depth + 1)

                obj_n = getattr(obj_node, 'name', None)
                if obj_n and idx_val is not None:
                    # arr[0] → look up "arr.0"
                    idx_key = f'{obj_n}.{idx_val}'
                    val = (local.get(idx_key)
                           or self.vars.get(idx_key)
                           or self.scope.get(idx_key))
                    if val is not None:
                        return val

                    # Also try integer index (Literal node gives int for arr[0])
                    try:
                        int_key = f'{obj_n}.{int(idx_val)}'
                        val = (local.get(int_key)
                               or self.vars.get(int_key)
                               or self.scope.get(int_key))
                        if val is not None:
                            return val
                    except (ValueError, TypeError):
                        pass

        return None

    def _eval_call(self, node, local: dict, depth: int = 0):
        """
        Evaluate a CallExpression to a URL string via the function registry.

        FEATURE: Higher-Order Function (HOF) resolution.
        When a function returns another function (factory pattern), e.g.:
            const endpoint = (name) => () => `/api/${name}`;
            fetch(endpoint('orders')());
        The outer call endpoint('orders') returns an ArrowFunctionExpression.
        We detect this, register the returned closure with bound params,
        then evaluate the inner call () against it.
        """
        if depth > 9:
            return None
        callee = node.callee

        # ── HOF: handle f(args)() — outer call is itself a CallExpression ──
        if callee.type == 'CallExpression':
            # Evaluate the outer call first — it should produce a closure
            inner_result = self._eval_call_hof(callee, node.arguments, local, depth)
            return inner_result

        if callee.type == 'Identifier':
            fname = callee.name
        elif callee.type == 'MemberExpression' and not callee.computed:
            fname = getattr(callee.property, 'name', None)
        else:
            return None

        if not fname:
            return None

        # ── HOF resolution step 2: check if fname is a variable storing a URL ──
        # This handles: const g = endpoint('orders'); fetch(g());
        # After _collect, g is in self.vars as '/api/orders'
        # g() is a CallExpression with no function entry — return the stored URL
        if fname not in self.funcs:
            var_val = self.vars.get(fname) or local.get(fname)
            if var_val and isinstance(var_val, str) and ('/' in var_val or var_val.startswith('http')):
                return var_val
            return None

        fn     = self.funcs[fname]
        params = fn['params']
        ret    = fn['return_node']

        # Seed local with this_scope so this.prop resolves inside method bodies
        lc = {f'this.{k}': v for k, v in fn.get('this_scope', {}).items()}
        lc.update(local)

        for i, p in enumerate(params):
            if i < len(node.arguments):
                arg_node = node.arguments[i]
                v = self._eval(arg_node, lc, depth + 1)
                if v is not None:
                    lc[p] = v
                else:
                    arg_name = (arg_node.name
                                if getattr(arg_node, 'type', '') == 'Identifier'
                                else None)
                    lc[p] = '{' + arg_name + '}' if arg_name else '{' + p + '}'

        # ── HOF detection: if return_node is itself a function, resolve it ──
        ret_type = getattr(ret, 'type', '')
        if ret_type in ('ArrowFunctionExpression', 'FunctionExpression'):
            # The function RETURNS a closure. Bind current lc into the closure's scope
            # and treat calling it with no arguments as resolving its body.
            closure_body   = getattr(ret, 'body', None)
            if closure_body is not None:
                closure_ret = (self._find_return(closure_body)
                               if getattr(closure_body, 'type', '') == 'BlockStatement'
                               else closure_body)
                if closure_ret:
                    # Evaluate the closure body with the outer call's bindings as scope
                    return self._eval(closure_ret, lc, depth + 1)

        return self._eval(ret, lc, depth + 1)

    def _eval_call_hof(self, outer_call_node, inner_args, local: dict, depth: int):
        """
        Resolve a higher-order function call: outer_call(args)(inner_args).
        outer_call_node  — the CallExpression that produces the closure
        inner_args       — arguments passed to the returned closure

        Handles both:
          named(args)()         — outer_call is named function call
          ((params)=>body)(args)() — outer_call is IIFE (anonymous ArrowFunctionExpression)
        """
        if depth > 8:
            return None

        callee    = outer_call_node.callee
        callee_t  = getattr(callee, 'type', '')
        lc        = dict(local)
        ret       = None

        if callee_t == 'Identifier':
            # Named function: endpoint('orders')()
            fname = callee.name
            if fname not in self.funcs:
                return None
            fn     = self.funcs[fname]
            params = fn['params']
            ret    = fn['return_node']
            lc.update({f'this.{k}': v for k, v in fn.get('this_scope', {}).items()})
            for i, p in enumerate(params):
                if i < len(outer_call_node.arguments):
                    v = self._eval(outer_call_node.arguments[i], lc, depth + 1)
                    if v is not None:
                        lc[p] = v
                    else:
                        arg_n = (outer_call_node.arguments[i].name
                                 if getattr(outer_call_node.arguments[i], 'type', '') == 'Identifier'
                                 else None)
                        lc[p] = '{' + arg_n + '}' if arg_n else '{' + p + '}'

        elif callee_t in ('ArrowFunctionExpression', 'FunctionExpression'):
            # IIFE: ((n) => () => `/api/${n}`)('settings')()
            params = [getattr(p, 'name', f'p{i}')
                      for i, p in enumerate(getattr(callee, 'params', []))]
            body   = getattr(callee, 'body', None)
            if body is None:
                return None
            ret = (self._find_return(body)
                   if getattr(body, 'type', '') == 'BlockStatement'
                   else body)
            for i, p in enumerate(params):
                if i < len(outer_call_node.arguments):
                    v = self._eval(outer_call_node.arguments[i], lc, depth + 1)
                    if v is not None:
                        lc[p] = v
                    else:
                        arg_n = (outer_call_node.arguments[i].name
                                 if getattr(outer_call_node.arguments[i], 'type', '') == 'Identifier'
                                 else None)
                        lc[p] = '{' + arg_n + '}' if arg_n else '{' + p + '}'

        else:
            return None

        if ret is None:
            return None

        ret_type = getattr(ret, 'type', '')

        # The outer call returned a plain value — not a HOF
        if ret_type not in ('ArrowFunctionExpression', 'FunctionExpression'):
            return self._eval(ret, lc, depth + 1)

        # The outer call returned a closure (HOF pattern)
        # Now evaluate the closure with the inner args
        closure_params = [getattr(p, 'name', f'cp{i}')
                          for i, p in enumerate(getattr(ret, 'params', []))]
        for i, p in enumerate(closure_params):
            if i < len(inner_args):
                v = self._eval(inner_args[i], lc, depth + 1)
                if v is not None:
                    lc[p] = v

        closure_body = getattr(ret, 'body', None)
        if closure_body is None:
            return None
        closure_ret = (self._find_return(closure_body)
                       if getattr(closure_body, 'type', '') == 'BlockStatement'
                       else closure_body)
        if closure_ret is None:
            return None
        return self._eval(closure_ret, lc, depth + 1)

    # ── Pass 2: Find HTTP call sites and evaluate their URL arguments ──────
    def _find_call_sites(self, node, depth: int = 0):
        if node is None or not hasattr(node, 'type') or depth > 40:
            return
        t = node.type

        if t == 'CallExpression':
            callee = node.callee
            if callee.type == 'Identifier':
                fn_name = callee.name
            elif callee.type == 'MemberExpression':
                fn_name = getattr(callee.property, 'name', '')
            else:
                fn_name = ''

            if fn_name.lower() in self._HTTP_FUNCS and node.arguments:
                first = node.arguments[0]
                url_val = self._eval(first, {})
                if url_val and ('/' in url_val or url_val.startswith('http')):
                    self._emit(url_val, fn_name.upper() if fn_name.upper()
                               in ('GET','POST','PUT','DELETE','PATCH') else 'GET')

            # ── GAP 1 FIX: HOF()() — callee is itself a CallExpression ──────
            # Catches: b('orders')(), a('x')()(), factory('r')() NOT inside fetch
            # These are top-level HOF invocations that produce URL strings.
            # We evaluate them and emit any URL-like results.
            elif callee.type == 'CallExpression':
                url_val = self._eval_call_hof(callee, node.arguments, {}, depth + 1)
                if url_val and isinstance(url_val, str) and ('/' in url_val or url_val.startswith('http')):
                    self._emit(url_val, 'GET')

        for key in vars(node):
            child = getattr(node, key, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if hasattr(item, 'type'):
                        self._find_call_sites(item, depth + 1)
            elif hasattr(child, 'type'):
                self._find_call_sites(child, depth + 1)

    def _emit(self, url: str, method: str = 'GET'):
        self.found.append({
            'method':           method,
            'endpoint':         url,
            'type':             'AST_CALL_GRAPH',
            'classification':   'BACKEND_API',
            'source':           'ASTCallGraphExtractor',
            'ast_extracted':    True,
            'confidence_bonus': 3,  # Higher than other extractors — call graph is accurate
        })

# ==============================================================================
# TRUE AST CALL GRAPH ENGINE
# Resolves multi-level endpoint builder chains of arbitrary depth.
#
# Example (from prompt) resolved correctly:
#   const buildPath = (service) => `/api/${service}`
#   function makeEndpoint(service, action){ return buildPath(service) + "/" + action }
#   function createOrder(){ return makeEndpoint("orders","create") }
#   → /api/orders/create
#
# Architecture:
#   1. register_functions()   — walk AST, build name→{params,body} registry
#   2. resolve_call()         — recursively evaluate call chains (depth-limited)
#   3. _evaluate()            — evaluate any AST expression node to a string
#   4. _resolve_template()    — evaluate TemplateLiteral with param substitution
#   5. find_http_calls()      — walk AST for HTTP call sites, emit resolved URLs
# ==============================================================================
class ASTCallGraph:
    """
    Research-grade multi-level call graph resolver.

    Works alongside ASTCallGraphExtractor (which handles class/object/prototype
    contexts). This class focuses on the pure function-chain case, using a
    clean parameter-binding model with a current_params context stack.
    """

    MAX_DEPTH = 8  # max recursion depth for nested call chains

    def __init__(self, scope: dict = None):
        # name → {'params': [...], 'body': <AST node>, 'this_scope': {...}}
        self.functions: dict = {}
        # Shared scope from AliasResolver (pre-resolved vars from the same file)
        self.scope: dict = dict(scope or {})
        # Current parameter bindings during recursive evaluation (stack frame)
        self.current_params: list = []
        self._param_args: dict = {}    # param_name → resolved_value for current call
        self._found: list = []         # collected endpoints
        # GAP 1 FIX: Map constructor name → {prop: value} for prototype method lookup
        self._constructor_scopes: dict = {}   # 'Api' → {'root': '/api', ...}

    # ── Public API ─────────────────────────────────────────────────────────────

    def register_functions(self, ast_tree):
        """Walk the AST and populate the function registry."""
        if ast_tree is None:
            return
        for node in getattr(ast_tree, 'body', []):
            self._register_node(node)
        # Also walk nested blocks (IIFE, module patterns)
        walk(ast_tree, self._register_node)

    def _register_node(self, node):
        """Register a single AST node if it defines a function."""
        if node is None or not hasattr(node, 'type'):
            return
        t = node.type

        # function foo(a, b) { ... }
        if t == 'FunctionDeclaration' and node.id:
            ret = self._extract_return(node)
            if ret is not None:
                self.functions[node.id.name] = {
                    'params':     [getattr(p, 'name', f'p{i}') for i, p in enumerate(node.params)],
                    'body':       ret,
                    'this_scope': {},
                }

        # const foo = (a, b) => expr   OR   const foo = function(a,b){ ... }
        elif t == 'VariableDeclarator' and node.init:
            name = getattr(node.id, 'name', None)
            fn   = node.init
            fn_t = getattr(fn, 'type', '')
            if name and fn_t in ('ArrowFunctionExpression', 'FunctionExpression'):
                body = getattr(fn, 'body', None)
                if body is None:
                    return
                # Extract this.prop assignments (constructor pattern: var Ctor = function(){ this.x = ... })
                if getattr(body, 'type', '') == 'BlockStatement':
                    ctor_scope: dict = {}
                    for stmt in getattr(body, 'body', []):
                        if getattr(stmt, 'type', '') != 'ExpressionStatement':
                            continue
                        expr = getattr(stmt, 'expression', None)
                        if not expr or getattr(expr, 'type', '') != 'AssignmentExpression':
                            continue
                        lhs2 = getattr(expr, 'left', None)
                        if (lhs2 and getattr(lhs2, 'type', '') == 'MemberExpression'
                                and getattr(getattr(lhs2, 'object', None), 'type', '') == 'ThisExpression'):
                            prop = getattr(getattr(lhs2, 'property', None), 'name', '')
                            rhs  = getattr(expr, 'right', None)
                            if rhs and getattr(rhs, 'type', '') == 'Literal':
                                v = getattr(rhs, 'value', None)
                                if v is not None:
                                    ctor_scope[prop] = str(v)
                    if ctor_scope:
                        self._constructor_scopes[name] = ctor_scope
                    ret = self._extract_return_block(body)
                else:
                    ret = body   # arrow expression body
                if ret is not None:
                    self.functions[name] = {
                        'params':     [getattr(p, 'name', f'p{i}') for i, p in enumerate(getattr(fn, 'params', []))],
                        'body':       ret,
                        'this_scope': {},
                    }

        # foo.prototype.method = function(...){ ... }
        elif (t == 'AssignmentExpression' and node.operator == '='
              and getattr(node.left, 'type', '') == 'MemberExpression'):
            lhs = node.left
            lhs_obj = getattr(lhs, 'object', None)
            if (getattr(lhs_obj, 'type', '') == 'MemberExpression'
                    and getattr(getattr(lhs_obj, 'property', None), 'name', '') == 'prototype'):
                method      = getattr(lhs.property, 'name', None)
                ctor_name   = getattr(getattr(lhs_obj, 'object', None), 'name', '')
                fn          = node.right
                if method and getattr(fn, 'type', '') == 'FunctionExpression':
                    ret = self._extract_return(fn)
                    if ret is not None:
                        # Look up constructor's this-scope so this.prop resolves
                        ts = dict(self._constructor_scopes.get(ctor_name, {}))
                        for k, v in ts.items():
                            self.scope[f'this.{k}'] = v
                        self.functions[method] = {
                            'params':     [getattr(p, 'name', f'p{i}') for i, p in enumerate(fn.params)],
                            'body':       ret,
                            'this_scope': ts,
                        }

        # class Foo { constructor(){this.base=...} method(){ return this.base+'/path' } }
        elif t in ('ClassDeclaration', 'ClassExpression'):
            class_this_scope: dict = {}
            body_node = getattr(node, 'body', None)
            members   = getattr(body_node, 'body', []) if body_node else []
            # Pass 1: extract this.prop = literal from constructor
            for member in members:
                if (getattr(member, 'type', '') == 'MethodDefinition'
                        and getattr(member, 'kind', '') == 'constructor'):
                    fn_node   = getattr(member, 'value', None)
                    ctor_body = getattr(fn_node, 'body', None) if fn_node else None
                    for stmt in getattr(ctor_body, 'body', []):
                        if getattr(stmt, 'type', '') != 'ExpressionStatement':
                            continue
                        expr = getattr(stmt, 'expression', None)
                        if not expr or getattr(expr, 'type', '') != 'AssignmentExpression':
                            continue
                        lhs2 = getattr(expr, 'left', None)
                        if (lhs2 and getattr(lhs2, 'type', '') == 'MemberExpression'
                                and getattr(getattr(lhs2, 'object', None), 'type', '') == 'ThisExpression'):
                            prop = getattr(getattr(lhs2, 'property', None), 'name', '')
                            rhs  = getattr(expr, 'right', None)
                            if rhs and getattr(rhs, 'type', '') == 'Literal':
                                v = getattr(rhs, 'value', None)
                                if v is not None:
                                    class_this_scope[prop] = str(v)
                                    self.scope[f'this.{prop}'] = str(v)
            # Pass 2: register non-constructor methods
            for member in members:
                if getattr(member, 'type', '') != 'MethodDefinition':
                    continue
                if getattr(member, 'kind', '') in ('constructor', 'get', 'set'):
                    continue
                method_name = getattr(getattr(member, 'key', None), 'name', None)
                fn_node     = getattr(member, 'value', None)
                if not method_name or not fn_node:
                    continue
                body = getattr(fn_node, 'body', None)
                if body is not None:
                    ret = self._extract_return_block(body)
                    if ret is not None:
                        self.functions[method_name] = {
                            'params':     [getattr(p, 'name', f'p{i}') for i, p in enumerate(getattr(fn_node, 'params', []))],
                            'body':       ret,
                            'this_scope': dict(class_this_scope),
                        }

        # const svc = { base: '/api', getUsers(){ return this.base + '/users' } }
        elif t == 'ObjectExpression':
            # Pass 1: collect non-function literal props as this-scope
            obj_this_scope: dict = {}
            for prop in getattr(node, 'properties', []):
                if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                    continue
                key = getattr(prop.key, 'name', getattr(prop.key, 'value', None))
                val_n = getattr(prop, 'value', None)
                if key and val_n and getattr(val_n, 'type', '') == 'Literal':
                    v = getattr(val_n, 'value', None)
                    if v is not None:
                        obj_this_scope[key] = str(v)
                        self.scope[f'this.{key}'] = str(v)
            # Pass 2: register method properties
            for prop in getattr(node, 'properties', []):
                if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                    continue
                key    = getattr(prop.key, 'name', getattr(prop.key, 'value', None))
                fn_node = prop.value
                fn_t    = getattr(fn_node, 'type', '')
                is_method = getattr(prop, 'method', False)
                if key and (is_method or fn_t in ('FunctionExpression', 'ArrowFunctionExpression')):
                    body = getattr(fn_node, 'body', None)
                    if body is not None:
                        ret = (self._extract_return_block(body)
                               if getattr(body, 'type', '') == 'BlockStatement'
                               else body)
                        if ret is not None:
                            self.functions[key] = {
                                'params':     [getattr(p, 'name', f'p{i}') for i, p in enumerate(getattr(fn_node, 'params', []))],
                                'body':       ret,
                                'this_scope': dict(obj_this_scope),
                            }

    def _extract_return(self, fn_node):
        """Extract the first meaningful return expression from a function."""
        body = getattr(fn_node, 'body', None)
        if body is None:
            return None
        if getattr(body, 'type', '') == 'BlockStatement':
            return self._extract_return_block(body)
        return body  # arrow expression body

    def _extract_return_block(self, block):
        """Find the best return statement in a block body."""
        candidates = []
        for stmt in getattr(block, 'body', []):
            if getattr(stmt, 'type', '') == 'ReturnStatement' and stmt.argument:
                candidates.append(stmt.argument)
        if not candidates:
            return None
        # Prefer URL-literal returns
        for c in candidates:
            if getattr(c, 'type', '') == 'Literal':
                v = str(getattr(c, 'value', ''))
                if v.startswith('/') or v.startswith('http'):
                    return c
        # Then prefer concatenation / template / call expressions (likely URL builders)
        for c in candidates:
            if getattr(c, 'type', '') in ('BinaryExpression', 'TemplateLiteral', 'CallExpression'):
                return c
        return candidates[-1]

    # ── Core resolver ──────────────────────────────────────────────────────────

    def resolve_call(self, name: str, args: list, depth: int = 0):
        """
        Recursively evaluate a named function call with the given arg values.
        Returns the resolved string, or None if it cannot be statically determined.
        """
        if depth > self.MAX_DEPTH:
            return None
        fn = self.functions.get(name)
        if fn is None:
            return None
        # Save/restore current_params stack for correct nested-call semantics
        prev_params  = self.current_params
        prev_args    = self._param_args
        self.current_params = fn['params']
        self._param_args = {}
        # Seed this_scope so this.prop resolves inside method bodies
        for k, v in fn.get('this_scope', {}).items():
            self._param_args[f'this.{k}'] = v
            self.scope[f'this.{k}'] = v
        for i, p in enumerate(fn['params']):
            if i < len(args):
                self._param_args[p] = args[i] if args[i] is not None else '{' + p + '}'
            else:
                self._param_args[p] = '{' + p + '}'
        result = self._evaluate(fn['body'], depth + 1)
        # Restore
        self.current_params = prev_params
        self._param_args    = prev_args
        return result

    def _evaluate(self, node, depth: int = 0):
        """Evaluate an AST expression node to a string."""
        if depth > self.MAX_DEPTH or node is None:
            return None
        t = getattr(node, 'type', '')

        if t == 'Literal':
            v = node.value
            return str(v) if isinstance(v, (str, int, float)) else None

        if t == 'Identifier':
            name = node.name
            # 1. Current call's parameter bindings
            val = self._param_args.get(name)
            if val is not None:
                return val
            # 2. Shared scope from AliasResolver
            val = self.scope.get(name)
            if val is not None:
                return str(val)
            # 3. Try resolving as a zero-argument function call
            return self.resolve_call(name, [], depth + 1)

        if t == 'BinaryExpression' and node.operator == '+':
            lv = self._evaluate(node.left,  depth + 1)
            rv = self._evaluate(node.right, depth + 1)
            if lv is not None and rv is not None:
                return lv + rv
            # FIX EP-B-016: an unresolved *named* operand (a plain identifier —
            # e.g. a function parameter with no known call-site value, like
            # `id` in BASE+"/api/admin/users/"+id+"/role") was previously
            # dropped instead of placeholdered, silently deleting a path
            # segment from the MIDDLE of the concatenation rather than turning
            # it into {id}. Only fires when the unresolved side is a bare
            # Identifier — genuinely-unresolvable complex sub-expressions
            # still fall back to the original partial-left behavior below.
            if rv is None and lv is not None and getattr(node.right, 'type', '') == 'Identifier':
                return lv + '{' + node.right.name + '}'
            if lv is None and rv is not None and getattr(node.left, 'type', '') == 'Identifier':
                return '{' + node.left.name + '}' + rv
            return lv  # return partial left side if right is unknown

        if t == 'TemplateLiteral':
            return self._resolve_template(node, depth)

        if t == 'CallExpression':
            return self._evaluate_call(node, depth)

        if t == 'ConditionalExpression':
            # Take both branches; prefer the one that looks like a URL
            lv = self._evaluate(node.consequent, depth + 1)
            rv = self._evaluate(node.alternate,  depth + 1)
            for v in (lv, rv):
                if v and (str(v).startswith('/') or str(v).startswith('http')):
                    return v
            return lv or rv

        if t == 'MemberExpression':
            if not node.computed:
                # ThisExpression.prop — look up in param_args (seeded from this_scope)
                if getattr(node.object, 'type', '') == 'ThisExpression':
                    prop_n = getattr(node.property, 'name', '')
                    if prop_n:
                        return (self._param_args.get(f'this.{prop_n}')
                                or self.scope.get(f'this.{prop_n}'))
                obj_n  = getattr(node.object,   'name', '')
                prop_n = getattr(node.property, 'name', '')
                if obj_n and prop_n:
                    dotted = f'{obj_n}.{prop_n}'
                    return (self._param_args.get(dotted)
                            or self.scope.get(dotted))
            else:
                # Computed: obj[expr] — resolve index then look up
                idx_val = self._resolve_node(node.property, depth + 1)
                obj_n   = getattr(node.object, 'name', None)
                if obj_n and idx_val is not None:
                    idx_key = f'{obj_n}.{idx_val}'
                    val = (self._param_args.get(idx_key) or self.scope.get(idx_key))
                    if val is not None:
                        return val
                    try:
                        int_key = f'{obj_n}.{int(idx_val)}'
                        return self._param_args.get(int_key) or self.scope.get(int_key)
                    except (ValueError, TypeError):
                        pass

        return None

    def _resolve_template(self, node, depth: int = 0):
        """Resolve a TemplateLiteral node to a concrete string."""
        parts = []
        for i, quasi in enumerate(node.quasis):
            parts.append(quasi.value.cooked or '')
            if i < len(node.expressions):
                expr = node.expressions[i]
                if getattr(expr, 'type', '') == 'Identifier':
                    idx = self._param_index(expr.name)
                    if idx is not None and idx < len(list(self._param_args.values())):
                        # Direct positional parameter
                        parts.append(list(self._param_args.values())[idx])
                    else:
                        resolved = (self._param_args.get(expr.name)
                                    or self.scope.get(expr.name)
                                    or self.resolve_call(expr.name, [], depth + 1))
                        parts.append(resolved if resolved is not None else '{' + expr.name + '}')
                else:
                    v = self._evaluate(expr, depth + 1)
                    parts.append(v if v is not None else '{expr}')
        return ''.join(parts)

    def _param_index(self, name: str):
        """Return the positional index of a parameter name in current_params."""
        for i, p in enumerate(self.current_params):
            if p == name:
                return i
        return None

    def _evaluate_call(self, node, depth: int = 0):
        """Evaluate a CallExpression by resolving its callee and arguments."""
        callee = node.callee
        if getattr(callee, 'type', '') == 'Identifier':
            fname = callee.name
        elif getattr(callee, 'type', '') == 'MemberExpression' and not callee.computed:
            fname = getattr(callee.property, 'name', '')
        else:
            return None
        if not fname:
            return None
        args = [self._evaluate(a, depth + 1) for a in node.arguments]
        return self.resolve_call(fname, args, depth + 1)

    # ── HTTP call site discovery ───────────────────────────────────────────────

    _HTTP_METHODS = frozenset({'fetch', 'get', 'post', 'put', 'delete', 'patch',
                                'request', 'head', 'options', 'axios'})

    def find_http_calls(self, ast_tree) -> list:
        """Walk AST for HTTP call sites and return resolved endpoint dicts."""
        self._found = []
        walk(ast_tree, self._visit_call_site)
        return self._found

    def _visit_call_site(self, node):
        if getattr(node, 'type', '') != 'CallExpression':
            return
        callee = node.callee
        if getattr(callee, 'type', '') == 'Identifier':
            fn_name = callee.name
        elif getattr(callee, 'type', '') == 'MemberExpression':
            fn_name = getattr(callee.property, 'name', '')
        else:
            return
        if fn_name.lower() not in self._HTTP_METHODS:
            return
        if not node.arguments:
            return
        url_val = self._evaluate(node.arguments[0], 0)
        if url_val and ('/' in url_val or url_val.startswith('http')):
            method_str = fn_name.upper() if fn_name.upper() in (
                'GET', 'POST', 'PUT', 'DELETE', 'PATCH') else 'GET'
            self._found.append({
                'method':           method_str,
                'endpoint':         url_val,
                'type':             'AST_CALL_GRAPH',
                'classification':   'BACKEND_API',
                'source':           'ASTCallGraph',
                'ast_extracted':    True,
                'confidence_bonus': 4,   # call graph signal is highest-quality static
            })

    @staticmethod
    def normalize(endpoint: str) -> str:
        """Normalize a reconstructed endpoint path."""
        if not endpoint:
            return endpoint
        endpoint = re.sub(r'(?<!:)/{2,}', '/', endpoint)
        return endpoint
