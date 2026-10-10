"""Regex-level inter-procedural URL-builder evaluation + SSA propagation."""
import re
class InterproceduralMixin:
    """Regex-level inter-procedural evaluation of URL-building functions."""

    def _extract_interprocedural_calls(self, code, source):
        """Function registry + call-site evaluation, then SSA-style variable propagation."""
        # ── G1 COMPLETE: Full Interprocedural Call-Graph Engine ──────────────
        # Handles ALL function definition styles and multi-level composition:
        #   function buildUrl(path) { return BASE + "/api/" + path }
        #   const apiUrl = (path) => BASE + "/api/" + path
        #   const fullUrl = path => `${BASE}/api/${path}`
        #   function getRoute(resource = "default") { return BASE + "/api/" + resource }
        #   const api = { url(path) { return this.base + "/api/" + path } }
        #   function buildEndpoint(svc,act) { return prefix(svc) + "/" + act }
        #
        # Algorithm:
        #   Phase 1 — Extract function registry: name → (params, return_template)
        #   Phase 2 — For every call-site with a literal arg, evaluate the return
        #             template with the arg substituted, resolving any nested calls
        #             recursively up to depth 3.

        # ── Phase 1: Build function registry ─────────────────────────────────
        func_registry: dict[str, dict] = {}

        # Pattern A: function declaration
        _FUNC_DECL = re.compile(
            r'\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]{0,120})\)\s*'
            r'\{[^{}]{0,600}?return\s+([^;{}]{4,300});',
            re.DOTALL
        )
        # Pattern B: arrow function — const f = (p) => expr
        _ARROW_BODY = re.compile(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'
            r'(?:\(([^)]{0,120})\)|([a-zA-Z_$][a-zA-Z0-9_$]*))\s*=>\s*'
            r'(?:\{[^{}]{0,300}?return\s+([^;{}]{4,300});[^{}]{0,100}\}|'
            r'([^{;,\n]{4,300}))',
            re.DOTALL
        )
        # Pattern C: object shorthand method — { url(path) { return ... } }
        _OBJ_METHOD = re.compile(
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]{0,80})\)\s*'
            r'\{[^{}]{0,300}?return\s+([^;{}]{4,200});',
            re.DOTALL
        )

        def _looks_like_url_template(expr: str) -> bool:
            return any(k in expr for k in ('/api', '+', 'base', 'BASE', 'root', 'ROOT',
                                            '`', 'return', '/v1', '/v2', '/v3', 'http'))

        # Registration: ALL functions with URL-like return values go into registry,
        # regardless of their name. Name filter is only used at call-site evaluation
        # to avoid false positives on non-URL-related functions.
        for m in _FUNC_DECL.finditer(code):
            name, params_raw, ret = m.group(1), m.group(2), m.group(3).strip()
            if _looks_like_url_template(ret):
                params = [p.split('=')[0].strip() for p in params_raw.split(',') if p.strip()]
                func_registry[name] = {'params': params, 'return': ret, 'style': 'func'}

        for m in _ARROW_BODY.finditer(code):
            name = m.group(1)
            params_raw = m.group(2) or m.group(3) or ''
            # Arrow body: either { return expr; } or bare expression
            ret_block = m.group(4)   # block body with return
            ret_expr  = m.group(5)   # bare expression body
            # For template literal arrows: `path => \`${BASE}/api/${path}\``
            # ret_expr captures the backtick template, but the regex may
            # stop at a newline. Capture it more aggressively:
            if not ret_block and not ret_expr:
                continue
            ret = (ret_block or ret_expr or '').strip()
            # Expand template literal arrows: if ret starts with backtick,
            # treat ${PARAM} as the param placeholder
            if not ret and name:
                # Try capturing the full template literal directly
                tmpl_m = re.search(
                    re.escape(name) + r'\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*=>\s*`([^`]+)`',
                    code
                )
                if tmpl_m:
                    ret = '`' + tmpl_m.group(1) + '`'
            if ret and _looks_like_url_template(ret):
                params = [p.split('=')[0].strip() for p in params_raw.split(',') if p.strip()]
                func_registry[name] = {'params': params, 'return': ret, 'style': 'arrow'}

        for m in _OBJ_METHOD.finditer(code):
            name, params_raw, ret = m.group(1), m.group(2), m.group(3).strip()
            if _looks_like_url_template(ret):
                params = [p.split('=')[0].strip() for p in params_raw.split(',') if p.strip()]
                func_registry[name] = {'params': params, 'return': ret, 'style': 'method'}

        # Also register any arrow with a template literal body not caught above
        for tmpl_arrow_m in re.finditer(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'
            r'(?:\(([^)]{0,60})\)|([a-zA-Z_$][a-zA-Z0-9_$]*))\s*=>\s*`([^`]{4,300})`',
            code
        ):
            name      = tmpl_arrow_m.group(1)
            prm_paren = tmpl_arrow_m.group(2) or ''
            prm_bare  = tmpl_arrow_m.group(3) or ''
            tmpl_body = tmpl_arrow_m.group(4)
            if name not in func_registry and _looks_like_url_template(tmpl_body):
                params_raw = prm_paren or prm_bare
                params = [p.strip() for p in params_raw.split(',') if p.strip()]
                func_registry[name] = {
                    'params': params,
                    'return': '`' + tmpl_body + '`',
                    'style':  'arrow_template'
                }

        # ── Phase 2: Evaluate call sites ──────────────────────────────────────
        def _evaluate_call(func_name: str, arg_vals: list, depth: int = 0):
            """
            Recursively evaluate a function call with given literal arguments.
            Returns resolved URL string or None.
            Handles: string concat, template literals, nested calls, default params.
            """
            if depth > 4 or func_name not in func_registry:
                return None
            fn      = func_registry[func_name]
            params  = fn['params']
            template = fn['return']

            # Build substitution map: param_name → arg_value
            subs = {}
            for i, p in enumerate(params):
                if i < len(arg_vals) and p:
                    subs[p] = arg_vals[i]

            resolved = template

            # ── Step 1: Handle template literal bodies ──────────────────────
            # Arrow: path => `${BASE}/api/${path}`
            # If resolved is a template literal (starts with backtick), process
            # ${param} substitutions first, THEN the ${VAR} variable references.
            if resolved.startswith('`') or '${' in resolved:
                # Substitute param placeholders: ${param} → literal value
                for pname, pval in subs.items():
                    if pname:
                        resolved = re.sub(r'\$\{' + re.escape(pname) + r'\}',
                                          pval, resolved)
                # Resolve ${VAR} variable references
                def _resolve_tmpl_ref(vm):
                    var = vm.group(1).strip()
                    val = (self.resolver.resolve_with_fallback(var)
                           or self.resolver.global_scope.get(var))
                    return val if (val and isinstance(val, str)) else ''
                resolved = re.sub(r'\$\{([^}]{1,60})\}', _resolve_tmpl_ref, resolved)
                # Strip backticks and extract result
                resolved = resolved.strip('`')
                if resolved and (resolved.startswith('/') or resolved.startswith('http')
                                 or '/api' in resolved):
                    return resolved
                return None

            # ── Step 2: String concatenation body ───────────────────────────
            # Substitute params: replace bare identifiers
            for pname, pval in subs.items():
                if pname:
                    resolved = re.sub(r'\b' + re.escape(pname) + r'\b',
                                      f'"{pval}"', resolved)

            # ── Step 3: Resolve nested function calls ────────────────────────
            # prefix(svc) + "/" + action  →  "http://..../api/orders" + "/" + "create"
            for _attempt in range(3):  # up to 3 nested call resolutions
                nested_call_re2 = re.compile(
                    r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*'
                    r'"([^"]{0,100})"\s*(?:,\s*"([^"]{0,100})"\s*)?\)'
                )
                matched_nested = False
                for nc in nested_call_re2.finditer(resolved):
                    nested_name = nc.group(1)
                    if nested_name in ('return', 'const', 'let', 'var'):
                        continue
                    nested_args = [a for a in [nc.group(2), nc.group(3)] if a is not None]
                    nested_result = _evaluate_call(nested_name, nested_args, depth + 1)
                    if nested_result:
                        resolved = (resolved[:nc.start()]
                                    + f'"{nested_result}"'
                                    + resolved[nc.end():])
                        matched_nested = True
                        break
                if not matched_nested:
                    break

            # ── Step 4: Resolve variable references (multi-pass) ────────────
            for _vpass in range(3):
                changed = False
                for var_m in re.finditer(
                    r'\b([A-Z_$][A-Z0-9_$]{0,40}|[a-z][a-zA-Z0-9_$]{1,40})\b', resolved
                ):
                    var = var_m.group(1)
                    if var in ('return', 'const', 'let', 'var', 'this',
                                'true', 'false', 'null', 'undefined'):
                        continue
                    pos = var_m.start()
                    # Skip if inside quotes (char immediately before is a quote)
                    ctx_before = resolved[max(0, pos-1):pos]
                    if ctx_before and ctx_before[-1] in ('"', "'", '`'):
                        continue
                    r_val = (self.resolver.resolve_with_fallback(var)
                             or self.resolver.global_scope.get(var))
                    if r_val and isinstance(r_val, str) and (
                        r_val.startswith('http') or r_val.startswith('/')
                    ):
                        resolved = (resolved[:var_m.start()]
                                    + f'"{r_val}"'
                                    + resolved[var_m.end():])
                        changed = True
                        break
                if not changed:
                    break

            # ── Step 5: Extract and join quoted string parts ─────────────────
            parts = re.findall(r'[\'"]([^\'"]+)[\'"]', resolved)
            if not parts:
                # Try backtick segments
                parts = re.findall(r'`([^`]+)`', resolved)
            if not parts:
                return None
            combined = ''.join(parts)
            if combined and (combined.startswith('/') or combined.startswith('http')
                             or '/api' in combined):
                return combined
            return None

        # Find all call sites with literal arguments
        _call_site_re = re.compile(
            r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*'
            r'[\'"`]([^\'"`]{2,100})[\'"`]'
            r'(?:\s*,\s*[\'"`]([^\'"`]{0,100})[\'"`])?\s*\)'
        )
        for cs_m in _call_site_re.finditer(code):
            func_name = cs_m.group(1)
            arg1 = cs_m.group(2)
            arg2 = cs_m.group(3)
            args = [a for a in [arg1, arg2] if a is not None]

            if func_name not in func_registry:
                continue

            result = _evaluate_call(func_name, args)
            if result:
                full_url = self.normalizer.normalize(result)
                if full_url:
                    method = self.detect_method(code, cs_m.start())
                    self.process(full_url, method, cs_m.start(), code, source,
                                 "INTERPROCEDURAL_FUNC", "BACKEND_API", 82)

        # ── FEATURE 3: SSA-style variable propagation ─────────────────────────
        # Handles: const url = buildApiUrl("orders"); fetch(url);
        # The variable 'url' receives the return value of a known function,
        # then is used as an argument to fetch/axios elsewhere.
        #
        # Algorithm:
        #   1. Find `const VAR = FUNC(args)` where FUNC is in func_registry
        #   2. Evaluate the call → URL string
        #   3. Substitute VAR → URL in all downstream fetch(VAR) calls
        _var_assign_call_re = re.compile(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*'
            r'(?:[\'"`]([^\'"`]{0,100})[\'"`])?'
            r'(?:\s*,\s*[\'"`]([^\'"`]{0,100})[\'"`])?\s*\)'
        )
        _ssa_bindings: dict = {}  # varName → resolved URL

        for m in _var_assign_call_re.finditer(code):
            var_name  = m.group(1)
            func_name = m.group(2)
            arg1 = m.group(3)
            arg2 = m.group(4)
            if func_name not in func_registry:
                continue
            args = [a for a in [arg1, arg2] if a is not None]
            result = _evaluate_call(func_name, args)
            if result and ('/' in result or result.startswith('http')):
                _ssa_bindings[var_name] = result

        # Also pick up zero-arg calls: const url = createOrderUrl();
        _var_assign_noarg_re = re.compile(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)'
        )
        for m in _var_assign_noarg_re.finditer(code):
            var_name  = m.group(1)
            func_name = m.group(2)
            if func_name in func_registry and var_name not in _ssa_bindings:
                result = _evaluate_call(func_name, [])
                if result and ('/' in result or result.startswith('http')):
                    _ssa_bindings[var_name] = result

        # Emit endpoints for all downstream uses of SSA-bound variables
        if _ssa_bindings:
            _ssa_use_re = re.compile(
                r'\b(?:fetch|axios(?:\.[a-z]+)?|http\.[a-z]+)\s*\(\s*'
                r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:[,)])'
            )
            for m in _ssa_use_re.finditer(code):
                var_name = m.group(1)
                if var_name in _ssa_bindings:
                    full_url = self.normalizer.normalize(_ssa_bindings[var_name])
                    if full_url:
                        method = self.detect_method(code, m.start())
                        self.process(full_url, method, m.start(), code, source,
                                     "SSA_PROPAGATED", "BACKEND_API", 83)

    def _expand_api_versions(self, code, source):
        """Expand {version}-style placeholders using version strings seen in the code."""
        # ── BONUS: Multi-version endpoint enumeration ─────────────────────
        # When a codebase defines multiple API versions and iterates over them,
        # enumerate all concrete endpoints instead of leaving {version} as placeholder.
        #
        # Patterns:
        #   const versions = ['v1','v2']; versions.forEach(v => fetch(`/api/${v}/users`));
        #   const APIS = {v1:'/api/v1', v2:'/api/v2'}; Object.values(APIS).forEach(...)
        #
        # Strategy: find {version}-like placeholders in emitted endpoints and
        # expand them using known version arrays from the variable resolver.
        _known_versions: list = []
        for k, v in self.resolver.global_scope.items():
            if isinstance(v, str) and re.match(r'^v\d+$', v):
                _known_versions.append(v)
        # Also check for version arrays: const versions=['v1','v2']
        for k, v_raw in self.resolver.variables.items():
            val = v_raw.get('value','') if isinstance(v_raw, dict) else v_raw
            if isinstance(val, str) and re.match(r'^v\d+$', val):
                if val not in _known_versions:
                    _known_versions.append(val)

        if len(_known_versions) >= 2:
            # Snapshot current endpoints before expansion (avoid infinite loop)
            _snap = list(self.endpoints)
            for ep in _snap:
                ep_url = ep.get('endpoint', '')
                # Look for {version}, {v}, {ver}, {apiVersion} placeholders
                if not re.search(r'\{v(?:ersion|er|)?\}|\{apiVersion\}', ep_url, re.I):
                    continue
                for ver in _known_versions[:6]:  # cap at 6 versions
                    expanded = re.sub(
                        r'\{v(?:ersion|er|)?\}|\{apiVersion\}', ver, ep_url, flags=re.I
                    )
                    if expanded != ep_url:
                        full_url = self.normalizer.normalize(expanded)
                        if full_url:
                            self.process(full_url, ep.get('method','GET'), 0, code, source,
                                         "VERSION_ENUMERATED", "BACKEND_API", 80)
