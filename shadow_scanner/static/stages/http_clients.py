"""HTTP-client call patterns (Angular, axios, fetch, Vue/React hooks, SOAP)."""
import re
class HttpClientPatternsMixin:
    """Endpoints passed to HTTP client APIs (Angular HttpClient, axios, fetch, SOAP...)."""

    def _extract_angular_http_calls(self, code, source):
        """this.http.get(...) and injected Angular service wrappers (this.api.get(...))."""
        # HTTP patterns
        for m in re.finditer(r'this\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP_THIS", "BACKEND_API", 95)

        for m in re.finditer(r'\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP", "BACKEND_API", 90)

        for m in re.finditer(r'this\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT_THIS", "BACKEND_API", 95)

        for m in re.finditer(r'\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT", "BACKEND_API", 90)

        # ── FIX FN-1: Injected Angular service wrapper calls ─────────────────
        # Catches: this.api.get('endpoint'), this.service.post('path'), etc.
        # Also handles TypeScript generics: this.api.get<Type>('endpoint')
        # where 'api'/'service' is an injected wrapper around HttpClient.
        # The variable resolver attempts to prepend the base URL if resolvable.
        for m in re.finditer(
            r'this\.([a-zA-Z_$][a-zA-Z0-9_$]{0,30})\.(get|post|put|delete|patch|request)'
            r'(?:<[^>]{0,80}>)?\s*\(\s*[\'"`]([^\'"`]{3,200})[\'"`]',
            code, re.IGNORECASE
        ):
            injected_var = m.group(1)
            http_method  = m.group(2).upper()
            raw_path     = m.group(3)
            # Skip if it's actually this.http.X (already handled above)
            if injected_var.lower() in ('http', 'httpclient', 'router', 'route', 'fb', 'formbuilder'):
                continue
            # Try to resolve base URL from the injected service
            base_url = (
                self.resolver.resolve_method_call(f"this.{injected_var}.getBase")
                or self.resolver.resolve_method_call(f"this.{injected_var}.getApiBase")
                or self.resolver.resolve_method_call(f"this.{injected_var}.getRootUrl")
                or self.resolver.resolve_method_call(f"this.{injected_var}.getUrl")
                or self.resolver.resolve_method_call("getBase")
                or self.resolver.resolve_method_call("getApiBase")
                or self.resolver.resolve_with_fallback(injected_var)
                or self.resolver.resolve_with_fallback(f"this.{injected_var}")
            )
            if base_url:
                full_url = self.normalizer.normalize(base_url.rstrip('/') + '/' + raw_path.lstrip('/'))
            else:
                full_url = self.normalizer.normalize(raw_path)
            self.process(full_url, http_method, m.start(), code, source, "ANGULAR_SERVICE_WRAPPER", "BACKEND_API", 88)

    def _extract_named_axios_calls(self, code, source):
        """Module-level axios.create() instances: apiClient.post("/path")."""
        # ── Named axios instance calls ────────────────────────
        # Catches: axiosInstance.post('/checkout/process', body)
        #          apiClient.get('/api/users', config)
        #          httpClient.delete('/api/items/1')
        # These are module-level (not this.) axios wrappers created via axios.create().
        # The AliasResolver should have already registered their baseURL from axios.create().
        for m in re.finditer(
            r'([a-zA-Z_$][a-zA-Z0-9_$]{1,40})\.(get|post|put|delete|patch|request)'
            r'(?:<[^>]{0,80}>)?\s*\(\s*[\'"`]([^\'"`]{3,200})[\'"`]',
            code, re.IGNORECASE
        ):
            var_name    = m.group(1)
            http_method = m.group(2).upper()
            raw_path    = m.group(3)
            # Skip already-handled patterns
            if var_name.lower() in ('this', 'axios', 'http', 'console', 're', 'fs',
                                     'path', 'os', 'url', 'crypto', 'stream', 'buffer'):
                continue
            # Only process if the variable looks like a named HTTP client
            var_lower = var_name.lower()
            _is_client = any(kw in var_lower for kw in (
                'api', 'http', 'client', 'service', 'axios', 'instance',
                'request', 'fetch', 'agent'
            ))
            if not _is_client:
                continue
            # Try to resolve base URL from the named variable (from axios.create)
            base_url = (
                self.resolver.resolve_with_fallback(var_name)
                or self.resolver.global_scope.get(f'{var_name}.__baseURL')
                or self.resolver.global_scope.get(var_name)
            )
            if base_url and (base_url.startswith('http') or base_url.startswith('/')):
                full_url = self.normalizer.normalize(base_url.rstrip('/') + '/' + raw_path.lstrip('/'))
            else:
                # No base URL resolved — emit path as-is (lower confidence)
                if not (raw_path.startswith('/') or raw_path.startswith('http')):
                    continue
                full_url = self.normalizer.normalize(raw_path)
            self.process(full_url, http_method, m.start(), code, source, "NAMED_AXIOS_INSTANCE", "BACKEND_API", 85)

    def _extract_fetch_and_hook_calls(self, code, source):
        """fetch("/path"), Vue/Nuxt useFetch/useAsyncData/$fetch, React useEffect+fetch."""
        # Fetch API
        for m in re.finditer(r'fetch\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            method = self.detect_method(code, m.start())
            self.process(full_url, method, m.start(), code, source, "FETCH_API", "BACKEND_API", 85)

        # ── FIX FN-4: Vue 3 Composition API / Nuxt patterns ─────────────────
        # useAsyncData('key', () => axios.get('/path'))
        # useFetch('/api/users')
        # $fetch('/api/data')
        # useAsyncData('key', () => $fetch('/path'))
        for m in re.finditer(
            r'(?:useAsyncData|useFetch|useLazyFetch)\s*\([^,)]+,?\s*(?:async\s*)?\(\s*\)\s*=>\s*[^)]*?[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, 'GET', m.start(), code, source, "VUE_ASYNC_DATA", "BACKEND_API", 85)

        for m in re.finditer(
            r'(?:useFetch|useLazyFetch|\$fetch)\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, 'GET', m.start(), code, source, "VUE_FETCH", "BACKEND_API", 85)

        # ── FIX FN-4b: React useEffect + fetch ──────────────────────────────
        # useEffect(() => { fetch('/api/dashboard/metrics') })
        for m in re.finditer(
            r'useEffect\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[^}]{0,300}?fetch\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, 'GET', m.start(), code, source, "REACT_USE_EFFECT_FETCH", "BACKEND_API", 88)

    def _extract_url_constructor_calls(self, code, source):
        """new URL("/path") and new URL(`${base}/path`)."""
        # ── new URL() constructor pattern ────────────────────────────────────
        # Catches: new URL(`${API_BASE}/api/dashboard/metrics`)
        #          new URL('/api/v2/products/' + id, baseUrl)
        for m in re.finditer(
            r'new\s+URL\s*\(\s*[\'"`]([^\'"`\s]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            method = self.detect_method(code, m.start())
            self.process(full_url, method, m.start(), code, source, "NEW_URL_CONSTRUCTOR", "BACKEND_API", 82)

        # Template literal inside new URL() — new URL(`${base}/path`)
        for m in re.finditer(r'new\s+URL\s*\(`([^`]{4,200})`', code, re.IGNORECASE):
            raw = m.group(1)
            # Strip ${VAR} interpolations; keep static path skeleton
            cleaned = re.sub(r'\$\{[^}]+\}', '', raw).strip('/')
            if cleaned and (cleaned.startswith('/') or '/api' in cleaned.lower() or 'api' in cleaned.lower()):
                full_url = self.normalizer.normalize(cleaned)
                if full_url:
                    self.process(full_url, 'GET', m.start(), code, source, "NEW_URL_TEMPLATE", "BACKEND_API", 78)

    def _extract_url_builder_calls(self, code, source):
        """buildApi("orders"), apiUrl("users") ... URL-builder helper calls."""
        # ── T09: URL builder functions ───────────────────────────────────────
        # Catches: buildApi("orders"), buildUrl("users"), apiPath("v1", "items")
        # Any function whose name contains 'build', 'url', 'api', 'path', 'endpoint'
        # and whose first argument is a string literal.
        _URL_BUILDER_RE = re.compile(
            r'\b(build(?:Api|Url|Endpoint|Path|Request)?|'
            r'get(?:Api|Url|Endpoint|Path)|'
            r'make(?:Api|Url|Request)|'
            r'create(?:Url|Api|Request)|'
            r'api(?:Url|Path|Endpoint)|'
            r'(?:url|path|endpoint)For|'
            r'formatUrl|constructUrl|composeUrl)\s*\(',
            re.IGNORECASE
        )
        for m in _URL_BUILDER_RE.finditer(code):
            # Extract the first string argument
            rest = code[m.end():m.end()+200]
            arg_m = re.match(r'''\s*['"`]([^'"`]{3,100})['"`]''', rest)
            if arg_m:
                fragment = arg_m.group(1)
                # Try to build the full URL with any known base
                base_val = (self.resolver.methods.get('getBase')
                            or self.resolver.methods.get('getApiBase')
                            or self.resolver.methods.get('environmentApiUrl'))
                if base_val:
                    full_url = self.normalizer.normalize(base_val.rstrip('/') + '/' + fragment.lstrip('/'))
                else:
                    full_url = self.normalizer.normalize(fragment)
                method = self.detect_method(code, m.start())
                self.process(full_url, method, m.start(), code, source, "URL_BUILDER_FUNC", "BACKEND_API", 75)

    def _extract_promise_chain_calls(self, code, source):
        """fetch()/axios calls nested inside .then() chains."""
        # ── T11: Promise chain fetch().then() endpoint extraction ────────────
        # Catches: fetch("/api/data").then(r => r.json())
        #          axios.get("/api/users").then(...)
        # The endpoint is already caught by the fetch/axios patterns above,
        # but this catches cases where fetch() appears inside .then() chains:
        #   somePromise.then(() => fetch("/api/nested"))
        for m in re.finditer(
            r'\.then\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*(?:\{[^}]{0,200})?fetch\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, 'GET', m.start(), code, source, "PROMISE_CHAIN_FETCH", "BACKEND_API", 80)

        # axios.get().then() — ensure axios inside promise chains is caught
        for m in re.finditer(
            r'\.then\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*(?:\{[^}]{0,200})?axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            http_method = m.group(1).upper()
            full_url    = self.normalizer.normalize(m.group(2))
            self.process(full_url, http_method, m.start(), code, source, "PROMISE_CHAIN_AXIOS", "BACKEND_API", 82)

    def _extract_interceptor_base_urls(self, code, source):
        """baseURL set inside axios request interceptors (registers a base, emits nothing)."""
        # ── T12/T20: axios interceptors — extract baseURL set via interceptor ─
        # Catches:
        #   axios.interceptors.request.use(config => { config.baseURL = '/api'; return config; })
        #   instance.interceptors.request.use(cfg => { cfg.url = base + cfg.url; ... })
        for m in re.finditer(
            r'interceptors\.request\.use\s*\(\s*(?:function\s*\([^)]*\)|[a-zA-Z_$]\w*\s*=>|\([^)]*\)\s*=>)\s*\{([^}]{0,500})\}',
            code, re.IGNORECASE | re.DOTALL
        ):
            interceptor_body = m.group(1)
            # Look for baseURL assignment or url prefix pattern inside interceptor
            for bm in re.finditer(
                r'(?:baseURL|baseUrl|config\.url\s*=\s*[a-zA-Z_$]\w*\s*\+)\s*[=:]\s*[\'"`]([^\'"`]{4,200})[\'"`]',
                interceptor_body, re.IGNORECASE
            ):
                base_val = bm.group(1)
                if base_val.startswith('/') or base_val.startswith('http'):
                    # Register as a base URL so downstream calls get prepended
                    self.resolver.global_scope['interceptor_baseURL'] = base_val
                    self.resolver.methods['getBase'] = (
                        self.resolver.methods.get('getBase') or base_val
                    )

    def _extract_soap_calls(self, code, source):
        """SOAP bridge / legacy RPC calls and SOAPAction / wsdl config values."""
        # ── FIX FN-5: SOAP bridge / legacy RPC pattern detection ────────────
        # Catches patterns like:
        #   soapClient.call('MethodName', ...)
        #   bridge.post('/api/legacy/bridge/getEmployeeRecord', ...)
        #   legacyService.invoke('/legacy/soap/endpoint', ...)
        for m in re.finditer(
            r'(?:soapClient|legacyClient|soapService|bridgeService|legacyService|soapBridge)'
            r'\s*[.]\s*(?:call|invoke|execute|send|post|get)\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            method_guess = 'POST'  # SOAP calls are POST by convention
            self.process(full_url, method_guess, m.start(), code, source, "SOAP_BRIDGE_CALL", "BACKEND_API", 88)

        # SOAP action header / wsdl endpoint patterns
        # FP3 FIX: Require value to start with / or http to avoid matching
        # config-object keys like  endpoint: 'MyService'  (no path structure)
        for m in re.finditer(
            r'(?:SOAPAction|soapAction|wsdl|wsdlUrl|endpoint)\s*[=:]\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            val = m.group(1)
            if not (val.startswith('/') or val.startswith('http') or val.startswith('wss')):
                continue   # FP3 FIX: skip bare names like "MyServiceEndpoint"
            full_url = self.normalizer.normalize(val)
            self.process(full_url, 'POST', m.start(), code, source, "SOAP_ACTION", "BACKEND_API", 75)
