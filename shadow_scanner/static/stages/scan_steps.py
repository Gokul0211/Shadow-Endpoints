"""The steps of the Phase-2 static scan (EnhancedStaticAnalyzer.scan)."""
import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from shadow_scanner.config import LOW_VALUE_JS, logger
from shadow_scanner.protocols.graphql import GraphQLIntrospector
from shadow_scanner.protocols.websockets import WebSocketDiscovery
from shadow_scanner.static.webpack_static import StaticWebpackModuleAnalyzer
class ScanStepsMixin:
    """The individual steps of EnhancedStaticAnalyzer.scan() (Phase 2)."""

    def _fetch_and_extract_variables(self, js_urls):
        """Step 1: parallel fetch of every JS file + variable extraction. Returns {url: code}."""
        # ==================================================================
        # STEP 1: Parallel fetch + variable extraction
        # I/O-bound: ThreadPoolExecutor gives 5-10x speedup over sequential
        # ==================================================================
        print("\n  [Step 1/4] Fetching & extracting variables (multi-threaded)...")
        js_contents = {}
        fetch_lock   = threading.Lock()   # guards js_contents writes
        resolve_lock = threading.Lock()   # guards self.resolver shared state
        completed    = [0]                # mutable counter for progress

        # Filter low-value files up-front (same logic as before)
        urls_to_fetch = [
            url for url in js_urls
            if not any(x in url.lower() for x in LOW_VALUE_JS)
        ]

        def _fetch_and_extract(url):
            """Fetch one JS file and extract variables. Thread-safe."""
            try:
                # ── Cache hit: skip network request ──────────────────────
                if self.scan_cache and self.scan_cache.has(url):
                    code = self.scan_cache.get(url)
                    if code:
                        logger.debug(f"[Cache] HIT {url}")
                        filename = url.split('/')[-1]
                        with resolve_lock:
                            self.resolver.extract_all_variables(code, filename)
                            self.analyzed_js_files.add(url)
                        with fetch_lock:
                            js_contents[url] = code
                            completed[0] += 1
                        return

                # ── Cache miss: rate-limited fetch ───────────────────────
                r = self.rate_limiter.throttled_get(
                    self.session, url, timeout=self.fetch_timeout, verify=False
                )
                if r.status_code != 200:
                    logger.debug(f"[Fetch] HTTP {r.status_code} for {url}")
                    return
                filename = url.split('/')[-1]
                code     = r.text

                # Store in cache for resume
                if self.scan_cache:
                    self.scan_cache.put(url, code)

                # --- variable extraction (regex-heavy, release GIL enough) ---
                with resolve_lock:
                    self.resolver.extract_all_variables(code, filename)
                    self.analyzed_js_files.add(url)

                with fetch_lock:
                    js_contents[url] = code
                    completed[0] += 1
                    done = completed[0]

                if done % 10 == 0:
                    print(f"    Progress: [{done}/{len(urls_to_fetch)}]", end='\r')

            except requests.exceptions.Timeout:
                logger.debug(f"[Fetch] Timeout: {url}")
            except Exception as exc:
                logger.debug(f"[Fetch] Error fetching {url}: {exc}")

        # Tune max_workers: 15 is a sweet spot for typical scan targets.
        # Too high → target rate-limits / WAF triggers. Too low → no speedup.
        with ThreadPoolExecutor(max_workers=self.MAX_FETCH_WORKERS) as executor:
            futures = {executor.submit(_fetch_and_extract, url): url for url in urls_to_fetch}
            for future in as_completed(futures):
                # Propagate any unexpected exceptions to the surface
                try:
                    future.result()
                except Exception:
                    pass

        print(f"\n    [+] Fetched {len(js_contents)}/{len(urls_to_fetch)} JS files")
        print(f"    [+] Extracted {len(self.resolver.variables)} unique variables")
        print(f"    [+] Found {len(self.resolver.methods)} method definitions")
        print(f"    [+] Found {len(self.resolver.service_properties)} service properties")
        print(f"    [+] Found {len(self.resolver.get_all_base_urls())} potential base URLs")

        return js_contents

    def _adopt_backend_api_host(self):
        """Point the URL normalizer at the API backend host if the bundle declares one."""
        # POST-EVAL FIX 1: Update URLNormalizer's host if an API backend is found
        for key in ('environmentApiUrl', 'apiUrl', 'baseUrl', 'serverUrl', 'apiEndpoint'):
            val = self.resolver.methods.get(key, '')
            if val and isinstance(val, str) and val.startswith('http'):
                try:
                    parsed = urllib.parse.urlparse(val)
                    self.normalizer.scheme = parsed.scheme
                    self.normalizer.netloc = parsed.netloc
                    break
                except Exception:
                    pass

    def _resolve_cross_file_di_chains(self):
        """Multi-pass resolution of cross-file DI chains (service -> config -> env URL)."""
        # ── FIX FN-1: Cross-file DI chain multi-pass resolution ───────────
        # After ALL JS files are loaded, run up to 5 resolution passes over
        # the method registry to resolve chains like:
        #   AppConfigService.getApiBase() → env.apiBaseUrl → 'http://localhost:4001/api/rc_permit/'
        #   ApiService.getBase()          → calls AppConfigService.getApiBase()
        #   PermitService.http.get()      → calls ApiService.getBase()
        # Single-pass analysis sees only the last call-site fragment; multi-pass
        # connects all three levels.
        print("\n  [DI Chain] Running cross-file multi-pass resolution...")
        _di_resolved = 0
        for _pass in range(self.DI_CHAIN_MAX_PASSES):
            _changed = False
            # Pass A: resolve methods whose return value is an indirect reference
            for _mn in list(self.resolver.methods.keys()):
                _mv = self.resolver.methods[_mn]
                if not _mv:
                    continue
                if _mv.startswith('http') or _mv.startswith('/'):
                    continue  # already a URL
                # Try to resolve the reference
                _resolved = (
                    self.resolver.resolve_with_fallback(_mv)
                    or self.resolver.methods.get(_mv)
                    or self.resolver.property_accesses.get(_mv)
                )
                if _resolved and isinstance(_resolved, str) and (
                    _resolved.startswith('http') or _resolved.startswith('/')
                ):
                    self.resolver.methods[_mn] = _resolved
                    _changed = True
                    _di_resolved += 1
            # Pass B: resolve variables whose value references another variable
            for _vn in list(self.resolver.variables.keys()):
                _vd = self.resolver.variables[_vn]
                _vv = _vd.get('value', '') if isinstance(_vd, dict) else str(_vd)
                if not _vv or _vv.startswith('http') or _vv.startswith('/'):
                    continue
                _resolved2 = (
                    self.resolver.resolve_with_fallback(_vv)
                    or self.resolver.methods.get(_vv)
                )
                if _resolved2 and isinstance(_resolved2, str) and (
                    _resolved2.startswith('http') or _resolved2.startswith('/')
                ):
                    if isinstance(_vd, dict):
                        self.resolver.variables[_vn]['value'] = _resolved2
                    else:
                        self.resolver.variables[_vn] = {
                            'value': _resolved2,
                            'source_file': 'di_chain_resolved',
                            'confidence': 90,
                        }
                    _changed = True
                    _di_resolved += 1
            if not _changed:
                break
        print(f"    [+] DI chain: {_di_resolved} reference(s) resolved in {_pass + 1} pass(es)")

        # Show discovered methods
        if self.resolver.methods:
            print("\n  [Discovered Methods]")
            for method, value in list(self.resolver.methods.items())[:10]:
                print(f"    {method}() = {value}")

        # Show discovered service properties
        if self.resolver.service_properties:
            print("\n  [Discovered Service Properties]")
            for prop, data in list(self.resolver.service_properties.items())[:20]:
                print(f"    this.{prop} = {data['method_call']} + \"{data['suffix']}\"")
                print(f"      → {data['endpoint']}")

    def _extract_rpc_and_array_endpoints(self, js_contents):
        """Step 2: RPC concatenation patterns + array-harvested CRUD names."""
        # STEP 2: Extract RPC patterns
        print("\n  [Step 2/4] Extracting RPC patterns with method calls...")
        rpc_count = 0

        for url, code in js_contents.items():
            filename = url.split('/')[-1]
            rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)

            for ep in rpc_endpoints:
                full_url = self.normalizer.normalize(ep['endpoint'])

                self.add_endpoint(
                    full_url,
                    ep['method'],
                    [],
                    ep['type'],
                    ep['source'],
                    ep['classification'],
                    ep['confidence']
                )
                rpc_count += 1

            # Check for Array Harvested Items
            for var_name, var_data in self.resolver.variables.items():
                if var_name.startswith("ARRAY_ITEM_"):
                    raw_val = var_data['value']
                    # ── FP FILTER: Reject React component/route names ──
                    # These are single PascalCase words (no slash, no dot) that
                    # appear in JSX import arrays but aren't API endpoints.
                    # e.g. "CategoryCreation", "CompletedTaskList", "Tiker"
                    # KEEP items with slashes (real paths) or api_ prefix.
                    stripped = raw_val.strip('/')
                    if '/' not in stripped and '.' not in stripped and not stripped.startswith('api_'):
                        # Single-word: only keep if it looks like a backend CRUD operation.
                        # FP6 FIX: Also require minimum length (≥6 chars) and disallow
                        # common UI/marketing words that share CRUD prefixes:
                        # "GetStarted", "FindMe", "AddToCart", "SendEmail", "SubmitFeedback"
                        # These are React prop names / event handlers, not API method names.
                        _CRUD_RE = re.compile(
                            r'^(Get|Create|Update|Delete|Insert|Fetch|Save|Find|Search|'
                            r'Upload|Download|Send|Submit|Add|Remove|Change|Mark|Verify|'
                            r'Endorse|Close|Extend|Bulk|Report)',
                            re.I
                        )
                        _UI_WORDS = {
                            'getstarted', 'gethelp', 'getmore', 'findme', 'findout',
                            'addtocart', 'additem', 'sendemail', 'sendmessage',
                            'submitfeedback', 'submitform', 'uploadfile', 'downloadapp',
                            'createaccount', 'createprofile', 'updateprofile',
                            'removeitem', 'deletefile', 'searchresults', 'searchbar',
                        }
                        lower_stripped = stripped.lower()
                        if not _CRUD_RE.match(stripped):
                            continue
                        if len(stripped) < 6:
                            continue
                        if lower_stripped in _UI_WORDS:
                            continue
                        # Must contain at least one uppercase letter after the first
                        # (real RPC methods are camelCase/PascalCase with noun subjects)
                        if not re.search(r'[A-Z]', stripped[1:]):
                            continue
                    full_url = self.normalizer.normalize(raw_val)
                    # Infer method from the last path segment name instead of hardcoding GET.
                    # e.g. DeleteTask → DELETE, CreateToken → POST, UpdateQuestion → PUT
                    ep_name = full_url.rstrip('/').split('/')[-1]
                    inferred_method = self._guess_method_from_key(ep_name)
                    self.add_endpoint(
                        full_url,
                        inferred_method,
                        [],
                        "ARRAY_HARVEST",
                        var_data['source_file'],
                        "BACKEND_API",
                        60
                    )

        print(f"    [+] Found {rpc_count} RPC-style endpoints")

    def _extract_service_property_endpoints(self):
        """Step 3: this.prop = this.method() + "/suffix" service properties."""
        # STEP 3: Extract service property endpoints
        print("\n  [Step 3/4] Extracting service property endpoints...")
        service_count = 0

        for prop_name, prop_data in self.resolver.service_properties.items():
            full_url = self.normalizer.normalize(prop_data['endpoint'])
            method = self._guess_method_from_key(prop_name)

            self.add_endpoint(
                full_url,
                method,
                [],
                'SERVICE_PROPERTY',
                prop_data['source'],
                'BACKEND_API',
                97
            )
            service_count += 1

        print(f"    [+] Found {service_count} service property endpoints")

    def _analyze_all_code_parallel(self, js_contents, json_urls):
        """Step 4: JSON configs + analyze_code() on every bundle (thread pool)."""
        # ==================================================================
        # STEP 4: Parallel JSON config analysis + parallel analyze_code
        # ==================================================================
        print("\n  [Step 4/4] Standard endpoint analysis (multi-threaded)...")

        add_lock = threading.Lock()   # guards self.add_endpoint / self.endpoints

        # --- 4a: JSON configs (I/O bound) ---
        def _analyze_json(json_url):
            try:
                self.analyze_json_config(json_url)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(_analyze_json, json_urls))

        # --- 4b: JS code analysis (CPU + regex bound) ---
        # analyze_code calls add_endpoint which mutates self.endpoints.
        # We patch add_endpoint to be thread-safe for this phase only.
        _original_add = self.add_endpoint

        def _safe_add(url, method, params, type_, source, classification, confidence, extra_fields=None):
            with add_lock:
                _original_add(url, method, params, type_, source, classification, confidence, extra_fields)

        self.add_endpoint = _safe_add  # monkeypatch for duration of parallel phase

        def _analyze_code_task(item):
            url, code = item
            try:
                self.analyze_code(code, url)
            except Exception:
                pass

        MAX_CODE_WORKERS = self.MAX_CODE_WORKERS   # regex is CPU-heavy; more workers risks GIL contention
        with ThreadPoolExecutor(max_workers=MAX_CODE_WORKERS) as executor:
            list(executor.map(_analyze_code_task, js_contents.items()))

        self.add_endpoint = _original_add  # restore original

    def _analyze_webpack_module_bodies(self, js_contents):
        """Run every webpack module body through analyze_code individually."""
        # ── UPGRADE: Static webpack module body analysis ──────────────────
        # Now that all JS files have been fetched and variable-resolved,
        # run the StaticWebpackModuleAnalyzer on every bundle that looks like
        # a webpack artifact. This surfaces endpoints hidden in modules that
        # are never navigated to during a normal crawl.
        _wpk_static = StaticWebpackModuleAnalyzer(self)
        _wpk_snap   = len(self.endpoints)
        _wpk_bundles = 0
        for _url, _code in js_contents.items():
            try:
                new_from_wpk = _wpk_static.analyze_bundle(_code, _url)
                if new_from_wpk > 0:
                    _wpk_bundles += 1
            except Exception:
                pass
        _wpk_new = len(self.endpoints) - _wpk_snap
        if _wpk_new:
            print(f"  [WPK-STATIC] {_wpk_new} endpoint(s) from webpack module bodies ({_wpk_bundles} bundles)")

    def _discover_static_websockets(self, js_contents):
        """WebSocket URLs found in the raw JS text."""
        print("\n  [WebSocket Discovery] Scanning JavaScript for WebSocket endpoints...")
        ws_discovery = WebSocketDiscovery()
        ws_count = 0

        for url, code in js_contents.items():
            ws_endpoints = ws_discovery.discover_from_js(code, url)
            for ws_ep in ws_endpoints:
                self.add_endpoint(
                    ws_ep['endpoint'],
                    'WS',
                    [],
                    'WEBSOCKET',
                    ws_ep['source'],
                    'WEBSOCKET_ENDPOINT',
                    85
                )
                ws_count += 1
                # Force correct classification/method if the URL was deduplicated
                # with a lower-confidence entry that had wrong classification.
                _ws_url_norm = ws_ep['endpoint'].rstrip('/')
                for _ep in self.endpoints:
                    if _ep['endpoint'].rstrip('/') == _ws_url_norm:
                        _ep['classification'] = 'WEBSOCKET_ENDPOINT'
                        _ep['method'] = 'WS'
                        _ep['confidence_score'] = max(_ep.get('confidence_score', 0), 85)
                        break

        if ws_count > 0:
            print(f"    [+] Found {ws_count} WebSocket endpoints")

    def _analyze_lazy_dynamic_imports(self, js_contents):
        """Fetch + analyze chunks queued in self._dynamic_imports (up to 2 rounds)."""
        # ── GAP 2 FIX: Fetch & analyze dynamically-imported JS chunks ─────────
        # During analyze_code() every import('/chunk.js') / require.ensure() /
        # __webpack_require__() call enqueued the resolved URL into _dynamic_imports.
        # Now that the initial pass is complete, fetch any NEW chunks and run the
        # full analysis pipeline on them (up to 2 rounds to handle nested splits).
        _dyn_rounds = 0
        while self._dynamic_imports and _dyn_rounds < 2:
            _dyn_rounds += 1
            _new_imports = self._dynamic_imports - set(js_contents.keys()) - self.analyzed_js_files
            if not _new_imports:
                break
            print(f"\n  [GAP2-DynamicImports] Round {_dyn_rounds}: fetching {len(_new_imports)} lazy chunk(s)...")
            self._dynamic_imports.clear()   # will be re-populated by analyze_code below
            _dyn_snap = len(self.endpoints)
            for _dyn_url in _new_imports:
                try:
                    _r = self.rate_limiter.throttled_get(self.session, _dyn_url, timeout=20, verify=False)
                    if _r.status_code != 200:
                        continue
                    _ct = _r.headers.get('content-type', '')
                    if 'html' in _ct.lower() or _r.text.strip().startswith('<'):
                        continue
                    _dyn_code = _r.text
                    if len(_dyn_code) < 80:
                        continue
                    # Variable extraction (for cross-file DI chain)
                    self.resolver.extract_all_variables(_dyn_code, _dyn_url.split('/')[-1])
                    # Full endpoint extraction
                    self.analyze_code(_dyn_code, _dyn_url)
                    js_contents[_dyn_url] = _dyn_code
                    self.analyzed_js_files.add(_dyn_url)
                    print(f"    ✓ {_dyn_url.split('/')[-1]} ({len(_dyn_code):,} bytes)")
                except Exception:
                    pass
            _dyn_new = len(self.endpoints) - _dyn_snap
            if _dyn_new:
                print(f"  [GAP2-DynamicImports] +{_dyn_new} endpoint(s) from lazy chunks")

    def _drop_low_confidence_endpoints(self):
        """Final strict confidence filter over self.endpoints."""
        # 🔥 FINAL FIX 2: Strict confidence filtering - remove all low-quality endpoints
        pre_filter_count = len(self.endpoints)
        self.endpoints = [
            ep for ep in self.endpoints
            if not (
                # Remove zero-confidence vendor garbage
                (ep.get("confidence_score", 0) == 0 and ep.get("origin", {}).get("is_vendor", False))
                or
                # 🚀 ULTIMATE FIX 2.3: Raised from 20 to 40 (matches add_endpoint threshold)
                (ep.get("confidence_score", 0) < 40 and ep.get("classification") in ["LIBRARY_ARTIFACT", "NOISE_CANDIDATE"])
                or
                # 🚀 ULTIMATE FIX 2.4: Also remove vendor sources with confidence < 40
                (ep.get("confidence_score", 0) < 40 and ep.get("origin", {}).get("is_vendor", False))
                or
                # Remove external references unless high confidence
                (ep.get("classification") == "EXTERNAL_REFERENCE" and ep.get("confidence_score", 0) < 50)
            )
        ]
        filtered_count = pre_filter_count - len(self.endpoints)
        if filtered_count > 0:
            print(f"    [FILTER] Removed {filtered_count} low-confidence/vendor endpoints")

    def _run_graphql_introspection(self):
        """GraphQL introspection + SPA-proxied GraphQL remapping; emits every operation."""
        # 🚀 LEGENDARY INTEGRATION 2: GraphQL Introspection
        print("\n  [GraphQL Introspection] Scanning for GraphQL APIs...")
        graphql = GraphQLIntrospector(self.session, base_url=self.base_url, resolver=self.resolver)
        graphql_schemas = graphql.scan(self.endpoints)

        # Add all discovered GraphQL operations as endpoints
        graphql_ops_count = 0

        # FIX EP-E GraphQL proxy remapping (TC-P4-001 GET HEURISTIC):
        # When GraphQL is found at a backend host (localhost:4002) but the SPA is
        # a different host (localhost:3005), detect if the SPA proxies GraphQL at
        # its own /graphql path using TC-P4-001: a GET probe that returns a JSON
        # indicator response (e.g. { introspection: 'enabled', playground: ... }).
        #
        # WHY GET not POST/static:
        # - Static JS: App E main.js has NO '/graphql' literal in the client bundle.
        # - POST introspection: App E proxies to Docker container hostname
        #   'graphql-backend:4002' which is unreachable from the host machine.
        # - GET probe: The handler immediately returns JSON with 'introspection'
        #   key WITHOUT proxying. This is TC-P4-001 — a deliberate signal.
        #
        # FP protection: Apps A/B/C/D return HTML (SPA catch-all) for GET /graphql
        # because they have no /graphql route. Content-Type check kills them.
        spa_parsed = urllib.parse.urlparse(self.base_url)
        spa_gql_bases = set()

        # Collect unique GQL paths from all backend schemas
        _gql_paths_to_check = set()
        for gql_ep in graphql_schemas:
            gql_parsed_tmp = urllib.parse.urlparse(gql_ep)
            if gql_parsed_tmp.netloc != spa_parsed.netloc:
                _gql_paths_to_check.add(gql_parsed_tmp.path)

        _already_probed = set()
        for _gql_path in _gql_paths_to_check:
            remapped = (f"{spa_parsed.scheme}://{spa_parsed.netloc}"
                        f"{_gql_path}").rstrip('/')
            if remapped in _already_probed:
                continue
            _already_probed.add(remapped)

            _spa_hosts_gql = False

            # SIGNAL 1 (TC-P1.5-007): sourcemap_gql_endpoints — populated when
            # _discover_nextjs_chunks() found api-graphql.js and its source map
            # contained the literal SPA-local URL "http://localhost:3005/graphql".
            # This is the definitive static signal — requires no runtime probing.
            _sm_gql_eps = getattr(self, 'sourcemap_gql_endpoints', set())
            if remapped in _sm_gql_eps:
                _spa_hosts_gql = True

            # SIGNAL 2 (TC-P4-001): GET probe for JSON GraphQL playground indicator.
            # Next.js /api/graphql route returns { introspection: 'enabled', ... }
            # on GET. Works when the app is served by Next.js runtime (not nginx).
            if not _spa_hosts_gql:
                try:
                    _get_r = self.session.get(
                        remapped,
                        headers={'Accept': 'application/json'},
                        timeout=5, verify=False, allow_redirects=False
                    )
                    if _get_r.status_code == 200:
                        _ct = _get_r.headers.get('Content-Type', '').lower()
                        if 'json' in _ct:
                            try:
                                _get_json = _get_r.json()
                                if isinstance(_get_json, dict):
                                    _keys = set(k.lower() for k in _get_json.keys())
                                    _gql_indicator_keys = {
                                        'introspection', 'playground', 'graphql',
                                        'schema', '__schema', 'resolvers',
                                    }
                                    if _keys & _gql_indicator_keys:
                                        _spa_hosts_gql = True
                            except Exception:
                                pass
                except Exception:
                    pass

            # SIGNAL 3: POST introspection fallback (works when proxy is reachable)
            if not _spa_hosts_gql:
                try:
                    _post_r = self.session.post(
                        remapped,
                        json={'query': '{ __typename }',
                              'operationName': None, 'variables': {}},
                        headers={'Content-Type': 'application/json',
                                 'Accept': 'application/json'},
                        timeout=5, verify=False
                    )
                    if _post_r.status_code in (200, 400):
                        _ct = _post_r.headers.get('Content-Type', '').lower()
                        if 'json' in _ct:
                            try:
                                _pj = _post_r.json()
                                if isinstance(_pj, dict) and (
                                    'data' in _pj or 'errors' in _pj
                                ):
                                    _spa_hosts_gql = True
                            except Exception:
                                pass
                except Exception:
                    pass

            if _spa_hosts_gql:
                for gql_ep in graphql_schemas:
                    gql_ep_parsed = urllib.parse.urlparse(gql_ep)
                    if (gql_ep_parsed.netloc != spa_parsed.netloc and
                            gql_ep_parsed.path == _gql_path):
                        spa_gql_bases.add((gql_ep, remapped))

        for gql_endpoint, schema in graphql_schemas.items():
            # RC7-FIX: Add the base GraphQL endpoint itself
            self.add_endpoint(
                gql_endpoint,
                'POST',
                [],
                'GRAPHQL_ENDPOINT',
                gql_endpoint,
                'GRAPHQL_API',
                100
            )
            graphql_ops_count += 1

            # Add each query as an endpoint (using fragment identifier format)
            for query in schema['queries']:
                self.add_endpoint(
                    f"{gql_endpoint}#{query['name']}",
                    'POST',
                    query['args'],
                    'GRAPHQL_QUERY',
                    gql_endpoint,
                    'GRAPHQL_API',
                    95
                )
                graphql_ops_count += 1

            # Add each mutation as an endpoint
            for mutation in schema['mutations']:
                self.add_endpoint(
                    f"{gql_endpoint}#{mutation['name']}",
                    'POST',
                    mutation['args'],
                    'GRAPHQL_MUTATION',
                    gql_endpoint,
                    'GRAPHQL_API',
                    95
                )
                graphql_ops_count += 1

            # Add each subscription as an endpoint
            for sub in schema.get('subscriptions', []):
                self.add_endpoint(
                    f"{gql_endpoint}#{sub['name']}",
                    'WS',
                    sub.get('args', []),
                    'GRAPHQL_SUBSCRIPTION',
                    gql_endpoint,
                    'GRAPHQL_API',
                    95
                )
                graphql_ops_count += 1

        # FIX EP-E: emit proxy-remapped ops onto SPA base_url for each backend schema
        for backend_ep, spa_ep in spa_gql_bases:
            schema = graphql_schemas[backend_ep]
            # Emit the SPA-proxied base endpoint
            self.add_endpoint(spa_ep, 'POST', [], 'GRAPHQL_ENDPOINT', backend_ep, 'GRAPHQL_API', 88)
            for query in schema['queries']:
                self.add_endpoint(f"{spa_ep}#{query['name']}", 'POST', query['args'],
                                  'GRAPHQL_QUERY', backend_ep, 'GRAPHQL_API', 88)
                graphql_ops_count += 1
            for mutation in schema['mutations']:
                self.add_endpoint(f"{spa_ep}#{mutation['name']}", 'POST', mutation['args'],
                                  'GRAPHQL_MUTATION', backend_ep, 'GRAPHQL_API', 88)
                graphql_ops_count += 1
            for sub in schema.get('subscriptions', []):
                self.add_endpoint(f"{spa_ep}#{sub['name']}", 'WS', sub.get('args', []),
                                  'GRAPHQL_SUBSCRIPTION', backend_ep, 'GRAPHQL_API', 88)
                graphql_ops_count += 1

        # GraphQL endpoints that confirmed Automatic Persisted Queries but have
        # introspection disabled (introspected ones were already added above).
        for apq_ep in graphql.apq_endpoints:
            if apq_ep not in graphql_schemas:
                self.add_endpoint(apq_ep, 'POST', [], 'GRAPHQL_APQ_ENDPOINT', apq_ep, 'GRAPHQL_API', 90)
                graphql_ops_count += 1

        if graphql_ops_count > 0:
            print(f"    [+] Discovered {graphql_ops_count} GraphQL operations from {len(graphql_schemas)} endpoints")
