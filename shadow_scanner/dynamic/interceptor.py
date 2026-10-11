"""Phase 3: Playwright-driven dynamic discovery with a recursive feedback loop."""
import json
import re
import time
import urllib.parse
from collections import deque

from shadow_scanner.config import PLAYWRIGHT_AVAILABLE, is_ignored_url, logger, sync_playwright
from shadow_scanner.dynamic.browser_scripts import INTERCEPTOR_SCRIPT
from shadow_scanner.dynamic.indexeddb import IndexedDBExtractor
from shadow_scanner.dynamic.webpack_runtime import WebpackModuleGraphReconstructor
from shadow_scanner.protocols.websockets import WebSocketDiscovery
# ==============================================================================
# DYNAMIC INTERCEPTOR - ENHANCED WITH FEEDBACK LOOP
# ==============================================================================
class DynamicInterceptor:
    """
    Enhanced Dynamic Interceptor with recursive feedback loop.
    
    Key improvements:
    1. Captures lazy-loaded JS files and feeds them back to static analyzer
    2. Multi-pass navigation with increasing depth
    3. Better handling of authentication redirects
    4. Intelligent route prioritization
    """

    def __init__(self, target_url, analyzer, cookies=None, max_routes=30, max_depth=5,
                 auth_headers=None):
        self.target_url = target_url
        self.analyzer = analyzer  # Feedback loop to static analyzer
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.cookies = cookies
        self.auth_headers = auth_headers or {}  # Extra headers from AuthEngine (Bearer, CSRF, etc.)
        self.endpoints = []
        self.seen_requests = set()
        self.analyzed_js_files = set()  # Track JS files we've already analyzed
        self.discovered_routes = set()
        self.max_routes = max_routes
        self.max_depth = max_depth
        self._depth1_routes = []
        self.skipped_clicks = []     # labels the denylist refused to click
        self.session_storage_data = {}
        self.local_storage_data = {}
        # Queue: decouple JS analysis from Playwright's event loop to prevent
        # blocking the browser's network thread during heavy AST/regex work.
        self.js_analysis_queue = deque()

    def run(self, static_endpoints=[]):
        if not PLAYWRIGHT_AVAILABLE:
            print("\n[PHASE 3] SKIP — Playwright not installed")
            print("  Install: pip install playwright && python -m playwright install chromium")
            self.skip_reason = 'playwright_not_installed'
            return []

        print("\n[PHASE 3] Dynamic Discovery with Recursive Feedback Loop")
        print(f"  Max routes per depth: {self.max_routes}, Max depth: {self.max_depth}")
        self.skip_reason = None

        # Multi-pass navigation with increasing depth
        for depth in range(1, self.max_depth + 1):
            print(f"\n  [Depth {depth}/{self.max_depth}] Navigating routes...")

            # Get routes for this depth level
            routes = self._get_routes_for_depth(static_endpoints, depth)

            if not routes:
                print(f"    No new routes at depth {depth}")
                break

            print(f"    Routes to visit: {len(routes)}")

            # Navigate with feedback loop
            self._navigate_routes_with_feedback(routes, depth)

            print(f"    Analyzed {len(self.analyzed_js_files)} JS files so far")
            print(f"    Discovered {len(self.discovered_routes)} unique routes")
            print(f"    Captured {len(self.endpoints)} API calls")

        # Re-pass: revisit the first routes of depth 1 now that the token is in
        # browser storage (effects that read the token on mount fire this time).
        # Uses routes this scan actually visited - no fixed route names.
        if self.auth_headers.get('Authorization') and PLAYWRIGHT_AVAILABLE and self._depth1_routes:
            _repass_routes = self._depth1_routes[:5]
            print(f"\n  [REPASS] Re-navigating {len(_repass_routes)} route(s) with auth token in storage...")
            self._navigate_routes_with_feedback(_repass_routes, depth=99)

        print(f"\n  [+] Total dynamic endpoints: {len(self.endpoints)}")
        print(f"  [+] Total JS files analyzed: {len(self.analyzed_js_files)}")

        # Every observed request becomes RUNTIME evidence in the shared store,
        # so it is merged and scored with the static findings (one store).
        for e in self.endpoints:
            try:
                self.analyzer.add_endpoint(
                    e['endpoint'], e.get('method', 'GET'), e.get('parameters', []),
                    e.get('type', 'DYNAMIC_XHR_INTERCEPT'), e.get('source', 'Browser'),
                    e.get('classification', 'VERIFIED_API'), e.get('confidence_score', 95))
            except Exception as exc:
                logger.debug(f"[PHASE 3] could not record {e.get('endpoint')}: {exc}")

        return self.endpoints

    def _get_routes_for_depth(self, static_endpoints, depth):
        """Get routes to visit at a specific depth level"""
        routes = []

        if depth == 1:
            # First pass: start with target URL
            routes = [self.target_url]

            # Add high-priority frontend routes
            for e in static_endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in routes:
                        routes.append(clean)

            # (No guessed route names: routes come from the code and the pages.)
        else:
            # Subsequent passes: use newly discovered routes
            routes = list(self.discovered_routes)

            # Also check for any new routes from the analyzer
            for e in self.analyzer.endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in self.discovered_routes:
                        routes.append(clean)

        # Prioritize routes with hash fragments and deeper paths (sorted first so
        # equal scores keep a stable order)
        routes = self._prioritize_routes(sorted(set(routes)), depth)

        # Limit routes per depth
        routes = routes[:self.max_routes]
        if depth == 1:
            self._depth1_routes = list(routes)
        return routes

    def _clean_route(self, endpoint):
        """Clean and normalize a route for navigation - WITH AGGRESSIVE FILTERING"""
        if not endpoint:
            return None

        # Remove quotes and whitespace
        clean = endpoint.replace('"', '').replace("'", "").strip()

        # CRITICAL FIX 1: Reject routes containing 'undefined' or 'null' string literals
        if 'undefined' in clean.lower() or '/null' in clean or '/null/' in clean:
            return None

        # CRITICAL FIX 2: Reject routes with template syntax
        if '${' in clean or '{{' in clean or '`' in clean:
            return None

        # CRITICAL FIX 3: Reject routes with spaces (malformed)
        if ' ' in clean:
            return None

        # CRITICAL FIX 4a: Reject routes where any path segment is a single character
        # (catches garbage fragments like /n/, /a/, /x/ from partial AST extraction)
        path_part = urllib.parse.urlparse(clean).path if clean.startswith('http') else clean
        if any(len(seg) == 1 for seg in path_part.strip('/').split('/') if seg):
            return None

        # CRITICAL FIX 4: Reject internal framework files
        if any(x in clean.lower() for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'template.html', '/xl/']):
            return None

        # Build full URL
        if clean.startswith('http'):
            full = clean
        elif clean.startswith('/'):
            full = urllib.parse.urljoin(self.base_url, clean)
        else:
            return None

        # Only return if it's from our domain
        if self.domain in full:
            return full

        return None

    def _prioritize_routes(self, routes, depth):
        """Prioritize routes based on depth and characteristics"""
        def route_score(route):
            score = 0

            # Prefer hash routes at all depths
            if '#/' in route:
                score += 100

            # Prefer deeper paths
            path_depth = route.count('/')
            score += path_depth * 10

            # Prefer routes with meaningful names (not just IDs)
            if any(keyword in route.lower() for keyword in ['dashboard', 'admin', 'user', 'profile', 'settings', 'manage', 'list', 'view', 'edit']):
                score += 50

            # Penalize routes that look like they need parameters
            if re.search(r'/\d+$', route) or re.search(r'/:[\w]+', route):
                score -= 30

            return score

        return sorted(routes, key=route_score, reverse=True)
    def _navigate_routes_with_feedback(self, routes, depth):
        """Navigate routes and feed discovered JS back to analyzer"""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Build extra HTTP headers for the browser context (Bearer tokens, CSRF, etc.)
            extra_headers = {}
            if self.auth_headers:
                extra_headers.update(self.auth_headers)

            context = browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1920, 'height': 1080},
                extra_http_headers=extra_headers if extra_headers else {}
            )

            # Set cookies
            if self.cookies:
                context.add_cookies([
                    {"name": k, "value": v, "domain": self.domain, "path": "/"}
                    for k, v in self.cookies.items()
                ])

            if extra_headers:
                print(f"      [AUTH] Injecting {len(extra_headers)} auth header(s) into browser context")

            # ── Full prototype-level instrumentation script ───────────────────
            # Intercepts ALL network APIs at the prototype level so they cannot
            # be bypassed by code that saved references before our override.
            # Covers: fetch, XHR, WebSocket, EventSource, sendBeacon, axios.
            interceptor_script = INTERCEPTOR_SCRIPT   # see dynamic/browser_scripts.py

            # ── shared extractors (survive across pages) ──────────────────────
            ws_discovery      = WebSocketDiscovery()
            wpk_reconstructor = WebpackModuleGraphReconstructor(self.domain)
            idb_extractor     = IndexedDBExtractor(self.base_url)
            wpk_done          = False

            # ── CORE FIX: fresh page per route ────────────────────────────────
            # A shared page that hangs on route N poisons ALL subsequent routes
            # because page.evaluate() / page.goto() on a broken context never
            # return.  Giving each route its own page guarantees isolation.
            for i, route in enumerate(routes, 1):
                print(f"      [{i}/{len(routes)}] {route[:80]}", end='\r')

                page = context.new_page()
                # Hard caps: navigation AND any JS evaluation both time out at 12 s.
                page.set_default_navigation_timeout(12000)
                page.set_default_timeout(12000)

                try:
                    page.add_init_script(interceptor_script)

                    # FIX PHASE3-FETCH: Inject bearer token into browser storage so
                    # React/Vue useEffect hooks can read it and fire authenticated requests.
                    if self.auth_headers.get('Authorization'):
                        _tok = self.auth_headers['Authorization'].replace('Bearer ', '').strip()
                        _storage_script = """
                        (() => {
                            const token = '%s';
                            const keys = ['token', 'authToken', 'accessToken', 'auth_token',
                                          'jwt', 'bearerToken', 'api_token', 'id_token',
                                          'access_token', 'userToken', 'jwtToken'];
                            for (const key of keys) {
                                try { localStorage.setItem(key, token); } catch(_) {}
                                try { sessionStorage.setItem(key, token); } catch(_) {}
                            }
                            // Also set the full "Bearer token" string for Axios defaults
                            try { localStorage.setItem('authHeader', 'Bearer ' + token); } catch(_) {}
                            window.__AUTH_TOKEN__   = token;
                            window.__BEARER_TOKEN__ = 'Bearer ' + token;
                        })();
                        """ % _tok.replace("'", "\\'")
                        try:
                            page.add_init_script(_storage_script)
                        except Exception:
                            pass

                    ws_discovery.intercept_playwright_websockets(page)
                    page.on("response", self._handle_response)
                    page.on("request",  self._handle_request)

                    # ── navigate ──────────────────────────────────────────────
                    nav_ok = False
                    try:
                        response = page.goto(route, wait_until="domcontentloaded", timeout=12000)
                        # FIX PHASE3-FETCH: was 1500 — increase to 3500 to let React useEffect
                        # and async fetch calls fully complete before capturing API calls.
                        page.wait_for_timeout(3500)
                        nav_ok = True
                    except Exception:
                        try: page.stop()
                        except Exception: pass

                    if not nav_ok:
                        continue

                    # ── auth redirect guard ───────────────────────────────────
                    if response and 'login' in page.url.lower() and 'login' not in route.lower():
                        print("\n      [!] AUTH REQUIRED: Redirected to login page")
                        print("      [!] Re-run with auth cookies for full results")
                        self.skip_reason = 'auth_redirect'
                        break

                    # ── webpack module graph (once, first good page) ──────────
                    if not wpk_done:
                        try:
                            wpk_new = wpk_reconstructor.extract_from_page(page, self.analyzer)
                            if wpk_new:
                                print(f"\n      [WPK] Module graph: {wpk_new} new endpoints")
                        except Exception:
                            pass
                        wpk_done = True

                    # ── route discovery ───────────────────────────────────────
                    try:
                        self._extract_routes_from_page(page)
                    except Exception:
                        pass

                    # ── active crawl (click buttons etc.) ────────────────────
                    try:
                        self._active_crawl_interactions(page)
                    except Exception:
                        pass

                    time.sleep(0.3)

                    # ── storage / IndexedDB ───────────────────────────────────
                    try:
                        self._extract_storage_data(page)
                    except Exception:
                        pass
                    try:
                        # FIX IDB: Wait for async IndexedDB writes before extracting
                        page.wait_for_timeout(2000)
                        idb_extractor.extract_from_page(page, self.analyzer)
                    except Exception:
                        pass

                    # ── WebSocket harvest ─────────────────────────────────────
                    try:
                        ws_discovery.extract_captured_websockets(page)
                    except Exception:
                        pass

                    # ── runtime API call harvest (fetch/XHR/SSE/beacon/axios/GraphQL) ──
                    self._harvest_runtime_api_calls(page)

                    # ── SSE endpoint harvest ──────────────────────────────────
                    self._harvest_sse_urls(page)

                except Exception:
                    pass   # never let one route kill the scan

                finally:
                    # GUARANTEED cleanup — this runs even if continue/break fired
                    try:
                        page.close()
                    except Exception:
                        pass

                    # ── Flush JS analysis queue (safe: outside Playwright event loop) ──
                    # Process any JS files captured during this page's network activity.
                    # Running here (after page.close()) means zero risk of blocking
                    # the browser's network thread with heavy AST/regex/esprima work.
                    while self.js_analysis_queue:
                        q_url, q_code = self.js_analysis_queue.popleft()
                        try:
                            self.analyzer.analyze_code_from_dynamic(q_code, q_url)
                        except Exception:
                            pass

            self._record_websocket_results(ws_discovery)

            print()  # New line after progress
            browser.close()

    def _harvest_runtime_api_calls(self, page):
        """Read window.__api_calls (filled by INTERCEPTOR_SCRIPT) into self.endpoints."""
        try:
            api_calls = page.evaluate("window.__api_calls || []")
            for call in (api_calls or []):
                url    = call.get('url', '')
                method = call.get('method', 'GET')
                ctype  = call.get('type', 'unknown')
                if not url or len(url) < 4:
                    continue
                # Ignore same-page fragment navigation
                if url.startswith('#') or url.startswith('javascript:'):
                    continue
                rkey = f"{method}:{url}"
                if rkey in self.seen_requests:
                    continue
                self.seen_requests.add(rkey)

                # Classification by interception type
                if ctype == 'graphql':
                    classification = 'GRAPHQL_API'
                    ep_type        = 'RUNTIME_GRAPHQL'
                    confidence     = 100
                elif ctype == 'eventsource':
                    classification = 'SSE_ENDPOINT'
                    ep_type        = 'RUNTIME_SSE'
                    confidence     = 95
                elif ctype == 'beacon':
                    classification = 'VERIFIED_API'
                    ep_type        = 'RUNTIME_BEACON'
                    confidence     = 90
                else:
                    classification = 'VERIFIED_API'
                    ep_type        = f'RUNTIME_{ctype.upper()}'
                    confidence     = 95

                self.endpoints.append({
                    "endpoint":         url.split('?')[0] if '?' in url and ctype != 'graphql' else url,
                    "method":           method,
                    "parameters":       list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys()) if '?' in url else [],
                    "type":             ep_type,
                    "source":           "RuntimeInterception",
                    "classification":   classification,
                    "confidence_score": confidence,
                    "origin": {"is_vendor": False, "extraction_type": ep_type, "provenance": ["RUNTIME"]},
                })
        except Exception:
            pass

    def _harvest_sse_urls(self, page):
        """Read EventSource URLs captured by INTERCEPTOR_SCRIPT."""
        try:
            sse_urls    = page.evaluate("window.__sse_urls || []")
            for ep_url in (sse_urls or []):
                if ep_url and ep_url not in self.seen_requests:
                    self.seen_requests.add(ep_url)
                    self.endpoints.append({"endpoint": ep_url, "method": "GET",
                        "parameters": [], "type": "RUNTIME_SSE",
                        "source": "EventSource", "classification": "SSE_ENDPOINT",
                        "confidence_score": 95,
                        "origin": {"is_vendor": False, "extraction_type": "RUNTIME_SSE"}})
        except Exception:
            pass

    def _record_websocket_results(self, ws_discovery):
        """Add Playwright-captured WebSocket connections and print a summary."""
        for ws_url in ws_discovery.websocket_endpoints:
            self.endpoints.append({
                "endpoint":         ws_url,
                "method":           "WS",
                "parameters":       [],
                "type":             "WEBSOCKET_DYNAMIC",
                "source":           "Playwright",
                "classification":   "WEBSOCKET_ENDPOINT",
                "confidence_score": 90,
            })
        if ws_discovery.websocket_endpoints:
            print(f"\n      [WebSocket] {len(ws_discovery.websocket_endpoints)} connections found")
            for ws_url in ws_discovery.websocket_endpoints[:5]:
                print(f"        • {ws_url}")
        if ws_discovery.captured_messages:
            total = sum(len(m) for m in ws_discovery.captured_messages.values())
            print(f"      [WebSocket] {total} messages from {len(ws_discovery.captured_messages)} connections")
    def _extract_routes_from_page(self, page):
        """Extract route references from the current page"""
        try:
            # Extract from href attributes
            links = page.query_selector_all('a[href]')
            for link in links[:50]:  # Limit to prevent hanging
                try:
                    href = link.get_attribute('href')
                    if href:
                        clean = self._clean_route(href)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # Extract from router-link or similar SPA navigation
            spa_links = page.query_selector_all('[routerlink], [ui-sref], [ng-href], [to]')
            for link in spa_links[:50]:
                try:
                    for attr in ['routerlink', 'ui-sref', 'ng-href', 'to']:
                        value = link.get_attribute(attr)
                        if value:
                            clean = self._clean_route(value)
                            if clean and clean not in self.discovered_routes:
                                self.discovered_routes.add(clean)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 🔥 FINAL FIX 3.1: Extract routes from JavaScript window.location usage
            try:
                js_routes = page.evaluate('''() => {
                    const routes = [];
                    // Try to extract from window.__ROUTES__ or similar globals
                    if (window.__ROUTES__) routes.push(...window.__ROUTES__);
                    if (window.routes) routes.push(...window.routes);
                    if (window.app && window.app.routes) routes.push(...window.app.routes);
                    return routes.filter(r => typeof r === 'string');
                }''')
                for route in js_routes:
                    clean = self._clean_route(route)
                    if clean and clean not in self.discovered_routes:
                        self.discovered_routes.add(clean)
            except Exception as _exc:
                logger.debug(f"[Suppressed] {_exc}")

        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

    def _extract_storage_data(self, page):
        """Extract localStorage, sessionStorage, IndexedDB — and mine API base URLs."""
        try:
            local_storage = page.evaluate('() => { return JSON.stringify(localStorage); }')
            session_storage = page.evaluate('() => { return JSON.stringify(sessionStorage); }')

            if local_storage:
                self.local_storage_data = json.loads(local_storage)
            if session_storage:
                self.session_storage_data = json.loads(session_storage)

            # T23: Parse localStorage/sessionStorage for API base URL keys
            # Apps sometimes cache their API base URL in localStorage on boot.
            _API_STORAGE_KEYS = re.compile(
                r'(?:api(?:Base|Url|Endpoint|Host|Root)|baseUrl|serverUrl|backendUrl'
                r'|serviceUrl|remoteUrl|graphqlUrl|wsUrl)',
                re.IGNORECASE
            )
            for store_data in [self.local_storage_data,
                               getattr(self, 'session_storage_data', {})]:
                if not isinstance(store_data, dict):
                    continue
                for key, val in store_data.items():
                    if not _API_STORAGE_KEYS.search(key):
                        continue
                    if not isinstance(val, str):
                        continue
                    if val.startswith(('http://', 'https://', '/')):
                        # Register as a base URL in the analyzer's resolver
                        if hasattr(self, 'analyzer') and self.analyzer:
                            self.analyzer.resolver.global_scope[key] = val
                            self.analyzer.resolver.global_scope[f'localStorage.{key}'] = val
                            # If no existing getBase, adopt this value
                            if not self.analyzer.resolver.methods.get('getBase'):
                                self.analyzer.resolver.methods['getBase'] = val
                            logger.debug(f"[localStorage] API base from key '{key}': {val}")
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

        # FIX FN-7: Read IndexedDB product-cache and similar API URL caches
        # React/Vue apps cache fetch() URLs in IndexedDB.
        try:
            idb_urls = page.evaluate('''
                () => new Promise((resolve) => {
                    const results = [];
                    try {
                        const req = indexedDB.databases ? indexedDB.databases() : Promise.resolve([]);
                        Promise.resolve(req).then(dbs => {
                            if (!dbs || dbs.length === 0) { resolve(results); return; }
                            let pending = dbs.length;
                            dbs.forEach(dbInfo => {
                                const openReq = indexedDB.open(dbInfo.name);
                                openReq.onsuccess = (e) => {
                                    const db = e.target.result;
                                    const storeNames = Array.from(db.objectStoreNames);
                                    let storePending = storeNames.length;
                                    if (storePending === 0) { if (--pending === 0) resolve(results); return; }
                                    storeNames.forEach(storeName => {
                                        const tx = db.transaction(storeName, 'readonly');
                                        const store = tx.objectStore(storeName);
                                        const getAllReq = store.getAll();
                                        getAllReq.onsuccess = (ev) => {
                                            const items = ev.target.result || [];
                                            items.forEach(item => {
                                                if (item && typeof item === 'object') {
                                                    const url = item.requestUrl || item.cacheUrl || item.url || item.apiUrl;
                                                    if (url && typeof url === 'string' && url.startsWith('/')) {
                                                        results.push(url);
                                                    }
                                                }
                                            });
                                            if (--storePending === 0 && --pending === 0) resolve(results);
                                        };
                                        getAllReq.onerror = () => { if (--storePending === 0 && --pending === 0) resolve(results); };
                                    });
                                };
                                openReq.onerror = () => { if (--pending === 0) resolve(results); };
                            });
                        });
                    } catch(err) { resolve(results); }
                })
            ''')
            if idb_urls:
                for raw_url in idb_urls:
                    if raw_url and isinstance(raw_url, str) and len(raw_url) > 3:
                        full_url = urllib.parse.urljoin(self.base_url, raw_url)
                        self.endpoints.append({
                            "endpoint":         full_url.split('?')[0],
                            "method":           "GET",
                            "parameters":       [],
                            "type":             "INDEXEDDB_CACHED_URL",
                            "source":           "Playwright_IndexedDB",
                            "classification":   "VERIFIED_API",
                            "confidence_score": 90,
                        })
                if idb_urls:
                    logger.debug(f"[IndexedDB] {len(idb_urls)} cached API URL(s) found")
        except Exception as _exc:
            logger.debug(f"[IndexedDB] {_exc}")

    def _handle_response(self, response):
        """
        Handle all responses - the core of the feedback loop.
        
        This captures:
        1. New JavaScript files → feeds back to static analyzer
        2. API calls → adds to endpoints list
        3. Route references → adds to discovered routes
        """
        url = response.url

        # Skip ignored domains
        if is_ignored_url(url):
            return

        # Skip if already seen
        if url in self.seen_requests:
            return

        self.seen_requests.add(url)

        try:
            content_type = response.headers.get("content-type", "").lower()

            # ── Live response header intel (T1.1) ────────────────────────────
            # Custom headers the server SENDS BACK often echo trust inputs it
            # honored (X-Internal-IP, X-User-Role) or leak infra (X-Backend,
            # X-Powered-By-Internal). Feed as server_read so trust headers escalate.
            try:
                _hx = getattr(self.analyzer, '_header_extractor', None)
                if _hx is not None and self.domain in url:
                    _rhdrs = response.all_headers()
                    _hx.extract_live_headers(_rhdrs, f'live-response:{url.split("?")[0]}',
                                             'server_read')
            except Exception as _exc:
                logger.debug(f"[Suppressed] {_exc}")

            # 1. FEEDBACK LOOP: Capture and analyze new JavaScript files
            if url.endswith('.js') or "javascript" in content_type:
                if url not in self.analyzer.analyzed_js_files:
                    self.analyzer.analyzed_js_files.add(url)
                    self.analyzed_js_files.add(url)

                    try:
                        code = response.text()
                        if len(code) > 100:
                            # Queue for analysis AFTER page.close() — never block
                            # the Playwright network thread with heavy AST/regex work.
                            self.js_analysis_queue.append((url, code))
                    except Exception as _exc:
                        logger.debug(f"[Suppressed] {_exc}")

            # 2. Capture API calls (JSON responses)
            elif "application/json" in content_type:
                try:
                    endpoint = url.split('?')[0]

                    # The method of the request this response answers (not assumed)
                    try:
                        method = (response.request.method or 'GET').upper()
                    except Exception:
                        method = "GET"
                    # Already recorded from the request event -> nothing new
                    if f"{method}:{endpoint}" in self.seen_requests:
                        return
                    if response.request.resource_type not in ('xhr', 'fetch'):
                        return

                    # Extract parameters from query string
                    params = []
                    parsed = urllib.parse.urlparse(url)
                    if parsed.query:
                        params.extend(urllib.parse.parse_qs(parsed.query).keys())

                    self.endpoints.append({
                        "endpoint": endpoint,
                        "method": method,
                        "parameters": list(set(params)),
                        "type": "DYNAMIC_API_CALL",
                        "source": "Browser",
                        "classification": "VERIFIED_API"
                    })
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 3. Extract route references from HTML responses
            elif "text/html" in content_type:
                try:
                    html = response.text()

                    # Extract hash routes from HTML
                    hash_routes = re.findall(r'href=["\']([^"\']*#/[^"\']+)["\']', html)
                    for route in hash_routes:
                        clean = self._clean_route(route)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

    # ⭐ ENHANCEMENT 1.3: Request interceptor to capture XHR/Fetch API calls
    def _handle_request(self, request):
        """
        Intercept outgoing requests to capture API calls (XHR/Fetch).
        This captures the METHOD correctly from the actual request.
        """
        url = request.url

        # Feed every live request URL into external link extractor
        if hasattr(self, '_ext_link_extractor') and self._ext_link_extractor:
            self._ext_link_extractor.feed_request_url(url, source='Browser_Request')

        # Skip ignored domains
        if is_ignored_url(url):
            return

        # ── Live header intel (T1.1) ──────────────────────────────────────────
        # The SPA's ACTUAL outgoing headers — real secret values, real trust
        # headers (X-Internal-IP, X-Api-Key, X-Tenant-Id) after all env/minify
        # substitution. Only same-origin, and only for API-ish requests to avoid
        # flooding on static assets.
        try:
            _hx = getattr(self.analyzer, '_header_extractor', None)
            if _hx is not None and self.domain in url and \
                    request.resource_type in ("xhr", "fetch", "websocket", "document"):
                _hdrs = request.all_headers()
                _hx.extract_live_headers(_hdrs, f'live-request:{url.split("?")[0]}',
                                         'client_set')
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

        # Only capture XHR and Fetch requests (these are API calls)
        if request.resource_type in ["xhr", "fetch"]:
            try:
                endpoint = url.split('?')[0]
                method = request.method

                # Extract parameters from query string
                params = []
                parsed = urllib.parse.urlparse(url)
                if parsed.query:
                    params.extend(urllib.parse.parse_qs(parsed.query).keys())

                # Every XHR/fetch the app sends is recorded, whatever its origin
                # (APIs usually live on another host than the SPA); third-party
                # hosts were already skipped above. Scope (target host, sibling
                # subdomains, referenced hosts) is decided at evaluation time.
                rkey = f"{method}:{endpoint}"
                if rkey not in self.seen_requests:
                    self.seen_requests.add(rkey)
                    self.endpoints.append({
                        "endpoint": endpoint,
                        "method": method,
                        "parameters": sorted(set(params)),
                        "type": "DYNAMIC_XHR_INTERCEPT",
                        "source": "Browser_Request",
                        "classification": "VERIFIED_API",
                        "confidence_score": 100
                    })
            except Exception as _exc:
                logger.debug(f"[Suppressed] {_exc}")

    # ⭐ ENHANCEMENT 1.4: Active crawling - interact with page elements
    # Elements whose text says they change or end something are never clicked:
    # the crawl runs with the user's session (DS2: requests are not blocked, so
    # the denylist is the safeguard). Matched against text, aria-label, title,
    # value and href.
    CLICK_DENYLIST = re.compile(
        r'log\s*-?\s*out|sign\s*-?\s*out|delete|remove|destroy|purge|erase|\bdrop\b|'
        r'\bpay\b|payment|purchase|\bbuy\b|checkout|place\s+order|submit\s+order|'
        r'confirm|transfer|withdraw|unsubscribe|deactivate|disable|revoke|reset|'
        r'cancel\s+(?:subscription|order|account)|close\s+account|terminate',
        re.IGNORECASE)

    def _click(self, elem, timeout):
        """Click unless the element's label matches CLICK_DENYLIST."""
        try:
            label = ' '.join(filter(None, [
                (elem.inner_text(timeout=500) or '')[:200],
                elem.get_attribute('aria-label') or '',
                elem.get_attribute('title') or '',
                elem.get_attribute('value') or '',
                elem.get_attribute('href') or '',
            ]))
        except Exception:
            label = ''
        if self.CLICK_DENYLIST.search(label):
            self.skipped_clicks.append(label.strip()[:80])
            return False
        elem.click(timeout=timeout)
        return True

    def _active_crawl_interactions(self, page):
        """
        Actively interact with page elements to trigger lazy-loaded API calls.
        This is what Burp does - click buttons, open dropdowns, etc.
        ⭐ IMPROVEMENT 5: Enhanced with authenticated role simulation
        """
        try:
            # ⭐ IMPROVEMENT 5: Click admin, settings, and authenticated UI elements
            admin_selectors = [
                'a[href*="admin"]:visible',
                'a[href*="dashboard"]:visible',
                'a[href*="settings"]:visible',
                'a[href*="profile"]:visible',
                'a[href*="management"]:visible',
                'button:has-text("Admin"):visible',
                'button:has-text("Settings"):visible',
                '[role="button"]:has-text("Menu"):visible',
                '.admin-link:visible',
                '.settings-link:visible',
                '.nav-item:visible',
                '.menu-item:visible'
            ]

            for selector in admin_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for elem in elements[:2]:  # Click up to 2 of each type
                        try:
                            self._click(elem, 1000)
                            time.sleep(0.5)  # Wait for navigation/API calls
                        except Exception as _exc:
                            logger.debug(f"[Suppressed] {_exc}")
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 🚀 ULTIMATE FIX 1.1: More aggressive button clicking (increased from 10 to 20)
            buttons = page.query_selector_all("button:visible")
            for i, button in enumerate(buttons[:20]):  # INCREASED limit to discover more lazy APIs
                try:
                    self._click(button, 1000)
                    time.sleep(0.3)  # Let API call complete
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 🚀 ULTIMATE FIX 1.2: Click submit/action buttons specifically (often trigger hidden APIs)
            action_buttons = page.query_selector_all("button[type='submit']:visible, input[type='submit']:visible, button.submit:visible, button.action:visible")
            for i, btn in enumerate(action_buttons[:10]):
                try:
                    self._click(btn, 1000)
                    time.sleep(0.4)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # Click all clickable divs/spans (common in modern SPAs)
            clickables = page.query_selector_all("[ng-click]:visible, [onclick]:visible, .clickable:visible")
            for i, elem in enumerate(clickables[:5]):  # Limit to 5
                try:
                    self._click(elem, 1000)
                    time.sleep(0.3)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 🚀 ULTIMATE FIX 1.3: Click tabs (often lazy-load content)
            tabs = page.query_selector_all("[role='tab']:visible, .tab:visible, .nav-link:visible")
            for i, tab in enumerate(tabs[:8]):
                try:
                    self._click(tab, 1000)
                    time.sleep(0.4)  # Give time for lazy-loaded APIs
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # Open all dropdowns/selects (triggers data loading)
            selects = page.query_selector_all("select:visible")
            for select in selects[:5]:
                try:
                    self._click(select, 500)
                    time.sleep(0.2)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # Hover over elements (can trigger lazy loading)
            hovers = page.query_selector_all("[data-hover]:visible, .has-dropdown:visible")
            for hover in hovers[:5]:
                try:
                    hover.hover(timeout=500)
                    time.sleep(0.2)
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")

            # 🚀 ULTIMATE FIX 1.4: Scroll to trigger infinite scroll / lazy loading
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                time.sleep(0.3)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(0.5)  # Give time for lazy-loaded content APIs
            except Exception as _exc:
                logger.debug(f"[Suppressed] {_exc}")

            # FIX Issue 12: Collect internal links for future depth passes instead of
            # navigating away. Previously page.goto() was called here, which corrupted
            # the current page context — subsequent extraction ran against the wrong URL.
            try:
                internal_links = page.query_selector_all("a[href^='/']:visible, a[href^='#/']:visible")
                for i, link in enumerate(internal_links[:5]):
                    try:
                        href = link.get_attribute('href')
                        if href and len(href) > 2:
                            # Build full URL
                            if href.startswith('/'):
                                target_url = f"{self.base_url}{href}"
                            else:
                                target_url = f"{self.base_url}/{href}"

                            # Queue for the next depth pass (was added to seen_requests,
                            # which nothing reads for navigation, so it was never visited)
                            clean = self._clean_route(target_url)
                            if clean:
                                self.discovered_routes.add(clean)
                    except Exception as _exc:
                        logger.debug(f"[Suppressed] {_exc}")
            except Exception as _exc:
                logger.debug(f"[Suppressed] {_exc}")

        except Exception:
            pass  # Don't let interaction failures stop the scan
