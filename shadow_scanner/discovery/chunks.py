"""Phase 1.5a/1.6: deterministic lazy-chunk discovery (webpack/Vite runtime, Next.js)."""
import re
import urllib.parse
# ==============================================================================
# WEBPACK CHUNK HARVESTER
# Deterministic lazy-chunk discovery by parsing webpack/Vite runtime bundles.
#
# Replaces fragile route-based Phase 1.6 sub-app discovery with complete
# bundle enumeration that needs zero navigation.
#
# Webpack 4 pattern:
#   script.src = __webpack_require__.p + chunkId + "." + {map}[chunkId] + ".js"
# Webpack 5 pattern:
#   __webpack_require__.u = (id) => id + "." + {103:"abc",201:"def"}[id] + ".js"
# Vite pattern: /.vite/manifest.json  or  /manifest.json
# ==============================================================================
class WebpackChunkHarvester:
    def __init__(self, session, base_url):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        _p = urllib.parse.urlparse(base_url)
        self.origin = f"{_p.scheme}://{_p.netloc}"

    # ------------------------------------------------------------------
    def harvest(self, js_files, known_urls=None):
        known     = set(known_urls or []) | set(js_files)
        discovered = set()

        print(f"\n[CHUNK HARVESTER] Scanning {len(js_files)} bundle(s) for chunk maps...")

        for fn in (self._try_vite_manifest, self._try_webpack_asset_manifest):
            hits = fn()
            if hits:
                print(f"  [+] Manifest: {len(hits)} chunk(s)")
                discovered.update(hits)

        runtime_hits = 0
        for js_url in js_files:
            try:
                r = self.session.get(js_url, timeout=15, verify=False)
                if r.status_code != 200 or len(r.text) < 800:
                    continue
                chunks = self._parse_runtime(r.text, js_url)
                new = chunks - known
                if new:
                    runtime_hits += len(new)
                    discovered.update(new)
                    known.update(new)
            except Exception:
                continue

        if runtime_hits:
            print(f"  [+] Runtime maps: {runtime_hits} chunk(s)")

        result = sorted(
            u for u in discovered
            if u not in set(known_urls or [])
            and u.endswith('.js')
            and u.startswith('http')
        )
        print(f"  [CHUNK HARVESTER] {len(result)} new bundle(s) total")
        return result

    # ------------------------------------------------------------------
    def _try_vite_manifest(self):
        found = set()
        for path in ('/.vite/manifest.json', '/manifest.json',
                     '/assets/manifest.json', '/build/manifest.json'):
            try:
                r = self.session.get(self.origin + path, timeout=6, verify=False)
                if r.status_code != 200:
                    continue
                ct = r.headers.get('content-type', '')
                if 'json' not in ct and not r.text.strip().startswith('{'):
                    continue
                data = r.json()
                for val in data.values():
                    if isinstance(val, dict):
                        f = val.get('file', '')
                        if f.endswith('.js'):
                            found.add(urllib.parse.urljoin(self.origin + '/', f.lstrip('/')))
                if found:
                    return found
            except Exception:
                continue
        return found

    def _try_webpack_asset_manifest(self):
        found = set()
        for path in ('/asset-manifest.json', '/static/asset-manifest.json',
                     '/build/asset-manifest.json'):
            try:
                r = self.session.get(self.origin + path, timeout=6, verify=False)
                if r.status_code != 200:
                    continue
                data = r.json()
                files = data.get('files', data)
                for v in files.values():
                    if isinstance(v, str) and v.endswith('.js'):
                        found.add(urllib.parse.urljoin(self.origin + '/', v.lstrip('/')))
                if found:
                    return found
            except Exception:
                continue
        return found

    # ------------------------------------------------------------------
    def _parse_runtime(self, code, source_url):
        found = set()
        if not re.search(r'__webpack_require__|webpackChunk|webpackJsonp', code):
            return found
        pub = self._extract_public_path(code, source_url)
        base = source_url.rsplit('/', 1)[0] + '/'
        found.update(self._wp5_u_fn(code, pub))
        found.update(self._wp4_script_src(code, pub))
        found.update(self._direct_filenames(code, base))
        return found

    def _extract_public_path(self, code, source_url):
        for pat in (
            r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']',
            r'publicPath\s*[=:]\s*["\']([^"\']+)["\']',
        ):
            m = re.search(pat, code)
            if m:
                p = m.group(1)
                if not p or p in ('/', ''):
                    return self.origin + '/'
                return p if p.startswith('http') else urllib.parse.urljoin(self.origin, p)
        return source_url.rsplit('/', 1)[0] + '/'

    def _wp5_u_fn(self, code, pub):
        """Webpack 5: __webpack_require__.u = function(e){ return ... }"""
        found = set()
        m = re.search(
            r'__webpack_require__\.u\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{(.{20,4000}?)\}\s*[,;]',
            code, re.DOTALL
        )
        if not m:
            # Arrow function variant
            m = re.search(
                r'__webpack_require__\.u\s*=\s*\(\s*(\w+)\s*\)\s*=>\s*\{(.{20,4000}?)\}\s*[,;]',
                code, re.DOTALL
            )
        if not m:
            return found

        param, fn_body = m.group(1), m.group(2)
        id_to_hash = {}
        id_to_name = {}

        for obj_m in re.finditer(
            r'\{((?:\s*\d+\s*:\s*["\'][^"\']*["\'],?\s*){2,})\}', fn_body
        ):
            pairs = re.findall(r'(\d+)\s*:\s*["\']([^"\']*)["\']', obj_m.group(1))
            if not pairs:
                continue
            sample = pairs[0][1]
            if re.match(r'^[a-f0-9]{5,20}$', sample) or re.match(r'^[a-zA-Z0-9_-]{5,20}$', sample):
                for cid, val in pairs:
                    id_to_hash[int(cid)] = val
            else:
                for cid, val in pairs:
                    id_to_name[int(cid)] = val

        if not id_to_hash:
            return found

        ret_m = re.search(r'return\s+(.+?);', fn_body, re.DOTALL)
        if not ret_m:
            return found

        for cid, chash in id_to_hash.items():
            try:
                fname = self._eval_tmpl(ret_m.group(1).strip(), param, cid,
                                        chash, id_to_name.get(cid, ''))
                if fname and fname.endswith('.js') and len(fname) < 120:
                    full = urllib.parse.urljoin(pub, fname)
                    if full.startswith('http'):
                        found.add(full)
            except Exception:
                continue
        return found

    def _wp4_script_src(self, code, pub):
        """Webpack 4: script.src = __webpack_require__.p + chunkId + {hash_map}[chunkId] + ".js" """
        found = set()
        # Find hash maps in the neighbourhood of script.src assignments
        for src_m in re.finditer(r'script\.src\s*=\s*__webpack_require__\.p', code):
            region = code[src_m.start(): src_m.start() + 500]
            all_maps = re.findall(
                r'\{((?:\s*["\']?\d+["\']?\s*:\s*["\'][^"\']+["\'],?\s*){2,})\}',
                region
            )
            for obj_str in all_maps:
                pairs = re.findall(r'["\']?(\d+)["\']?\s*:\s*["\']([^"\']+)["\']', obj_str)
                for cid, val in pairs:
                    # Try both common patterns
                    for tmpl in (f"{cid}.{val}.js", f"{cid}.{val}.chunk.js"):
                        full = urllib.parse.urljoin(pub, tmpl)
                        if full.startswith('http'):
                            found.add(full)
        return found

    def _direct_filenames(self, code, base):
        """Catch chunk filenames directly embedded as string literals."""
        found = set()
        for m in re.finditer(
            r'["\'](\d+\.[a-f0-9]{5,20}\.(?:chunk\.)?js)["\']', code
        ):
            found.add(urllib.parse.urljoin(base, m.group(1)))
        for m in re.finditer(
            r'["\']([a-zA-Z][a-zA-Z0-9_-]{2,40}\.[a-f0-9]{5,20}\.(?:chunk\.)?js)["\']',
            code
        ):
            fname = m.group(1)
            if any(x in fname for x in ('vendor', 'polyfill', 'runtime', 'common')):
                continue
            full = urllib.parse.urljoin(base, fname)
            if full.startswith('http') and 'localhost' not in full:
                found.add(full)
        return found

    def _eval_tmpl(self, expr, var, cid, chash, cname):
        """Minimal JS expression evaluator for webpack URL templates."""
        def _lookup(m):
            pairs = dict(re.findall(r'(\d+)\s*:\s*["\']([^"\']*)["\']', m.group(1)))
            return f'"{pairs.get(str(cid), chash)}"'

        result = re.sub(
            r'\{((?:\s*\d+\s*:\s*["\'][^"\']*["\'],?\s*){1,})\}\[' + re.escape(var) + r'\]',
            _lookup, expr
        )
        result = re.sub(
            r'\(.*?\[' + re.escape(var) + r'\]\s*\|\|\s*' + re.escape(var) + r'\)',
            f'"{cname or cid}"', result
        )
        result = re.sub(r'\b' + re.escape(var) + r'\b', str(cid), result)

        url_parts = []
        for p in re.split(r'\s*\+\s*', result):
            p = p.strip()
            if p.startswith(('"', "'")):
                url_parts.append(p.strip('"\''))
            elif p.isdigit():
                url_parts.append(p)
            elif re.match(r'^[a-zA-Z0-9_.\-]+$', p):
                url_parts.append(p)
        return ''.join(url_parts)


def _discover_nextjs_chunks(session, base_url, existing_js_files):
    """
    TC-P1.5-007 / backend_sourcemap_recovery:
    When Next.js is detected (any discovered JS URL contains /_next/), enumerate
    additional chunks from /_next/static/chunks/ that are NOT linked from the HTML.

    Next.js exposes API route bundles (api-graphql.js, api-auth.js, etc.) and
    resolver/feature bundles as static files under /_next/static/chunks/.
    These are NOT listed in buildManifest.json (which may not exist) and NOT
    referenced from <script> tags — they are purely server-side route bundles
    that nginx exposes as static files.

    Strategy:
    1. Check if any existing JS URL has /_next/static/ → confirms Next.js
    2. Probe /_next/static/chunks/ as a directory (nginx may return listing)
    3. Probe a comprehensive list of semantic chunk names used by Next.js apps
       covering: API routes (api-*.js), resolvers (*.resolver.js), pages,
       services, hooks, utils, and common Next.js internals
    4. Return all discovered URLs for sourcemap processing

    RCA: App E (nextjs-saas) has api-graphql.js.map with source content
    containing "http://localhost:3005/graphql" — the literal SPA-local GraphQL
    URL. And *.resolver.js.map files contain "/graphql#operationName" patterns.
    These files are served by nginx but never linked from HTML, so the standard
    Phase 1 discovery misses them entirely. This function adds them.
    """
    # Only activate when Next.js is confirmed
    is_nextjs = any('/_next/' in u for u in existing_js_files)
    if not is_nextjs:
        return []

    base = base_url.rstrip('/')
    chunks_base = f"{base}/_next/static/chunks"
    known = set(existing_js_files)
    discovered = []

    print("  [NEXT.JS CHUNKS] Enumerating hidden /_next/static/chunks/ bundles...")

    # Step 1: Try directory listing (works if nginx has autoindex on)
    try:
        _r = session.get(chunks_base + '/', timeout=5, verify=False)
        if _r.status_code == 200 and 'text/html' in _r.headers.get('Content-Type',''):
            # Parse href links from directory listing
            _hrefs = [m.group(1) for m in re.finditer(rb'href=[^>]+?([\w./-]+[.]js)', _r.content)]
            for h in _hrefs:
                if h.startswith('/'):
                    url = f"{base}{h}"
                elif h.startswith('http'):
                    url = h
                else:
                    url = f"{chunks_base}/{h}"
                if url not in known:
                    discovered.append(url)
                    known.add(url)
    except Exception:
        pass

    if discovered:
        print(f"    [+] Directory listing: {len(discovered)} chunk(s)")
        return discovered

    # Step 2: Heuristic probe list — covers API routes, resolvers, services,
    # hooks, pages, utils, and common Next.js internals
    _heuristic_names = [
        # API route chunks (pages/api/*.ts → api-NAME.js)
        'api-graphql', 'api-auth', 'api-users', 'api-user',
        'api-dashboard', 'api-data', 'api-search', 'api-admin',
        'api-config', 'api-health', 'api-status', 'api-webhook',
        'api-stripe', 'api-payment', 'api-billing', 'api-email',
        'api-upload', 'api-image', 'api-file', 'api-export',
        'api-import', 'api-report', 'api-analytics', 'api-metrics',
        'api-notifications', 'api-messages', 'api-chat', 'api-rooms',
        'api-orders', 'api-products', 'api-cart', 'api-checkout',
        'api-teams', 'api-members', 'api-roles', 'api-permissions',
        'api-settings', 'api-profile', 'api-account',
        # GraphQL resolver chunks
        'user.resolver', 'order.resolver', 'product.resolver',
        'dashboard.resolver', 'team.resolver', 'billing.resolver',
        'audit.resolver', 'checkout.resolver', 'payment.resolver',
        'notification.resolver', 'message.resolver', 'search.resolver',
        'analytics.resolver', 'admin.resolver', 'auth.resolver',
        # Service/feature chunks
        'graphql-auth', 'graphql-client', 'graphql-config',
        'dash-service', 'notif-service', 'auth-service',
        'user-service', 'order-service', 'product-service',
        'metrics-component', 'dashboard-component',
        # Hook chunks
        'hooks-auth', 'hooks-ws', 'hooks-api', 'hooks-data',
        'hooks-user', 'hooks-graphql',
        # Util/type chunks
        'utils-api', 'utils-auth', 'utils-graphql', 'utils-totp',
        'types-api', 'types-graphql', 'types-user',
        # Config/runtime
        'config', 'settings', 'constants', 'schema',
        # Next.js standard chunks
        'polyfills', 'framework', 'webpack-runtime',
        '_app', '_document', '_error',
        'index', 'login', 'register', 'dashboard',
        'billing', 'settings', 'team', 'profile',
        'context-auth', 'context-user', 'context-theme',
        'package', 'tsconfig',
    ]

    probed = 0
    found = 0
    for name in _heuristic_names:
        url = f"{chunks_base}/{name}.js"
        if url in known:
            continue
        probed += 1
        try:
            r = session.get(url, timeout=4, verify=False)
            if r.status_code == 200 and len(r.content) > 10:
                # Quick sanity check: should look like JS
                content_type = r.headers.get('Content-Type', '').lower()
                body_start = r.text.strip()[:20].lower()
                if ('javascript' in content_type or
                        body_start.startswith('(()=>{') or
                        body_start.startswith('(function') or
                        body_start.startswith('//')  or
                        '//# sourceMappingURL' in r.text):
                    discovered.append(url)
                    known.add(url)
                    found += 1
        except Exception:
            pass

    if found:
        print(f"    [+] Heuristic probing: {found}/{probed} chunk(s) found")
    else:
        print(f"    [-] No additional chunks found ({probed} names probed)")

    return discovered
