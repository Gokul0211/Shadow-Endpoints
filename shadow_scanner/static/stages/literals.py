"""Broad string-literal sweeps over the whole bundle."""
import re
import urllib.parse

from shadow_scanner.config import is_ignored_host, is_noise
from shadow_scanner.core import diagnostics
class LiteralSweepMixin:
    """Broad string-literal sweeps (template literals, LinkFinder-style regexes, IPs, env vars)."""

    def _extract_internal_ip_urls(self, code, source):
        """Hard-coded RFC-1918 URLs (http://10.x / 172.16-31.x / 192.168.x)."""
        # ── FIX BUG-4: Hardcoded private/internal IP extraction ──────────────
        # Catches: fetch('http://10.0.1.45:8080/internal/api/reports/annual', ...)
        #          axios.get('http://192.168.1.10:3000/api/data')
        # These are internal_ip_hardcoded endpoints that never appear via the
        # base_url normalizer because their host differs from the scanned target.
        _PRIVATE_IP_RE = re.compile(
            r'["\'`](https?://(?:10\.(?:\d{1,3}\.){2}\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3})'
            r'(?::\d{2,5})?'          # optional port
            r'(/[^"\' `\s<>]{3,200})'  # must have a path
            r')["\'`]',
            re.IGNORECASE
        )
        for _ipm in _PRIVATE_IP_RE.finditer(code):
            _priv_url = _ipm.group(1)
            # Skip the current target host — already handled by normal extraction
            try:
                _priv_host = urllib.parse.urlparse(_priv_url).netloc
                _base_host = urllib.parse.urlparse(self.base_url).netloc
                if _priv_host == _base_host:
                    continue
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)
            if not is_noise(_priv_url):
                self.add_endpoint(
                    _priv_url, 'GET', [], 'INTERNAL_IP_HARDCODED',
                    source, 'BACKEND_API', 72
                )

    def _extract_env_var_urls(self, code, source):
        """process.env / import.meta.env fallbacks and BASE + "/path" fetch calls."""
        # ── process.env / import.meta.env API URL extraction ─────────────────
        # Catches:
        #   const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api'
        #   const BASE = import.meta.env.VITE_API_BASE_URL
        #   fetch(process.env.API_BASE + '/users')
        # Step 1: Register env var fallback values as base URLs
        _ENV_VAR_ASSIGN_RE = re.compile(
            r'(?:const|let|var)\s+([A-Z_$][A-Z0-9_$]{1,40})\s*='
            r'\s*(?:process\.env\.[A-Z_]+|import\.meta\.env\.[A-Z_]+)'
            r'\s*\|\|\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            re.IGNORECASE
        )
        for m in _ENV_VAR_ASSIGN_RE.finditer(code):
            var_name  = m.group(1)
            fallback  = m.group(2)
            if fallback.startswith('http') or fallback.startswith('/'):
                self.resolver.global_scope[var_name] = fallback
                self.resolver.variables[var_name] = {
                    'value': fallback, 'source_file': source, 'confidence': 88
                }

        # Step 2: Direct process.env / import.meta.env access with || fallback
        _IMPORT_META_RE = re.compile(
            r'import\.meta\.env\.([A-Z_][A-Z0-9_]*)\s*\|\|\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            re.IGNORECASE
        )
        for m in _IMPORT_META_RE.finditer(code):
            env_key  = m.group(1).lower().replace('_', '')
            fallback = m.group(2)
            if fallback.startswith('http') or fallback.startswith('/'):
                self.resolver.global_scope[env_key]  = fallback
                self.resolver.global_scope[m.group(1)] = fallback
                if 'api' in env_key and not self.resolver.methods.get('getBase'):
                    self.resolver.methods['getBase'] = fallback

        # Step 3: Fetch/axios calls using env var names directly
        _ENV_CONCAT_RE = re.compile(
            r'(?:fetch|axios\.[a-z]+)\s*\(\s*([A-Z_$][A-Z0-9_$]{1,40})\s*\+'
            r'\s*[\'"`]([^\'"`]{2,200})[\'"`]',
            re.IGNORECASE
        )
        for m in _ENV_CONCAT_RE.finditer(code):
            var_name = m.group(1)
            suffix   = m.group(2)
            base_val = (self.resolver.global_scope.get(var_name)
                        or self.resolver.resolve_with_fallback(var_name))
            if base_val:
                full_url = self.normalizer.normalize(base_val.rstrip('/') + suffix)
                method   = self.detect_method(code, m.start())
                self.process(full_url, method, m.start(), code, source,
                             "ENV_VAR_CONCAT", "BACKEND_API", 82)

    def _extract_dynamic_websockets(self, code, source):
        """new WebSocket(base + "/ws") and new WebSocket(variable)."""
        # ── T32: Dynamic WebSocket URL construction ──────────────────────────
        # Catches: const wsUrl = base + "/ws"; new WebSocket(wsUrl)
        #          new WebSocket(this.wsBase + "/live")
        #          new WebSocket(`${host}/ws/notifications`)
        for m in re.finditer(
            r'new\s+WebSocket\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*[\'"`]([^\'"`]{2,100})[\'"`]',
            code, re.IGNORECASE
        ):
            base_var = m.group(1)
            suffix   = m.group(2)
            base_val = (self.resolver.resolve_with_fallback(base_var)
                        or self.resolver.resolve_method_call(base_var))
            if base_val:
                ws_url = base_val.rstrip('/') + suffix
                self.add_endpoint(ws_url, 'WS', [], 'WEBSOCKET_DYNAMIC_CONCAT', source, 'WEBSOCKET_ENDPOINT', 87)

        # new WebSocket(variable) — resolve variable to URL
        for m in re.finditer(
            r'new\s+WebSocket\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]{2,60})\s*\)',
            code, re.IGNORECASE
        ):
            var_name = m.group(1)
            resolved = (self.resolver.resolve_with_fallback(var_name)
                        or self.resolver.global_scope.get(var_name))
            if resolved and ('ws://' in resolved or 'wss://' in resolved or resolved.startswith('/')):
                self.add_endpoint(resolved, 'WS', [], 'WEBSOCKET_DYNAMIC_VAR', source, 'WEBSOCKET_ENDPOINT', 85)

    def _extract_websocket_literals(self, code, source):
        """Static "ws://" / "wss://" string literals."""
        # ── WebSocket static string literals ──────────────────────────────────
        for m in re.finditer(r'[\'"`](wss?://[^\'"` \t<>{}]{4,200})[\'"`]', code):
            ws_url = m.group(1)
            if 'example.com' not in ws_url.lower() and 'placeholder' not in ws_url.lower():
                self.add_endpoint(ws_url, 'WS', [], 'WEBSOCKET_STATIC_LITERAL', source, 'WEBSOCKET_ENDPOINT', 88)

    def _extract_indexeddb_cache_keys(self, code, source):
        """requestUrl/cacheUrl/apiUrl keys (static IndexedDB cache hints)."""
        # ── FIX FN-7: IndexedDB API cache key extraction (regex fallback) ────
        # Catches static patterns: store.put({requestUrl: '/api/...'}, ...)
        # Dynamic IndexedDB reading is handled in the Playwright phase.
        for m in re.finditer(
            r'(?:requestUrl|cacheUrl|apiUrl|cachedUrl)\s*[=:,]\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, 'GET', m.start(), code, source, "INDEXEDDB_CACHE_KEY", "BACKEND_API", 72)

    def _extract_resolved_template_literals(self, code, source):
        """Every `...${VAR}...` template literal, with VAR resolved or turned into {param}."""
        # ── G1 FIX: Full template literal resolution with variable substitution ──
        # Catches: fetch(`${apiBase}/api/orders/${userId}`)
        # The regex finds ALL backtick strings, then resolves each ${VAR} segment.
        # If VAR is a known base URL → prepend it. If unknown → use {param}.
        for m in re.finditer(r'`([^`]{4,400})`', code):
            raw_tmpl = m.group(1)
            if '${' not in raw_tmpl:
                continue  # Plain string — already caught by other patterns

            # Resolve template: replace each ${VAR} with its known value or {param}
            def _resolve_tmpl_var(vm):
                var = vm.group(1).strip()
                # Try chained resolution: this.X.Y, obj.prop, plain var
                resolved = (
                    self.resolver.resolve_with_fallback(var)
                    or self.resolver.resolve_method_call(var)
                    or self.resolver.global_scope.get(var)
                )
                if resolved and isinstance(resolved, str):
                    return resolved
                # For path-segment variables (id, userId etc.) use {param}
                return '{' + var.split('.')[-1] + '}'

            resolved_str = re.sub(r'\$\{([^}]{1,60})\}', _resolve_tmpl_var, raw_tmpl)

            # Only process if the result looks like an API path
            if not (resolved_str.startswith('http') or '/api' in resolved_str.lower()
                    or resolved_str.startswith('/')):
                continue
            # Strip any double-slash artifacts from empty base resolution
            resolved_str = re.sub(r'(?<!:)/{2,}', '/', resolved_str)

            full_url = self.normalizer.normalize(resolved_str)
            if full_url:
                method = self.detect_method(code, m.start())
                self.process(full_url, method, m.start(), code, source,
                             "TEMPLATE_LITERAL_RESOLVED", "BACKEND_API", 82)

    def _extract_api_string_literals(self, code, source):
        """Quoted "/api/..." / "#/..." paths with an API indicator."""
        for m in re.finditer(r'["\']([/#][^\'"]{3,100}?)["\']', code):
            url = m.group(1)
            if self.has_api_pattern(url):
                cls = self.classify(url)
                if cls != "NOISE":
                    full_url = self.normalizer.normalize(url)
                    self.process(full_url, self.detect_method(code, m.start()), m.start(), code, source, "STATIC_CODE", cls, 50)

    def _extract_external_subdomain_literals(self, code, source):
        """Full https:// URLs on other hosts that carry an API-looking path."""
        # RC2b-FIX: External subdomain URLs embedded as full https:// strings inside JS
        # Catches: 'https://gis.example.com/service/Api/Item/Delete'
        # These go through the ExternalLinkExtractor for classification but ALSO need to
        # enter the endpoint pool when they carry an API path (not just CDN/analytics noise).
        for m in re.finditer(r'["\`](https?://([^/\s"\'`<>{}]{4,})/([A-Za-z][^"\'`\s<>{}]{4,}))["\`]', code):
            ext_url = m.group(1)
            ext_host = m.group(2).lower()
            # Skip same host (already caught by other patterns)
            try:
                target_host = urllib.parse.urlparse(self.normalizer.base_url).netloc.lower()
            except Exception:
                target_host = ''
            if ext_host == target_host:
                continue
            # Skip third-party hosts (analytics, CDNs, schema namespaces)
            if is_ignored_host(ext_host):
                continue
            # Must have a meaningful path that looks like an API call
            if self.has_api_pattern(ext_url) or re.search(r'/api\b|/Api\b|/v\d|/sso\b|/auth\b|/token\b|/login\b|/signin\b|/oauth2?\b', ext_url):
                self.process(ext_url, self.detect_method(code, m.start()), m.start(), code, source, "EXTERNAL_SUBDOMAIN_LITERAL", "BACKEND_API", 80)

    def _linkfinder_sweep(self, code, source):
        """LinkFinder-style relative / REST / external URL sweep with FP filtering."""
        # =====================================================================
        # LINKFINDER-STYLE SWEEP: Catch relative paths, REST paths, and full
        # external URLs that the targeted extractors above may have missed.
        # This is inspired by GerbenJavado/LinkFinder's regex_str but with
        # ASM.py's superior noise filtering applied on top.
        #
        # FALSE POSITIVE GUARD: The filters below are designed to surgically
        # eliminate framework module imports, locale files, crypto lib paths,
        # Excel/PDF internals, and source tree paths — without blocking any
        # real API endpoints.
        # =====================================================================

        # --- Precompiled patterns for FP filtering (avoid recompilation per match) ---
        _FP_MODULE_SUFFIX = re.compile(
            r'\.(service|module|component|guard|pipe|directive|resolver|reducer|effects|actions|selectors)$'
        )
        _FP_TEMPLATE_SUFFIX = re.compile(r'\.(html|scss|css|less|sass)$')
        _FP_LOCALE_FILE = re.compile(r'^\.?\.?/?[a-z]{2}(?:-[a-zA-Z]{2,4})?(?:\.js)?$')
        _FP_CRYPTO_LIB = re.compile(
            r'^\.?\.?/?(sha\d*|sha/\d+|md5|aes|des|cbc|ecb|ofb|ctr|cfb\d*|ghash|hmac|'
            r'hash|sign|verify|cipher|encrypt|decrypt|mont|edwards|curve|elliptic|'
            r'asn1|base64|buffer|pem|der|certificate|key|legacy|mgf|xor|'
            r'privateDecrypt|publicEncrypt|withPublic|generatePrime|'
            r'incr32|adler32|crc32|flate|streamCipher|authCipher|decrypter|encrypter)$'
        )
        _FP_NPM_INTERNAL = re.compile(
            r'^\.?\.?/?(lib/|internal/|_stream_|stream/|readable-stream|node_modules|'
            r'NodeBufferReader|StringReader|ArrayReader|DataReader|Uint8ArrayReader|'
            r'GenericWorker|ConvertWorker|DataWorker|ZipFileWorker|zipEntries|zipEntry|zipObject|'
            r'compressedObject|nodejsUtils|nodeparser|nodecontainer|'
            r'browserify|process/browser|promish)'
        )
        _FP_EXCEL_XFORM = re.compile(
            r'(-xform$|xform/|/xl/|/docProps/|sharedStrings\.xml|workbook\.xml|'
            r'styles\.xml|theme1\.xml|_rels/|content-types\.xml)'
        )
        _FP_CONTAINER_RENDERER = re.compile(
            r'(container|fontmetrics|formatter|stackingcontext|renderer|'
            r'pseudoelement|svgnode|webkit|framec|lineargrad|dummyimage|proxyimage)$'
        )
        _FP_SOURCE_TREE = re.compile(r'^\.?\.?/?src/')
        _FP_DATE_FORMAT = re.compile(r'^[DMYdmy]{1,4}[/\-][DMYdmy]{1,4}')

        def _is_module_import(path):
            """Return True if the path looks like a JS/TS framework import, not an API endpoint."""
            # Angular/React service/module/component imports
            if _FP_MODULE_SUFFIX.search(path):
                return True
            # Template file references (.html, .scss)
            if _FP_TEMPLATE_SUFFIX.search(path):
                return True
            # Locale files: ./ar, ./en-gb, ./zh-cn.js, etc.
            basename = path.rsplit('/', 1)[-1] if '/' in path else path
            if _FP_LOCALE_FILE.match(basename):
                return True
            # Crypto library internal modules
            stripped = path.lstrip('./')
            if _FP_CRYPTO_LIB.match(stripped):
                return True
            # Node.js/npm internal modules
            if _FP_NPM_INTERNAL.match(path):
                return True
            # Excel/Office XML xform patterns
            if _FP_EXCEL_XFORM.search(path):
                return True
            # HTML2Canvas/renderer containers
            if _FP_CONTAINER_RENDERER.search(stripped):
                return True
            # Source tree paths (src/app/*, not API endpoints)
            if _FP_SOURCE_TREE.match(path):
                return True
            # Bare single-word imports without slashes: ./buffer, ./clone, ./core, ./load, etc.
            if path.startswith('./') and '/' not in path[2:] and not path[2:].startswith('api'):
                # Single segment after ./ — almost always a module import
                # Exception: ./assets, ./config, ./doc  (keep these)
                seg = path[2:].split('.')[0].lower()
                _KEEP_SINGLE = {'assets', 'config', 'doc', 'api', 'login', 'dashboard'}
                if seg not in _KEEP_SINGLE and len(seg) < 20:
                    return True
            # Multi-segment dotslash paths that are Angular imports, not APIs
            if path.startswith('./') or path.startswith('../'):
                segs = path.lstrip('./').lower()
                _ANGULAR_IMPORT_PARTS = ('guards/', 'services/', 'components/', 'environments/',
                                          'modules/', 'pipes/', 'directives/', 'resolvers/',
                                          'encryption', 'decryp')
                if any(segs.startswith(p) for p in _ANGULAR_IMPORT_PARTS):
                    # Exception: ./services/ConfirmAlert could be confused but is clearly an import
                    # Real APIs never start with dotslash + framework folder
                    if '/config/' not in segs and '/environment.' not in segs:
                        return True
            return False

        # module specifiers (import x from '../auth', require('./y'), import('./z')) are not URLs
        _import_specs = set(re.findall(
            r'''(?:\bfrom|\bimport|\brequire\s*\(|\bimport\s*\()\s*[\'"]([^\'"]+)[\'"]''', code))

        # LF Pattern 1: Relative paths starting with ../ or ./
        for m in re.finditer(r'["\']((\.\.?/)[^"\'><,;| *()%%$^\\[\]]{1}[^"\'><,;|()]{1,})["\']', code):
            url = m.group(1)
            if _is_module_import(url) or url in _import_specs:
                continue
            if is_noise(url):
                continue
            full_url = self.normalizer.normalize(url)
            self.process(full_url, "GET", m.start(), code, source, "RELATIVE_PATH", "BACKEND_API", 45)

        # LF Pattern 2: REST-style paths (word/word, at least 3 chars after /)
        # FIX FP-1: Requires a real API indicator before emitting — eliminates
        # stream/transform, moment/locale/de, reason/get, des/cbc etc. FPs.
        _REST_API_RE = re.compile(
            r'(?:/api[/_]|api[/_]|\bapi\b|/v\d+[/_/]|/graphql|/rest[/_/]|/odata|'
            r'/auth[/_/]|/login|/token|/logout|/service[s/]|/endpoint|/rpc|'
            r'/admin[/_/]|/internal|/user[s/]|/data[/_/]|\.json$)',
            re.IGNORECASE
        )
        for m in re.finditer(r'["\']([a-zA-Z0-9_\-]{1,}/[a-zA-Z0-9_\-/.]{3,})["\']', code):
            url = m.group(1)
            # Skip if already caught by leading-slash, hash, or api_ patterns
            if url.startswith('/') or url.startswith('#') or url.startswith('api_'):
                continue
            # Skip MIME types (e.g. application/json, text/html, image/png)
            if re.match(r'^(?:application|text|image|audio|video|font|multipart|message|model)/', url):
                continue
            # Skip locale files (e.g. ar.js, en-gb.js)
            if _FP_LOCALE_FILE.match(url.rsplit('/', 1)[-1] if '/' in url else url):
                continue
            # Skip source tree paths (src/app/services/*)
            if _FP_SOURCE_TREE.match(url):
                continue
            # Skip npm package paths (browserify-aes/browser, readable-stream/duplex.js, etc.)
            if re.match(r'^(browserify|readable-stream|create-hash|promish|pdfjs-dist|process)/', url):
                continue
            # Skip date format strings (D/M/YYYY, MM/DD/YYYY, etc.)
            if _FP_DATE_FORMAT.match(url):
                continue
            # Skip Excel/Office XML internal paths (xl/workbook.xml, docProps/core.xml, etc.)
            if re.match(r'^(xl|docProps|_rels|worksheets|theme)/', url):
                continue
            # Skip crypto library paths (hash/sha, des/cbc, elliptic/curve, etc.)
            if re.match(r'^(hash|des|sha|elliptic|asn1|lib|zlib|modes|stream|internal|reason|node)/', url):
                continue
            # Skip timezone strings (America/New_York, Europe/London, etc.)
            if re.match(r'^(America|Europe|Asia|Africa|Australia|Pacific|Atlantic|Indian|Antarctica|Arctic)/', url):
                continue
            # FIX FP-1: Must have a real API indicator — not just word/word
            if not _REST_API_RE.search(url):
                continue
            if is_noise(url):
                continue
            full_url = self.normalizer.normalize(url)
            cls = self.classify(url)
            if cls != "NOISE":
                self.process(full_url, self.detect_method(code, m.start()), m.start(), code, source, "REST_PATH", cls, 40)

        # LF Pattern 3: Full external URLs not caught by EXTERNAL_SUBDOMAIN_LITERAL
        # Catches broader set: http:// URLs, URLs without obvious API path patterns
        for m in re.finditer(r'["\'\'`](https?://[^"\'`\s<>{}]{8,200})["\'\'`]', code):
            ext_url = m.group(1)
            try:
                parsed_ext = urllib.parse.urlparse(ext_url)
                ext_host = parsed_ext.netloc.lower()
                target_host = urllib.parse.urlparse(self.normalizer.base_url).netloc.lower()
            except Exception:
                continue
            if ext_host == target_host:
                continue
            if is_ignored_host(ext_host):
                continue
            if is_noise(ext_url):
                continue
            # Only add if it has a path beyond just /
            if parsed_ext.path and len(parsed_ext.path.strip('/')) > 1:
                self.process(ext_url, self.detect_method(code, m.start()), m.start(), code, source, "EXTERNAL_SUBDOMAIN_API", "BACKEND_API", 35)
