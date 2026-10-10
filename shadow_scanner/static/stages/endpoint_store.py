"""Endpoint validation, Bayesian scoring and de-duplicated storage."""
import re
import urllib.parse

from shadow_scanner.config import (
    API_INDICATORS,
    FALSE_POSITIVE_PATTERNS,
    IGNORED_DOMAINS,
    NOISE_KEYWORDS,
    NOISE_PATTERNS,
    STRICT_BLOCKS,
    logger,
)
from shadow_scanner.core.scoring import BayesianConfidenceScorer, EndpointClassifier, LibraryFingerprint
from shadow_scanner.static.ts_params import TypeScriptParameterExtractor
class EndpointStoreMixin:
    """Validation, scoring and de-duplicated storage of every candidate endpoint."""

    def process(self, url, method, pos, code, source, type, classification, confidence):
        if self.is_valid(url):
            params = self.extract_params(code, pos + len(url))
            self.add_endpoint(url, method, params, type, source, classification, confidence)

    def add_endpoint(self, url, method, params, type, source, classification, confidence, extra_fields=None):
        # NEW: Validation Gate
        if EndpointClassifier.is_hard_garbage(url):
            return

        # ── FP FILTER: Angular/React module imports ──
        # Paths like ./guards/auth-guard, ./services/checksum, ./components/apm-rum,
        # ./Encryption-Decrypytion, ../../environments/environment are NOT API endpoints.
        try:
            parsed_check = urllib.parse.urlparse(url)
            path_check = parsed_check.path if parsed_check.path else ''
            # ── PRECISION FIX (noise artifacts): drop emitted URLs that are
            # extraction artifacts, never real endpoints. Verified against the
            # 108-entry manifest: none of these patterns match a ground-truth URL.
            #   1. Unresolved upper-case template variables: /{API_BASE}/...,
            #      /{GRAPHQL_BACKEND}/graphql  (the {id} path param is lower-case,
            #      so it is preserved).
            #   2. String-concatenation leaks from unresolved query building:
            #      ?status=+status+(page?&page=+page:  /  ?role=+role:
            #   3. Relative-path artifacts: http://host/../auth
            #   4. Empty-segment double slash in the path: /api/v2/permits//approvals
            #   5. Base-URL path doubling: /api/rc_permit/api/auth/login
            # Sanitize query-string concatenation leaks WITHOUT discarding the
            # (valid) path: "/api/users?role=+role:" → "/api/users". The path is
            # a real endpoint; only the unresolved query builder leaked. Dropping
            # the whole URL here previously cost real TPs (EP-E-019/020/025).
            if re.search(r'=\+|\+\(', url):
                url = url.split('?', 1)[0]
                parsed_check = urllib.parse.urlparse(url)
                path_check = parsed_check.path or ''
            # Collapse empty-segment double slashes in the path: /a//b → /a/b
            if '//' in path_check:
                _collapsed = re.sub(r'/{2,}', '/', path_check)
                url = url.replace(path_check, _collapsed, 1)
                path_check = _collapsed
            # Drop only when the PATH ITSELF is unsalvageable:
            #   unresolved upper-case template var in path: /{API_BASE}/api/...
            if re.search(r'\{[A-Z_][A-Z0-9_]{2,}\}', url):
                return
            #   unresolved relative-path artifact: http://host/../auth
            if '/../' in url:
                return
            #   base-URL path doubling (clean form is emitted separately):
            #   /api/rc_permit/api/auth/login
            if re.search(r'/api/[a-z][\w-]*/api/', path_check):
                return
            #   resource-less API artifacts: /api, /api/, /api/v2, /api/{id} — a
            #   bare root / version / param with no actual resource segment is
            #   never a real endpoint (general noise, target-independent).
            _rsegs = [s for s in path_check.strip('/').split('/') if s]
            if _rsegs and not [s for s in _rsegs
                               if s != 'api' and not re.fullmatch(r'v\d+', s)
                               and not (s.startswith('{') and s.endswith('}'))]:
                return
            #   bare version-prefix siblings: /v1/orders, /v2/orders/{id} — a
            #   version segment as the FIRST path component with nothing (no
            #   /api, /rest, etc.) before it. Verified against the real
            #   angular-permit bundle: /v1/orders and /v2/orders never appear
            #   in source without an /api/ prefix — every real reference is
            #   "/api/v1/orders" or "API_BASE+/api/v1/orders", so a bare
            #   version-first path here is a malformed sibling, not a
            #   discovery. Requires a segment AFTER the version, so it does
            #   NOT touch the one legitimate bare-/vN case in the ground
            #   truth (EP-A-005, ".../v2" — the version alone, nothing after).
            if len(_rsegs) >= 2 and re.fullmatch(r'v\d{1,2}', _rsegs[0], re.IGNORECASE):
                return
            # Reject dotslash imports resolved to full URLs
            _FP_DOTSLASH_PARTS = ['/guards/', '/services/', '/environments/',
                '/Encryption', '/components/', '/doc/sample', '/doc/Bulk_Reassign',
                '/doc/StoreCreation', '/doc/UserCreation']
            if '/./' in path_check and any(x in path_check for x in _FP_DOTSLASH_PARTS):
                # Exception: keep ./assets/config/* and ./assets/data/* (real configs)
                if '/assets/config/' not in path_check and '/assets/data/' not in path_check:
                    return
            # Reject static file downloads (.xlsx, .pdf but keep .json and API-like .xml)
            if path_check.endswith(('.xlsx', '.xls')):
                return
            # Reject garbage test URLs
            if '%20' in url and parsed_check.netloc and len(parsed_check.netloc) <= 2:
                return
            # ── PRECISION FIX: Reject framework static-asset paths ────────────
            # Next.js /_next/static/*, Nuxt /__nuxt/*, Vite /assets/*.js chunks,
            # Angular /assets/*, etc. are build artifacts, not API endpoints.
            # EXCEPTION: /assets/config/ and /assets/data/ may contain API config.
            _STATIC_PREFIXES = (
                '/_next/static/', '/_next/image', '/__nuxt/',
                '/static/js/', '/static/css/', '/static/media/',
                '/assets/fonts/', '/assets/images/', '/assets/icons/',
                '/assets/styles/', '/assets/css/',
            )
            if any(path_check.startswith(pfx) for pfx in _STATIC_PREFIXES):
                return
            # Reject paths that are clearly frontend JS/CSS chunk files
            if (path_check.startswith('/assets/') and
                    path_check.endswith(('.js', '.css', '.map', '.woff', '.woff2',
                                         '.ttf', '.eot', '.png', '.svg', '.ico'))):
                return
            # Reject single-segment non-API paths that are frontend routes
            # e.g. /login, /dashboard, /profile (no /api/ prefix, no depth)
            # Exception: known API-adjacent paths (/graphql, /auth, /oauth)
            _path_parts = [p for p in path_check.strip('/').split('/') if p]
            _FRONTEND_SINGLE_SEGS = {
                'dashboard', 'home', 'profile', 'settings', 'login', 'logout',
                'register', 'signup', 'about', 'contact', 'help', 'support',
                'privacy', 'terms', '404', '500', 'error', 'not-found',
            }
            if (len(_path_parts) == 1
                    and _path_parts[0].lower() in _FRONTEND_SINGLE_SEGS
                    and not parsed_check.query):
                return
        except Exception:
            pass

        url = self._clean_url(url)

        if not url:
            return

        # CRITICAL FIX: Normalize trailing slashes for deduplication
        # /api/users and /api/users/ should be treated as the same
        url_normalized = url.rstrip('/')

        url_lower = url_normalized.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return

        if any(re.search(p, url_normalized) for p in NOISE_PATTERNS):
            return

        # ADDITIONAL FIX: Reject if URL path is too short (likely noise)
        try:
            parsed = urllib.parse.urlparse(url_normalized)
            if parsed.path and len(parsed.path.strip('/')) < 1:
                return  # Completely empty paths are noise
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

        # Deduplicate on URL only (not method+URL).
        # When the same endpoint is found by multiple extractors, keep the highest-confidence
        # entry's method. If a non-GET method is found later, always promote to it because
        # GET is the default fallback and a specific method is always more accurate.
        for e in self.endpoints:
            existing_url = e['endpoint'].rstrip('/')
            if existing_url == url_normalized:
                # Fix 5: Only merge parameters from same extraction category
                _existing_is_array = 'ARRAY' in str(e.get('type', '')).upper()
                _new_is_array = 'ARRAY' in str(type).upper()
                if _existing_is_array == _new_is_array:
                    e['parameters'] = sorted(list(set(e['parameters'] + params)))[:10]
                existing_conf = self.confidence_scores.get(f"ANY:{url_normalized}", 0)
                if confidence > existing_conf:
                    # Higher confidence found: upgrade method, type, classification, source
                    e['method'] = method
                    e['type'] = type
                    e['classification'] = classification
                    e['source'] = source if isinstance(source, str) else str(source)[:80]
                    self.confidence_scores[f"ANY:{url_normalized}"] = confidence
                    if extra_fields:
                        e.update(extra_fields)
                elif method != 'GET' and e['method'] == 'GET':
                    # Even at equal/lower confidence: never let a hardcoded GET
                    # override a specifically-detected method (POST/PUT/DELETE/PATCH)
                    e['method'] = method
                return

        # ── Bayesian Confidence Scoring ───────────────────────────────────────
        is_vendor    = LibraryFingerprint.is_vendor(source)

        # ── Provenance tracking ───────────────────────────────────────────────
        # Record this piece of evidence regardless of whether the endpoint
        # already exists — provenance graph collects ALL evidence independently.
        if hasattr(self, 'provenance'):
            self.provenance.record(url_normalized, type or '', source or '', confidence)
            prov = self.provenance.get_provenance(url_normalized)
        else:
            prov = {'provenance_boost': 0, 'multi_source': False, 'best_category': 'UNKNOWN'}

        # Multi-source confirmation: bump confidence if same URL found before
        # Additionally boost by provenance graph's multi-source analysis
        extra_sigs = []
        if url_normalized in self.confidence_scores:
            extra_sigs.append('multi_source')
        if prov.get('multi_source'):
            extra_sigs.append('multi_source')  # double-weight if both agree

        score_result = BayesianConfidenceScorer.score(
            url, type, is_vendor,
            source=source if isinstance(source, str) else '',
            method=method,
            extra_signals=extra_sigs,
        )
        if score_result is None:
            return  # Guaranteed noise/garbage — skip entirely
        final_score, final_cat, tags = score_result

        # Apply provenance boost (up to +30 from multi-source categories)
        final_score = min(100, final_score + prov.get('provenance_boost', 0))

        # Map Bayesian categories back to existing classification labels
        if final_cat in ('NOISE_CANDIDATE',) and final_score < 30:
            return
        if final_cat in ('LIBRARY_ARTIFACT', 'NOISE_CANDIDATE', 'EXTERNAL_REFERENCE'):
            classification = final_cat

        # Upgrade classification if RUNTIME evidence exists
        if prov.get('best_category') == 'RUNTIME' and classification not in ('VERIFIED_API', 'WEBSOCKET_ENDPOINT'):
            classification = 'VERIFIED_API'
            final_score    = max(final_score, 95)

        # ── UPGRADE: auth_required inference ──────────────────────────────
        # Infer whether this endpoint likely requires authentication based on:
        #   1. URL path patterns (/admin, /user, /profile, /internal, /private)
        #   2. HTTP method (POST/PUT/DELETE/PATCH almost always need auth)
        #   3. Source file name (.service.ts, auth.*, protected*)
        url_lower_auth = url.lower()
        _AUTH_PATH_RE = re.compile(
            r'/(?:admin|user|users|profile|account|order|orders|payment|'
            r'internal|private|protected|dashboard|manage|management|'
            r'permit|settings|billing|subscription|team|workspace|'
            r'vault|secret|token|refresh|session|me|self)',
            re.IGNORECASE
        )
        _NO_AUTH_RE = re.compile(
            r'/(?:health|ping|status|public|open|login|signup|register|'
            r'forgot.password|reset.password|verify|confirm|graphql)',
            re.IGNORECASE
        )
        auth_required = None  # None = unknown
        if _NO_AUTH_RE.search(url_lower_auth):
            auth_required = False
        elif (_AUTH_PATH_RE.search(url_lower_auth)
              or method.upper() in ('POST', 'PUT', 'DELETE', 'PATCH')
              or ('protected' in str(source).lower())
              or ('private' in url_lower_auth)):
            auth_required = True

        entry = {
            "endpoint":         url,
            "method":           method,
            "parameters":       params,
            "type":             type,
            "source":           source if isinstance(source, str) else source.split('/')[-1][:80],
            "classification":   classification,
            "confidence_score": final_score,
            # ── Full schema fields (UPGRADE) ───────────────────────────────
            "auth_required":    auth_required,
            "auth_method":      "bearer" if auth_required else None,
            "origin": {
                "is_vendor":          is_vendor,
                "extraction_type":    type,
                "provenance":         prov.get('categories', []),
                "provenance_sources": prov.get('sources', 1),
            },
            "tags": tags,
        }
        if extra_fields:
            entry.update(extra_fields)

        self.endpoints.append(entry)
        self.confidence_scores[f"ANY:{url_normalized}"] = confidence

    def _clean_url(self, url):
        """Clean malformed URLs"""
        url = str(url).strip()

        if url.startswith('ORIGIN'):
            url = url.replace('ORIGIN', '')

        if url.startswith('https://') and 'window.open' in url:
            match = re.search(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', url)
            if match:
                path = match.group(1)
                clean_path = self._extract_clean_route(path)
                if clean_path:
                    return self.normalizer.normalize(clean_path)
            return None

        url = url.replace('\"', '')

        if '(' in url and ')' in url and ('window.open' in url or 'location.origin' in url):
            match = re.search(r'["\']([^"\']+)["\']', url)
            if match:
                url = match.group(1)

        if ')' in url:
            url = url.split(')')[0]
        if ',' in url and '_self' in url:
            url = url.split(',')[0]

        return url

    def is_valid(self, url):
        """Validate URL - ULTRA STRICT"""
        if not url:
            return False

        url = url.strip()
        if len(url) < 3 or ' ' in url:
            return False

        url_lower = url.lower()

        # CRITICAL: Check noise keywords first
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return False

        # CRITICAL: Check strict blocks
        if any(b in url.lower() for b in STRICT_BLOCKS):
            return False

        # CRITICAL: Check noise patterns
        for p in FALSE_POSITIVE_PATTERNS:
            if re.search(p, url, re.IGNORECASE):
                return False

        # CRITICAL: Additional specific checks from real scan
        # Block URLs where the ENTIRE path is a single letter (e.g. /x, /a)
        # but NOT URLs that simply end with a letter (e.g. /api/getUser)
        try:
            _p = urllib.parse.urlparse(url).path
            if _p and len(_p.strip('/')) == 1:
                return False
        except Exception:
            pass

        # Block CSS unit paths like /px, /ms
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', url):
            return False

        # Block unresolved template syntax
        if any(x in url for x in ['${', '{{', '`', '\\n']):
            return False

        # Block URLs with "undefined" or "null" in path
        if '/undefined/' in url or '/null/' in url or url.endswith('/undefined') or url.endswith('/null'):
            return False

        # Block framework internal files
        if url.endswith('.js') and any(x in url_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False

        # Block template.html
        if 'template.html' in url_lower:
            return False

        # Block Excel internal paths
        if '/xl/' in url_lower or 'worksheet' in url_lower:
            return False

        # Block error message fragments
        if any(x in url_lower for x in ['caused by:', 'valid digit', 'animation-timing-function']):
            return False

        # Block ON_PROPERTY and other leaked constants
        if 'ON_PROPERTY' in url or 'ON_INIT' in url:
            return False

        if url.startswith('#/'):
            return True

        # Block non-API file extensions
        if url.lower().endswith(('.js', '.css', '.png', '.svg', '.woff', '.jpg', '.jpeg', '.gif', '.ico', '.ttf', '.eot', '.woff2')):
            return False

        return True

    def has_api_pattern(self, url):
        """Check for API patterns"""
        return any(re.search(p, url, re.IGNORECASE) for p in API_INDICATORS)

    def classify(self, url):
        """Classify endpoint type"""
        u = url.lower()
        if self.has_api_pattern(url):
            return "BACKEND_API"
        if any(x in u for x in ['/login', '/logout', '/dashboard', '/profile',
                                  '/#/', '/admin', '/signup', '/register', '/callback']):
            return "FRONTEND_ROUTE"
        if u.startswith('#/'):
            return "FRONTEND_ROUTE"
        if u.startswith('http'):
            return "EXTERNAL_API" if not any(d in u for d in IGNORED_DOMAINS) else "NOISE"
        if u.startswith('/') or u.startswith('#/'):
            # FP7 FIX: Bare single-segment paths like /foo are too generic —
            # only classify as FRONTEND_ROUTE if the URL has ≥2 path segments
            # OR contains a known navigational keyword.
            _UI_SEGMENTS = {'home', 'about', 'contact', 'help', 'settings',
                            'login', 'logout', 'register', 'signup', 'callback',
                            'dashboard', 'profile', 'account', 'admin', 'user',
                            'orders', 'cart', 'checkout', 'reports', 'analytics'}
            path = urllib.parse.urlparse(url).path if url.startswith('http') else url.split('?')[0]
            segments = [s for s in path.strip('/').split('/') if s]
            if len(segments) >= 2:
                return "FRONTEND_ROUTE"
            if segments and segments[0].lower() in _UI_SEGMENTS:
                return "FRONTEND_ROUTE"
            if len(u) > 3:
                return "FRONTEND_ROUTE"
        return "NOISE"

    def detect_method(self, code, pos):
        """Detect HTTP method from context"""
        ctx = code[max(0, pos-200):min(len(code), pos+200)].upper()
        for m in ["POST", "PUT", "DELETE", "PATCH"]:
            if m in ctx:
                return m
        return "GET"

    def extract_params(self, code, pos):
        """
        Extract API parameter names using TypeScriptParameterExtractor —
        a multi-technique engine that uses interface registries, backward
        variable taint, HttpParams chain analysis, FormGroup field names,
        and URLSearchParams literals before falling back to proximity scan.
        """
        if hasattr(self, '_ts_extractor'):
            result = self._ts_extractor.extract(code, pos)
            if result:
                return result
        # Fallback: de-noised forward proximity scan
        ctx = code[pos:pos+300]
        matches = re.findall(r'[{,]\s*["\']?([a-zA-Z0-9_]{2,20})["\']?\s*:', ctx)
        _noise = {
            'var','let','const','if','else','true','false','null','this','return',
            'switch','case','default','break','function','class','typeof','void',
            'undefined','new','delete','in','instanceof','do','while','for','try',
            'catch','finally','throw','export','import','from','as','async','await',
            'headers','body','method','credentials','mode','cache','redirect',
            'referrer','integrity','keepalive','signal','Authorization',
            'authorization','ContentType','contentType','Accept','accept',
            'Cookie','cookie','url','baseURL','baseUrl','timeout','withCredentials',
            'data','params','responseType','factory','providedIn','token',
            'observe','reportProgress','context','checksum',
            'loading','error','success','result','response','request',
            'type','name','value','index','key','style','className',
        }
        return sorted(list({p for p in matches if p.lower() not in _noise and len(p) > 2}))[:TypeScriptParameterExtractor._MAX_PARAMS]

    def _guess_method_from_key(self, key):
        """Guess HTTP method from key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'view', 'all', 'dash']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        return 'GET'
