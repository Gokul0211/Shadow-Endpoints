"""Endpoint validation, Bayesian scoring and de-duplicated storage."""
import re
import urllib.parse

from shadow_scanner.config import (
    API_INDICATORS,
    FALSE_POSITIVE_PATTERNS,
    NOISE_KEYWORDS,
    NOISE_PATTERNS,
    STRICT_BLOCKS,
    is_ignored_url,
    logger,
)
from shadow_scanner.core.evidence import evidence_kind
from shadow_scanner.core.scoring import BayesianConfidenceScorer, EndpointClassifier, LibraryFingerprint
from shadow_scanner.static.ts_params import TypeScriptParameterExtractor
class EndpointStoreMixin:
    """Validation, scoring and de-duplicated storage of every candidate endpoint."""

    def process(self, url, method, pos, code, source, type, classification, confidence):
        if self.is_valid(url):
            params = self.extract_params(code, pos + len(url))
            self.add_endpoint(url, method, params, type, source, classification, confidence)

    # ── Endpoint store ───────────────────────────────────────────────────────
    #
    # One record per URL (trailing slash ignored), holding EVERY sighting as an
    # evidence item {type, kind, source, method, method_explicit, confidence,
    # phase}. Scores are not decided at insertion time: finalize_scores()
    # computes them once from all evidence, and materialize() turns a record
    # with several explicitly observed methods into one entry per method.
    # self.endpoints stays a list of dicts (other phases read it); self._index
    # maps the normalised URL to its record.

    # Extraction types whose method comes from the call itself (axios.post,
    # this.http.get, fetch(url) == GET, ...). Other types guess the method from
    # names or nearby text, so their method is a guess unless it is not GET.
    CALL_METHOD_TYPES = frozenset({
        'HTTP_THIS', 'HTTP', 'HTTPCLIENT_THIS', 'HTTPCLIENT', 'ANGULAR_SERVICE_WRAPPER',
        'NAMED_AXIOS_INSTANCE', 'PROMISE_CHAIN_AXIOS', 'PROMISE_CHAIN_FETCH', 'FETCH_API',
        'VUE_FETCH', 'VUE_ASYNC_DATA', 'REACT_USE_EFFECT_FETCH', 'RTK_QUERY_ENDPOINT',
        'AST_HTTP_CALL', 'AST_COMPUTED_KEY', 'RPC_HTTP_CALL', 'RPC_DI_CHAIN',
        'ANGULAR_SERVICE_PROP_CONCAT', 'SOAP_BRIDGE_CALL', 'NEXTJS_COMMENT_ROUTE',
        'GQL_TAG_QUERY', 'GQL_TAG_MUTATION', 'GQL_TAG_SUBSCRIPTION',
        'WEBSOCKET', 'WEBSOCKET_STATIC_LITERAL', 'WEBSOCKET_DYNAMIC_CONCAT', 'WEBSOCKET_DYNAMIC_VAR',
    })
    # Types that pick the method from an identifier name (deleteTask -> DELETE).
    NAME_GUESS_TYPES = frozenset({
        'ARRAY_HARVEST', 'SERVICE_PROPERTY', 'RPC_METHOD_CALL', 'RPC_OBJECT_PROPERTY',
    })
    HTTP_METHODS = frozenset({'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
                              'WS', 'GRAPHQL'})

    def _passes_client_code_filters(self, url):
        """Heuristic filters for strings recovered from CLIENT CODE. Returns the
        (possibly cleaned) URL, or None to drop it. Runtime, spec and probe
        evidence never goes through these - it was observed or declared."""
        try:
            parsed_check = urllib.parse.urlparse(url)
            path_check = parsed_check.path if parsed_check.path else ''
            # Extraction artifacts, never real endpoints:
            #   1. Unresolved upper-case template variables: /{API_BASE}/...
            #      (the {id} path param is lower-case, so it is preserved).
            #   2. String-concatenation leaks from unresolved query building:
            #      ?status=+status+(page?&page=+page:  /  ?role=+role:
            #   3. Relative-path artifacts: http://host/../auth
            #   4. Empty-segment double slash in the path: /api/v2/permits//approvals
            #   5. Base-URL path doubling: /api/x/api/auth/login
            # Query-string concatenation leaks are cut off, keeping the path.
            if re.search(r'=\+|\+\(', url):
                url = url.split('?', 1)[0]
                parsed_check = urllib.parse.urlparse(url)
                path_check = parsed_check.path or ''
            if '//' in path_check:
                _collapsed = re.sub(r'/{2,}', '/', path_check)
                url = url.replace(path_check, _collapsed, 1)
                path_check = _collapsed
            if re.search(r'\{[A-Z_][A-Z0-9_]{2,}\}', url):
                return None
            if '/../' in url:
                return None
            if re.search(r'/api/[a-z][\w-]*/api/', path_check):
                return None
            #   resource-less API artifacts: /api, /api/v2, /api/{id}
            _rsegs = [s for s in path_check.strip('/').split('/') if s]
            if _rsegs and not [s for s in _rsegs
                               if s != 'api' and not re.fullmatch(r'v\d+', s)
                               and not (s.startswith('{') and s.endswith('}'))]:
                return None
            # Module imports resolved to URLs: ./guards/x, ./services/y, ./environments/z
            _FP_DOTSLASH_PARTS = ['/guards/', '/services/', '/environments/', '/components/']
            if '/./' in path_check and any(x in path_check for x in _FP_DOTSLASH_PARTS):
                if '/assets/config/' not in path_check and '/assets/data/' not in path_check:
                    return None
            if path_check.endswith(('.xlsx', '.xls')):
                return None
            if '%20' in url and parsed_check.netloc and len(parsed_check.netloc) <= 2:
                return None
            # Framework build output, not APIs (except /assets/config|data/)
            _STATIC_PREFIXES = (
                '/_next/static/', '/_next/image', '/__nuxt/',
                '/static/js/', '/static/css/', '/static/media/',
                '/assets/fonts/', '/assets/images/', '/assets/icons/',
                '/assets/styles/', '/assets/css/',
            )
            if any(path_check.startswith(pfx) for pfx in _STATIC_PREFIXES):
                return None
            if (path_check.startswith('/assets/') and
                    path_check.endswith(('.js', '.css', '.map', '.woff', '.woff2',
                                         '.ttf', '.eot', '.png', '.svg', '.ico'))):
                return None
            # Single-segment frontend routes (/login, /dashboard ...) without a query
            _path_parts = [p for p in path_check.strip('/').split('/') if p]
            _FRONTEND_SINGLE_SEGS = {
                'dashboard', 'home', 'profile', 'settings', 'login', 'logout',
                'register', 'signup', 'about', 'contact', 'help', 'support',
                'privacy', 'terms', '404', '500', 'error', 'not-found',
            }
            if (len(_path_parts) == 1
                    and _path_parts[0].lower() in _FRONTEND_SINGLE_SEGS
                    and not parsed_check.query):
                return None
        except Exception as exc:
            logger.debug(f"[store] filter error for {url!r}: {exc}")
        url = self._clean_url(url)
        if not url:
            return None
        url_lower = url.rstrip('/').lower()
        if any(keyword in url_lower for keyword in NOISE_KEYWORDS):
            return None
        if any(re.search(p, url.rstrip('/')) for p in NOISE_PATTERNS):
            return None
        return url

    def _method_is_explicit(self, method, type, kind):
        if kind in ('runtime', 'spec'):
            return True
        if (type or '').upper() in self.CALL_METHOD_TYPES:
            return True
        return method != 'GET' and (type or '').upper() not in self.NAME_GUESS_TYPES

    def add_endpoint(self, url, method, params, type, source, classification, confidence, extra_fields=None):
        """Record one sighting of an endpoint (see the store comment above)."""
        if EndpointClassifier.is_hard_garbage(url):
            return
        kind = evidence_kind(type)
        if kind in ('static', 'storage'):
            url = self._passes_client_code_filters(url)
        else:
            url = self._clean_url(url)
        if not url:
            return
        url_normalized = url.rstrip('/')
        try:
            if urllib.parse.urlparse(url_normalized).path and not urllib.parse.urlparse(url_normalized).path.strip('/'):
                return
        except Exception as exc:
            logger.debug(f"[store] {exc}")

        method = (method or 'GET').upper()
        method_unknown = method not in self.HTTP_METHODS     # e.g. .request(...) -> "REQUEST"
        if method_unknown:
            method = 'GET'
        source_str = source if isinstance(source, str) else str(source)[:80]
        is_vendor = LibraryFingerprint.is_vendor(source_str)

        # Each sighting must stand on its own: a sighting the scorer rejects
        # outright (vendor noise, garbage) is not evidence.
        single = BayesianConfidenceScorer.score(url, type, is_vendor, source=source_str, method=method)
        if single is None:
            return
        s_score, s_cat, s_tags = single
        if s_cat == 'NOISE_CANDIDATE' and s_score < 30 and kind == 'static':
            return

        ev = {
            'type':            type,
            'kind':            kind,
            'source':          source_str,
            'method':          method,
            'method_explicit': (not method_unknown) and self._method_is_explicit(method, type, kind),
            'confidence':      confidence,
            'score':           s_score,
            'vendor':          is_vendor,
            'phase':           getattr(self, 'current_phase', None),
        }
        if hasattr(self, 'provenance'):
            self.provenance.record(url_normalized, type or '', source_str, confidence)

        index = self.__dict__.setdefault('_index', {})
        entry = index.get(url_normalized)
        if entry is not None:
            entry['evidence'].append(ev)
            _existing_is_array = 'ARRAY' in str(entry.get('type', '')).upper()
            if _existing_is_array == ('ARRAY' in str(type).upper()):
                entry['parameters'] = sorted(set(entry['parameters'] + list(params or [])))[:10]
            if extra_fields:
                for k, v in extra_fields.items():
                    entry.setdefault(k, v)
            self._refresh_entry(entry)
            return

        if s_cat in ('LIBRARY_ARTIFACT', 'NOISE_CANDIDATE', 'EXTERNAL_REFERENCE'):
            classification = s_cat
        entry = {
            "endpoint":         url,
            "method":           method,
            "parameters":       sorted(set(params or []))[:10],
            "type":             type,
            "source":           source_str.split('/')[-1][:80] if not isinstance(source, str) else source,
            "classification":   classification,
            "confidence_score": s_score,
            "auth_required":    None,
            "auth_method":      None,
            "origin": {
                "is_vendor":          is_vendor,
                "extraction_type":    type,
                "provenance":         [],
                "provenance_sources": 1,
            },
            "tags":     s_tags,
            "evidence": [ev],
        }
        if extra_fields:
            entry.update(extra_fields)
        index[url_normalized] = entry
        self.endpoints.append(entry)
        self._refresh_entry(entry)

    # ── scoring from all evidence ────────────────────────────────────────────
    def _refresh_entry(self, entry):
        """Recompute method / type / classification / score / provenance of one
        record from its evidence (deterministic, independent of arrival order
        except for exact ties, which are broken by type name)."""
        evs = entry.get('evidence') or []
        if not evs:
            return
        url = entry['endpoint']
        kinds = sorted({e['kind'] for e in evs})
        cats = sorted({self.provenance._category(e['type'], e['source']) for e in evs}) if hasattr(self, 'provenance') else []

        # Methods: explicitly observed ones win; otherwise the most frequent guess.
        explicit = sorted({e['method'] for e in evs if e['method_explicit']})
        if explicit:
            non_get = [m for m in explicit if m != 'GET']
            entry['method'] = non_get[0] if len(explicit) > 1 and non_get else explicit[0]
            entry['methods'] = explicit
            entry['method_inferred'] = False
        else:
            counts = {}
            for e in evs:
                counts[e['method']] = counts.get(e['method'], 0) + 1
            entry['method'] = sorted(counts, key=lambda m: (-counts[m], m))[0]
            entry['methods'] = [entry['method']]
            entry['method_inferred'] = True

        # Strongest single piece of evidence, raised by independent confirmation.
        best = max(evs, key=lambda e: (e['score'], e['type'] or ''))
        all_vendor = all(e['vendor'] for e in evs)
        if 'runtime' in kinds:
            score, tags = 100, ['verified_dynamic']
            rt = [e for e in evs if e['kind'] == 'runtime']
            best = max(rt, key=lambda e: (e['score'], e['type'] or ''))
        else:
            extra = ['multi_source'] if len(cats) >= 2 else []
            res = BayesianConfidenceScorer.score(url, best['type'], all_vendor, source=best['source'],
                                                 method=best['method'], extra_signals=extra)
            if res is None:
                score, tags = best['score'], []
            else:
                score, _, tags = res
            if len(cats) >= 2:
                score = min(100, score + min(30, (len(cats) - 1) * 10))
        entry['confidence_score'] = score
        entry['tags'] = tags
        entry['type'] = best['type']
        entry['source'] = best['source']
        entry['origin'] = {
            'is_vendor':          all_vendor,
            'extraction_type':    best['type'],
            'provenance':         cats,
            'provenance_sources': len(evs),
            'evidence_kinds':     kinds,
        }
        if 'runtime' in kinds and entry.get('classification') not in (
                'VERIFIED_API', 'WEBSOCKET_ENDPOINT', 'GRAPHQL_API', 'SSE_ENDPOINT'):
            entry['classification'] = 'VERIFIED_API'
        elif 'runtime' not in kinds and entry.get('classification') == 'VERIFIED_API':
            # VERIFIED_API means "seen in browser traffic" - nothing else may claim it
            entry['classification'] = 'BACKEND_API'
        entry['probe_only'] = kinds == ['probe']

    def finalize_scores(self):
        """Recompute every record from its evidence (call before filtering/reporting)."""
        for entry in self.endpoints:
            self._refresh_entry(entry)

    def materialize(self):
        """Report entries: one per (URL, explicitly observed method), evidence summarised."""
        self.finalize_scores()
        out = []
        for entry in self.endpoints:
            methods = entry.get('methods') or [entry.get('method', 'GET')]
            for m in methods:
                e = {k: v for k, v in entry.items() if k != 'evidence'}
                e['method'] = m
                evs = [ev for ev in entry.get('evidence', [])
                       if ev['method'] == m or not ev['method_explicit']]
                e['evidence'] = [{k: ev[k] for k in ('type', 'kind', 'source', 'method', 'phase')}
                                 for ev in sorted(evs, key=lambda ev: (ev['kind'], ev['type'] or '', ev['source']))][:20]
                out.append(e)
        return out

    def _rebuild_index(self):
        """Re-derive the URL index after self.endpoints was filtered."""
        self._index = {e['endpoint'].rstrip('/'): e for e in self.endpoints}

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
            return "EXTERNAL_API" if not is_ignored_url(u) else "NOISE"
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

    _METHOD_OPT_RE = re.compile(r"""\bmethod\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]""", re.I)
    _METHOD_CALL_RE = re.compile(r'\.(get|post|put|patch|delete|head|options)\s*(?:<[^>]{0,80}>)?\s*\(\s*$', re.I)

    def detect_method(self, code, pos):
        """HTTP method of the call at `pos`, from the call itself only:
        a `method: "X"` option before the end of the statement, or a
        `.post(` / `.delete(` ... immediately before the URL. Otherwise GET
        (which is also what fetch()/XHR default to)."""
        ahead = code[pos:pos + 300].split(';', 1)[0]
        m = self._METHOD_OPT_RE.search(ahead)
        if m:
            return m.group(1).upper()
        m = self._METHOD_CALL_RE.search(code[max(0, pos - 60):pos + 1].rstrip('"\'`'))
        if m:
            return m.group(1).upper()
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
