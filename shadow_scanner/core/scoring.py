"""
Confidence scoring.

* LibraryFingerprint      - is this source file third-party/vendor code?
* EndpointClassifier      - hard-garbage gate (XML/binary/unresolved base vars)
* BayesianConfidenceScorer - THE single unified scorer.  Produces tiers
  HIGH_CONFIDENCE (>=85) / BACKEND_API (55-84) / LOW_CONFIDENCE (30-54) with
  (VERIFIED_API is reserved for requests observed in browser traffic)
  Wilson 95% CIs and data-driven LR calibration.  Route every new signal
  through this class - do not introduce a competing scorer.
"""
import re
from collections import defaultdict

from shadow_scanner.core.evidence import is_runtime
# ==============================================================================
# CLASS: LIBRARY FINGERPRINT (Identify Vendor Code)
# ==============================================================================
class LibraryFingerprint:
    """Identifies source files that belong to third-party libraries."""

    VENDOR_INDICATORS = [
        'node_modules', 'webpack', 'chunk', 'vendor', 'min.js',
        'react', 'angular', 'vue', 'axios', 'jquery', 'lodash', 'moment',
        'xlsx', 'sheetjs', 'chart.js', 'd3', 'fontawesome'
    ]
    # FIX BUG-1: Application bundle filenames that must NEVER be classified as
    # vendor code even if they contain a VENDOR_INDICATORS substring (e.g.
    # 'bundle.js' contains 'bundle' — but it IS the app's primary bundle).
    # Also covers Angular/Vite/Nuxt entry-point naming conventions.
    _APP_BUNDLE_NAMES = frozenset([
        'bundle.js', 'main.js', 'app.js', 'index.js', 'entry.js',
        'main-bundle.js', 'app-bundle.js', 'runtime.js',
        'remoteentry.js',  # Module Federation host entry
    ])

    @staticmethod
    def is_vendor(file_path):
        if not file_path:
            return False

        path_lower = file_path.lower()

        # FIX BUG-1: App bundle early-exit — these are NEVER vendor files.
        # Check both the bare filename and the last path component so that
        # 'http://localhost:3001/dist/bundle.js' is handled correctly.
        basename = path_lower.split('/')[-1].split('\\')[-1]
        if basename in LibraryFingerprint._APP_BUNDLE_NAMES:
            return False
        # Also match *.worker.js files — they're app-authored, not library code
        if basename.endswith('.worker.js'):
            return False

        # FIX BUG-E-CHUNK: Next.js emits application code (page handlers, GraphQL
        # resolvers, services) as hashed bundles under /_next/static/chunks/.
        # The generic 'chunk' VENDOR_INDICATOR below would misclassify every one
        # of these as vendor code, applying a confidence penalty that drops real
        # App-E endpoints below the keep threshold. Treat the Next.js app-chunk
        # directory as application code. Genuine third-party chunks still carry a
        # 'node_modules'/'vendor' marker and fall through to the indicator scan.
        if '/_next/static/chunks/' in path_lower and not (
            'node_modules' in path_lower or 'vendor' in path_lower):
            return False

        # Check for known vendor paths/names
        for ind in LibraryFingerprint.VENDOR_INDICATORS:
            if ind in path_lower:
                return True

        # Check for hashes often found in vendor chunks (e.g., 2.7b57cd2c.chunk.js)
        # 8+ hex chars usually indicate a built artifact
        if re.search(r'[a-f0-9]{8,}', path_lower):
            # But exclude typical main application files if clearly named
            if 'main.' in path_lower or 'app.' in path_lower or 'index.' in path_lower:
                return False
            return True

        return False

# ==============================================================================
# CLASS: ENDPOINT CLASSIFIER (Confidence Tiering)
# ==============================================================================
class EndpointClassifier:
    """
    Hard garbage gate used by EnhancedStaticAnalyzer.add_endpoint().

    (The old score_and_classify() shim was removed: it was never called and
    simply forwarded to BayesianConfidenceScorer.score().)
    """
    @staticmethod
    def is_hard_garbage(endpoint):
        """
        Returns True ONLY for guaranteed non-API artifacts (XML, Binary).
        These are safe to drop completely.
        """
        if not endpoint:
            return True
        s = str(endpoint)
        # Hard block XML/HTML tags and Binary control chars
        if '<' in s or '>' in s or '\x05' in s or '!DataSpaces' in s:
            return True
        # FP FIX: Unresolved template variable in URL.
        # {apiBase}/api/auth/login or host/{apiBase}/path → variable was never substituted.
        # Distinguish from intentional path params like {id}, {userId} which are short
        # and commonly used as REST placeholders. Unresolved variables tend to be longer
        # camelCase names: {apiBase}, {baseUrl}, {serviceUrl}, {environmentApiUrl} etc.
        try:
            import urllib.parse as _up
            _parsed = _up.urlparse(s)
            # If the netloc (host:port) contains a brace → definitely unresolved
            if _parsed.netloc and '{' in _parsed.netloc:
                return True
            # Check path segments: a segment that is entirely {word} AND the word
            # is a known base-URL variable name (not a standard REST id param)
            _unresolved_var_re = re.compile(
                r'^\{(apiBase|baseUrl|baseURL|serviceUrl|serviceURL|serverUrl|serverURL|'
                r'environmentApiUrl|apiEndpoint|apiHost|backendUrl|backendURL|'
                r'rootUrl|rootURL|getApiBase|getBase|getApiUrl|getRootUrl)[^\}]*\}$',
                re.IGNORECASE
            )
            _path = _parsed.path or ''
            for _seg in _path.strip('/').split('/'):
                if _unresolved_var_re.match(_seg):
                    return True
        except Exception:
            pass
        return False

# ==============================================================================
# BAYESIAN CONFIDENCE SCORER
# Replaces arbitrary integer scores with P(real_api | signals).
# Prior: ~35% of candidates are real backend APIs (calibrated from scan data).
# ==============================================================================
class BayesianConfidenceScorer:
    # ── Prior ────────────────────────────────────────────────────────────────
    # P(API | candidate string) — empirically calibrated: ~35% of string-like
    # candidates extracted from a typical SPA bundle are genuine API endpoints.
    # Override at class level before scanning to adjust for target density.
    PRIOR: float = 0.35

    # ── Tier thresholds (must match paper Table II) ─────
    TIER_VERIFIED:      int = 85   # HIGH_CONFIDENCE (name kept for compatibility)
    TIER_BACKEND:       int = 55   # BACKEND_API
    TIER_LOW_CONF:      int = 30   # LOW_CONFIDENCE
    # Below TIER_LOW_CONF → NOISE_CANDIDATE (filtered from output)

    LR = {
        'verified_dynamic':   1e9,
        'ts_service_file':    8.0,
        'httpclient_angular': 7.0,
        'httpclient_generic': 5.0,
        'angular_wrapper':    6.0,
        'vue_async_data':     5.5,
        'react_useeffect':    5.0,
        'soap_bridge':        4.5,
        'indexeddb_cache':    4.0,
        'nextjs_route':       5.0,   # IMPL-3: Next.js API route
        'sw_proxy_route':     4.0,   # IMPL-7: Service worker proxy
        'internal_ip':        4.5,   # FIX BUG-4: hardcoded private IP URL
        'web_worker':         4.0,   # FIX BUG-2: Web Worker fetch()
        'url_builder':        3.5,   # IMPL-2: URL builder functions
        'promise_chain':      3.0,   # IMPL-2: Promise chain fetch
        'computed_http_call': 4.0,   # IMPL-1: api["get"]("/path")
        'websocket_url':      4.5,   # WebSocket URL in client code (literal or built)
        # Provisional (Phase A): server-declared routes (OpenAPI, Actuator, WSDL,
        # Next.js server manifest, GraphQL introspection). Replaced by learned
        # weights in Phase E.
        'schema_declared':    9.0,
        'apq_persisted':      5.0,   # IMPL-6: APQ persisted queries
        'interceptor_base':   3.5,   # IMPL-2: axios interceptor baseURL
        'rtk_query':          5.5,   # G10: RTK Query / React Query / SWR
        'jsdoc_openapi':      6.0,   # G9: JSDoc @openapi annotations
        'interprocedural':    4.0,   # G2b: interprocedural function analysis
        'ssa_propagated':     4.5,   # SSA-style variable propagation
        'ast_call_graph':     7.5,   # TRUE AST call graph — highest static signal
        'template_resolved':  4.5,   # G1: resolved template literals
        'trpc_procedure':     6.0,   # tRPC router procedures
        'nuxt_server_route':  6.5,   # Nuxt 3 server/api filesystem routes
        'gql_tag':            5.5,   # gql`` tagged template GraphQL ops
        'env_var_concat':     3.5,   # process.env / import.meta.env concat
        'tanstack_route':     3.0,   # Tanstack Router / React Router v6
        'sourcemap_ts':       4.0,
        'sourcemap_jsx':      3.5,
        'json_config':        3.5,
        'rpc_call':           3.0,
        'multi_source':       5.0,
        'api_path':           2.0,
        'naming_convention':  1.8,
        'non_get_method':     2.5,
        'fetch_api':          2.0,
        'static_code':        1.5,
        'ast_call':           2.5,
        'vendor_source':      0.2,
        'array_harvest':      0.6,
        'single_word':        0.3,
        'hash_route':         0.1,
        'frontend_route_nav': 0.05,
        'library_artifact':   0.05,
    }
    _ET_MAP = {
        'HTTP_THIS':                    ['httpclient_angular'],
        'HTTPCLIENT_THIS':              ['httpclient_angular'],
        'HTTPCLIENT':                   ['httpclient_generic'],
        'HTTP':                         ['httpclient_generic'],
        'RPC_CALL':                     ['rpc_call'],
        'RPC_VARIABLE_CONCAT':          ['rpc_call'],
        'RPC_TEMPLATE_LITERAL':         ['rpc_call'],
        'AST_HTTP_CALL':                ['ast_call'],
        'AST_TEMPLATE_LITERAL':         ['ast_call'],
        'AST_COMPUTED_KEY':             ['computed_http_call'],
        'FETCH_API':                    ['fetch_api'],
        'STATIC_CODE':                  ['static_code'],
        'ARRAY_HARVEST':                ['array_harvest'],
        'JSON_CONFIG':                  ['json_config'],
        'ROUTER_NAV_THIS':              ['frontend_route_nav'],
        'ROUTER_NAV':                   ['frontend_route_nav'],
        'ROUTE_NAV_THIS':               ['frontend_route_nav'],
        'ROUTE_NAV':                    ['frontend_route_nav'],
        'HISTORY_PUSH':                 ['frontend_route_nav'],
        'REACT_NAVIGATE':               ['frontend_route_nav'],
        'HASH_ROUTE':                   ['hash_route'],
        # Framework wrappers
        'ANGULAR_SERVICE_WRAPPER':      ['angular_wrapper'],
        'VUE_ASYNC_DATA':               ['vue_async_data'],
        'VUE_FETCH':                    ['vue_async_data'],
        'REACT_USE_EFFECT_FETCH':       ['react_useeffect'],
        'SOAP_BRIDGE_CALL':             ['soap_bridge'],
        'SOAP_ACTION':                  ['soap_bridge'],
        # Storage / cache (a URL found in IndexedDB is not observed traffic)
        'INDEXEDDB_CACHE_KEY':          ['indexeddb_cache'],
        'INDEXEDDB_CACHED_URL':         ['indexeddb_cache'],
        # Server-declared routes (see core/evidence.py SPEC_TYPES)
        'OPENAPI_SPEC':                 ['schema_declared'],
        'ACTUATOR_ENDPOINT':            ['schema_declared'],
        'WSDL_OPERATION':               ['schema_declared', 'soap_bridge'],
        # New IMPL types
        'NEXTJS_API_ROUTE':             ['nextjs_route', 'schema_declared'],
        'NEXTJS_API_PROBE':             ['nextjs_route'],
        'SW_PRECACHE_ROUTE':            ['sw_proxy_route'],
        'SW_RESPOND_WITH':              ['sw_proxy_route'],
        'URL_BUILDER_FUNC':             ['url_builder'],
        'PROMISE_CHAIN_FETCH':          ['promise_chain'],
        'PROMISE_CHAIN_AXIOS':          ['promise_chain'],
        'WEBSOCKET_DYNAMIC_CONCAT':     ['websocket_url'],
        'WEBSOCKET_DYNAMIC_VAR':        ['websocket_url'],
        'WEBSOCKET_STATIC_LITERAL':     ['websocket_url'],
        'WEBSOCKET':                    ['websocket_url'],
        # UPGRADE: New runtime interception types
        'RUNTIME_SSE':                  ['verified_dynamic'],
        'RUNTIME_BEACON':               ['verified_dynamic'],
        'RUNTIME_GRAPHQL':              ['verified_dynamic', 'gql_tag'],
        'RUNTIME_AXIOS':                ['verified_dynamic'],
        'RUNTIME_FETCH':                ['verified_dynamic'],
        'RUNTIME_XHR':                  ['verified_dynamic'],
        'NEW_URL_CONSTRUCTOR':          ['fetch_api'],
        'NEW_URL_TEMPLATE':             ['fetch_api'],
        'NAMED_AXIOS_INSTANCE':         ['angular_wrapper'],
        'NEXTJS_COMMENT_ROUTE':         ['nextjs_route'],
        'NEXTJS_FILE_ROUTE':            ['nextjs_route'],
        # G1/G2b/G9/G10 new types
        'TEMPLATE_LITERAL_RESOLVED':    ['template_resolved'],
        'RTK_QUERY_ENDPOINT':           ['rtk_query'],
        'REACT_QUERY_HOOK':             ['rtk_query'],
        'SWR_HOOK':                     ['rtk_query'],
        'APOLLO_MUTATION_URL':          ['rtk_query'],
        'JSDOC_OPENAPI':                ['jsdoc_openapi'],
        'JSDOC_OPENAPI_PATH':           ['jsdoc_openapi'],
        'INTERPROCEDURAL_FUNC':         ['interprocedural'],
        # TRUE AST call graph — resolves multi-level function chains
        'AST_CALL_GRAPH':               ['ast_call_graph', 'ast_call'],
        # tRPC, Nuxt, gql-tag, env-var, Tanstack
        'TRPC_PROCEDURE':               ['trpc_procedure'],
        'TRPC_NESTED_PROCEDURE':        ['trpc_procedure'],
        'NUXT_SERVER_ROUTE':            ['nuxt_server_route'],
        'GQL_TAG_QUERY':                ['gql_tag'],          # client code
        'GQL_TAG_MUTATION':             ['gql_tag'],
        'GQL_TAG_SUBSCRIPTION':         ['gql_tag'],
        'GRAPHQL_QUERY':                ['schema_declared'],  # server introspection
        'GRAPHQL_MUTATION':             ['schema_declared'],
        'GRAPHQL_SUBSCRIPTION':         ['schema_declared'],
        'ENV_VAR_CONCAT':               ['env_var_concat'],
        'TANSTACK_ROUTE':               ['tanstack_route'],
        'INTERNAL_IP_HARDCODED':        ['internal_ip'],
        'RPC_3PART_CONCAT':             ['rpc_call'],
        'SW_WEB_WORKER':               ['web_worker'],
        'GRAPHQL_APQ_ENDPOINT':        ['apq_persisted'],
    }

    @classmethod
    def _derive_signals(cls, url, extraction_type, is_vendor, source='', method='GET'):
        signals = []
        et = (extraction_type or '').upper()
        signals.extend(cls._ET_MAP.get(et, []))
        # Only requests actually observed in browser traffic are runtime-verified
        # (core/evidence.py). Type names are never matched by substring.
        if is_runtime(et):
            signals.append('verified_dynamic')
        if is_vendor:
            signals.append('vendor_source')
        src = (source or '').lower()
        if '.service.ts' in src:
            signals.append('ts_service_file')
        elif src.endswith('.ts') or src.endswith('.tsx'):
            signals.append('sourcemap_ts')
        elif src.endswith('.jsx'):
            signals.append('sourcemap_jsx')
        elif 'environment' in src and '.json' in src:
            signals.append('json_config')
        u = (url or '').lower()
        if any(p in u for p in ('/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/rest/')):
            signals.append('api_path')
        if any(v in (url or '') for v in ('Get', 'Post', 'Create', 'Update',
                                           'Delete', 'Save', 'Fetch', 'Load',
                                           'Find', 'Search')):
            signals.append('naming_convention')
        url_no_prefix = (url or '').strip('/')
        if '/' not in url_no_prefix and '.' not in url_no_prefix and url_no_prefix:
            signals.append('single_word')
        if method and method.upper() in ('POST', 'PUT', 'DELETE', 'PATCH'):
            signals.append('non_get_method')
        return signals

    @classmethod
    def score(cls, url, extraction_type, is_vendor,
              source='', method='GET', extra_signals=None):
        """Returns (score_int, category_str, tags_list) or None if garbage."""
        if not url:
            return None
        u_low = (url or '').lower()
        for poly in ('browserify-sign', 'elliptic', 'create-ecdh', 'bn.js', 'pbkdf2'):
            if poly in u_low:
                return None
        for bad in ('schemas.openxmlformats.org', 'reactjs.org', 'w3.org',
                    'schemas.microsoft.com', 'mozilla.org'):
            if bad in u_low:
                return (10, 'EXTERNAL_REFERENCE', ['external_schema'])
        if 'a:dimension' in u_low or 'a:sheets' in u_low:
            return None

        signals = cls._derive_signals(url, extraction_type, is_vendor, source, method)
        if extra_signals:
            signals.extend(extra_signals)

        if 'verified_dynamic' in signals:
            return (100, 'VERIFIED_API', signals)
        if 'library_artifact' in signals:
            p = 0.02
        elif 'frontend_route_nav' in signals:
            p = 0.04
        elif 'hash_route' in signals:
            p = 0.08
        else:
            p_prior = cls.PRIOR
            lr_prod = 1.0
            seen = set()
            for sig in signals:
                if sig not in seen:
                    lr_prod *= cls.LR.get(sig, 1.0)
                    seen.add(sig)
            p_num = p_prior * lr_prod
            p = p_num / (p_num + (1.0 - p_prior))

        score_int = min(100, max(1, round(p * 100)))
        if score_int >= cls.TIER_VERIFIED:
            cat = 'HIGH_CONFIDENCE'      # high score, NOT observed at runtime
        elif score_int >= cls.TIER_BACKEND:
            cat = 'BACKEND_API'
        elif score_int >= cls.TIER_LOW_CONF:
            cat = 'LOW_CONFIDENCE'
        else:
            cat = 'NOISE_CANDIDATE'

        if score_int < 40 and cat in ('NOISE_CANDIDATE', 'LOW_CONFIDENCE'):
            if is_vendor or 'array_harvest' in signals or 'frontend_route_nav' in signals:
                return None
        # FIX FP-4: tighten overall noise floor — REST_PATH (score≈35-44) from
        # vendor/array sources that have no other signals should be dropped.
        if score_int < 42 and 'array_harvest' in signals and 'api_path' not in signals:
            return None
        return (score_int, cat, signals)

    # ── Statistical helpers ──────────────────────────────────────────────────

    @staticmethod
    def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
        """Wilson score confidence interval for a binomial proportion.

        Returns (lower, upper) as fractions in [0, 1].
        Uses z=1.96 for 95% CI by default.

        Wilson CI is preferred over the naive p ± z*sqrt(p(1-p)/n) because it
        remains well-calibrated when k=0, k=n, or n is small — all of which
        occur in benchmark evaluation where per-technique sample sizes are small.

        Args:
            k: Number of successes (true positives, or correct classifications).
            n: Total trials (ground-truth endpoints, or total output).
            z: z-score for desired confidence level (1.96 → 95%, 2.576 → 99%).

        Returns:
            (lower, upper) Wilson CI bounds as floats in [0, 1].
        """
        if n == 0:
            return (0.0, 1.0)
        p_hat = k / n
        denom = 1.0 + (z ** 2) / n
        centre = (p_hat + (z ** 2) / (2 * n)) / denom
        margin = (z * ((p_hat * (1 - p_hat) / n) + (z ** 2) / (4 * n ** 2)) ** 0.5) / denom
        return (max(0.0, centre - margin), min(1.0, centre + margin))

    @classmethod
    def calibrate_from_labels(
        cls,
        labelled_data: list[tuple],
        min_occurrences: int = 3,
        smoothing: float = 0.5,
        apply: bool = False,
    ) -> dict[str, float]:
        """Derive likelihood ratios from labelled ground-truth data using MLE.

        This method implements data-driven LR estimation as an alternative to
        the practitioner-assigned priors in cls.LR.  It operates on benchmark
        ground-truth labels and produces per-signal LR estimates with
        Laplace-smoothed MLE.

        Statistical model
        -----------------
        For each signal s, the likelihood ratio is:

            LR(s) = P(s | API=True) / P(s | API=False)

        where both conditional probabilities are estimated from the labelled
        corpus with Laplace smoothing to avoid zero-frequency problems:

            P(s | API=True)  = (count(s & TP) + alpha) / (count(TP) + 2*alpha)
            P(s | API=False) = (count(s & FP) + alpha) / (count(FP) + 2*alpha)

        Signals with fewer than ``min_occurrences`` total appearances are
        excluded from calibration and fall back to the practitioner prior.

        Args:
            labelled_data: List of tuples, each:
                (url, extraction_type, is_vendor, source, method, is_tp)
                where is_tp is True for a true positive (genuine API endpoint)
                and False for a false positive (noise or misclassified string).
            min_occurrences: Minimum number of times a signal must appear in
                the corpus to be included in calibration.  Signals below this
                threshold retain their practitioner-assigned LR value.
            smoothing: Laplace smoothing alpha.  0.5 = Jeffreys prior.
            apply: If True, update cls.LR in-place with calibrated values.
                If False (default), return calibrated values without modifying
                the live scorer — useful for comparison and reporting.

        Returns:
            dict mapping signal name → calibrated LR.  Also includes metadata
            keys '_n_tp', '_n_fp', '_n_total', '_signals_calibrated',
            '_signals_skipped' for reporting.
        """
        tp_rows = [r for r in labelled_data if r[5] is True]
        fp_rows = [r for r in labelled_data if r[5] is False]
        n_tp = len(tp_rows)
        n_fp = len(fp_rows)

        if n_tp == 0 or n_fp == 0:
            raise ValueError(
                "calibrate_from_labels requires both TP and FP examples. "
                f"Got n_tp={n_tp}, n_fp={n_fp}."
            )

        # Collect per-signal occurrence counts
        sig_tp: dict[str, int] = defaultdict(int)   # signal present in TP rows
        sig_fp: dict[str, int] = defaultdict(int)   # signal present in FP rows
        sig_total: dict[str, int] = defaultdict(int)

        for (url, et, is_vendor, source, method, is_tp) in labelled_data:
            signals = set(cls._derive_signals(url, et, is_vendor, source, method))
            for s in signals:
                sig_total[s] += 1
                if is_tp:
                    sig_tp[s] += 1
                else:
                    sig_fp[s] += 1

        calibrated: dict[str, float] = {}
        skipped: list[str] = []

        all_signals = set(cls.LR.keys()) | set(sig_total.keys())
        for sig in all_signals:
            total = sig_total.get(sig, 0)
            if total < min_occurrences:
                skipped.append(sig)
                calibrated[sig] = cls.LR.get(sig, 1.0)   # retain prior
                continue

            # Laplace-smoothed MLE
            p_sig_given_tp = (sig_tp.get(sig, 0) + smoothing) / (n_tp + 2 * smoothing)
            p_sig_given_fp = (sig_fp.get(sig, 0) + smoothing) / (n_fp + 2 * smoothing)

            if p_sig_given_fp < 1e-12:
                lr = cls.LR.get(sig, 1.0)   # avoid division by zero; keep prior
            else:
                lr = p_sig_given_tp / p_sig_given_fp

            # Cap extreme values at the same bounds used by the practitioner priors
            lr = max(0.01, min(1e9, lr))
            calibrated[sig] = round(lr, 4)

        calibrated['_n_tp']               = n_tp
        calibrated['_n_fp']               = n_fp
        calibrated['_n_total']            = len(labelled_data)
        calibrated['_signals_calibrated'] = len(all_signals) - len(skipped)
        calibrated['_signals_skipped']    = len(skipped)

        if apply:
            for sig, lr in calibrated.items():
                if not sig.startswith('_'):
                    cls.LR[sig] = lr

        return calibrated

    @classmethod
    def tier_statistics(
        cls,
        results: list[dict],
        ground_truth_tps: set[str] | None = None,
    ) -> dict:
        """Compute per-tier counts and Wilson confidence intervals.

        Produces the statistical summary required for academic reporting.
        When ``ground_truth_tps`` is provided (a set of known-TP URLs, e.g.
        from a benchmark evaluator), also computes per-tier precision with 95%
        Wilson CIs.

        Args:
            results: List of endpoint dicts as produced by save_report().
            ground_truth_tps: Optional set of URLs known to be true positives.
                When present, enables precision CI computation per tier.

        Returns:
            dict with keys:
                'tiers'  — per-tier breakdown with counts and CIs
                'totals' — aggregate totals
                'wilson_z' — z-score used (1.96 = 95% CI)
        """
        from collections import Counter

        Z = 1.96  # 95% confidence intervals throughout

        counts: Counter = Counter()
        for ep in results:
            cat = ep.get('classification', ep.get('category', 'UNKNOWN'))
            counts[cat] += 1

        tiers_out = {}
        for cat, n in counts.most_common():
            entry: dict = {'count': n}
            if ground_truth_tps is not None:
                tp_in_tier = sum(
                    1 for ep in results
                    if ep.get('classification', ep.get('category', '')) == cat
                    and ep.get('endpoint', ep.get('url', '')) in ground_truth_tps
                )
                lo, hi = cls.wilson_ci(tp_in_tier, n, Z)
                entry['true_positives']           = tp_in_tier
                entry['precision_point_estimate'] = round(tp_in_tier / n, 4) if n else 0.0
                entry['precision_ci_lower_95']    = round(lo, 4)
                entry['precision_ci_upper_95']    = round(hi, 4)
            tiers_out[cat] = entry

        total_n = len(results)
        totals: dict = {'total_output': total_n}
        if ground_truth_tps is not None:
            total_tp = sum(
                1 for ep in results
                if ep.get('endpoint', ep.get('url', '')) in ground_truth_tps
            )
            lo_all, hi_all = cls.wilson_ci(total_tp, total_n, Z)
            totals['true_positives']           = total_tp
            totals['precision_point_estimate'] = round(total_tp / total_n, 4) if total_n else 0.0
            totals['precision_ci_lower_95']    = round(lo_all, 4)
            totals['precision_ci_upper_95']    = round(hi_all, 4)

        return {
            'tiers':   tiers_out,
            'totals':  totals,
            'wilson_z': Z,
            'ci_level': '95%',
        }
