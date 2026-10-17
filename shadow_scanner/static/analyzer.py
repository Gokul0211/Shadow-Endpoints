"""
EnhancedStaticAnalyzer - the Phase-2 static-analysis hub.

The class itself only holds state and the two orchestrators:

* scan(js_urls, json_urls) - fetch every bundle, resolve variables and DI
  chains, run analyze_code() on everything, then GraphQL introspection.
* analyze_code(code, source) - run every extraction technique over one
  blob of JS, in a FIXED ORDER (add_endpoint() keeps the first entry's
  method/type when confidences tie, so reordering changes results).

Each technique lives in a mixin under static/stages/.
"""
from shadow_scanner import config
from shadow_scanner.config import LOW_VALUE_JS, logger
from shadow_scanner.core.provenance import EndpointProvenanceGraph
from shadow_scanner.core.rate_limiter import RateLimiter
from shadow_scanner.core.scan_cache import ScanCache
from shadow_scanner.core.url_normalizer import URLNormalizer
from shadow_scanner.static.ast_engine.layer import ASTExtractionLayer
from shadow_scanner.static.registry import CODE_EXTRACTORS
from shadow_scanner.static.rpc_extractor import EnhancedRPCExtractor
from shadow_scanner.static.security_headers import SecurityHeaderExtractor
from shadow_scanner.static.stages.dynamic_imports import DynamicImportsMixin
from shadow_scanner.static.stages.endpoint_store import EndpointStoreMixin
from shadow_scanner.static.stages.frameworks import FrameworkPatternsMixin
from shadow_scanner.static.stages.http_clients import HttpClientPatternsMixin
from shadow_scanner.static.stages.interprocedural import InterproceduralMixin
from shadow_scanner.static.stages.json_config import JsonConfigMixin
from shadow_scanner.static.stages.literals import LiteralSweepMixin
from shadow_scanner.static.stages.preprocessing import PreprocessingMixin
from shadow_scanner.static.stages.routes import RoutePatternsMixin
from shadow_scanner.static.stages.scan_steps import ScanStepsMixin
from shadow_scanner.static.valueflow import ValueFlowMixin
from shadow_scanner.static.ts_params import TypeScriptParameterExtractor
from shadow_scanner.static.variable_resolver import EnhancedVariableResolver
from shadow_scanner.core import diagnostics


class EnhancedStaticAnalyzer(
    ValueFlowMixin,
    ScanStepsMixin,
    PreprocessingMixin,
    DynamicImportsMixin,
    HttpClientPatternsMixin,
    FrameworkPatternsMixin,
    InterproceduralMixin,
    RoutePatternsMixin,
    LiteralSweepMixin,
    JsonConfigMixin,
    EndpointStoreMixin,
):
    # Maximum number of cross-file DI-chain resolution passes.
    # The loop breaks early when nothing changes, so the cap only matters
    # for genuinely deep chains.  5 covers all known real-world patterns.
    DI_CHAIN_MAX_PASSES = 5

    # Thread-pool sizes — tuned empirically.
    # FETCH_WORKERS: 15 balances throughput vs. WAF rate-limit triggers.
    # CODE_WORKERS: 8 — regex/AST is CPU-heavy; more workers risks GIL contention.
    MAX_FETCH_WORKERS = 15
    MAX_CODE_WORKERS  = 8

    def __init__(self, session, base_url, rate_limiter: 'RateLimiter' = None,
                 scan_cache: 'ScanCache' = None,
                 workers: int = None, fetch_timeout: float = 30.0):
        self.session = session
        self.base_url = base_url
        self.normalizer = URLNormalizer(base_url)
        self.endpoints = []
        self._index = {}               # normalised URL -> record in self.endpoints
        self.recorder = None           # core.run_meta.RunRecorder (per-phase time / requests)
        self._extractor = None         # name of the extractor currently running
        self.code_corpus = {}          # label -> code: everything fetched, for the value-flow analysis
        self.value_flow_stats = None
        self.extractor_stats = {}      # name -> {'sightings': n, 'errors': n}
        self._phase = '2'
        self.resolver = EnhancedVariableResolver()
        self.rpc_extractor = EnhancedRPCExtractor(self.resolver)
        self.analyzed_js_files = set()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.scan_cache   = scan_cache if scan_cache is not None else ScanCache()
        # Allow CLI overrides for tunable values; fall back to class-level defaults.
        if workers is not None:
            self.MAX_FETCH_WORKERS = workers
        self.fetch_timeout = fetch_timeout
        # TypeScript parameter extractor — shared across all source files in this scan
        self._ts_extractor = TypeScriptParameterExtractor()
        # Endpoint provenance graph — tracks multi-source confirmation
        self.provenance = EndpointProvenanceGraph()
        # GAP 2: Tracks dynamic import() URLs discovered during analysis for later fetch
        self._dynamic_imports: set = set()
        # Security-relevant HTTP header mining (client-set secrets + server-read
        # trust headers). Shared across every analyze_code() call so findings from
        # all JS bundles and source-map-recovered files accumulate + dedupe.
        self._header_extractor = SecurityHeaderExtractor()

    @property
    def current_phase(self):
        """Phase label stored on every evidence item; setting it also switches the
        per-phase counters of the recorder and the HTTP client."""
        return self._phase

    @current_phase.setter
    def current_phase(self, name):
        self._phase = name
        if self.recorder is not None:
            self.recorder.start_phase(name)
        if hasattr(self.session, 'set_phase'):
            self.session.set_phase(name)

    # ── Phase 2 entry point ──────────────────────────────────────────────
    def scan(self, js_urls, json_urls):
        print("\n[PHASE 2] Enhanced Analysis with Method Call Resolution")
        print(f"  Processing: {len(js_urls)} JS files, {len(json_urls)} JSON configs")

        js_contents = self._fetch_and_extract_variables(js_urls)
        self._adopt_backend_api_host()
        self._resolve_cross_file_di_chains()
        self.run_extractor('rpc_patterns', self._extract_rpc_and_array_endpoints, js_contents)
        self.run_extractor('array_harvest', self._extract_array_harvest_endpoints)
        self.run_extractor('service_properties', self._extract_service_property_endpoints)
        self._analyze_all_code_parallel(js_contents, json_urls)
        self.run_extractor('webpack_modules', self._analyze_webpack_module_bodies, js_contents)
        self.run_extractor('static_websockets', self._discover_static_websockets, js_contents)
        self._analyze_lazy_dynamic_imports(js_contents)
        self._drop_low_confidence_endpoints()
        self.run_extractor('graphql_introspection', self._run_graphql_introspection)

        print(f"\n  [+] Total endpoints discovered: {len(self.endpoints)}")
        # Expose js_contents for ServiceWorkerAnalyzer (called from main after scan())
        self.js_contents = js_contents


        return self.endpoints

    # ── Per-file extraction pipeline ─────────────────────────────────────
    def analyze_code(self, code, source):
        """Analyze JavaScript code for endpoints (every technique, fixed order)."""
        if any(x in source.lower() for x in LOW_VALUE_JS):
            return
        if '::' not in source:                 # webpack module bodies are slices of a bundle already kept
            self.code_corpus.setdefault(source, code)

        # ── Security-relevant HTTP header mining ──────────────────────────────
        # Runs on the RAW code (before comment stripping) so we catch both the
        # secrets the frontend sends and the trust headers the backend reads.
        # Cheap, self-contained, never raises. See SecurityHeaderExtractor.
        try:
            self._header_extractor.extract(code, source)
        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

        code = self._preprocess_code(code)
        self._queue_dynamic_imports(code, source)      # infrastructure: queues files, finds nothing itself

        for name, method in CODE_EXTRACTORS:
            self.run_extractor(name, getattr(self, method), code, source)

        self._queue_lazy_chunk_paths(code, source)     # infrastructure
        self._queue_import_expressions(code, source)   # infrastructure

    # ── extractor bookkeeping ────────────────────────────────────────────
    def extractor_enabled(self, name):
        return config.extractor_enabled(name)

    def run_extractor(self, name, fn, *args):
        """Run one extractor if enabled. Its name is stored on every evidence item
        it produces; an exception is logged and counted, and the other extractors
        still run (it used to abort the rest of the file)."""
        if not config.extractor_enabled(name):
            return None
        previous, self._extractor = self._extractor, name
        try:
            return fn(*args)
        except Exception as exc:
            st = self.extractor_stats.setdefault(name, {'sightings': 0, 'errors': 0})
            st['errors'] += 1
            logger.warning(f"[extractor {name}] {type(exc).__name__}: {exc}")
            return None
        finally:
            self._extractor = previous

    def _run_ast_layer(self, code, source):
        """esprima AST extractors (call graphs, computed keys, templates, branches)."""
        # -------------------------------------------------------------------------
        # AST INTEGRATION START
        # -------------------------------------------------------------------------
        try:
            simple_bindings = {}
            # Include regular variables
            for k, v in self.resolver.variables.items():
                if isinstance(v, dict) and 'value' in v:
                    simple_bindings[k] = v['value']
                elif isinstance(v, str):
                    simple_bindings[k] = v
            # Include global_scope — this carries dotted keys like:
            #   "VERSIONS.prod" = "v2"  (object property paths)
            #   "arr.0" = "v1"           (array element indices)
            # These enable ASTCallGraphExtractor to resolve ${VERSIONS.prod}
            # and api[cfg.method] patterns.
            for k, v in self.resolver.global_scope.items():
                if isinstance(v, str) and k not in simple_bindings:
                    simple_bindings[k] = v

            ast_layer = ASTExtractionLayer(existing_bindings=simple_bindings)
            ast_endpoints = ast_layer.extract(code, source)

            for ep in ast_endpoints:
                url = ep.get('endpoint')
                method = ep.get('method', 'GET')
                # Base confidence 95 + bonus
                bonus = ep.get('confidence_bonus', 0)
                confidence = 95 + (bonus * 2)

                # Extract extra fields strictly for AST endpoints
                extra = {
                    'ast_extracted': ep.get('ast_extracted', False),
                    'alias_name': ep.get('alias_name')
                }

                self.add_endpoint(
                    url,
                    method,
                    [],
                    ep.get('type'),
                    source,
                    ep.get('classification', 'BACKEND_API'),
                    confidence,
                    extra_fields=extra
                )
        except Exception as _exc:
            # Fallback contract: never suppress regex output on AST failure
            diagnostics.swallowed(__name__, _exc)
        # -------------------------------------------------------------------------
        # AST INTEGRATION END
        # -------------------------------------------------------------------------

    def analyze_code_from_dynamic(self, code, source):
        """
        Analyze code that arrived after Phase 2 (feedback loop, module bodies,
        remotes, source-map sources): register its variables, run the RPC
        patterns, then analyze_code(). Everything found here is STATIC evidence
        - the code was fetched, not executed - so extraction types are kept
        as-is (no "_DYNAMIC" suffix; see core/evidence.py).
        """
        filename = source.split('/')[-1] if '/' in source else source

        # Extract variables and methods from this new code
        self.resolver.extract_all_variables(code, filename)

        # Extract RPC patterns
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

        # Run standard code analysis
        self.analyze_code(code, source)
