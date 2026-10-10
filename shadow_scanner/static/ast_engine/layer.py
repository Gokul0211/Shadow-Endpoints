"""ASTExtractionLayer - parses JS with esprima and runs every AST extractor."""
from shadow_scanner.config import ESPRIMA_AVAILABLE, esprima
from shadow_scanner.static.ast_engine.alias_resolver import AliasResolver
from shadow_scanner.static.ast_engine.call_graph import ASTCallGraph, ASTCallGraphExtractor
from shadow_scanner.static.ast_engine.node_extractors import (
    BranchLogicExtractor,
    ComputedPropertyExtractor,
    ObjectExpressionExtractor,
    TemplateLiteralExtractor,
)
class ASTExtractionLayer:
    """
    Orchestrates all AST extractors, including the call-graph engine.
    On parse failure, returns [] so the regex pipeline continues unaffected.
    """
    def __init__(self, existing_bindings=None):
        self.existing_bindings = existing_bindings or {}

    def extract(self, js_source, source_label=''):
        if not ESPRIMA_AVAILABLE:
            return []

        MAX_JS_SIZE = 15 * 1024 * 1024
        js_size = len(js_source.encode('utf-8'))
        if js_size > MAX_JS_SIZE:
            size_mb = js_size / (1024 * 1024)
            print(f"    [AST] Skipping AST parse for {source_label} "
                  f"({size_mb:.1f}MB > {MAX_JS_SIZE // (1024*1024)}MB cap) — regex sweeps still run")
            return []

        try:
            tree = esprima.parseScript(js_source, tolerant=True, jsx=False)
        except Exception:
            try:
                tree = esprima.parseModule(js_source, tolerant=True)
            except Exception:
                return []

        resolver = AliasResolver(self.existing_bindings)
        scope    = resolver.build_scope(tree)

        results = []

        # Standard extractors (pattern-based, fast)
        standard_extractors = [
            ComputedPropertyExtractor(scope),
            TemplateLiteralExtractor(scope),
            BranchLogicExtractor(scope),
            ObjectExpressionExtractor(scope),
        ]
        for extractor in standard_extractors:
            try:
                found = extractor.extract(tree)
                results.extend(found)
            except Exception:
                pass

        # ── True AST Call Graph extractor (ASTCallGraphExtractor) ──────────
        # Handles class/object/prototype method contexts with this-scope.
        try:
            cg_extractor = ASTCallGraphExtractor(scope=scope,
                                                 known_vars=self.existing_bindings)
            cg_results = cg_extractor.extract(tree)
            results.extend(cg_results)
        except Exception:
            pass

        # ── ASTCallGraph — pure function-chain resolver (new) ───────────────
        # Resolves multi-level builder chains:
        #   const buildPath = (svc) => `/api/${svc}`
        #   function makeEndpoint(svc, action) { return buildPath(svc) + "/" + action }
        #   function createOrder() { return makeEndpoint("orders","create") }
        #   → /api/orders/create
        try:
            acg = ASTCallGraph(scope=scope)
            acg.register_functions(tree)
            # Also expose existing_bindings so identifier resolution finds them
            acg.scope.update(self.existing_bindings)
            acg_http = acg.find_http_calls(tree)
            # Also walk every registered function body as a standalone call site
            # so indirect calls like createOrder() → makeEndpoint() → fetch()
            # are resolved even when createOrder() is never called with literal args.
            for fn_name, fn_def in acg.functions.items():
                ret_node = fn_def.get('body')
                if ret_node is None:
                    continue
                # Zero-arg call resolves builder chains with known literal args
                resolved = acg.resolve_call(fn_name, [], depth=0)
                if resolved:
                    resolved = ASTCallGraph.normalize(resolved)
                    if resolved and (resolved.startswith('/') or resolved.startswith('http')):
                        acg_http.append({
                            'method':           'GET',
                            'endpoint':         resolved,
                            'type':             'AST_CALL_GRAPH',
                            'classification':   'BACKEND_API',
                            'source':           source_label,
                            'ast_extracted':    True,
                            'confidence_bonus': 4,
                        })
            results.extend(acg_http)
        except Exception:
            pass

        for ep in results:
            ep.setdefault('source', source_label)

        return results
