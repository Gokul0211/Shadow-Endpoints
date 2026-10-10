"""Endpoint provenance graph: multi-source confirmation + audit trail."""
from collections import defaultdict
# ==============================================================================
# ENDPOINT PROVENANCE GRAPH
# Tracks the evidence chain for each endpoint across all discovery sources.
# When the same endpoint is seen from multiple independent techniques, confidence
# is boosted ("multi-source confirmation"). Provenance is preserved in the output
# so security engineers can audit exactly HOW each endpoint was found.
# ==============================================================================
class EndpointProvenanceGraph:
    """
    A lightweight directed graph of endpoint evidence.

    Nodes  : canonical endpoint URLs
    Edges  : (source_type, source_file, confidence) tuples
    Purpose: multi-source confirmation scoring + audit trail

    Provenance categories and their base credibility:
      STATIC     : extracted by static code analysis
      SOURCEMAP  : recovered via source map decompilation
      RUNTIME    : observed live in Playwright network traffic (highest)
      SCHEMA     : from GraphQL introspection / OpenAPI spec
      CONFIG     : from environment files / JSON configs
      STORAGE    : from localStorage / IndexedDB / service worker cache
    """

    # Credibility weights per provenance category
    WEIGHTS = {
        'RUNTIME':   1.0,
        'SCHEMA':    0.95,
        'CONFIG':    0.85,
        'SOURCEMAP': 0.80,
        'STATIC':    0.65,
        'STORAGE':   0.75,
        'UNKNOWN':   0.40,
    }

    # Map extraction types → provenance category
    _ET_TO_CATEGORY = {
        # Runtime
        'DYNAMIC_XHR_INTERCEPT': 'RUNTIME', 'DYNAMIC_API_CALL': 'RUNTIME',
        'WEBSOCKET_DYNAMIC':     'RUNTIME', 'INDEXEDDB_CACHED_URL': 'RUNTIME',
        'SW_RESPOND_WITH':       'RUNTIME', 'NEXTJS_API_PROBE': 'RUNTIME',
        # Schema
        'GRAPHQL_QUERY':         'SCHEMA',  'GRAPHQL_MUTATION': 'SCHEMA',
        'GRAPHQL_SUBSCRIPTION':  'SCHEMA',  'OPENAPI_ENDPOINT': 'SCHEMA',
        'JSDOC_OPENAPI':         'SCHEMA',  'JSDOC_OPENAPI_PATH': 'SCHEMA',
        'ACTUATOR_ENDPOINT':     'SCHEMA',
        # Config
        'JSON_CONFIG':           'CONFIG',  'ENVIRONMENT_URL': 'CONFIG',
        'NEXTJS_API_ROUTE':      'CONFIG',  'NEXTJS_FILE_ROUTE': 'CONFIG',
        'NEXTJS_COMMENT_ROUTE':  'CONFIG',
        # Sourcemap
        'SOURCEMAP_RECOVERY':    'SOURCEMAP',
        # Storage
        'SW_PRECACHE_ROUTE':     'STORAGE', 'INDEXEDDB_CACHE_KEY': 'STORAGE',
        'LOCALSTORAGE_API_KEY':  'STORAGE',
    }

    def __init__(self):
        # url_key → list of evidence records
        self._graph: dict[str, list[dict]] = defaultdict(list)

    @staticmethod
    def _category(extraction_type: str) -> str:
        et = (extraction_type or '').upper()
        for key, cat in EndpointProvenanceGraph._ET_TO_CATEGORY.items():
            if et.startswith(key):
                return cat
        # Heuristic fallback
        if 'DYNAMIC' in et or 'RUNTIME' in et or 'VERIFIED' in et:
            return 'RUNTIME'
        if 'SOURCEMAP' in et or 'TS_SERVICE' in et:
            return 'SOURCEMAP'
        if 'CONFIG' in et or 'ENVIRON' in et or 'JSON' in et:
            return 'CONFIG'
        return 'STATIC'

    def record(self, url: str, extraction_type: str, source: str, confidence: int):
        """Record one piece of evidence for an endpoint."""
        key = url.rstrip('/')
        cat = self._category(extraction_type)
        self._graph[key].append({
            'type':       extraction_type,
            'source':     source,
            'confidence': confidence,
            'category':   cat,
        })

    def get_provenance(self, url: str) -> dict:
        """Return provenance summary for a URL."""
        key = url.rstrip('/')
        evidence = self._graph.get(key, [])
        if not evidence:
            return {'categories': [], 'sources': 0, 'multi_source': False,
                    'provenance_boost': 0, 'best_category': 'UNKNOWN'}
        cats      = list({e['category'] for e in evidence})
        sources   = len(evidence)
        best_cat  = max(cats, key=lambda c: self.WEIGHTS.get(c, 0))
        # Multi-source boost: +10 per unique category beyond the first (max +30)
        boost     = min(30, (len(cats) - 1) * 10)
        return {
            'categories':       cats,
            'sources':          sources,
            'multi_source':     sources > 1,
            'provenance_boost': boost,
            'best_category':    best_cat,
            'evidence':         evidence[:5],  # cap for JSON size
        }
