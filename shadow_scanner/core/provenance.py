"""Endpoint provenance graph: multi-source confirmation + audit trail."""
from collections import defaultdict

from shadow_scanner.core.evidence import evidence_kind
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
        'PROBE':     0.70,
        'STATIC':    0.65,
        'STORAGE':   0.75,
        'UNKNOWN':   0.40,
    }

    _KIND_TO_CATEGORY = {'runtime': 'RUNTIME', 'spec': 'SCHEMA', 'probe': 'PROBE', 'storage': 'STORAGE'}
    _CONFIG_TYPES = frozenset({'JSON_CONFIG', 'ENVIRONMENT_URL', 'ENV_VAR_CONCAT'})
    _MAP_SOURCE_EXT = ('.ts', '.tsx', '.jsx', '.vue', '.svelte', '.mts', '.cts')

    def __init__(self):
        # url_key → list of evidence records
        self._graph: dict[str, list[dict]] = defaultdict(list)

    @staticmethod
    def _category(extraction_type: str, source: str = '') -> str:
        """Where the evidence came from: RUNTIME / SCHEMA / PROBE / STORAGE by
        evidence kind (core/evidence.py); for client code, SOURCEMAP when the
        code was recovered from a source map, CONFIG for configuration values,
        else STATIC."""
        kind = evidence_kind(extraction_type)
        if kind in EndpointProvenanceGraph._KIND_TO_CATEGORY:
            return EndpointProvenanceGraph._KIND_TO_CATEGORY[kind]
        et = (extraction_type or '').upper()
        src = (source or '').replace('\\', '/').lower()
        if (et.startswith('SOURCEMAP') or '/sourcemaps/' in src
                or src.split('?')[0].endswith(EndpointProvenanceGraph._MAP_SOURCE_EXT)):
            return 'SOURCEMAP'
        if et in EndpointProvenanceGraph._CONFIG_TYPES or src.split('?')[0].endswith('.json'):
            return 'CONFIG'
        return 'STATIC'

    def record(self, url: str, extraction_type: str, source: str, confidence: int):
        """Record one piece of evidence for an endpoint."""
        key = url.rstrip('/')
        cat = self._category(extraction_type, source)
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
        cats      = sorted({e['category'] for e in evidence})
        sources   = len(evidence)
        best_cat  = max(cats, key=lambda c: (self.WEIGHTS.get(c, 0), c))
        # Multi-source boost: +10 per unique category beyond the first (max +30)
        boost     = min(30, (len(cats) - 1) * 10)
        return {
            'categories':       cats,
            'sources':          sources,
            # independent confirmation = more than one category of evidence
            'multi_source':     len(cats) > 1,
            'provenance_boost': boost,
            'best_category':    best_cat,
            'evidence':         evidence[:5],  # cap for JSON size
        }
