"""
What kind of evidence an extraction type is - the single source of truth.

Every sighting of an endpoint is one piece of evidence, and its *kind* says
how we know about it:

  runtime  the browser was seen sending the request (network interception)
  spec     the server declares it (OpenAPI document, Actuator route dump,
           WSDL, Next.js server manifest, GraphQL introspection)
  probe    a well-known path was requested and answered; nothing referenced it
  storage  the URL was found in browser storage (IndexedDB) at runtime
  static   recovered from client code (bundles, source maps, configs)

Only ``runtime`` evidence makes an endpoint runtime-verified. Type names are
looked up exactly; nothing is inferred from substrings like "DYNAMIC".
"""

RUNTIME_TYPES = frozenset({
    'DYNAMIC_XHR_INTERCEPT',     # Playwright request event (xhr / fetch)
    'DYNAMIC_API_CALL',          # Playwright response event (JSON)
    'WEBSOCKET_DYNAMIC',         # Playwright websocket event
    'RUNTIME_FETCH', 'RUNTIME_XHR', 'RUNTIME_AXIOS', 'RUNTIME_GRAPHQL',
    'RUNTIME_SSE', 'RUNTIME_BEACON', 'RUNTIME_UNKNOWN',
})

SPEC_TYPES = frozenset({
    'OPENAPI_SPEC',              # operation listed in an OpenAPI / Swagger document
    'ACTUATOR_ENDPOINT',         # route listed by Spring /actuator/mappings
    'WSDL_OPERATION',            # SOAP operation listed in a WSDL
    'NEXTJS_API_ROUTE',          # route listed in the Next.js server pages manifest
    'GRAPHQL_QUERY', 'GRAPHQL_MUTATION', 'GRAPHQL_SUBSCRIPTION',   # introspection
})

PROBE_TYPES = frozenset({
    'NEXTJS_API_PROBE',          # well-known Next.js API path answered
    'ACTUATOR_MAPPINGS_ROOT',    # /actuator/mappings answered with a route dump
    'GRAPHQL_ENDPOINT',          # a GraphQL endpoint answered an introspection query
    'GRAPHQL_APQ_ENDPOINT',      # a GraphQL endpoint answered an APQ probe
})

STORAGE_TYPES = frozenset({
    'INDEXEDDB_CACHED_URL',
})

KINDS = ('runtime', 'spec', 'probe', 'storage', 'static')


def evidence_kind(extraction_type):
    """Kind of evidence for an extraction type (exact match; default 'static')."""
    t = (extraction_type or '').upper()
    if t in RUNTIME_TYPES or t.startswith('RUNTIME_'):
        return 'runtime'
    if t in SPEC_TYPES:
        return 'spec'
    if t in PROBE_TYPES:
        return 'probe'
    if t in STORAGE_TYPES:
        return 'storage'
    return 'static'


def is_runtime(extraction_type):
    return evidence_kind(extraction_type) == 'runtime'
