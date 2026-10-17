"""GraphQL endpoint discovery: introspection + persisted-query (APQ) probing."""
import re
import urllib.parse
from shadow_scanner import config
from shadow_scanner.core import diagnostics
class GraphQLIntrospector:
    """
    Automatically discovers and introspects GraphQL endpoints.
    Extracts complete schema: queries, mutations, types, fields.
    """

    def __init__(self, session, base_url=None, resolver=None):
        self.session = session
        self.base_url = base_url.rstrip('/') if base_url else None
        self.resolver = resolver
        self.schemas = {}
        # Endpoints that confirmed Automatic Persisted Queries (see
        # _probe_persisted_queries); registered by the analyzer's GraphQL step.
        self.apq_endpoints = []

        # Standard GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type { ...TypeRef }
            }
            type { ...TypeRef }
          }
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        """

    def scan(self, discovered_endpoints):
        """Scan all discovered endpoints for GraphQL"""
        print("\n[GRAPHQL] Scanning for GraphQL endpoints...")

        graphql_candidates = []

        # Find potential GraphQL endpoints from already-discovered endpoints
        for endpoint_data in discovered_endpoints:
            endpoint = endpoint_data.get('endpoint', '')
            if self._looks_like_graphql(endpoint):
                graphql_candidates.append(endpoint)

        # RC7-FIX: Also probe common GraphQL paths directly against base_url.
        # Previously, /graphql was probed in Phase 1 as a common endpoint but
        # the 200 result went into json_configs, NOT into discovered_endpoints.
        # So this scan() never saw it as a candidate.
        if self.base_url and config.PROBING_ENABLED:
            common_gql_paths = [
                '/graphql', '/gql', '/api/graphql', '/v1/graphql',
                '/api/gql', '/graphql/v1', '/query', '/api/query',
            ]
            for path in common_gql_paths:
                candidate = f"{self.base_url}{path}"
                if candidate not in graphql_candidates:
                    graphql_candidates.append(candidate)

            # Also probe any API backend host found in resolver methods
            if self.resolver:
                for val in list(self.resolver.methods.values())[:5]:
                    if val and isinstance(val, str) and val.startswith('http'):
                        try:
                            api_host = urllib.parse.urlparse(val)
                            base_parsed = urllib.parse.urlparse(self.base_url)
                            if (api_host.port != base_parsed.port
                                    and config.is_first_party(val, self.base_url)):
                                gql_base = f"{api_host.scheme}://{api_host.netloc}"
                                for path in common_gql_paths:
                                    candidate = f"{gql_base}{path}"
                                    if candidate not in graphql_candidates:
                                        graphql_candidates.append(candidate)
                        except Exception as _exc:
                            diagnostics.swallowed(__name__, _exc)

        print(f"  Found {len(graphql_candidates)} potential GraphQL endpoints")

        # Introspect each candidate
        for endpoint in graphql_candidates:
            self._introspect_endpoint(endpoint)

        return self.schemas

    def _looks_like_graphql(self, url):
        """Check if URL looks like a GraphQL endpoint"""
        graphql_patterns = [
            '/graphql', '/gql', '/api/graphql', '/v1/graphql',
            '/query', '/api/query', '/graphql/v1'
        ]
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in graphql_patterns)

    def _introspect_endpoint(self, endpoint):
        """Send introspection query to endpoint, and probe for persisted queries / APQ."""
        print(f"  [→] Introspecting: {endpoint}")

        try:
            response = self.session.post(
                endpoint,
                json={'query': self.introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    self._parse_schema(endpoint, schema)
                    print("  [✓] Successfully introspected!")
                    # T30: Try APQ / persisted query detection after successful introspection
                    self._probe_persisted_queries(endpoint)
                    return True

            # T30: Introspection disabled — probe for persisted queries anyway
            # Many prod GQL APIs block introspection but still serve persisted queries.
            if response.status_code in (400, 403, 200):
                self._probe_persisted_queries(endpoint)

        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

        return False

    def _probe_persisted_queries(self, endpoint):
        """
        T30: Probe for Automatic Persisted Queries (APQ) and query whitelists.

        Strategy:
          1. Send a known bad hash — if server returns PersistedQueryNotFound,
             APQ is enabled. Register the endpoint with a note.
          2. Probe /.well-known/apollo/persisted-queries (Apollo manifest).
          3. Look for __persisted_queries__ global in already-analyzed JS (static).
        """
        # 1. APQ probe — send a fake SHA-256 hash
        apq_probe = {
            'extensions': {
                'persistedQuery': {
                    'version': 1,
                    'sha256Hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                }
            },
            'operationName': None,
            'variables': {}
        }
        try:
            r = self.session.post(endpoint, json=apq_probe,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=6, verify=False)
            if r.status_code == 200:
                body = r.text
                if 'PersistedQueryNotFound' in body or 'persisted query not found' in body.lower():
                    # APQ confirmed: the server speaks GraphQL even if introspection is off
                    if endpoint not in self.apq_endpoints:
                        self.apq_endpoints.append(endpoint)
                    print(f"  [APQ] Automatic Persisted Queries confirmed on {endpoint}")
        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

        # 2. Apollo persisted query manifest
        base = endpoint.rsplit('/graphql', 1)[0] if '/graphql' in endpoint else endpoint.rsplit('/', 1)[0]
        manifest_paths = [
            f"{base}/.well-known/apollo/persisted-queries",
            f"{base}/persisted-queries.json",
            f"{base}/query-map.json",
            f"{base}/queryMap.json",
        ]
        for mpath in manifest_paths:
            try:
                r = self.session.get(mpath, timeout=5, verify=False)
                if r.status_code == 200:
                    try:
                        manifest = r.json()
                        count = 0
                        # manifest format: { "hash": "query body" } or { "operationName": "hash" }
                        for key, val in manifest.items():
                            if isinstance(val, str) and ('query' in val.lower() or 'mutation' in val.lower()):
                                op_m = re.search(r'\b(query|mutation|subscription)\s+(\w+)', val)
                                op_name = op_m.group(2) if op_m else key
                                op_type = op_m.group(1).upper() if op_m else 'GRAPHQL'
                                self.schemas.setdefault(endpoint, {'queries': [], 'mutations': [], 'subscriptions': [], 'types': []})
                                bucket = 'queries' if op_type == 'QUERY' else ('mutations' if op_type == 'MUTATION' else 'subscriptions')
                                self.schemas[endpoint][bucket].append({'name': op_name, 'description': f'persisted:{key[:16]}', 'args': []})
                                count += 1
                        if count:
                            print(f"  [APQ] {count} persisted operation(s) from manifest: {mpath}")
                    except Exception as _exc:
                        diagnostics.swallowed(__name__, _exc)
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

    def _parse_schema(self, endpoint, schema):
        """Parse GraphQL schema and extract all operations"""
        operations = {
            'queries': [],
            'mutations': [],
            'subscriptions': [],
            'types': []
        }

        # Extract all types
        for type_def in schema.get('types', []):
            if type_def['name'].startswith('__'):
                continue  # Skip introspection types

            type_name = type_def['name']
            type_kind = type_def['kind']

            if type_kind == 'OBJECT':
                fields = type_def.get('fields', [])

                # Check if this is Query type
                if schema.get('queryType', {}).get('name') == type_name:
                    for field in fields:
                        operations['queries'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })

                # Check if this is Mutation type
                elif schema.get('mutationType', {}).get('name') == type_name:
                    for field in fields:
                        operations['mutations'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })

                # Check if this is Subscription type
                elif schema.get('subscriptionType', {}).get('name') == type_name:
                    for field in fields:
                        operations['subscriptions'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })

                # Store all types
                operations['types'].append({
                    'name': type_name,
                    'kind': type_kind,
                    'fields': [f['name'] for f in fields] if fields else []
                })

        self.schemas[endpoint] = operations

        # Print summary
        print(f"    • Queries: {len(operations['queries'])}")
        print(f"    • Mutations: {len(operations['mutations'])}")
        print(f"    • Subscriptions: {len(operations['subscriptions'])}")
        print(f"    • Types: {len(operations['types'])}")
