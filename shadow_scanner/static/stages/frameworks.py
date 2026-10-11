"""Framework route conventions (Next.js, tRPC, Nuxt, GraphQL tags, RTK Query...)."""
import re
class FrameworkPatternsMixin:
    """Framework-specific route conventions (Next.js, tRPC, Nuxt, GraphQL, RTK Query...)."""

    def _extract_nextjs_routes(self, code, source):
        """Next.js "// METHOD /api/..." route comments and pages/api file routes."""
        # ── Next.js API route comment extraction (e.g. /api/auth, /api/users) ─
        # Next.js /pages/api/*.ts files often have leading comments documenting routes:
        #   // POST /api/auth/login
        #   // GET /api/users/[id]
        # Extract these as endpoints — the file path itself is also an API route.
        _NEXTJS_COMMENT_RE = re.compile(
            r'//\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/api/[^\s\n]{3,200})',
            re.IGNORECASE | re.MULTILINE
        )
        for m in _NEXTJS_COMMENT_RE.finditer(code):
            method_str = m.group(1).upper()
            raw_path   = m.group(2).replace('[', '{').replace(']', '}')
            # Express/Next route comments use ':param' for path
            # params (e.g. "// DELETE /api/users/:id"). Normalize to the manifest's
            # '{param}' form so the URL matches; the method is already captured.
            raw_path   = re.sub(r':([A-Za-z_]\w*)', r'{\1}', raw_path)
            full_url   = self.normalizer.normalize(raw_path)
            self.process(full_url, method_str, m.start(), code, source, "NEXTJS_COMMENT_ROUTE", "BACKEND_API", 82)

        # Also infer the route from the source file name if it's a pages/api file
        if 'pages/api' in source.lower() or 'pages\\api' in source.lower():
            # e.g. source = "auth.ts" from /pages/api/auth.ts → /api/auth
            basename = re.sub(r'\.(ts|tsx|js|jsx)$', '', source.split('/')[-1].split('\\')[-1])
            if basename and basename not in ('index', '_app', '_document'):
                inferred = f'/api/{basename}'
                full_url = self.normalizer.normalize(inferred)
                self.process(full_url, 'GET', 0, code, source, "NEXTJS_FILE_ROUTE", "BACKEND_API", 78)

    def _extract_trpc_procedures(self, code, source):
        """tRPC router procedures -> /api/trpc/<name> and /api/trpc/<ns>.<name>."""
        # ── tRPC router procedure extraction ──────────────────────────────────
        # Catches:
        #   const appRouter = router({ getUser: procedure.query(...), createOrder: procedure.mutation(...) })
        #   publicProcedure.input(Schema).query(handler)
        #   t.router({ user: { get: t.procedure.query(handler) } })
        #
        # tRPC endpoints are accessed as /api/trpc/procedureName
        # Nested routers become /api/trpc/namespace.procedureName
        _trpc_base = '/api/trpc'
        # Try to find tRPC basePath if configured
        _trpc_base_m = re.search(
            r'(?:trpc|createTRPCNext|createTRPCReact)\s*\(\s*\{[^}]{0,300}'
            r'basePath\s*:\s*[\'"`]([^\'"`]{2,100})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        )
        if _trpc_base_m:
            _trpc_base = _trpc_base_m.group(1).rstrip('/')

        # Extract router structure: { procedureName: procedure.query|mutation|subscription }
        _trpc_flat_re = re.compile(
            r'([a-zA-Z_$][a-zA-Z0-9_$]{1,40})\s*:\s*'
            r'(?:publicProcedure|protectedProcedure|procedure|t\.procedure|[a-z]+Procedure)'
            # Handle nested parens: .input(z.object({...})) or .input(z.string())
            r'(?:\.[a-zA-Z]+\([^()]*(?:\([^()]*\)[^()]*)*\))*\.'
            r'(query|mutation|subscription)\s*\(',
            re.IGNORECASE
        )
        for m in _trpc_flat_re.finditer(code):
            proc_name = m.group(1)
            proc_type = m.group(2).lower()
            http_method = 'GET' if proc_type == 'query' else 'POST'
            trpc_path = f"{_trpc_base}/{proc_name}"
            full_url  = self.normalizer.normalize(trpc_path)
            self.process(full_url, http_method, m.start(), code, source,
                         "TRPC_PROCEDURE", "BACKEND_API", 85)

        # Nested namespace: router({ user: router({ get: procedure.query }) })
        # → /api/trpc/user.get
        # The nested router body may be multiline and contain closing braces,
        # so we use a bracket-depth approach instead of [^}]{0,500}
        _trpc_nested_re = re.compile(
            r'([a-zA-Z_$][a-zA-Z0-9_$]{1,40})\s*:\s*'
            r'(?:[a-zA-Z_$][a-zA-Z0-9_$.]{0,20}\.)?'     # optional prefix: t., trpc., router.
            r'(?:router|createRouter|createTRPCRouter)\s*\(\s*\{',
            re.IGNORECASE
        )
        for ns_m in _trpc_nested_re.finditer(code):
            namespace = ns_m.group(1)
            # Extract the body by counting braces from the opening {
            brace_start = ns_m.end() - 1
            depth = 0
            body_end = brace_start
            for i, ch in enumerate(code[brace_start:], start=brace_start):
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        body_end = i
                        break
            ns_body = code[brace_start + 1: body_end]
            for proc_m in _trpc_flat_re.finditer(ns_body):
                proc_name = proc_m.group(1)
                proc_type = proc_m.group(2).lower()
                http_method = 'GET' if proc_type == 'query' else 'POST'
                trpc_path = f"{_trpc_base}/{namespace}.{proc_name}"
                full_url  = self.normalizer.normalize(trpc_path)
                self.process(full_url, http_method, ns_m.start(), code, source,
                             "TRPC_NESTED_PROCEDURE", "BACKEND_API", 83)

    def _extract_nuxt_server_routes(self, code, source):
        """Nuxt 3 server/api/*.ts filesystem routes (defineEventHandler)."""
        # ── Nuxt server routes (defineEventHandler) ───────────────────────────
        # Nuxt 3 server routes live at server/api/*.ts
        # The file path determines the API route: server/api/users/index.get.ts → GET /api/users
        if 'defineEventHandler' in code or 'defineWebSocketHandler' in code:
            # Infer route from source file path
            if 'server/api' in source.lower() or 'server\\api' in source.lower():
                # Normalize path: server/api/users/[id].get.ts → /api/users/{id}
                src_lower = source.replace('\\', '/')
                idx = src_lower.find('server/api')
                if idx >= 0:
                    route_part = src_lower[idx + len('server/api'):]
                    # Remove extension and method suffix (.get, .post etc.)
                    route_part = re.sub(r'\.(get|post|put|delete|patch|head)\.[a-z]+$', '', route_part, flags=re.I)
                    route_part = re.sub(r'\.[a-z]+$', '', route_part)
                    # Replace [param] → {param}
                    route_part = re.sub(r'\[([^\]]+)\]', r'{\1}', route_part)
                    route_part = re.sub(r'/(index)?$', '', route_part)
                    if route_part:
                        full_url = self.normalizer.normalize('/api' + route_part)
                        # Infer method from filename
                        method_sfx = re.search(r'\.(get|post|put|delete|patch)\.', source, re.I)
                        method_str = method_sfx.group(1).upper() if method_sfx else 'GET'
                        self.process(full_url, method_str, 0, code, source,
                                     "NUXT_SERVER_ROUTE", "BACKEND_API", 90)

    def _extract_graphql_tag_operations(self, code, source):
        """gql`query Name {...}` client operations -> <graphql endpoint>#Name."""
        # ── gql tag GraphQL operation extraction ──────────────────────────────
        # Catches: const QUERY = gql`query GetUsers { ... }`
        # Complements live introspection with static client-side query discovery.
        _GQL_TAG_RE = re.compile(
            r'(?:gql|graphql|GraphQL\.tag|gql\.experimental)\s*`([^`]{10,2000})`',
            re.IGNORECASE | re.DOTALL
        )
        for gql_m in _GQL_TAG_RE.finditer(code):
            gql_body = gql_m.group(1)
            # Extract operation type and name
            op_m = re.search(
                r'\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)',
                gql_body
            )
            if not op_m:
                continue
            op_type = op_m.group(1).lower()
            op_name = op_m.group(2)

            # Find the GraphQL endpoint URL (look nearby or use known base)
            gql_endpoint = (
                self.resolver.global_scope.get('GRAPHQL_ENDPOINT')
                or self.resolver.global_scope.get('GQL_URL')
                or self.resolver.global_scope.get('GRAPHQL_URL')
                or (self.base_url.rstrip('/') + '/graphql')
            )

            # Emit as  /graphql#OperationName
            op_url   = f"{gql_endpoint}#{op_name}"
            gql_http = 'GRAPHQL'
            # GQL_TAG_* (client code) is kept distinct from GRAPHQL_* (server
            # introspection): the two are different kinds of evidence.
            gql_type_map = {'query': 'GQL_TAG_QUERY', 'mutation': 'GQL_TAG_MUTATION',
                            'subscription': 'GQL_TAG_SUBSCRIPTION'}
            self.add_endpoint(
                op_url, gql_http, [], gql_type_map.get(op_type, 'GQL_TAG_QUERY'),
                source, 'GRAPHQL_API', 88
            )

    def _extract_tanstack_routes(self, code, source):
        """Tanstack Router / React Router route paths that are API paths."""
        # ── Tanstack Router / React Router v6 path patterns ───────────────────
        # Catches: new Route({ path: '/api/settings/$id', component: X })
        #          <Route path="/api/users/:id" element={<Users />} />
        #          createRoute({ path: '/api/dashboard' })
        _TANSTACK_ROUTE_RE = re.compile(
            r'(?:new\s+Route|createRoute|Route)\s*\(\s*\{[^}]{0,300}'
            r'path\s*:\s*[\'"`]([^\'"`]{3,200})[\'"`]',
            re.IGNORECASE | re.DOTALL
        )
        for rt_m in _TANSTACK_ROUTE_RE.finditer(code):
            raw_path = rt_m.group(1)
            # Normalize $id → {id} (Tanstack uses $ prefix)
            norm_path = re.sub(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}', raw_path)
            # Only emit API paths
            if not (norm_path.startswith('/api') or '/api/' in norm_path):
                continue
            full_url = self.normalizer.normalize(norm_path)
            self.process(full_url, 'GET', rt_m.start(), code, source,
                         "TANSTACK_ROUTE", "BACKEND_API", 78)

    def _extract_jsdoc_openapi(self, code, source):
        """Inline @openapi / @swagger JSDoc path annotations."""
        # ── G9: JSDoc @openapi / @swagger annotation extraction ──────────────
        # Catches inline OpenAPI specs in comments:
        #   * @openapi
        #   * /api/users:
        #   *   get:
        #   *     summary: Get users
        _JSDOC_OPENAPI_RE = re.compile(
            r'@(?:openapi|swagger)\s*\n'
            r'(?:\s*\*\s*.*\n)*?'
            r'(?:\s*\*\s*(/[^\s:]+):\s*\n'
            r'(?:\s*\*\s*\n)*'
            r'\s*\*\s*(get|post|put|delete|patch|head|options):)',
            re.IGNORECASE | re.MULTILINE
        )
        for m in _JSDOC_OPENAPI_RE.finditer(code):
            path    = m.group(1)
            method  = m.group(2).upper()
            full_url = self.normalizer.normalize(path)
            self.process(full_url, method, m.start(), code, source, "JSDOC_OPENAPI", "BACKEND_API", 88)

        # Simpler line-by-line @openapi path scanner (catches multiline blocks)
        _in_openapi = False
        for line in code.splitlines():
            line_s = line.strip().lstrip('* ')
            if '@openapi' in line_s or '@swagger' in line_s:
                _in_openapi = True
                continue
            if _in_openapi:
                # Path line: starts with /
                path_m = re.match(r'^(/[a-zA-Z0-9/_\-{}.]+):\s*$', line_s)
                if path_m:
                    _current_path = path_m.group(1)
                # Method line under a path
                method_m = re.match(r'^(get|post|put|delete|patch|head|options):\s*$', line_s, re.I)
                if method_m and '_current_path' in dir():
                    full_url = self.normalizer.normalize(_current_path)
                    self.add_endpoint(full_url, method_m.group(1).upper(), [], 'JSDOC_OPENAPI_PATH',
                                      source, 'BACKEND_API', 88)
                # End of block (empty line or new top-level comment)
                if line_s == '' and not line.startswith(' *'):
                    _in_openapi = False

    def _extract_rtk_query_endpoints(self, code, source):
        """RTK Query createApi endpoint builders under fetchBaseQuery({baseUrl})."""
        # ── G10: RTK Query createApi endpoint builder ──────────────────────
        # Catches:
        #   createApi({ baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
        #     endpoints: (builder) => ({
        #       getUser: builder.query({ query: (id) => `users/${id}` }),
        #       createOrder: builder.mutation({ query: () => ({ url: 'orders', method: 'POST' }) }),
        #     })
        #   })
        _rtk_base_re = re.compile(
            r'fetchBaseQuery\s*\(\s*\{[^}]*baseUrl\s*:\s*[\'"`]([^\'"`]{2,100})[\'"`]',
            re.IGNORECASE
        )
        for rtk_m in _rtk_base_re.finditer(code):
            rtk_base = rtk_m.group(1).rstrip('/')
            # Find the endpoints block that follows
            endpoints_start = code.find('endpoints:', rtk_m.start())
            if endpoints_start == -1:
                continue
            # Scan up to 3000 chars ahead for builder.query/mutation({ query: ... })
            block = code[endpoints_start: endpoints_start + 3000]
            # Pattern A: query: (arg) => `path/${arg}` or 'path'
            for ep_m in re.finditer(
                r'builder\.(query|mutation)\s*\(\s*\{[^}]*?query\s*:\s*'
                r'(?:\([^)]*\)\s*=>\s*)?[\'"`]([^\'"`\s]{2,100})[\'"`]',
                block, re.IGNORECASE | re.DOTALL
            ):
                op_type  = ep_m.group(1)
                ep_path  = ep_m.group(2)
                http_m   = 'GET' if op_type == 'query' else 'POST'
                norm_path = re.sub(r'\$\{[^}]+\}', '/{param}', ep_path)
                full_url  = self.normalizer.normalize(rtk_base + '/' + norm_path.lstrip('/'))
                self.process(full_url, http_m, rtk_m.start(), code, source,
                             "RTK_QUERY_ENDPOINT", "BACKEND_API", 87)
            # Pattern B: query: (arg) => ({ url: 'path', method: 'DELETE' })
            for ep_m in re.finditer(
                r'builder\.(query|mutation)\s*\(\s*\{[^}]*?query\s*:\s*'
                r'(?:\([^)]*\)\s*=>\s*)?\(\s*\{[^}]*?url\s*:\s*[\'"`]([^\'"`\s]{2,100})[\'"`]'
                r'[^}]*?(?:method\s*:\s*[\'"`]([A-Z]+)[\'"`])?',
                block, re.IGNORECASE | re.DOTALL
            ):
                ep_path  = ep_m.group(2)
                http_m   = ep_m.group(3) or ('GET' if ep_m.group(1) == 'query' else 'POST')
                norm_path = re.sub(r'\$\{[^}]+\}', '/{param}', ep_path)
                full_url  = self.normalizer.normalize(rtk_base + '/' + norm_path.lstrip('/'))
                self.process(full_url, http_m.upper(), rtk_m.start(), code, source,
                             "RTK_QUERY_ENDPOINT", "BACKEND_API", 87)

    def _extract_query_hooks(self, code, source):
        """React Query useQuery/useMutation, SWR and Apollo mutation URLs."""
        # ── React Query useQuery/useMutation hooks ────────────────────────────
        # Catches: useQuery({ queryKey: ['users'], queryFn: () => fetch('/api/users') })
        #          useMutation({ mutationFn: (d) => axios.post('/api/orders', d) })
        for rq_m in re.finditer(
            r'use(?:Query|InfiniteQuery|Mutation)\s*\(\s*\{[^}]{0,400}'
            r'(?:query|mutation)Fn\s*:\s*(?:async\s*)?(?:\([^)]*\)\s*=>|function[^{]*\{)[^}]{0,200}'
            r'(?:fetch|axios\.[a-z]+)\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            raw_path = rq_m.group(1)
            full_url = self.normalizer.normalize(raw_path)
            method   = 'POST' if 'mutation' in rq_m.group(0).lower() else 'GET'
            self.process(full_url, method, rq_m.start(), code, source,
                         "REACT_QUERY_HOOK", "BACKEND_API", 85)

        # ── G10b: SWR useSWR / useSWRMutation hooks ──────────────────────────
        # Catches: useSWR('/api/users', fetcher)
        #          useSWRMutation('/api/orders', poster)
        for swr_m in re.finditer(
            r'useSWR(?:Mutation|Infinite)?\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            raw_path = swr_m.group(1)
            full_url = self.normalizer.normalize(raw_path)
            method   = 'POST' if 'Mutation' in swr_m.group(0) else 'GET'
            self.process(full_url, method, swr_m.start(), code, source,
                         "SWR_HOOK", "BACKEND_API", 85)

        # ── G10c: Apollo useQuery / useMutation (GraphQL client) ──────────────
        # Catches: useQuery(GET_USERS, { variables: { id } })
        # Apollo queries are already caught via GraphQL introspection — this
        # catches the REST-like mutation paths Apollo sends to non-GraphQL backends.
        for apollo_m in re.finditer(
            r'useMutation\s*\([^,)]+,\s*\{[^}]{0,300}variables\s*:\s*\{[^}]{0,200}'
            r'url\s*:\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE | re.DOTALL
        ):
            full_url = self.normalizer.normalize(apollo_m.group(1))
            self.process(full_url, 'POST', apollo_m.start(), code, source,
                         "APOLLO_MUTATION_URL", "BACKEND_API", 80)
