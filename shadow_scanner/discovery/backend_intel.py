"""Phase 1.8: exposed API intelligence (OpenAPI, Actuator, WSDL, backend maps, Next.js)."""
import hashlib
import json
import os
import re
import urllib.parse

from shadow_scanner import config
from shadow_scanner.config import is_first_party
from shadow_scanner.discovery.sourcemaps import run_sourcemap_harvest
# ==============================================================================
# EXPOSED API INTELLIGENCE HARVESTER
# Replaces the old BackendFileHunter with 3 academically rigorous categories:
#   1. Backend Node.js source maps   (dist/*.js.map  -> full server-side TS)
#   2. OpenAPI / Swagger specs       (openapi.json   -> parsed into endpoint pool)
#   3. Spring Actuator /mappings     (actuator/mappings -> parsed route dump)
#
# ALL three parsers feed discovered endpoints directly into analyzer.add_endpoint()
# rather than just saving files to disk.  This makes the contribution measurable
# by the precision/recall framework in the paper.
# ==============================================================================

class BackendFileHunter:
    """
    Probes for three classes of publicly accessible artifacts that expose
    machine-readable API structure, and parses each one directly into the
    endpoint pool via analyzer.add_endpoint().

    Categories:
      1. BACKEND SOURCE MAPS   -- Node.js dist/*.js.map files containing
                                  full server-side TypeScript source code.
                                  Passed through SourceMapEngine + analyzer pipeline.

      2. OPENAPI / SWAGGER     -- swagger.json / openapi.yaml / etc.
                                  Parsed: every `paths` entry becomes an endpoint
                                  with correct HTTP method and extracted parameters.
                                  Supports OpenAPI 2.0 (Swagger) and 3.x.

      3. SPRING ACTUATOR       -- /actuator/mappings endpoint on Spring Boot apps.
                                  Returns JSON route dump; every handler mapping
                                  becomes an endpoint with method and path pattern.
    """

    BACKEND_MAP_PATHS = [
        "dist/server.js.map", "dist/main.js.map", "dist/app.js.map",
        "dist/index.js.map",  "build/server.js.map", "build/main.js.map",
        "server.js.map",      "main.js.map",   "app.js.map",   "index.js.map",
        "api/dist/index.js.map",    "api/dist/main.js.map",
        "backend/dist/index.js.map","backend/dist/main.js.map",
        "out/server.js.map",
    ]

    SWAGGER_PATHS = [
        "swagger.json",          "openapi.json",
        "api-docs",              "api-docs.json",
        "api/docs",              "api/swagger.json",   "api/openapi.json",
        "v1/api-docs",           "v2/api-docs",        "v3/api-docs",
        "swagger/v1/swagger.json","swagger/v2/swagger.json",
        "docs/api.json",         "docs/swagger.json",
        "swagger.yaml",          "swagger.yml",
        "openapi.yaml",          "openapi.yml",
        "redoc",                 "scalar",
    ]

    ACTUATOR_MAPPINGS_PATHS = [
        "actuator/mappings",
        "manage/mappings",
        "management/mappings",
    ]

    WSDL_PATHS = [
        'api/soap?wsdl',
        'api/ws?wsdl',
        'services?wsdl',
        '?wsdl',
        'wsdl',
        'service.wsdl',
        'wsdl/service.wsdl',
        'api/wsdl',
        'soap/wsdl',
    ]
    # WSDL documents the client itself references (a literal such as
    # "/wsdl/HrService.wsdl" or "…?wsdl" in any analysed bundle) are probed too.
    _WSDL_LITERAL_RE = re.compile(r'''["'`]([^"'`\s]*(?:\.wsdl|\?wsdl)(?:\?[^"'`\s]*)?)["'`]''', re.IGNORECASE)

    def __init__(self, session, base_url, output_dir=None, analyzer=None):
        self.session    = session
        self.base_url   = base_url.rstrip('/')
        self.analyzer   = analyzer
        self.output_dir = output_dir or os.path.join("output", "backend_intel")
        os.makedirs(self.output_dir, exist_ok=True)
        self.findings = []
        self._spa_fingerprints = set()

    def hunt(self):
        """
        Run all three probe categories.
        Returns list of finding dicts (for save_report).
        Side-effect: calls self.analyzer.add_endpoint() for every discovered route.
        """
        print(f"\n{'='*70}")
        print("PHASE 1.8: EXPOSED API INTELLIGENCE HARVESTER")
        print(f"{'='*70}")

        self._init_spa_fingerprint()

        if not config.PROBING_ENABLED:
            # --no-probe: no well-known-path wordlists; only WSDL documents that
            # the target's own code references are fetched.
            print("  [--no-probe] well-known path probing disabled")
            _saved_paths, self.WSDL_PATHS = self.WSDL_PATHS, []
            print("\n  [SOAP WSDL] (referenced by the code only)")
            wsdl_eps = self._probe_wsdl()
            self.WSDL_PATHS = _saved_paths
            print(f"    -> {wsdl_eps} operation(s) extracted from WSDL")
            return self.findings

        # Collect additional API base URLs from the analyzer's resolver
        # (environment / config URLs). Only first-party hosts (same host or a
        # subdomain of the target's site) are probed - never third parties.
        _extra_base_urls = set()
        if self.analyzer and hasattr(self.analyzer, 'resolver'):
            resolver = self.analyzer.resolver
            for key in ('environmentApiUrl', 'apiUrl', 'baseUrl', 'serverUrl', 'apiEndpoint'):
                val = resolver.methods.get(key, '')
                if val and val.startswith('http'):
                    try:
                        p = urllib.parse.urlparse(val)
                        api_base = f"{p.scheme}://{p.netloc}"
                        if api_base != self.base_url:
                            _extra_base_urls.add(api_base)
                    except Exception:
                        pass
            # Also check resolved variables for full URLs with different hosts
            for var_name, var_data in resolver.variables.items():
                val = var_data.get('value', '') if isinstance(var_data, dict) else (var_data if isinstance(var_data, str) else '')
                if val and val.startswith('http') and '/api' in val:
                    try:
                        p = urllib.parse.urlparse(val)
                        api_base = f"{p.scheme}://{p.netloc}"
                        if api_base != self.base_url:
                            _extra_base_urls.add(api_base)
                    except Exception:
                        pass

        _extra_base_urls = {u for u in _extra_base_urls if is_first_party(u, self.base_url)}

        print("\n  [BACKEND SOURCE MAPS]")
        sm_found = self._probe_backend_source_maps()
        print(f"    -> {sm_found} map(s) found and fed into source-map pipeline")

        print("\n  [OPENAPI / SWAGGER]")
        oa_eps, oa_specs = self._probe_openapi()
        # RC2-FIX: Also probe extra API hosts for swagger specs
        for api_base in sorted(_extra_base_urls):
            saved_base = self.base_url
            self.base_url = api_base
            _extra_eps, _extra_specs = self._probe_openapi()
            oa_eps += _extra_eps
            oa_specs += _extra_specs
            self.base_url = saved_base
        print(f"    -> {oa_specs} spec(s) found, {oa_eps} endpoint(s) extracted")

        print("\n  [SPRING ACTUATOR /mappings]")
        ac_eps = self._probe_actuator_mappings()
        # RC2-FIX: Also probe extra API hosts for actuator
        # Some deployments proxy the actuator through the SPA's own origin, so
        # self.base_url is probed first (above), then every extra API host.
        _all_actuator_hosts = set(_extra_base_urls)
        # Also probe any host discovered from static analysis endpoints that
        # differs from self.base_url — catches cases where MFE bundles reference
        # different internal hosts not picked up by the resolver variable scan.
        if self.analyzer is not None:
            for ep in self.analyzer.endpoints:
                ep_url = ep.get('endpoint', '') or ep.get('url', '')
                if ep_url and ep_url.startswith('http'):
                    try:
                        p = urllib.parse.urlparse(ep_url)
                        candidate = f"{p.scheme}://{p.netloc}"
                        if candidate != self.base_url and is_first_party(candidate, self.base_url):
                            _all_actuator_hosts.add(candidate)
                    except Exception:
                        pass
        for api_base in sorted(_all_actuator_hosts):
            saved_base = self.base_url
            self.base_url = api_base
            ac_eps += self._probe_actuator_mappings()
            self.base_url = saved_base
        print(f"    -> {ac_eps} route(s) extracted from actuator")

        print("\n  [SOAP WSDL]")
        wsdl_eps = self._probe_wsdl()
        print(f"    -> {wsdl_eps} operation(s) extracted from WSDL")

        print("\n  [NEXT.JS API ROUTES]")
        nextjs_eps = self._probe_nextjs_api_routes()
        print(f"    -> {nextjs_eps} Next.js API route(s) discovered")

        total_eps = oa_eps + ac_eps + wsdl_eps + nextjs_eps
        print(f"\n  [TOTAL] {len(self.findings)} artifact(s) found | "
              f"{total_eps} endpoint(s) injected into pool")
        return self.findings

    def _probe_nextjs_api_routes(self):
        """
        T35/Next.js: Probe /_next/static and /pages/api/* route patterns.

        Next.js embeds its API route manifest at:
          /_next/static/<build_id>/pages-manifest.json
          /_next/server/pages-manifest.json

        Any key starting with /api/ is a real serverless API endpoint.
        Also probes well-known Next.js API route paths directly.
        Returns count of endpoints added.
        """
        count = 0
        base = self.base_url.rstrip('/')

        # 1. Try to fetch /_next/server/pages-manifest.json
        manifest_paths = [
            '/_next/server/pages-manifest.json',
            '/_next/server/app-paths-manifest.json',
            '/_next/static/development/pages-manifest.json',
        ]
        for mpath in manifest_paths:
            try:
                r = self.session.get(f"{base}{mpath}", timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        manifest = r.json()
                        for route_path in manifest.keys():
                            if route_path.startswith('/api/') or '/api/' in route_path:
                                full_url = f"{base}{route_path}"
                                if self.analyzer:
                                    self.analyzer.add_endpoint(
                                        full_url, 'GET', [], 'NEXTJS_API_ROUTE',
                                        f'pages-manifest:{mpath}', 'BACKEND_API', 88
                                    )
                                count += 1
                    except Exception:
                        pass
            except Exception:
                pass

        # 2. Probe common Next.js API paths directly
        nextjs_common = [
            '/api/auth', '/api/auth/[...nextauth]', '/api/auth/session',
            '/api/auth/signin', '/api/auth/signout', '/api/auth/csrf',
            '/api/auth/providers', '/api/trpc', '/api/graphql',
            '/api/users', '/api/user', '/api/me',
            '/api/health', '/api/status', '/api/ping',
        ]
        for path in nextjs_common:
            try:
                r = self.session.get(f"{base}{path}", timeout=5, verify=False)
                # 200/401/403/405 all indicate the route exists
                if r.status_code in (200, 401, 403, 405, 422):
                    # FP FIX: SPA catch-all nginx returns 200 for EVERY path with index.html.
                    # Check the SPA fingerprint before emitting — if the response matches the
                    # catch-all fingerprint it is NOT a real API route, it's the SPA shell page.
                    if self._matches_spa_fingerprint(r):
                        continue
                    # Also reject HTML responses that aren't catch-all (e.g. login page redirects)
                    _ct = r.headers.get('Content-Type', '').lower()
                    if 'html' in _ct and r.status_code == 200:
                        # Could still be a JSON API — only reject if content looks like HTML
                        _body_start = r.text.strip()[:50].lower()
                        if _body_start.startswith('<!') or _body_start.startswith('<html'):
                            continue
                    if self.analyzer:
                        self.analyzer.add_endpoint(
                            f"{base}{path}", 'GET', [], 'NEXTJS_API_PROBE',
                            'BackendFileHunter', 'BACKEND_API', 82
                        )
                    count += 1
            except Exception:
                pass

        return count

    def _referenced_wsdl(self):
        """{host: [path, …]} for WSDL URLs written in the analysed JS (absolute or
        relative to the target)."""
        out = {}
        contents = getattr(self.analyzer, 'js_contents', None) or {}
        for code in list(contents.values()):
            for m in self._WSDL_LITERAL_RE.finditer(code or ''):
                full = urllib.parse.urljoin(self.base_url + '/', m.group(1))
                pu = urllib.parse.urlparse(full)
                if not pu.scheme.startswith('http'):
                    continue
                host = f"{pu.scheme}://{pu.netloc}"
                path = pu.path.lstrip('/') + (('?' + pu.query) if pu.query else '')
                out.setdefault(host, [])
                if path not in out[host]:
                    out[host].append(path)
        return out

    def _probe_wsdl(self):
        """
        Probe for SOAP WSDL files on the SPA host, on API hosts found in the
        analysed configuration, and at WSDL URLs the client code references.

        Parses <operation name="..."> elements and emits each as POST bridgeBase/op.
        Returns count of endpoints added.
        """
        total_added = 0

        # Collect all hosts to probe: SPA host + any API backend host from resolver
        hosts_to_probe = [self.base_url.rstrip('/')]
        if self.analyzer and hasattr(self.analyzer, 'resolver'):
            for val in self.analyzer.resolver.methods.values():
                if val and isinstance(val, str) and val.startswith('http'):
                    try:
                        parsed = urllib.parse.urlparse(val)
                        api_host = f"{parsed.scheme}://{parsed.netloc}"
                        if api_host not in hosts_to_probe:
                            hosts_to_probe.append(api_host)
                    except Exception:
                        pass

        referenced = self._referenced_wsdl()
        for _h in referenced:
            if _h not in hosts_to_probe:
                hosts_to_probe.append(_h)

        for host in hosts_to_probe:
            # the well-known-path list only on first-party hosts; WSDL URLs the
            # code itself references on any host
            wordlist = self.WSDL_PATHS if is_first_party(host, self.base_url) else []
            for path in wordlist + [p for p in referenced.get(host, []) if p not in wordlist]:
                url = f"{host}/{path.lstrip('/')}"
                try:
                    r = self.session.get(url, timeout=8, verify=False,
                                         allow_redirects=False)
                    if r.status_code not in (200, 206):
                        continue
                    text = r.text
                    # Must contain WSDL markers
                    if not any(m in text for m in
                               ('definitions', 'wsdl:', 'portType', 'binding',
                                '<operation')):
                        continue
                    if self._matches_spa_fingerprint(r):
                        continue

                    print(f"    FOUND WSDL [HIGH]: {url}")

                    # Extract operation names — WSDL 1.1 and 2.0
                    op_names = re.findall(
                        r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']',
                        text, re.IGNORECASE
                    )
                    op_names = list(dict.fromkeys(op_names))  # preserve order, deduplicate

                    if not op_names:
                        continue

                    # Derive the bridge base from the WSDL soap:address location
                    # element (e.g. <soap:address location="http://localhost:4004/api/legacy/bridge"/>)
                    # rather than from the WSDL URL path itself (which may be /wsdl/legacy-service.wsdl).
                    # Fall back: check if the host has a known /api/legacy/bridge path pattern,
                    # then fall back to URL-without-?wsdl.
                    soap_base = None

                    # 1. Try soap:address location attribute
                    addr_m = re.search(
                        r'<(?:soap|soap12|http):address\s+location=["\']([^"\']+)["\']',
                        text, re.IGNORECASE
                    )
                    if addr_m:
                        soap_base = addr_m.group(1).rstrip('/')

                    # 2. Try to find bridge path already discovered by static analyzer
                    if not soap_base and self.analyzer is not None:
                        host = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
                        for ep in self.analyzer.endpoints:
                            ep_url = ep.get('endpoint', '') or ep.get('url', '')
                            if 'bridge' in ep_url.lower() and ep_url.startswith(host):
                                # Strip any trailing /{id} or /opname to get base
                                parts = ep_url.rstrip('/').rsplit('/', 1)
                                candidate = parts[0]
                                if 'bridge' in candidate.lower():
                                    soap_base = candidate
                                    break

                    # 3. Probe common bridge paths on the same host
                    if not soap_base:
                        host_base = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
                        for bridge_path in ['/api/bridge', '/api/soap/bridge', '/soap/bridge']:
                            probe_url = host_base + bridge_path
                            try:
                                pr = self.session.head(probe_url, timeout=4, verify=False, allow_redirects=False)
                                if pr.status_code in (200, 405, 404, 301, 302):
                                    soap_base = probe_url
                                    break
                            except Exception:
                                pass

                    # 4. Fall back: URL without ?wsdl suffix
                    if not soap_base:
                        soap_base = url.split('?')[0].rstrip('/')
                        # If soap_base ends in .wsdl it's a file path, go up one level
                        if soap_base.endswith('.wsdl'):
                            soap_base = soap_base.rsplit('/', 1)[0]

                    for op in op_names:
                        # Skip spurious matches from XML comments (e.g. "...")
                        if not re.match(r'^[A-Za-z][A-Za-z0-9_]{2,99}$', op):
                            continue

                        # Build the set of candidate base URLs to emit:
                        # The WSDL soap:address may reference a backend port while the
                        # SPA proxy exposes the same path on self.base_url's port.
                        # Emit both so the evaluator can match either.
                        soap_bases_to_emit = [soap_base]
                        if soap_base:
                            try:
                                sb_parsed = urllib.parse.urlparse(soap_base)
                                spa_parsed = urllib.parse.urlparse(self.base_url)
                                if sb_parsed.netloc != spa_parsed.netloc:
                                    # Remap the path onto the SPA host
                                    remapped = f"{spa_parsed.scheme}://{spa_parsed.netloc}{sb_parsed.path}"
                                    soap_bases_to_emit.append(remapped.rstrip('/'))
                            except Exception:
                                pass

                        for sbase in soap_bases_to_emit:
                            endpoint_url = f"{sbase}/{op}"

                            # FP FIX (WSDL cross-app contamination): The port sweep finds the
                            # WSDL on port 4004 for EVERY scan (App B, C, D, E all trigger it).
                            # But the SOAP bridge belongs only to the app whose static analysis
                            # contains the bridge path prefix (e.g. /api/legacy/bridge).
                            # Before emitting, verify the bridge base path appears somewhere in
                            # the target app's already-discovered endpoints or static strings.
                            # If it doesn't → this WSDL belongs to a different app → skip.
                            _bridge_path = soap_base.rstrip('/') if soap_base else ''
                            _bridge_rel = urllib.parse.urlparse(_bridge_path).path if _bridge_path else ''
                            _bridge_confirmed = False
                            if self.analyzer is not None and _bridge_rel:
                                for _existing_ep in self.analyzer.endpoints:
                                    _eu = (_existing_ep.get('endpoint') or
                                           _existing_ep.get('url') or '')
                                    if _bridge_rel.rstrip('/') in _eu:
                                        _bridge_confirmed = True
                                        break
                            else:
                                # No analyzer or no bridge path → can't verify → skip
                                _bridge_confirmed = False

                            if not _bridge_confirmed:
                                # Bridge path not seen in this app's static analysis → FP
                                continue

                            if self.analyzer is not None:
                                self.analyzer.add_endpoint(
                                    url            = endpoint_url,
                                    method         = 'POST',
                                    params         = [],
                                    type           = 'WSDL_OPERATION',
                                    source         = url,
                                    classification = 'BACKEND_API',
                                    confidence     = 85,
                                )
                                total_added += 1
                                print(f"       + SOAP op: {op} -> {endpoint_url}")

                    self.findings.append({
                        "category":            "wsdl",
                        "severity":            "HIGH",
                        "url":                 url,
                        "local_path":          None,
                        "description":         f"SOAP WSDL — {len(op_names)} operation(s)",
                        "endpoints_extracted": len(op_names),
                    })
                    # Stop at first valid WSDL per host
                    break

                except Exception:
                    continue

        return total_added

    # ---- Category 1: Backend Node.js source maps ----------------------------

    def _probe_backend_source_maps(self):
        """
        Probes well-known paths for server-side JS source maps (dist/*.js.map).
        When found, delegates to run_sourcemap_harvest() so the existing
        SourceMapEngine + analyzer pipeline handles TypeScript extraction --
        exactly the same code path as frontend source maps.
        """
        found = 0
        for path in self.BACKEND_MAP_PATHS:
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                r = self.session.get(url, timeout=8, verify=False,
                                     allow_redirects=False)
                if r.status_code not in (200, 206):
                    continue
                if self._matches_spa_fingerprint(r):
                    continue
                text = r.text[:2000]
                if '"sources"' not in text or '"mappings"' not in text:
                    continue

                local_path = self._save_file(r, path, "backend_map")
                self.findings.append({
                    "category":           "backend_map",
                    "severity":           "HIGH",
                    "url":                url,
                    "local_path":         os.path.abspath(local_path) if local_path else None,
                    "description":        "Server-side Node.js source map -- may contain "
                                          "full backend TypeScript (routes, DB calls, secrets)",
                    "content_length":     len(r.content),
                    "endpoints_extracted": 0,
                })
                print(f"    FOUND [HIGH]: {url}")

                if self.analyzer is not None:
                    before = len(self.analyzer.endpoints)
                    run_sourcemap_harvest(
                        self.session, self.base_url,
                        [url],
                        self.analyzer,
                        output_dir=os.path.join(self.output_dir, "backend_maps"),
                    )
                    delta = len(self.analyzer.endpoints) - before
                    self.findings[-1]["endpoints_extracted"] = delta
                    if delta:
                        print(f"       +{delta} server-side endpoint(s) extracted")
                found += 1

            except Exception:
                continue
        return found

    # ---- Category 2: OpenAPI / Swagger parser --------------------------------

    def _probe_openapi(self):
        """
        Fetches OpenAPI 2.x / 3.x specifications and parses every path entry
        directly into analyzer.add_endpoint().

        Returns (total_endpoints_added, specs_found).

        Parsing logic:
          - Supports JSON and YAML (falls back to regex for YAML to avoid dependency)
          - Iterates spec['paths'] -> each path key is the endpoint URL
          - For each path: iterates HTTP method keys (get/post/put/delete/patch/options)
          - Extracts query/body parameter names from parameters[] and requestBody
          - Assigns extraction_type='OPENAPI_SPEC' so Bayesian scorer treats it as
            ground truth (confidence=100, classification='VERIFIED_API')
        """
        total_eps   = 0
        specs_found = 0

        for path in self.SWAGGER_PATHS:
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                r = self.session.get(url, timeout=8, verify=False,
                                     allow_redirects=False)
                if r.status_code not in (200, 206):
                    continue
                if self._matches_spa_fingerprint(r):
                    continue

                spec = self._parse_openapi_response(r, url)
                if spec is None:
                    continue

                paths_obj = spec.get('paths')
                if not paths_obj or not isinstance(paths_obj, dict):
                    continue
                if not any(k in spec for k in ('swagger', 'openapi', 'info')):
                    continue

                specs_found += 1
                local_path = self._save_file(r, path, "swagger")

                # Determine base path (OpenAPI 2.x basePath vs 3.x servers[])
                base_path = ''
                if 'basePath' in spec:
                    base_path = spec['basePath'].rstrip('/')
                elif 'servers' in spec and spec['servers']:
                    first = spec['servers'][0].get('url', '')
                    try:
                        base_path = urllib.parse.urlparse(first).path.rstrip('/')
                    except Exception:
                        base_path = ''

                print(f"    FOUND [HIGH]: {url}")
                eps_this_spec = self._extract_openapi_endpoints(
                    spec, base_path, source=url
                )
                total_eps += eps_this_spec

                self.findings.append({
                    "category":            "swagger",
                    "severity":            "HIGH",
                    "url":                 url,
                    "local_path":          os.path.abspath(local_path) if local_path else None,
                    "description":         "OpenAPI/Swagger specification -- machine-readable "
                                           "ground truth for all API routes and parameters",
                    "content_length":      len(r.content),
                    "openapi_version":     spec.get('openapi') or spec.get('swagger', 'unknown'),
                    "endpoints_extracted": eps_this_spec,
                    "paths_in_spec":       len(paths_obj),
                })
                print(f"       Parsed {len(paths_obj)} path(s) -> "
                      f"+{eps_this_spec} endpoint(s) injected")

            except Exception:
                continue

        return total_eps, specs_found

    def _parse_openapi_response(self, response, url):
        """
        Parse the HTTP response into a Python dict representing the OpenAPI spec.
        Handles:
          - application/json  -> json.loads()
          - application/yaml / text/plain (.yaml/.yml) -> PyYAML if available,
            otherwise a regex-based minimal YAML parser for simple flat mappings
          - HTML page embedding a JSON spec (Redoc / Scalar) -> extracts
            the embedded JSON blob from the page source
        Returns dict or None on failure.
        """
        ct   = response.headers.get('Content-Type', '').lower()
        text = response.text

        # JSON
        if 'json' in ct or url.endswith('.json') or url.endswith('api-docs'):
            try:
                return json.loads(text)
            except Exception:
                pass

        # YAML
        if 'yaml' in ct or url.endswith(('.yaml', '.yml')):
            try:
                import yaml  # type: ignore
                return yaml.safe_load(text)
            except ImportError:
                pass
            except Exception:
                pass
            return self._minimal_yaml_paths_parse(text)

        # HTML page with embedded spec (Redoc, Scalar, SwaggerUI)
        if 'html' in ct:
            # Redoc: <redoc spec-url='...'> -- fetch referenced URL
            m = re.search(r"spec-url=['\"]([^'\"]+)['\"]", text, re.I)
            if m:
                spec_url = urllib.parse.urljoin(url, m.group(1))
                try:
                    r2 = self.session.get(spec_url, timeout=8, verify=False)
                    if r2.status_code == 200:
                        return json.loads(r2.text)
                except Exception:
                    pass

            # SwaggerUI / Scalar embedded JSON blobs
            for pat in (
                r'window\.__OPENAPI__\s*=\s*(\{.*?\});',
                r'swaggerDoc\s*=\s*(\{.*?\})',
                r'"spec"\s*:\s*(\{.*?"paths".*?\})',
            ):
                m = re.search(pat, text, re.S)
                if m:
                    try:
                        return json.loads(m.group(1))
                    except Exception:
                        pass

            # Last resort: find largest JSON blob in page that has "paths" key
            blobs = re.findall(r'(\{[^{}]{200,}\})', text, re.S)
            for blob in sorted(blobs, key=len, reverse=True)[:3]:
                try:
                    obj = json.loads(blob)
                    if 'paths' in obj:
                        return obj
                except Exception:
                    continue

        return None

    def _minimal_yaml_paths_parse(self, text):
        """
        Regex-based minimal YAML parser for environments without PyYAML.
        Extracts top-level swagger/openapi version key and the paths block.
        Returns a dict with at least {'paths': {'/route': {...}}}.
        Intentionally limited -- good enough to feed the endpoint parser.
        """
        result = {}
        for key in ('swagger', 'openapi'):
            m = re.search(rf'^{key}:\s*["\']?([^\n"\']+)["\']?\s*$', text, re.M)
            if m:
                result[key] = m.group(1).strip()

        paths_m = re.search(r'^paths:\s*\n((?:[ \t]+[^\n]*\n?)*)', text, re.M)
        if not paths_m:
            return result

        paths_block = paths_m.group(1)
        paths = {}
        # FIX Issue 15: Find all path entries and their line positions
        path_entries = list(re.finditer(r'^\s{2}(/[^\s:]+)\s*:', paths_block, re.M))
        method_pattern = re.compile(
            r'^\s{4}(get|post|put|delete|patch|head|options)\s*:',
            re.M | re.I
        )
        for idx, entry_m in enumerate(path_entries):
            # FIX Issue 15: Scope method search to THIS path entry's block only,
            # not the entire paths_block. Previously all methods from all paths
            # were assigned to every path.
            start = entry_m.end()
            end = path_entries[idx + 1].start() if idx + 1 < len(path_entries) else len(paths_block)
            entry_block = paths_block[start:end]
            methods = {}
            for mm in method_pattern.finditer(entry_block):
                methods[mm.group(1).lower()] = {}
            paths[entry_m.group(1)] = methods or {'get': {}}
        result['paths'] = paths
        return result

    def _extract_openapi_endpoints(self, spec, base_path, source):
        """
        Walk spec['paths'] and call analyzer.add_endpoint() for every
        (path, method) combination.

        Parameter extraction covers:
          - OpenAPI 2.x: parameters[] with 'in' == 'query', 'body', 'formData', 'path'
          - OpenAPI 3.x: parameters[] + requestBody -> content -> schema -> properties
          - $ref resolution for both parameter objects and schema objects

        Returns count of endpoints added.
        """
        if self.analyzer is None:
            return 0

        added       = 0
        paths       = spec.get('paths', {})
        HTTP_METHODS = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options'}

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            endpoint_path = base_path + path_key
            if not endpoint_path.startswith('/'):
                endpoint_path = '/' + endpoint_path

            # Collect path-level parameters (apply to all methods)
            path_level_params = []
            for p in path_item.get('parameters', []):
                p = self._resolve_ref(p, spec)
                if isinstance(p, dict) and p.get('name') and p.get('in') in (
                        'query', 'path', 'body', 'formData'):
                    path_level_params.append(p['name'])

            for method_key, operation in path_item.items():
                if method_key.lower() not in HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue

                method = method_key.upper()
                op_params = self._extract_operation_params(operation, spec)
                # Merge path-level and operation-level params, deduplicate
                all_params = list(dict.fromkeys(path_level_params + op_params))[:15]

                self.analyzer.add_endpoint(
                    url            = endpoint_path,
                    method         = method,
                    params         = all_params,
                    type           = 'OPENAPI_SPEC',
                    source         = source,
                    classification = 'VERIFIED_API',
                    confidence     = 100,
                    extra_fields   = {
                        'openapi_operation_id': operation.get('operationId', ''),
                        'openapi_summary':      operation.get('summary', ''),
                        'openapi_tags':         operation.get('tags', []),
                    }
                )
                added += 1

        return added

    def _extract_operation_params(self, operation, spec):
        """
        Extract parameter names from a single OpenAPI operation object.
        Handles both OpenAPI 2.x and 3.x parameter styles.
        Resolves $ref pointers within the same document.
        """
        params = []

        for p in operation.get('parameters', []):
            p = self._resolve_ref(p, spec)
            if not isinstance(p, dict):
                continue
            name = p.get('name', '')
            loc  = p.get('in', '')
            if name and loc in ('query', 'path', 'body', 'formData'):
                params.append(name)

        # OpenAPI 3.x requestBody
        req_body = self._resolve_ref(operation.get('requestBody', {}), spec)
        if isinstance(req_body, dict):
            content = req_body.get('content', {})
            for media_type in ('application/json',
                               'application/x-www-form-urlencoded',
                               'multipart/form-data'):
                mt = content.get(media_type, {})
                if not mt:
                    continue
                schema = self._resolve_ref(mt.get('schema', {}), spec)
                if isinstance(schema, dict):
                    params.extend(list(schema.get('properties', {}).keys())[:10])
                break

        return list(dict.fromkeys(params))[:15]

    def _resolve_ref(self, obj, spec):
        """
        Resolve a JSON $ref pointer within the same document.
        Only handles local #/... refs (not remote URLs).
        e.g. {'$ref': '#/components/schemas/User'} -> spec['components']['schemas']['User']
        """
        if not isinstance(obj, dict) or '$ref' not in obj:
            return obj
        ref = obj['$ref']
        if not ref.startswith('#/'):
            return obj
        parts = ref.lstrip('#/').split('/')
        node = spec
        try:
            for part in parts:
                part = part.replace('~1', '/').replace('~0', '~')
                node = node[part]
            return node
        except (KeyError, TypeError):
            return obj

    # ---- Category 3: Spring Actuator /mappings -------------------------------

    def _probe_actuator_mappings(self):
        """
        Fetches Spring Boot Actuator /actuator/mappings and parses every
        handler mapping into the endpoint pool.


        Spring Boot 2.x response structure:
          {
            "contexts": {
              "application": {
                "mappings": {
                  "dispatcherServlets": {
                    "dispatcherServlet": [
                      {
                        "handler": "...",
                        "predicate": "{GET [/api/users]}",
                        "details": {
                          "requestMappingConditions": {
                            "methods": ["GET"],
                            "patterns": ["/api/users"]
                          }
                        }
                      }
                    ]
                  }
                }
              }
            }
          }

        Spring Boot 1.x / flat-list style is also handled.
        Returns count of endpoints added across all actuator URLs.
        """
        total_added = 0

        for path in self.ACTUATOR_MAPPINGS_PATHS:
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                # Some SPAs serve actuator on the same origin and rely on
                # content negotiation to distinguish actuator requests from SPA requests.
                # Always request with Accept: application/json so Spring Boot returns JSON
                # instead of the SPA catch-all HTML.
                for accept_hdr in ('application/json', '*/*'):
                    r = self.session.get(url, timeout=8, verify=False,
                                         allow_redirects=False,
                                         headers={'Accept': accept_hdr})
                    if r.status_code not in (200, 206):
                        continue
                    if self._matches_spa_fingerprint(r):
                        continue
                    ct = r.headers.get('Content-Type', '').lower()
                    if 'html' in ct:
                        continue
                    # Check if it parses as JSON actuator payload
                    try:
                        data = json.loads(r.text)
                    except Exception:
                        continue
                    if not isinstance(data, dict):
                        continue
                    if not any(k in data for k in ('contexts', 'mappings', 'dispatcherServlets')):
                        continue
                    # Valid actuator response found — break out of accept_hdr loop
                    break
                else:
                    # No valid response from either Accept header — skip this path
                    continue

                print(f"    FOUND [HIGH]: {url}")

                # POST-EVAL FIX 8: Add the actuator base url as an endpoint itself
                if self.analyzer is not None:
                    self.analyzer.add_endpoint(
                        url            = url,
                        method         = 'GET',
                        params         = [],
                        type           = 'ACTUATOR_MAPPINGS_ROOT',
                        source         = url,
                        classification = 'BACKEND_API',
                        confidence     = 95,
                    )
                    total_added += 1


                local_path = self._save_file(r, path, "actuator")
                added = self._parse_actuator_mappings(data, source=url)
                total_added += added

                self.findings.append({
                    "category":            "actuator",
                    "severity":            "HIGH",
                    "url":                 url,
                    "local_path":          os.path.abspath(local_path) if local_path else None,
                    "description":         "Spring Boot Actuator /mappings -- server-side "
                                           "route dump equivalent to reading RouteConfig source",
                    "content_length":      len(r.content),
                    "endpoints_extracted": added,
                })
                print(f"       +{added} route(s) extracted from actuator")

            except Exception:
                continue

        return total_added

    def _parse_actuator_mappings(self, data, source):
        """
        Walk the actuator /mappings JSON and call add_endpoint() for every
        handler mapping entry.

        Handles:
          - Spring Boot 2.x: contexts -> <n> -> mappings -> dispatcherServlets -> list
          - Spring Boot 1.x: flat mappings dict keyed by predicate string
          - Predicate string fallback: parses "{GET [/api/users]}" format

        Returns count of endpoints added.
        """
        if self.analyzer is None:
            return 0

        added         = 0
        mappings_list = []

        # Spring Boot 2.x
        for ctx_name, ctx in data.get('contexts', {}).items():
            if not isinstance(ctx, dict):
                continue
            for servlet_name, servlet_list in (
                ctx.get('mappings', {}).get('dispatcherServlets', {}).items()
            ):
                if isinstance(servlet_list, list):
                    mappings_list.extend(servlet_list)

        # Spring Boot 1.x fallback
        if not mappings_list:
            raw = data.get('mappings', {})
            if isinstance(raw, list):
                mappings_list = raw
            elif isinstance(raw, dict):
                for key, val in raw.items():
                    if isinstance(val, list):
                        mappings_list.extend(val)
                    elif isinstance(val, dict):
                        mappings_list.append(val)

        for mapping in mappings_list:
            if not isinstance(mapping, dict):
                continue

            details  = mapping.get('details', {})
            rmc      = details.get('requestMappingConditions', {})
            patterns = rmc.get('patterns', []) or rmc.get('patternValues', [])
            methods  = list(rmc.get('methods', []))

            # Predicate string fallback: "{GET [/api/users], /api/v2/users}"
            if not patterns:
                predicate = mapping.get('predicate', '')
                for chunk in re.findall(r'\[([^\]]+)\]', predicate):
                    for part in chunk.split(','):
                        part = part.strip()
                        if part.startswith('/'):
                            patterns.append(part)
                        elif part.upper() in ('GET','POST','PUT','DELETE',
                                              'PATCH','HEAD','OPTIONS'):
                            methods.append(part.upper())
                if not patterns:
                    continue

            if not methods:
                methods = ['GET']

            for pattern in patterns:
                pattern = pattern.strip()
                if not pattern.startswith('/'):
                    continue
                for method in methods:
                    method = method.strip().upper()
                    if method not in ('GET','POST','PUT','DELETE',
                                      'PATCH','HEAD','OPTIONS'):
                        continue
                    # Prepend the origin of the actuator probe URL so that
                    # evaluate.py can match the full URL.  `source` is e.g.
                    # http://localhost:4001/actuator/mappings, so _api_origin
                    # becomes http://localhost:4001.
                    try:
                        _sp = urllib.parse.urlparse(source)
                        _api_origin = f"{_sp.scheme}://{_sp.netloc}"
                    except Exception:
                        _api_origin = self.base_url.rstrip('/')
                    full_url = f"{_api_origin}{pattern}"
                    # FP FIX (actuator cross-contamination): When the actuator is on a
                    # different port than the SPA (e.g. scanning 3002 but actuator at 4001),
                    # the extracted routes belong to the shared backend, not the target SPA.
                    # Tag them as ACTUATOR_ENDPOINT_CROSS_HOST at reduced confidence so they
                    # are visible in the report but don't count as target-app endpoints.
                    try:
                        _source_parsed = urllib.parse.urlparse(source)
                        _scan_base_parsed = urllib.parse.urlparse(self.base_url)
                        _is_cross_host = (_source_parsed.netloc != _scan_base_parsed.netloc)
                    except Exception:
                        _is_cross_host = False

                    if _is_cross_host:
                        # NOTE: kept distinct from the same-host tag below (rather than an
                        # identical 'ACTUATOR_ENDPOINT' string) on purpose — collapsing both
                        # into one type string would make this cross-host, reduced-confidence
                        # finding inherit the same-host tag's SCHEMA provenance weight (0.95
                        # vs the intended 0.40 UNKNOWN fallback), silently boosting its score
                        # and reintroducing the cross-application contamination this branch
                        # exists to suppress.
                        _emit_type = 'ACTUATOR_ENDPOINT_CROSS_HOST'
                        _emit_class = 'EXTERNAL_REFERENCE'
                        _emit_conf = 30
                    else:
                        _emit_type = 'ACTUATOR_ENDPOINT'
                        _emit_class = 'VERIFIED_API'
                        _emit_conf = 100

                    self.analyzer.add_endpoint(
                        url            = full_url,
                        method         = method,
                        params         = [],
                        type           = _emit_type,
                        source         = source,
                        classification = _emit_class,
                        confidence     = _emit_conf,
                    )
                    added += 1

        return added

    # ---- SPA fingerprint helpers (unchanged) ---------------------------------

    def _init_spa_fingerprint(self):
        # FIX Issue 16: Single hashlib import (removed unused _hashlib alias)
        import hashlib as _hh
        canary_paths = [
            "/__canary_probe_xyz_does_not_exist__",
            "/zzzz_nonexistent_path_abc123/",
        ]
        for cp in canary_paths:
            try:
                r = self.session.get(f"{self.base_url}{cp}", timeout=6,
                                     verify=False, allow_redirects=True)
                if r.status_code == 200 and len(r.content) > 0:
                    body      = r.content
                    full_hash = _hh.md5(body).hexdigest()
                    head_hash = _hh.md5(body[:512]).hexdigest()
                    self._spa_fingerprints.add((len(body), full_hash, head_hash))
            except Exception:
                pass
        if self._spa_fingerprints:
            sizes = [str(s) for s, _, _ in self._spa_fingerprints]
            print(f"  [SPA FINGERPRINT] Catch-all detected: sizes={sizes}")
        else:
            print("  [SPA FINGERPRINT] No catch-all detected")

    def _matches_spa_fingerprint(self, response):
        import hashlib as _hh
        if not self._spa_fingerprints:
            return False
        # RC5-FIX: JSON responses are NEVER SPA catch-all pages.
        # This prevents false-positives on actuator/mappings, swagger.json, etc.
        ct = response.headers.get("Content-Type", "").lower()
        if 'json' in ct or 'yaml' in ct or 'xml' in ct:
            return False
        body  = response.content
        blen  = len(body)
        bfull = _hh.md5(body).hexdigest()
        bhead = _hh.md5(body[:512]).hexdigest()
        for fp_len, fp_full, fp_head in self._spa_fingerprints:
            if blen == fp_len and bfull == fp_full:
                return True
            if abs(blen - fp_len) <= 5 and bhead == fp_head:
                return True
            if abs(blen - fp_len) <= 5:
                text = response.text[:1000].lower()
                if "text/html" in ct and any(
                    m in text for m in ("<!doctype html", "<base href=",
                                        "<app-root", "<router-outlet")
                ):
                    return True
        return False

    def _save_file(self, response, path, category):
        try:
            cat_dir = os.path.join(self.output_dir, category)
            os.makedirs(cat_dir, exist_ok=True)
            safe_name = re.sub(r'[<>:"|*?\\\/]', '_', path.lstrip('/'))
            if not safe_name:
                safe_name = hashlib.md5(response.url.encode()).hexdigest()
            local_path = os.path.join(cat_dir, safe_name)
            with open(local_path, 'wb') as f:
                f.write(response.content)
            return local_path
        except Exception:
            return None
