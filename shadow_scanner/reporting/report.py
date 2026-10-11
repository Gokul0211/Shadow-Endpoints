"""Phase 4: merge, de-duplicate, filter and write the JSON report (+ console summary)."""
import json
import os
import re
import time
import urllib.parse
from collections import defaultdict

from shadow_scanner.config import PLAYWRIGHT_AVAILABLE, is_ignored_url
from shadow_scanner.core.scoring import BayesianConfidenceScorer
from shadow_scanner.reporting.excel import json_to_excel


def _extract_security_findings(results: list) -> list:
    """
    Identify security-relevant endpoints from the result pool.

    Categories:
      - admin_panel:        /admin, /internal, /private, /management
      - auth_endpoint:      /auth, /login, /token, /oauth, /sso
      - debug_endpoint:     /debug, /actuator, /health, /status, /_debug
      - staging_url:        staging/dev/test domains in resolved URLs
      - internal_ip:        RFC-1918 addresses in discovered URLs
      - graphql_exposed:    GraphQL endpoint without auth evidence
      - openapi_exposed:    OpenAPI/Swagger spec publicly accessible
      - websocket_endpoint: Any WebSocket connection
    """
    findings = []
    seen = set()

    _ADMIN_RE    = re.compile(r'/(?:admin|internal|private|management|backoffice|cp|controlpanel)(/|$)', re.I)
    _AUTH_RE     = re.compile(r'/(?:auth|login|token|oauth|sso|saml|signin|signout|logout)(/|$)', re.I)
    _DEBUG_RE    = re.compile(r'/(?:debug|actuator|trace|swagger|api-docs|redoc|graphiql|altair)(/|$)', re.I)
    _STAGING_RE  = re.compile(r'(?:staging|dev\.|develop|test\.|preprod|sandbox|qa\.)', re.I)
    _INTERNAL_IP = re.compile(r'https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)')

    for ep in results:
        url = ep.get('endpoint', '')
        if not url or url in seen:
            continue

        cat = None
        if _ADMIN_RE.search(url):
            cat = 'admin_panel'
        elif _AUTH_RE.search(url):
            cat = 'auth_endpoint'
        elif _DEBUG_RE.search(url):
            cat = 'debug_endpoint'
        elif _STAGING_RE.search(url):
            cat = 'staging_url'
        elif _INTERNAL_IP.search(url):
            cat = 'internal_ip_address'
        elif url.startswith(('ws://', 'wss://')):
            cat = 'websocket_endpoint'
        elif ep.get('classification') == 'GRAPHQL_API':
            cat = 'graphql_exposed'

        if cat:
            seen.add(url)
            findings.append({
                'url':            url,
                'method':         ep.get('method', 'GET'),
                'category':       cat,
                'confidence':     ep.get('confidence_score', 0),
                'source':         ep.get('source', ''),
                'provenance':     ep.get('origin', {}).get('provenance', []),
            })

    return findings


def _prepare_output_paths(filename, target_url):
    """Create output/<domain>/{json,excel,sourcemaps,backend}/ and return file paths."""
    # ── Build organized output directory structure ────────────────────────────
    # Derive domain slug from target URL for unique naming
    if target_url:
        _parsed = urllib.parse.urlparse(target_url)
        _domain_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', _parsed.netloc.lower()).strip('_')
    else:
        # Fallback: derive from filename
        _domain_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', os.path.basename(filename).rsplit('.', 1)[0])

    _timestamp = time.strftime("%Y%m%d_%H%M%S")
    _scan_id   = f"{_domain_slug}_{_timestamp}"

    # ── output/{domain}/json|excel|sourcemaps|backend ────────────────────────
    output_root    = os.path.join("output", _domain_slug)
    json_dir       = os.path.join(output_root, "json")
    excel_dir      = os.path.join(output_root, "excel")
    sourcemaps_dir = os.path.join(output_root, "sourcemaps")
    backend_dir    = os.path.join(output_root, "backend")
    for _d in [output_root, json_dir, excel_dir, sourcemaps_dir, backend_dir]:
        os.makedirs(_d, exist_ok=True)
    # Final file paths use scan_id so every run is non-destructive
    json_path  = os.path.join(json_dir,  f"{_scan_id}.json")
    excel_path = os.path.join(excel_dir, f"{_scan_id}.xlsx")
    return json_path, excel_path, output_root


def _materialize(analyzer, endpoints):
    """Report entries from the shared store: one per (URL, explicitly observed
    method), scored from all evidence. Runtime requests were added to the same
    store by Phase 3, so there is nothing left to merge."""
    if analyzer is not None and hasattr(analyzer, 'materialize'):
        return analyzer.materialize()
    return [dict(e) for e in endpoints]      # fallback: already-final entries


def _filter_endpoints(entries):
    """Final noise-removal pass over the merged endpoints."""
    # ⭐ ENHANCED: Final filtering pass — comprehensive noise removal
    pre_filter_count = len(entries)
    filtered_results = []


    _STATIC_EXTENSIONS = {
        '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.css', '.map',
        '.pdf', '.zip', '.tar', '.gz',
    }

    _GARBAGE_PATTERNS = ['//', '/../', '/./']

    for endpoint in entries:
        ep_url         = str(endpoint.get('endpoint', ''))
        ep_lower       = ep_url.lower()
        conf_score     = endpoint.get('confidence_score', 0)
        classification = endpoint.get('classification', '')
        is_vendor      = endpoint.get('origin', {}).get('is_vendor', False)
        tags           = endpoint.get('tags', [])

        # 1. Hard-blocked domains
        if is_ignored_url(ep_url):
            continue

        # 2. External schema tag
        if 'external_schema' in tags:
            continue

        # 3. Static asset extensions
        # FIX: WebSocket URLs and VERIFIED_API always pass through all filters
        _is_websocket = ep_url.startswith(('ws://', 'wss://'))
        _is_verified  = classification in ('VERIFIED_API', 'WEBSOCKET_ENDPOINT')

        try:
            path = ep_url.split('?')[0].split('#')[0]
            last = path.rsplit('/', 1)[-1]
            ext  = ('.' + last.rsplit('.', 1)[-1].lower()) if '.' in last else ''

            # Module Federation entry points are reported (they reveal remote apps)
            exempt_js = ext == '.js' and last.lower().startswith('remoteentry')

            if ext in _STATIC_EXTENSIONS and not exempt_js and not _is_websocket:
                continue
        except Exception:
            pass

        # 4. AST garbage patterns (bare //, /../0 etc.)
        if ep_url in ('//', '/../0', '/./', '/../') or (
            any(p in ep_url for p in _GARBAGE_PATTERNS) and
            not (ep_url.startswith('http://') or ep_url.startswith('https://')
                 or ep_url.startswith('wss://') or ep_url.startswith('ws://'))
        ):
            continue

        # 5. Library/noise low confidence
        if not _is_verified and conf_score < 40 and classification in ['LIBRARY_ARTIFACT', 'NOISE_CANDIDATE']:
            continue

        # 6. Vendor sources: raise threshold to 60
        if not _is_verified and is_vendor and conf_score < 60:
            continue

        # 7. External references — always drop
        if classification == 'EXTERNAL_REFERENCE':
            continue

        # 8. Component names (PascalCase single segment) masquerading as API paths
        # These are PascalCase single-segment paths with no API sub-path.
        try:
            _fp_path = urllib.parse.urlparse(ep_url).path
            _segs = [s for s in _fp_path.split('/') if s]
            if len(_segs) == 1 and _segs[0][0].isupper() and not any(
                ind in ep_lower for ind in ('/api', '/v1', '/v2', '/v3', '/auth', '/token')
            ):
                if 'frontend_route_nav' in tags or conf_score < 50:
                    continue
        except Exception:
            pass

        # 9. Pure SPA router paths emitted from ROUTER_NAV
        # as BACKEND_API with no dynamic evidence and no API path indicator.
        _nav_types = ('ROUTER_NAV_THIS', 'ROUTER_NAV', 'ROUTE_NAV_THIS',
                      'ROUTE_NAV', 'HISTORY_PUSH', 'REACT_NAVIGATE', 'HASH_ROUTE')
        if (endpoint.get('type') in _nav_types
                and classification != 'VERIFIED_API'
                and conf_score < 55
                and not any(ind in ep_lower for ind in
                            ('/api', '/v1', '/v2', '/v3', '/graphql', '/token',
                             '/login', '/auth', '/rest', '/service'))):
            continue

        filtered_results.append(endpoint)

    filtered_count = pre_filter_count - len(filtered_results)
    if filtered_count > 0:
        print(f"  [FILTER] Removed {filtered_count} low-confidence vendor/noise endpoints")
    return filtered_results


def _collect_security_findings(results, analyzer):
    """Security headers from SecurityHeaderExtractor + security-relevant endpoints."""
    # ── Security-relevant HTTP headers (client-set secrets + server-read trust) ─
    # Mined during static analysis by SecurityHeaderExtractor. HIGH/CRITICAL
    # findings are also surfaced in security_findings so a pentester sees them
    # next to the endpoints.
    security_headers = []
    _hdr_engine = getattr(analyzer, '_header_extractor', None)
    if _hdr_engine is not None:
        try:
            security_headers = _hdr_engine.results()
        except Exception:
            security_headers = []

    base_security_findings = _extract_security_findings(results)
    for _h in security_headers:
        if _h.get('severity') in ('HIGH', 'CRITICAL'):
            base_security_findings.append({
                'category':  'trusted_header' if _h['direction'] == 'server_read' else 'header_secret',
                'header':    _h['name'],
                'direction': _h['direction'],
                'severity':  _h['severity'],
                'note':      _h['note'],
                'source':    (_h.get('sources') or [''])[0],
            })
    return security_headers, base_security_findings


def _build_report(target_url, results, dynamic, interceptor, summary, source_maps,
                  base_security_findings, security_headers, ext_links,
                  sourcemap_engine, backend_findings):
    """Assemble the JSON report dict (endpoint / confidence_score format)."""
    report = {
        "scan_metadata": {
            "scanner":   "shadow_scanner (refactored)",
            "version":   "3.0.0-dev (Phase A)",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target":    target_url or "",
            "total_endpoints": len(results),
            "capabilities": [
                "static_ast_analysis", "angular_di_chain", "react_hooks",
                "vue_composition_api", "nuxt_server_routes", "trpc_procedures",
                "rtk_query", "swr_hooks", "react_query", "graphql_introspection",
                "graphql_gql_tag", "websocket_static", "websocket_dynamic",
                "service_worker_proxy", "indexeddb_extraction", "localstorage_mining",
                "openapi_swagger", "spring_actuator", "nextjs_api_routes",
                "source_map_recovery", "module_federation", "jsdoc_openapi",
                "interprocedural_analysis", "template_literal_resolution",
                "bayesian_scoring", "endpoint_provenance_graph", "apq_persisted_queries",
            ],
            "dynamic_phase": {
                "ran": PLAYWRIGHT_AVAILABLE,
                "endpoints_found": len(dynamic),
                "skip_reason": getattr(interceptor, 'skip_reason', None) if interceptor else (
                    'playwright_not_installed' if not PLAYWRIGHT_AVAILABLE else None
                ),
                "routes_visited": len(getattr(interceptor, 'seen_requests', set())) if interceptor else 0,
            },
            # ── Bayesian scorer configuration ─────────────────────────────
            "bayesian_scorer": {
                "prior":          BayesianConfidenceScorer.PRIOR,
                "tier_verified":  BayesianConfidenceScorer.TIER_VERIFIED,
                "tier_backend":   BayesianConfidenceScorer.TIER_BACKEND,
                "tier_low_conf":  BayesianConfidenceScorer.TIER_LOW_CONF,
                "n_signals":      len(BayesianConfidenceScorer.LR),
            },
        },
        "summary": dict(summary),
        # ── Statistical tier breakdown with Wilson 95% confidence intervals ──
        # Wilson CIs are computed on the assumption that all output endpoints
        # are true positives (no ground-truth labels available at scan time).
        # To compute precision CIs against a ground-truth set, call:
        #   BayesianConfidenceScorer.tier_statistics(results, ground_truth_tps)
        # and merge the returned dict into this report after evaluation.
        "tier_statistics": BayesianConfidenceScorer.tier_statistics(results),
        "source_maps_found": len(source_maps) if source_maps else 0,
        "endpoints": results,
        # ── SECURITY FINDINGS — high-value items surfaced ──────────────────────
        "security_findings": base_security_findings,
        # ── SECURITY-RELEVANT HTTP HEADERS — client-set secrets + server-read
        #    trust headers recovered from JS / leaked source (pentester intel) ──
        "security_headers": security_headers,
        # ── PROVENANCE SUMMARY — multi-source confirmed endpoints ─────────────
        "provenance_summary": {
            # independent confirmation = evidence from 2+ provenance categories
            "multi_source_confirmed": len([
                r for r in results
                if len(r.get('origin', {}).get('provenance', [])) > 1
            ]),
            "by_evidence_kind": {
                k: len([r for r in results if k in r.get('origin', {}).get('evidence_kinds', [])])
                for k in ('runtime', 'spec', 'probe', 'storage', 'static')
            },
            "probe_only": len([r for r in results if r.get('probe_only')]),
            "runtime_verified": len([
                r for r in results if r.get('classification') == 'VERIFIED_API'
            ]),
            "schema_discovered": len([
                r for r in results if r.get('classification') in ('GRAPHQL_API', 'OPENAPI_ENDPOINT')
            ]),
        },
        "external_links": ext_links.get_results() if ext_links else [],
        "discovered_source_maps": source_maps if source_maps else [],
        "ts_architecture_catalog": getattr(sourcemap_engine, 'ts_source_catalog', []) if sourcemap_engine else [],
        "ts_declaration_files":    getattr(sourcemap_engine, 'dts_files', []) if sourcemap_engine else [],
        "webpack_module_paths":    getattr(sourcemap_engine, 'webpack_module_paths', []) if sourcemap_engine else [],
        "backend_intelligence": {
            "total_artifacts": len(backend_findings) if backend_findings else 0,
            "total_endpoints_injected": sum(
                f.get("endpoints_extracted", 0) for f in (backend_findings or [])
            ),
            "swagger_specs":   [f for f in (backend_findings or []) if f.get("category") == "swagger"],
            "backend_maps":    [f for f in (backend_findings or []) if f.get("category") == "backend_map"],
            "actuator_routes": [f for f in (backend_findings or []) if f.get("category") == "actuator"],
            "all_findings": backend_findings or [],
        },
    }
    return report


def _print_scan_summary(report, results, summary, ext_links, json_path):
    """Console summary: tiers, auth breakdown, techniques, findings, headers, links."""
    print(f"\n{'='*70}\nSCAN COMPLETE\n{'='*70}")
    print(f"  Total Endpoints:          {len(results)}")
    print(f"  Backend API:              {summary['BACKEND_API']}")
    print(f"  Frontend Routes:          {summary['FRONTEND_ROUTE']}")
    print(f"  RPC Endpoints:            {summary['RPC_ENDPOINT']}")
    print(f"  Verified Runtime:         {summary['VERIFIED_API']}")
    print(f"  Vendor/Artifacts:         {summary['LIBRARY_ARTIFACT'] + summary['NOISE_CANDIDATE']}")
    if summary.get('GRAPHQL_API', 0) > 0:
        print(f"  GraphQL Operations:       {summary['GRAPHQL_API']}")
    if summary.get('WEBSOCKET_ENDPOINT', 0) > 0:
        print(f"  WebSocket Endpoints:      {summary['WEBSOCKET_ENDPOINT']}")
    if summary.get('SSE_ENDPOINT', 0) > 0:
        print(f"  Server-Sent Events (SSE): {summary['SSE_ENDPOINT']}")

    # ── Auth-required breakdown ──────────────────────────────────────────
    _auth_yes  = sum(1 for r in results if r.get('auth_required') is True)
    _auth_no   = sum(1 for r in results if r.get('auth_required') is False)
    _auth_unk  = len(results) - _auth_yes - _auth_no
    if _auth_yes or _auth_no:
        print("\n  Auth-Required Breakdown:")
        print(f"    Likely protected:    {_auth_yes}")
        print(f"    Likely public:       {_auth_no}")
        print(f"    Unknown:             {_auth_unk}")

    # ── Extraction technique breakdown ──────────────────────────────────────
    _tech_counts = {}
    for r in results:
        t = r.get('type', 'UNKNOWN')
        _tech_counts[t] = _tech_counts.get(t, 0) + 1
    _notable = {k: v for k, v in _tech_counts.items()
                if v > 0 and k in (
                    'TRPC_PROCEDURE', 'TRPC_NESTED_PROCEDURE',
                    'NUXT_SERVER_ROUTE', 'RTK_QUERY_ENDPOINT', 'SWR_HOOK',
                    'REACT_QUERY_HOOK', 'JSDOC_OPENAPI', 'JSDOC_OPENAPI_PATH',
                    'TEMPLATE_LITERAL_RESOLVED', 'INTERPROCEDURAL_FUNC',
                    'ENV_VAR_CONCAT', 'TANSTACK_ROUTE',
                )}
    if _notable:
        print("\n  Modern Framework Endpoints:")
        for tech, cnt in sorted(_notable.items(), key=lambda x: -x[1]):
            print(f"    {tech:<35} {cnt:>4}")

    # ── Provenance summary ─────────────────────────────────────────────────
    _multi_src = len([r for r in results if len(r.get('origin', {}).get('provenance', [])) > 1])
    _runtime   = len([r for r in results if r.get('classification') == 'VERIFIED_API'])
    if _multi_src or _runtime:
        print("\n  Provenance:")
        if _runtime:   print(f"    Runtime-verified:             {_runtime:>4}")
        if _multi_src: print(f"    Multi-source confirmed:       {_multi_src:>4}")

    # ── Security findings highlight ────────────────────────────────────────
    sec = report.get('security_findings', [])
    if sec:
        _by_cat = {}
        for f in sec:
            # endpoint findings carry 'url'; header findings carry 'header'.
            _label = f.get('url') or f.get('header') or '?'
            _by_cat.setdefault(f['category'], []).append(_label)
        print(f"\n  ⚠  Security-Relevant Findings: {len(sec)}")
        _cat_order = ['admin_panel', 'debug_endpoint', 'staging_url',
                      'internal_ip_address', 'auth_endpoint',
                      'graphql_exposed', 'websocket_endpoint',
                      'trusted_header', 'header_secret']
        for cat in _cat_order:
            if cat in _by_cat:
                print(f"    [{cat.upper()}] ({len(_by_cat[cat])})")
                for u in _by_cat[cat][:3]:
                    print(f"      • {u}")

    # ── Security-relevant HTTP headers summary ────────────────────────────────
    shdr = report.get('security_headers', [])
    if shdr:
        print(f"\n  🔑 Security-Relevant HTTP Headers: {len(shdr)}")
        for h in shdr[:12]:
            _dir = 'server-reads' if h['direction'] == 'server_read' else 'client-sets'
            _leak = '  [HARDCODED VALUE]' if h.get('leaked_value') else ''
            print(f"    [{h['severity']}] {h['name']} ({_dir}, {h['category']}){_leak}")
        if len(shdr) > 12:
            print(f"      ... and {len(shdr)-12} more")
    # Print external links summary
    if ext_links:
        el = ext_links.get_results()
        by_tier = {}
        for e in el:
            by_tier.setdefault(e['tier'], []).append(e['url'])
        if el:
            print(f"\n  External Links Found: {len(el)}")
            for tier in ['INTERNAL_SUBDOMAIN', 'SSO_AUTH', 'PARTNER_API', 'OTHER_EXTERNAL', 'CDN_ASSET', 'ANALYTICS']:
                if tier in by_tier:
                    print(f"    [{tier}] ({len(by_tier[tier])})")
                    for u in by_tier[tier][:5]:
                        print(f"      • {u}")
                    if len(by_tier[tier]) > 5:
                        print(f"      ... and {len(by_tier[tier])-5} more")
    print(f"\n[FILE] JSON saved: {json_path}")


def _print_backend_summary(backend_findings, output_root):
    """Console summary of Phase 1.8 exposed-API artifacts."""
    # ── Backend intelligence summary ──────────────────────────────────────────
    if backend_findings:
        high = [f for f in backend_findings if f.get('severity') == 'HIGH']
        total_injected = sum(f.get('endpoints_extracted', 0) for f in backend_findings)
        print(f"\n{'='*70}")
        print(f"  EXPOSED API INTELLIGENCE  ({len(backend_findings)} artifact(s) found)")
        print(f"{'='*70}")
        swagger_hits  = [f for f in high if f.get('category') == 'swagger']
        map_hits      = [f for f in high if f.get('category') == 'backend_map']
        actuator_hits = [f for f in high if f.get('category') == 'actuator']
        if swagger_hits:
            ep_count = sum(f.get('endpoints_extracted', 0) for f in swagger_hits)
            print(f"  OpenAPI/Swagger  : {len(swagger_hits):2d} spec(s)  -> {ep_count} endpoint(s) injected")
        if map_hits:
            ep_count = sum(f.get('endpoints_extracted', 0) for f in map_hits)
            print(f"  Backend maps     : {len(map_hits):2d} map(s)   -> {ep_count} endpoint(s) injected")
        if actuator_hits:
            ep_count = sum(f.get('endpoints_extracted', 0) for f in actuator_hits)
            print(f"  Actuator routes  : {len(actuator_hits):2d} hit(s)  -> {ep_count} endpoint(s) injected")
        if total_injected:
            print(f"\n  Total injected into endpoint pool: {total_injected}")
        print(f"\n  Local copies saved -> {os.path.join(output_root, 'backend_intel')}/")
        for f in high:
            ep = f.get('endpoints_extracted', 0)
            suffix = f"  (+{ep} endpoints)" if ep else ""
            print(f"    * [{f['category'].upper()}] {f['url']}{suffix}")
            if f.get('local_path'):
                print(f"      -> {f['local_path']}")


def _print_sourcemap_summary(sourcemap_engine):
    """Console summary of the source-map TS architecture catalog."""
    # ── TS architecture catalog summary ────────────────────────────────────────
    if sourcemap_engine:
        catalog = getattr(sourcemap_engine, 'ts_source_catalog', [])
        dts = getattr(sourcemap_engine, 'dts_files', [])
        wmp = getattr(sourcemap_engine, 'webpack_module_paths', [])
        if catalog or dts or wmp:
            print("\n[SOURCEMAP INTELLIGENCE]")
            print(f"  Original TS paths cataloged  : {len(catalog)}")
            print(f"  Paths with embedded code     : {len([e for e in catalog if e.get('has_content')])}")
            print(f"  .d.ts declaration files      : {len(dts)}")
            print(f"  Webpack module paths         : {len(wmp)}")
            if catalog:
                # Show sample of discovered TS paths
                sample = [e['clean_path'] for e in catalog[:8] if e.get('clean_path')]
                if sample:
                    print("  Sample paths:")
                    for p in sample:
                        print(f"    → {p}")


def save_report(static, dynamic, filename="results.json", source_maps=None, interceptor=None, ext_links=None, backend_findings=None, target_url=None, sourcemap_engine=None, analyzer=None):
    print("\n[PHASE 4] Generating Report with Confidence Tiering")

    json_path, excel_path, output_root = _prepare_output_paths(filename, target_url)
    # Expose paths for callers
    save_report._last_json_path  = json_path
    save_report._last_excel_path = excel_path

    entries = _materialize(analyzer, static)
    filtered_results = _filter_endpoints(entries)

    # Stable order: score, then URL, then method (ties no longer depend on
    # insertion order - S14)
    results = sorted(filtered_results,
                     key=lambda x: (-x.get('confidence_score', 0), x.get('endpoint', ''), x.get('method', '')))

    # Group by Category for Summary
    summary = defaultdict(int)
    for r in results:
        summary[r.get('classification', 'UNKNOWN')] += 1

    security_headers, base_security_findings = _collect_security_findings(results, analyzer)
    report = _build_report(target_url, results, dynamic, interceptor, summary, source_maps,
                           base_security_findings, security_headers, ext_links,
                           sourcemap_engine, backend_findings)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    _print_scan_summary(report, results, summary, ext_links, json_path)
    _print_backend_summary(backend_findings, output_root)
    _print_sourcemap_summary(sourcemap_engine)

    json_to_excel(json_path, excel_path)
