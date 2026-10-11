"""
The scan pipeline - every phase in execution order.

    run_scan()
      Phase 1     phase1_discovery           HTML crawl, JS/JSON bundles, federation
                  prepare_output_dirs        output/<domain>/...
      Phase 1.5   phase1_5_sourcemaps        Next.js hidden chunks + source maps
      Phase 2     phase2_static_analysis     EnhancedStaticAnalyzer.scan()
      Phase 1.55  phase1_55_subapp_index_pages
      Phase 1.6   phase1_6_bundle_discovery  webpack chunk maps + sub-app bundles
      Phase 1.75  phase1_75_service_workers
      Phase 1.8   phase1_8_backend_intel     OpenAPI / Actuator / WSDL / Next.js
      Phase 1.85  phase1_85_external_js      Module Federation remotes
      Phase 3     phase3_dynamic             Playwright feedback loop
      Phase 1.5b  phase1_5b_phase3_sourcemaps
      Phase 4/5   report (JSON + Excel)

(The phase numbers are historical - they are the labels used in the paper and
in the console output, which is why 1.55 etc. run after Phase 2.)

One endpoint store: analyzer.endpoints (filtered in place, indexed by URL).
Every phase adds evidence to it through analyzer.add_endpoint(); Phase 3 adds
its observed requests to it too. `static_endpoints` below is the same list
object, kept only as a name for readability - nothing copies or extends it.
Each phase sets analyzer.current_phase, which is stored on every evidence item.
"""
import os
import re
import shutil
import time
import urllib.parse

from shadow_scanner.config import PLAYWRIGHT_AVAILABLE
from shadow_scanner.discovery.backend_intel import BackendFileHunter
from shadow_scanner.discovery.chunks import WebpackChunkHarvester, _discover_nextjs_chunks
from shadow_scanner.discovery.external_links import ExternalLinkExtractor
from shadow_scanner.discovery.federation import EnhancedFederationHunter
from shadow_scanner.discovery.service_worker import ServiceWorkerAnalyzer
from shadow_scanner.discovery.sourcemaps import run_sourcemap_harvest
from shadow_scanner.discovery.subapps import (
    _discover_subapp_bundles_postanalysis,
    _discover_subapp_index_pages,
)
from shadow_scanner.dynamic.interceptor import DynamicInterceptor
from shadow_scanner.reporting.report import save_report
from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer


def phase1_discovery(session, target):
    """Phase 1: crawl HTML, discover JS/JSON bundles (shared ExternalLinkExtractor)."""
    # Phase 1: Discovery
    # External link extractor — shared across all phases
    ext_links = ExternalLinkExtractor(target)

    hunter = EnhancedFederationHunter(session, target)
    hunter.ext_link_extractor = ext_links   # Phase 1 hook
    js_files, json_files = hunter.run()

    # DEBUG CHECK: Warn if no JS files found
    if len(js_files) == 0:
        print("\n" + "!"*70)
        print("WARNING: No JavaScript files were found in Phase 1!")
        print("!"*70)
        print("\nPossible causes:")
        print("  1. The site is a pure SPA that renders <script> tags dynamically")
        print("  2. The site blocked the scraper (WAF/Cloudflare/403)")
        print("  3. The URL points to a directory listing, not an HTML page")
        print("  4. The site requires authentication cookies")

        if PLAYWRIGHT_AVAILABLE:
            print("\n[*] Playwright is available - continuing to Phase 3 for dynamic discovery")
        else:
            print("\n[!] Playwright not installed. Install it for better SPA support:")
            print("    pip install playwright")
            print("    python -m playwright install chromium")

        print("\nContinuing scan with limited data...\n")
    return ext_links, hunter, js_files, json_files


def prepare_output_dirs(target):
    """Create output/<domain>/{sourcemaps,backend} and wipe stale extracted sources."""
    # ── domain-scoped output dirs ──────────────────────────────────────────
    _tgt_parsed  = urllib.parse.urlparse(target)
    domain_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', _tgt_parsed.netloc.lower()).strip('_')
    _output_root = os.path.join("output", domain_slug)
    sourcemap_dir      = os.path.join(_output_root, "sourcemaps")
    backend_dir = os.path.join(_output_root, "backend")
    for _d in [_output_root, sourcemap_dir, backend_dir]:
        os.makedirs(_d, exist_ok=True)

    # ⭐ FIX 1: Clean stale extracted files before new scan
    # Prevents cross-contamination from prior runs on different targets.
    _extracted_dir = os.path.join(sourcemap_dir, "extracted")
    if os.path.isdir(_extracted_dir):
        shutil.rmtree(_extracted_dir)
        print(f"[CLEANUP] Removed stale extracted files from {_extracted_dir}")
    os.makedirs(_extracted_dir, exist_ok=True)
    return domain_slug, sourcemap_dir, backend_dir


def phase1_5_sourcemaps(session, target, js_files, analyzer, sourcemap_dir):
    """Phase 1.5: Next.js hidden chunks + source-map harvest fed into the analyzer."""
    # PHASE 1.5a: Next.js chunk discovery (build manifest + runtime chunk map)
    # Discovers API route and resolver bundles not linked from HTML.
    # These contain source maps with SPA-local GraphQL URLs and resolver names.
    analyzer.current_phase = '1.5'
    _nextjs_extra = _discover_nextjs_chunks(session, target, js_files)
    if _nextjs_extra:
        js_files = sorted(set(js_files) | set(_nextjs_extra))
        print(f"  [NEXT.JS CHUNKS] +{len(_nextjs_extra)} hidden chunk(s) added to harvest")

    # Run source map harvest (non-intrusive)
    _, found_maps = run_sourcemap_harvest(session, target, js_files, analyzer,
                                                        output_dir=sourcemap_dir)
    return js_files, found_maps


def phase2_static_analysis(analyzer, js_files, json_files):
    """Phase 2: EnhancedStaticAnalyzer.scan() over every discovered bundle."""
    # Phase 2: Static Analysis
    # analyzer already created above, just run scan
    analyzer.current_phase = '2'
    static_endpoints = analyzer.scan(js_files, json_files)

    if len(static_endpoints) == 0 and len(js_files) > 0:
        print("\n[!] WARNING: Found JS files but extracted 0 endpoints")
        print("[!] The JavaScript might be heavily obfuscated or use dynamic imports")
    return static_endpoints


def phase1_55_subapp_index_pages(session, target, analyzer, js_files, static_endpoints, found_maps, sourcemap_dir):
    """Phase 1.55: probe sub-app index pages (ui_*, app_* ...) for more bundles (2 rounds)."""
    # ── PHASE 1.55: SUB-APP INDEX PAGE DISCOVERY ─────────────────────
    # Scan fetched JS content for sub-app base paths (e.g. ui_rc_permit,
    # ui_isolation) and probe those paths as HTML index pages to extract
    # their own JS bundles.  These sub-apps are independent Angular/React
    # applications deployed at separate base paths on the same origin.
    analyzer.current_phase = '1.55'
    _subapp_js = _discover_subapp_index_pages(
        session, target, analyzer, set(js_files)
    )
    if _subapp_js:
        js_files = sorted(set(js_files) | set(_subapp_js))
        # Analyze the raw JS content of discovered sub-app bundles
        print(f"[PHASE 1.55] Analyzing {len(_subapp_js)} sub-app bundle(s)...")
        _snap155 = len(analyzer.endpoints)
        analyzer.scan(_subapp_js, [])
        _new_155 = len(analyzer.endpoints) - _snap155
        if _new_155:
            print(f"[PHASE 1.55] +{_new_155} endpoint(s) from sub-app JS bundles")
        # Harvest source maps from sub-app bundles
        _, maps_155 = run_sourcemap_harvest(
            session, target, _subapp_js, analyzer, output_dir=sourcemap_dir
        )
        if maps_155:
            found_maps = sorted(set(found_maps or []) | set(maps_155))

        # ── RECURSIVE PASS: sub-app bundles may reference MORE sub-apps ──
        # e.g. ui_rc_permit/main.js (9.4MB) references ui_isolation,
        # ui_rc_archival which are separate Angular apps with their own JS.
        _subapp_js_r2 = _discover_subapp_index_pages(
            session, target, analyzer, set(js_files)
        )
        if _subapp_js_r2:
            js_files = sorted(set(js_files) | set(_subapp_js_r2))
            print(f"[PHASE 1.55] Recursive pass: {len(_subapp_js_r2)} more bundle(s)...")
            _snap155r = len(analyzer.endpoints)
            analyzer.scan(_subapp_js_r2, [])
            _new_r2 = len(analyzer.endpoints) - _snap155r
            if _new_r2:
                print(f"[PHASE 1.55] +{_new_r2} endpoint(s) from recursive sub-app discovery")
            _, maps_r2 = run_sourcemap_harvest(
                session, target, _subapp_js_r2, analyzer, output_dir=sourcemap_dir
            )
            if maps_r2:
                found_maps = sorted(set(found_maps or []) | set(maps_r2))
    return js_files, found_maps


def phase1_6_bundle_discovery(session, target, analyzer, js_files, static_endpoints, found_maps, sourcemap_dir):
    """Phase 1.6: webpack/Vite chunk maps + post-analysis sub-app bundle discovery."""
    # ── PHASE 1.6: DETERMINISTIC BUNDLE DISCOVERY ───────────────────────
    # Step A: WebpackChunkHarvester — reads chunk maps from runtime bundles
    #   deterministically, replacing fragile route-heuristic navigation.
    # Step B: Legacy _discover_subapp_bundles_postanalysis as fallback for
    #   micro-frontends that use custom loading (not webpack chunk maps).
    analyzer.current_phase = '1.6'
    _chunk_harvester = WebpackChunkHarvester(session, target)
    _wp_chunks = _chunk_harvester.harvest(js_files, known_urls=set(js_files))
    if _wp_chunks:
        js_files = sorted(set(js_files) | set(_wp_chunks))
        print(f"[PHASE 1.6a] Webpack chunk harvester: +{len(_wp_chunks)} bundle(s)")
    _new_subapp_js = sorted(set(
        _wp_chunks
        + _discover_subapp_bundles_postanalysis(
            session, target, static_endpoints, set(js_files)
        )
    ))
    if _new_subapp_js:
        print(f"\n[PHASE 1.6] Sub-app discovery: {len(_new_subapp_js)} new bundle(s) found")
        js_files = sorted(set(js_files) | set(_new_subapp_js))

        # 1.6a: Analyze raw JS bundles (catches hardcoded string literals
        #        in scripts bundles even when sourcesContent is null/empty)
        print("[PHASE 1.6] Analyzing raw JS content of sub-app bundles...")
        _snap16a = len(analyzer.endpoints)
        analyzer.scan(_new_subapp_js, [])
        if len(analyzer.endpoints) > _snap16a:
            print(f"[PHASE 1.6] +{len(analyzer.endpoints) - _snap16a} endpoint(s) from sub-app raw JS")

        # 1.6b: Harvest source maps (catches TypeScript service patterns
        #        in sourcesContent when the map has embedded source code)
        print("[PHASE 1.6] Harvesting source maps for sub-app bundles...")
        _snap16b = len(analyzer.endpoints)
        _, extra_maps16 = run_sourcemap_harvest(session, target, _new_subapp_js, analyzer, output_dir=sourcemap_dir)
        if len(analyzer.endpoints) > _snap16b:
            print(f"[PHASE 1.6] +{len(analyzer.endpoints) - _snap16b} endpoint(s) from sub-app source maps")
        if extra_maps16:
            found_maps = sorted(set(found_maps or []) | set(extra_maps16))
    return js_files, found_maps


def phase1_75_service_workers(session, target, hunter, analyzer):
    """Phase 1.75: service / web worker scripts."""
    # ── PHASE 1.75: SERVICE WORKER ANALYSIS ──────────────────────────────
    # Runs after static analysis so analyze_code_from_dynamic() has full
    # variable resolver context, but before dynamic phase so SW-discovered
    # endpoints feed into Phase 3 route prioritisation.
    analyzer.current_phase = '1.75'
    sw_analyzer = ServiceWorkerAnalyzer(session, target)
    sw_urls = sw_analyzer.discover_and_analyze(
        html        = hunter.raw_html,
        js_contents = getattr(analyzer, 'js_contents', {}),
        analyzer    = analyzer,
    )
    if sw_urls:
        print("  [SW] Service workers contributed to endpoint pool")


def phase1_8_backend_intel(session, target, backend_dir, analyzer):
    """Phase 1.8: exposed API artifacts (OpenAPI, Actuator, WSDL, backend maps, Next.js)."""
    # ── PHASE 1.8: BACKEND FILE HUNTER ───────────────────────────────────
    # Probe for exposed config, secret, source, and API spec files.
    # Completely passive — no fuzzing, only checks well-known paths.
    analyzer.current_phase = '1.8'
    backend_hunter = BackendFileHunter(session, target, output_dir=backend_dir, analyzer=analyzer)
    backend_findings = backend_hunter.hunt()
    return backend_findings


def phase1_85_external_js(session, target, analyzer, js_files, ext_links, static_endpoints, found_maps, sourcemap_dir):
    """Phase 1.85: Module Federation remoteEntry.js + sibling main.js bundles."""
    # ── PHASE 1.85: EXTERNAL JS CRAWL (RC4-FIX) ─────────────────────────
    # remoteEntry.js files from Module Federation appear in external_links
    # as PARTNER_API tier but are never fetched or analyzed. Fetch .js files
    # on the target's host or its sibling subdomains and analyse them.

    # Extract ALL federation remotes from the shell bundle, including same-origin
    # path-based remotes like "admin@https://app.example.com/admin/remoteEntry.js"
    # which never appear in external_links because they share the target's origin.
    # Pattern: "name@http://host:port/path/remoteEntry.js" inside
    # __webpack_require__.federation.runtime.remotes = {...}
    analyzer.current_phase = '1.85'
    _fed_remote_urls = set()
    _fed_re = re.compile(r'["\']?\w+["\']?\s*:\s*["\'][\w]+@(https?://[^"\']+remoteEntry\.js)["\']')
    for _jf in sorted(set(js_files)):
        try:
            _jf_content = ''
            _r = session.get(_jf, timeout=10, verify=False)
            if _r.status_code == 200:
                _jf_content = _r.text
            for _m in _fed_re.finditer(_jf_content):
                _fed_remote_urls.add(_m.group(1))
        except Exception:
            continue

    _ext_js_urls = []
    _seen_ext = set(js_files)
    # Add federation remote URLs (including same-netloc co-hosted ones)
    for _fu in sorted(_fed_remote_urls):
        if _fu not in _seen_ext:
            _ext_js_urls.append(_fu)
            _seen_ext.add(_fu)
    # Add other first-party JS from external_links: same host (any port) or a
    # subdomain of the target's parent domain (cdn.example.com for app.example.com)
    _t_host = (urllib.parse.urlparse(target).hostname or '').lower()
    _t_labels = _t_host.split('.')
    _t_parent = ('.'.join(_t_labels[-2:]) if len(_t_labels) >= 2
                 and not re.fullmatch(r'[\d.]+', _t_host) else _t_host)
    for _el in ext_links.get_results():
        _eu = _el.get('url', '')
        if not _eu.endswith('.js'):
            continue
        try:
            _eh = (urllib.parse.urlparse(_eu).hostname or '').lower()
            if _eh == _t_host or _eh == _t_parent or _eh.endswith('.' + _t_parent):
                if _eu not in _seen_ext:
                    _ext_js_urls.append(_eu)
                    _seen_ext.add(_eu)
        except Exception:
            continue

    if _ext_js_urls:
        print(f"\n[PHASE 1.85] External JS crawl: {len(_ext_js_urls)} remote JS file(s) from external_links")
        _snap_ext = len(analyzer.endpoints)
        # Remote main.js bundles are never analysed via their source map by
        # the recursive main.js fetch below runs raw analyze_code() on the minified
        # text, but never fetches main.js.map — so the same TS-aware / object-literal
        # / string-concatenation extraction that finds config values and array-assembled
        # URLs in the PRIMARY bundle (via run_sourcemap_harvest below) never runs on
        # recursively-discovered remotes. Collect them here and harvest afterward,
        # mirroring PHASE 1.5b's already-working pattern for Phase-3-discovered bundles.
        _recursive_main_js_urls = set()
        for _ext_url in _ext_js_urls:
            try:
                r = session.get(_ext_url, timeout=15, verify=False)
                if r.status_code != 200:
                    continue
                ct = r.headers.get('content-type', '')
                if 'html' in ct.lower() or r.text.strip().startswith('<'):
                    continue
                code = r.text
                if len(code) < 100:
                    continue
                analyzer.analyze_code_from_dynamic(code, _ext_url)
                js_files.append(_ext_url)
                # Report the remoteEntry.js URL itself (it reveals a remote app).
                analyzer.add_endpoint(
                    _ext_url, 'GET', [], 'MODULE_FEDERATION_REMOTE_ENTRY',
                    'ExternalJSCrawl', 'BACKEND_API', 80
                )
                print(f"    \u2713 {_ext_url.split('/')[-1]} ({len(code):,} bytes)")

                # remoteEntry.js is a tiny loader stub — the actual
                # module code (with API endpoints in __webpack_modules__) lives in main.js
                # beside it. Follow import('./main.js') references and run the FULL
                # analyze_code() pipeline (Pattern E, Pattern 2b, EXTERNAL_SUBDOMAIN_LITERAL).
                _main_js_candidates = set()
                for _imp_m in re.finditer(
                    # import("./main.js") or import(publicPath + "main.js")
                    r'import\s*\(\s*(?:[\w.$]+\s*\+\s*)?["\']((?:\./)?[\w./-]+\.js)["\']',
                    code
                ):
                    _rel = _imp_m.group(1).lstrip('./')
                    _base = _ext_url.rsplit('/', 1)[0]
                    _main_js_candidates.add(f"{_base}/{_rel}")
                # Also try ./main.js as a heuristic for all remoteEntry.js siblings
                _base_dir = _ext_url.rsplit('/', 1)[0]
                _main_js_candidates.add(f"{_base_dir}/main.js")
                for _mjs_url in sorted(_main_js_candidates):
                    if _mjs_url in set(js_files):
                        continue
                    try:
                        _mr = session.get(_mjs_url, timeout=15, verify=False)
                        if _mr.status_code != 200:
                            continue
                        _mct = _mr.headers.get('content-type', '')
                        if 'html' in _mct.lower() or _mr.text.strip().startswith('<'):
                            continue
                        _mcode = _mr.text
                        if len(_mcode) < 100:
                            continue
                        # Full pipeline — catches Pattern E, EXTERNAL_SUBDOMAIN_LITERAL, etc.
                        analyzer.analyze_code(_mcode, _mjs_url)
                        js_files.append(_mjs_url)
                        _recursive_main_js_urls.add(_mjs_url)
                        print(f"    \u2713 {_mjs_url.split('/')[-1]} from {_ext_url.split('/')[-2]}/ ({len(_mcode):,} bytes)")
                    except Exception:
                        pass
            except Exception:
                pass
        _new_ext = len(analyzer.endpoints) - _snap_ext
        if _new_ext:
            print(f"[PHASE 1.85] +{_new_ext} endpoint(s) from external JS bundles")
        # Also harvest source maps from external JS
        _, _ext_maps = run_sourcemap_harvest(session, target, _ext_js_urls, analyzer, output_dir=sourcemap_dir)
        if _ext_maps:
            found_maps = sorted(set(found_maps or []) | set(_ext_maps))

        # Harvest source maps for the recursively-discovered
        # main.js files too (remoteEntry.js is only ever a loader stub — the actual
        # module code, and its source map, lives in the sibling main.js).
        if _recursive_main_js_urls:
            print(f"[PHASE 1.85] Source map harvest for {len(_recursive_main_js_urls)} "
                  "recursively-discovered remote bundle(s)...")
            _snap_recur = len(analyzer.endpoints)
            _, _recur_maps = run_sourcemap_harvest(
                session, target, sorted(_recursive_main_js_urls), analyzer, output_dir=sourcemap_dir
            )
            if len(analyzer.endpoints) > _snap_recur:
                print(f"[PHASE 1.85] +{len(analyzer.endpoints) - _snap_recur} endpoint(s) from recursive remote bundle source maps")
            if _recur_maps:
                found_maps = sorted(set(found_maps or []) | set(_recur_maps))
    return found_maps


def phase3_dynamic(target, analyzer, cookies, args, auth_headers, ext_links, static_endpoints):
    """Phase 3: Playwright dynamic discovery with the static-analyzer feedback loop."""
    # Phase 3: Dynamic Interception with Feedback Loop
    interceptor = DynamicInterceptor(
        target,
        analyzer,  # Pass analyzer for feedback loop
        cookies,
        max_routes=args.max_routes,
        max_depth=args.max_depth,
        auth_headers=auth_headers,
    )
    interceptor._ext_link_extractor = ext_links   # Phase 3 hook
    analyzer.current_phase = '3'
    # run() records every observed request as runtime evidence in the store
    dynamic_endpoints = interceptor.run(analyzer.endpoints)
    return interceptor, dynamic_endpoints


def phase1_5b_phase3_sourcemaps(session, target, analyzer, interceptor, js_files, static_endpoints, found_maps, sourcemap_dir):
    """Phase 1.5b: source maps for bundles first seen during Phase 3."""
    # ── PHASE 1.5b: SOURCE MAP HARVEST FOR PHASE-3-DISCOVERED BUNDLES ────
    # Playwright intercepts bundles (e.g. ui_rc_permit/main.d2968.js) not
    # in Phase 1 js_files. Phase 1.5 already ran, so their .map files were
    # never fetched. Do a second pass now using the analyzer's tracked set.
    phase3_js = getattr(interceptor, 'analyzed_js_files', set())
    phase1_js = set(js_files)
    analyzer.current_phase = '1.5b'
    new_js_from_phase3 = sorted(u for u in phase3_js if u not in phase1_js and u.endswith('.js'))
    if new_js_from_phase3:
        print(f"\n[PHASE 1.5b] Source map harvest for {len(new_js_from_phase3)} Phase-3-only JS bundle(s)...")
        _snap15b = len(analyzer.endpoints)
        _, extra_maps_b = run_sourcemap_harvest(session, target, new_js_from_phase3, analyzer, output_dir=sourcemap_dir)
        if len(analyzer.endpoints) > _snap15b:
            print(f"[PHASE 1.5b] +{len(analyzer.endpoints) - _snap15b} endpoint(s) from Phase-3 bundle source maps")
        if extra_maps_b:
            found_maps = sorted(set(found_maps or []) | set(extra_maps_b))
    return found_maps


def _promote_external_links(session, json_files, ext_links, analyzer):
    """Feed JSON configs to the link extractor, then promote same-org API links to endpoints."""
    # Feed JSON configs into external link extractor before saving
    for jf in sorted(set(json_files)):
        try:
            r = session.get(jf, timeout=8, verify=False)
            if r.status_code == 200:
                try:
                    ext_links.feed_json(r.json(), source=jf)
                except Exception:
                    ext_links.feed_js(r.text, source=jf)
        except Exception:
            pass

    # RC5-FIX: Promote INTERNAL_SUBDOMAIN and SSO_AUTH entries from ExternalLinkExtractor
    # into the main endpoint pool. These are same-org subdomains (e.g. rcowgis.ril.com)
    # carrying real API paths. Previously they were classified correctly but silently
    # dropped from the endpoint pool — only appearing in the external_links report section.
    analyzer.current_phase = '4-links'
    _PROMOTABLE_TIERS = {'INTERNAL_SUBDOMAIN', 'SSO_AUTH'}
    _NOISE_PATH_RE = re.compile(
        r'(?:\.(js|css|png|jpg|svg|woff|ttf|eot|ico|gif|map)$'
        r'|/[a-z]{1,2}$'          # single/double-char paths (but NOT /v1 /v2 etc.)
        r'|/[0-9]+$)',             # purely numeric segment
        re.IGNORECASE
    )
    # FP8 FIX: /v1, /v2, /v3 … /v99 are valid API version segments that
    # the single/double-char pattern above incorrectly blocks.
    _VERSION_SUFFIX_RE = re.compile(r'/v\d{1,2}$', re.IGNORECASE)
    for _el in ext_links.get_results():
        if _el.get('tier') not in _PROMOTABLE_TIERS:
            continue
        _eu = _el.get('url', '')
        if not _eu:
            continue
        # Block noise paths but exempt versioned suffixes like /v1, /v2
        if _NOISE_PATH_RE.search(_eu) and not _VERSION_SUFFIX_RE.search(_eu):
            continue
        # Only promote URLs that carry a non-trivial path segment
        try:
            _ep = urllib.parse.urlparse(_eu).path
            if not _ep or len(_ep.strip('/')) < 3:
                continue
        except Exception:
            continue
        analyzer.add_endpoint(
            _eu, 'GET', [], 'EXTERNAL_SUBDOMAIN_API',
            _el.get('source', 'ExternalLinkExtractor'),
            'BACKEND_API', 75
        )


def _write_report(args, static_endpoints, dynamic_endpoints, found_maps, interceptor,
                  ext_links, backend_findings, target, analyzer, domain_slug):
    """Phase 4/5: JSON + Excel report and the output-location banner."""
    output_file = args.output or 'results.json'   # only used by save_report as a naming fallback

    save_report(analyzer.endpoints, dynamic_endpoints, output_file,
                source_maps=found_maps, interceptor=interceptor,
                ext_links=ext_links, backend_findings=backend_findings,
                target_url=target,
                sourcemap_engine=analyzer._sourcemap_engine if hasattr(analyzer, '_sourcemap_engine') else None,
                analyzer=analyzer)

    # Print absolute path to results
    _json_out  = getattr(save_report, '_last_json_path',  output_file)
    _excel_out = getattr(save_report, '_last_excel_path', None)
    print(f"\n[RESULTS] JSON  → {os.path.abspath(_json_out)}")
    # --output FILE: also save a copy of the JSON report there (e.g. for evaluate.py)
    if args.output:
        _copy_dir = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(_copy_dir, exist_ok=True)
        shutil.copyfile(_json_out, args.output)
        print(f"[RESULTS] Copy  → {os.path.abspath(args.output)}")
    if _excel_out and os.path.exists(_excel_out):
        print(f"[RESULTS] Excel → {os.path.abspath(_excel_out)}")
    _res_root = os.path.abspath(os.path.join("output", domain_slug))
    print(f"[RESULTS] Dir   → {_res_root}/")
    print("          ├── json/")
    print("          ├── excel/")
    print("          ├── sourcemaps/")
    print("          └── backend/")


def _print_troubleshooting(static_endpoints, dynamic_endpoints):
    """Hints printed when the scan found nothing."""
    # Final summary
    total = len(static_endpoints) + len(dynamic_endpoints)
    if total == 0:
        print("\n" + "="*70)
        print("NO ENDPOINTS FOUND - TROUBLESHOOTING")
        print("="*70)
        print("\nThe scan completed but found 0 endpoints. This usually means:")
        print("  1. The target blocks automated scrapers (check for 403 errors above)")
        print("  2. The site is a pure SPA with no initial JavaScript in HTML")
        print("  3. All endpoints are dynamically loaded and Playwright is not installed")
        print("\nSolutions:")
        print("  • Add authentication cookies if the site requires login")
        print("  • Install Playwright: pip install playwright && python -m playwright install chromium")
        print("  • Try a different target URL (e.g., a specific page instead of root)")
        print("  • Check if the site has a WAF/Cloudflare protection")


def run_scan(args, target, session, cookies, auth_headers, rate_limiter, scan_cache):
    """Run every scan phase in order and write the report."""
    start_time = time.time()

    print("\n" + "="*70)
    print("STARTING ENHANCED SCAN")
    print("="*70)

    ext_links, hunter, js_files, json_files = phase1_discovery(session, target)
    domain_slug, sourcemap_dir, backend_dir = prepare_output_dirs(target)

    # ⭐ PHASE 1.5: SOURCE MAP HARVESTING (NEW - PURE ADDITION)
    # Create analyzer instance BEFORE sourcemap harvest
    analyzer = EnhancedStaticAnalyzer(session, target,
                                      rate_limiter=rate_limiter,
                                      scan_cache=scan_cache,
                                      workers=args.workers,
                                      fetch_timeout=args.timeout)
    # Relative references resolve against the page's <base href>, like a browser
    _base_m = re.search(r'<base\s[^>]*href=["\']([^"\']+)["\']', hunter.raw_html or '', re.I)
    if _base_m:
        analyzer.normalizer.set_base_href(_base_m.group(1))

    js_files, found_maps = phase1_5_sourcemaps(session, target, js_files, analyzer, sourcemap_dir)
    static_endpoints = phase2_static_analysis(analyzer, js_files, json_files)
    js_files, found_maps = phase1_55_subapp_index_pages(
        session, target, analyzer, js_files, static_endpoints, found_maps, sourcemap_dir)
    js_files, found_maps = phase1_6_bundle_discovery(
        session, target, analyzer, js_files, static_endpoints, found_maps, sourcemap_dir)
    phase1_75_service_workers(session, target, hunter, analyzer)
    backend_findings = phase1_8_backend_intel(session, target, backend_dir, analyzer)
    found_maps = phase1_85_external_js(
        session, target, analyzer, js_files, ext_links, static_endpoints, found_maps, sourcemap_dir)
    interceptor, dynamic_endpoints = phase3_dynamic(
        target, analyzer, cookies, args, auth_headers, ext_links, static_endpoints)
    found_maps = phase1_5b_phase3_sourcemaps(
        session, target, analyzer, interceptor, js_files, static_endpoints, found_maps, sourcemap_dir)

    elapsed = time.time() - start_time
    print(f"\n[TIME] Total scan time: {elapsed:.1f}s")

    # Persist cache so next run can resume
    if scan_cache:
        scan_cache.save()
        stats = scan_cache.stats()
        print(f"[Cache] {stats['entries']} entries saved → {stats['path']}")

    # Phase 4 & 5: Save results
    _promote_external_links(session, json_files, ext_links, analyzer)
    _write_report(args, static_endpoints, dynamic_endpoints, found_maps, interceptor,
                  ext_links, backend_findings, target, analyzer, domain_slug)
    _print_troubleshooting(static_endpoints, dynamic_endpoints)
