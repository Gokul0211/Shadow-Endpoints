"""Phase 1.5: source-map harvesting and feeding recovered sources to the analyzer."""
import hashlib
import json
import os
import re
import urllib.parse

from shadow_scanner.config import logger
from shadow_scanner import config
from shadow_scanner.core import diagnostics
# ==============================================================================
# SOURCE MAP ENGINE - LEGITIMATE PASSIVE EXTRACTION
# ==============================================================================

class SourceMapEngine:
    """
    Passive source map harvester - only extracts what's publicly exposed.
    Detects, downloads, and extracts source maps from discovered JS files.
    """

    def __init__(self, session, base_url, output_dir=None):
        self.session = session
        self.base_url = base_url.rstrip('/')
        # Keep default as "sourcemaps" (original) — changing this loses cached .map files
        self.output_dir = output_dir if output_dir else "sourcemaps"
        self.maps_dir = os.path.join(self.output_dir, "maps")
        self.extracted_dir = os.path.join(self.output_dir, "extracted")

        # Create directories — MUST exist before any file writes
        os.makedirs(self.maps_dir, exist_ok=True)
        os.makedirs(self.extracted_dir, exist_ok=True)

        self.source_map_urls = []
        self.extracted_files = []
        self.subapp_js_urls = []   # JS bundles discovered from HTML sub-app pages
        # Application module paths as webpack names them (webpack://app/./src/...),
        # reported as "webpack_module_paths" (node_modules / webpack internals excluded).
        self.webpack_module_paths = []

    def harvest(self, js_files):
        """
        Main entry point - detects, downloads, extracts source maps.
        Returns list of extracted source file paths and found map URLs.
        """
        print(f"\n{'='*70}")
        print("PHASE 1.5: SOURCE MAP HARVESTING")
        print(f"{'='*70}")

        # Step 1: Detect source maps (passive only)
        print("\n[STEP 1] Detection")
        self._detect_enhanced_manifests()
        self._detect_from_js_files(js_files)
        self._derive_passive_maps(js_files)  # NEW: Passive Rule

        if not self.source_map_urls:
            print("  [!] No source maps found")
            return [], []

        print(f"  [+] Found {len(self.source_map_urls)} source map(s)")

        # Step 2: Download source maps
        print("\n[STEP 2] Download")
        downloaded = self._download_maps()
        print(f"  [+] Downloaded {downloaded} map file(s)")
        if self.subapp_js_urls:
            print(f"  [+] Discovered {len(self.subapp_js_urls)} sub-app JS bundle(s) from HTML redirects")

        # Step 3: Check for inline maps
        print("\n[STEP 3] Inline Maps")
        self._extract_inline_source_maps(js_files)

        # Step 4: Extract source code
        print("\n[STEP 4] Extraction")
        self._extract_all_maps()
        print(f"  [+] Extracted {len(self.extracted_files)} source file(s)")

        # Step 5: Probe TypeScript declaration files (.d.ts)
        print("\n[STEP 5] TypeScript Declaration File (.d.ts) Probe")
        self._probe_dts_files(js_files)

        # Step 6: Architecture catalog report
        catalog = getattr(self, 'ts_source_catalog', [])
        if catalog:
            with_content = [e for e in catalog if e['has_content']]
            without_content = [e for e in catalog if not e['has_content']]
            print("\n[SOURCEMAP ARCHITECTURE CATALOG]")
            print(f"  Total original source paths found : {len(catalog)}")
            print(f"  With embedded sourcesContent      : {len(with_content)}")
            print(f"  Path-only (no embedded code)      : {len(without_content)}")
            # Save catalog to JSON for reference
            catalog_path = os.path.join(self.output_dir, "ts_architecture_catalog.json")
            try:
                with open(catalog_path, 'w', encoding='utf-8') as f:
                    json.dump(catalog, f, indent=2)
                print(f"  Catalog saved → {catalog_path}")
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        return self.extracted_files, self.source_map_urls

    def _derive_passive_maps(self, js_files):
        """
        Deterministically derive .map URLs, but only for files where heuristics
        suggest a source map likely exists. Skips known CDN/library domains entirely.
        NO new HTTP requests — purely URL manipulation.
        """
        CDN_DOMAINS = {
            'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            'fonts.googleapis.com', 'ajax.googleapis.com',
            'code.jquery.com', 'maxcdn.bootstrapcdn.com',
        }

        print(f"  [*] Checking {len(js_files)} JS files for heuristic map candidates...")
        count = 0

        for js_url in js_files:
            # Skip known CDN/library hosts — they never serve app source maps
            try:
                domain = urllib.parse.urlparse(js_url).netloc
            except Exception:
                continue
            if any(cdn in domain for cdn in CDN_DOMAINS):
                continue

            filename = js_url.rstrip('/').split('/')[-1].lower()

            # Heuristic 1: URL contains a content hash (webpack prod bundle pattern)
            # e.g. main.abc123ef.chunk.js, app.7b57cd2c.js
            has_hash = bool(re.search(r'\.[a-f0-9]{7,}(?:\.chunk)?\.js(?:\?|$)', js_url, re.IGNORECASE))

            # Heuristic 2: filename contains 'chunk' (webpack lazy-loaded chunk)
            has_chunk = 'chunk' in filename

            # Heuristic 3: common app bundle names
            has_bundle_name = any(x in filename for x in ['main.', 'bundle.', 'app.', 'vendor.', 'runtime.', 'index.'])

            # ── Fix 4: Heuristic 4: service-level JS files ──
            # Angular/React apps often ship individual service files like
            # permit.service.js, auth.service.js, auth.guard.js etc.
            # that each have their own .map file.
            has_service_name = bool(re.search(
                r'\.(service|guard|interceptor|resolver|pipe|directive|component|module|factory|provider|controller|helper|util|model|store|reducer|action|effect|selector)\.',
                filename, re.IGNORECASE
            ))

            if has_hash or has_chunk or has_bundle_name or has_service_name:
                # ── Fix 6: Skip .chunk.js.map from inline import() references ──
                # e.g. import('/admin-panel.chunk.js') derives admin-panel.chunk.js.map
                # but the actual file is usually admin-module.js.map. Only skip
                # if the filename looks like a raw chunk name without a content hash.
                if has_chunk and not has_hash and not has_bundle_name and not has_service_name:
                    # Pure chunk name with no hash — likely from import() reference,
                    # high chance of 404. Skip to avoid wasted requests.
                    continue
                map_url = js_url + ".map"
                if map_url not in self.source_map_urls:
                    self.source_map_urls.append(map_url)
                    count += 1

        print(f"  [+] Derived {count} heuristic map URL candidates (from {len(js_files)} files)")

    def _detect_enhanced_manifests(self):
        """
        [NEW] Parse HTML for manifest links and check common SPA paths.
        """
        # 1. Fetch root HTML to look for <link rel="manifest">
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            if resp.status_code == 200:
                # Regex for manifest link
                link_match = re.search(r'<link[^>]+rel=["\']manifest["\'][^>]+href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                if link_match:
                    manifest_href = link_match.group(1)
                    full_url = self._build_absolute_url(manifest_href)
                    print(f"  [+] Found manifest in HTML: {manifest_href}")
                    self._check_and_parse_manifest(full_url)
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

        # 2. Check common paths
        common_paths = [
            "manifest.json", "asset-manifest.json",
            "static/manifest.json", "static/asset-manifest.json",
            "build/manifest.json", "build/asset-manifest.json",
            "assets/manifest.json", "assets/asset-manifest.json",
            "dist/manifest.json", "public/manifest.json",
            "static/js/manifest.json", "static/js/asset-manifest.json"
        ]

        for path in common_paths:
            full_url = f"{self.base_url}/{path}"
            self._check_and_parse_manifest(full_url)

    def _check_and_parse_manifest(self, manifest_url):
        """Fetch and parse manifest file for .map references"""
        try:
            resp = self.session.get(manifest_url, timeout=5, verify=False)
            if resp.status_code == 200:
                try:
                    manifest = resp.json()
                    files = manifest.get('files', manifest)

                    found = False
                    for key, value in files.items():
                        if isinstance(value, str) and value.endswith('.map'):
                            map_url = self._build_absolute_url(value)
                            if map_url not in self.source_map_urls:
                                self.source_map_urls.append(map_url)
                                found = True

                    if found:
                        print(f"  [+] Found source maps in manifest: {manifest_url}")
                except Exception as _exc:
                    logger.debug(f"[Suppressed] {_exc}")
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

    def _detect_from_js_files(self, js_files):
        """Detect source maps from //# sourceMappingURL comments"""
        print(f"  [*] Scanning {len(js_files)} JS files for sourceMappingURL...")

        for js_url in js_files[:50]:  # Limit to first 50 files
            try:
                resp = self.session.get(js_url, timeout=10, verify=False)
                if resp.status_code == 200:
                    content = resp.text[-500:]  # Check last 500 chars only

                    # Look for sourceMappingURL
                    matches = re.findall(r'//[@#]\s*sourceMappingURL=(.+?)(?:\s|$)', content)

                    for match in matches:
                        match = match.strip()

                        # Skip data URIs (handled separately)
                        if match.startswith('data:'):
                            continue

                        # Build absolute URL
                        if match.startswith('http'):
                            map_url = match
                        elif match.startswith('/'):
                            map_url = f"{self.base_url}{match}"
                        else:
                            # Relative to JS file
                            js_base = js_url.rsplit('/', 1)[0]
                            map_url = f"{js_base}/{match}"

                        if map_url not in self.source_map_urls:
                            self.source_map_urls.append(map_url)
            except Exception:
                continue

    def _extract_inline_source_maps(self, js_files):
        """Extract source maps embedded as base64 data URIs"""
        import base64

        for js_url in js_files[:50]:
            try:
                resp = self.session.get(js_url, timeout=10, verify=False)
                if resp.status_code != 200:
                    continue

                # Look for data URI source maps
                match = re.search(
                    r'//[@#]\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)',
                    resp.text
                )

                if match:
                    try:
                        decoded = base64.b64decode(match.group(1))
                        source_map = json.loads(decoded)

                        # Save to file
                        filename = hashlib.md5(js_url.encode()).hexdigest() + '_inline.js.map'
                        filepath = os.path.join(self.maps_dir, filename)

                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(source_map, f, indent=2)

                        print(f"    ✓ INLINE MAP: {os.path.basename(js_url)}")

                        # Extract immediately
                        self._extract_single_map(filepath)
                    except Exception:
                        continue
            except Exception:
                continue

    def _download_maps(self):
        """Download all detected source maps"""
        downloaded = 0

        # De-duplicate URLs
        unique_urls = list(set(self.source_map_urls))
        self.source_map_urls = unique_urls

        # Track which map_urls returned sub-app HTML instead of JSON
        _known_subapp_js = set()

        for map_url in self.source_map_urls:
            try:
                resp = self.session.get(map_url, timeout=15, verify=False)
                if resp.status_code == 200:
                    # Validate that the response is actually JSON, not an HTML
                    # SPA catch-all page (common with Angular/React SPAs)
                    body = resp.text.strip()
                    if body.startswith('<') or body.startswith('<!DOCTYPE'):
                        # ── SUB-APP BUNDLE DISCOVERY ──────────────────────
                        # Source map URL redirected to a sub-app HTML page.
                        # These contain <script src="main-es2015.xxx.js">
                        # with the REAL JS bundles for that sub-application
                        # (e.g. /ui_isolation/, /ui_rc_permit/, etc.).
                        # Extract those <script> URLs so they get analyzed.
                        self._extract_subapp_bundles_from_html(
                            body, map_url, _known_subapp_js
                        )
                        continue

                    # Generate filename from URL
                    filename = hashlib.md5(map_url.encode()).hexdigest() + '.js.map'
                    filepath = os.path.join(self.maps_dir, filename)

                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(resp.text)

                    downloaded += 1
                    print(f"    ✓ {map_url.split('/')[-1]}")
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        return downloaded

    def _extract_subapp_bundles_from_html(self, html, source_url, known):
        """Extract JS bundle URLs from an HTML sub-app page returned instead of a source map."""
        # Determine base URL for resolving relative script paths
        # e.g. <base href="/ui_isolation/"> means scripts are relative to that path
        base_m = re.search(r'<base\s+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if base_m:
            base_href = base_m.group(1)
            parsed = urllib.parse.urlparse(source_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{base_href}"
        else:
            base_url = source_url.rsplit('/', 1)[0] + '/'

        # Extract title for logging
        title_m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        title = title_m.group(1).strip() if title_m else 'unknown'

        # Find all <script src="..."> tags, skip CDN/external libraries
        _CDN_SKIP = ('googleapis.com', 'bootstrapcdn', 'fontawesome', 'jquery',
                     'cdnjs.', 'unpkg.', 'jsdelivr.', 'cloudflare')
        found = 0
        for m in re.finditer(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            # Skip CDN / external library scripts
            if any(cdn in src for cdn in _CDN_SKIP):
                continue
            # Only JS files (skip .css, .ico, etc.)
            if not src.endswith('.js'):
                continue
            # Build absolute URL
            if src.startswith('http'):
                js_url = src
            else:
                js_url = urllib.parse.urljoin(base_url, src)
            if js_url not in known:
                known.add(js_url)
                self.subapp_js_urls.append(js_url)
                found += 1

        if found:
            print(f"    ⚡ Sub-app '{title}': +{found} JS bundle(s) from {base_url}")

    def _extract_all_maps(self):
        """Extract source code from all downloaded .map files"""
        map_files = [f for f in os.listdir(self.maps_dir) if f.endswith('.js.map')]

        for map_file in map_files:
            map_path = os.path.join(self.maps_dir, map_file)
            self._extract_single_map(map_path)

    def _extract_single_map(self, map_path):
        """Extract source code from a single .map file"""
        try:
            with open(map_path, 'r', encoding='utf-8') as f:
                source_map = json.load(f)

            sources = source_map.get('sources', [])
            contents = source_map.get('sourcesContent', [])
            # sourceRoot is prepended to every entry in sources[] per the spec
            source_root = source_map.get('sourceRoot', '') or ''

            # Handle index maps (v3 spec)
            if 'sections' in source_map:
                self._process_source_map_index(source_map, map_path)
                return

            # Initialize architecture catalog if not present
            if not hasattr(self, 'ts_source_catalog'):
                self.ts_source_catalog = []

            for i, source_path in enumerate(sources):
                # Apply sourceRoot prefix per spec
                if source_root and not source_path.startswith(('webpack://', 'http')):
                    full_source_path = source_root.rstrip('/') + '/' + source_path.lstrip('/')
                else:
                    full_source_path = source_path

                # Always catalog the source path for architecture mapping,
                # even when sourcesContent is missing (previously silently dropped)
                clean_path = self._sanitize_source_path(full_source_path)
                if clean_path:
                    catalog_entry = {
                        "original_path": full_source_path,
                        "clean_path": clean_path,
                        "map_file": os.path.basename(map_path),
                        "has_content": bool(i < len(contents) and contents[i]),
                        "type": "SOURCEMAP_ORIGINAL_SOURCE"
                    }
                    self.ts_source_catalog.append(catalog_entry)
                    if (full_source_path.startswith('webpack://')
                            and full_source_path not in self.webpack_module_paths):
                        self.webpack_module_paths.append(full_source_path)

                # Only write files if we have actual embedded source content
                if i >= len(contents) or not contents[i]:
                    continue

                if not clean_path:
                    continue

                # Build output path
                output_path = os.path.join(self.extracted_dir, clean_path)

                # Create directories
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                # Write source file
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(contents[i])

                    self.extracted_files.append(output_path)
                except Exception as _exc:
                    diagnostics.swallowed(__name__, _exc)

        except Exception as _exc:
            # print(f"    ✗ Failed to extract {os.path.basename(map_path)}")
            diagnostics.swallowed(__name__, _exc)

    def _process_source_map_index(self, source_map, map_path):
        """Handle source map index files (v3 spec)"""
        sections = source_map.get('sections', [])
        print(f"    📑 INDEX MAP: {os.path.basename(map_path)} ({len(sections)} sections)")

        for section in sections:
            if 'url' in section:
                # Download sub-map
                sub_map_url = self._build_absolute_url(section['url'])

                try:
                    resp = self.session.get(sub_map_url, timeout=10, verify=False)
                    if resp.status_code == 200:
                        # Save sub-map
                        sub_filename = hashlib.md5(sub_map_url.encode()).hexdigest() + '.js.map'
                        sub_filepath = os.path.join(self.maps_dir, sub_filename)

                        with open(sub_filepath, 'w', encoding='utf-8') as f:
                            f.write(resp.text)

                        # Recursively extract
                        self._extract_single_map(sub_filepath)
                        print(f"      ✓ SUB-MAP: {section['url']}")
                except Exception:
                    continue

    def _sanitize_source_path(self, source_path):
        """
        Clean webpack:// paths and remove invalid characters.
        Returns None for paths we should skip.
        """
        # Remove webpack prefix
        clean = re.sub(r'^webpack:\/\/[^/]*\/', '', source_path)
        clean = re.sub(r'^webpack:\/\/\/', '', clean)
        clean = clean.lstrip('/')

        # Skip node_modules - we don't care about dependencies
        if 'node_modules' in clean:
            return None

        # Skip webpack internals
        if clean.startswith('webpack/'):
            return None

        # Skip if path is too short (likely garbage)
        if len(clean) < 3:
            return None

        # Skip developer absolute paths embedded in source maps.
        # These are local machine paths that got baked into the map's "sources" array.
        # Concatenating them with the base URL produces nonsense like:
        #   https://app.example.com/Users/someone/Documents/...
        if re.match(r'^/?(?:Users|home|[A-Z]:[/\\])', clean, re.IGNORECASE):
            return None

        # Remove query params
        clean = clean.split('?')[0]

        # Sanitize invalid filename characters
        clean = re.sub(r'[<>:"|*?]', '_', clean)

        # Replace backslashes with forward slashes
        clean = clean.replace('\\', '/')

        return clean

    def _probe_dts_files(self, js_files):
        """
        Probe for TypeScript declaration files (.d.ts) by deriving likely paths
        from known JS bundle URLs.  These files reveal service interfaces, type
        signatures, and exported API shapes without any embedded source code.
        """
        if not config.PROBING_ENABLED:          # guessed .d.ts paths are probes
            return
        probed = 0
        found = 0
        dts_files = getattr(self, 'dts_files', [])

        for js_url in js_files:
            # Only bother for app bundles, skip vendor/CDN
            filename = js_url.rstrip('/').split('/')[-1].lower()
            if not any(x in filename for x in ['main.', 'bundle.', 'app.', 'vendor.', 'runtime.', 'index.', 'chunk']):
                continue

            # Derive .d.ts candidate: strip hash and chunk suffix, swap extension
            # e.g. main.abc123de.chunk.js → main.d.ts
            base = re.sub(r'\.[a-f0-9]{7,}(?:\.chunk)?\.js$', '', js_url, flags=re.IGNORECASE)
            base = re.sub(r'\.js$', '', base, flags=re.IGNORECASE)
            dts_url = base + '.d.ts'

            if dts_url == js_url:
                continue

            probed += 1
            try:
                r = self.session.get(dts_url, timeout=6, verify=False)
                if r.status_code == 200 and ('interface ' in r.text or 'export ' in r.text or 'declare ' in r.text):
                    # Save the .d.ts file
                    safe_name = hashlib.md5(dts_url.encode()).hexdigest() + '.d.ts'
                    dts_path = os.path.join(self.extracted_dir, safe_name)
                    with open(dts_path, 'w', encoding='utf-8') as f:
                        f.write(r.text)
                    dts_files.append({'url': dts_url, 'local': dts_path})
                    self.extracted_files.append(dts_path)
                    found += 1
                    print(f"  [+] .d.ts found: {dts_url}")
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        self.dts_files = dts_files
        if probed:
            print(f"  [*] .d.ts probe: checked {probed} candidates, found {found}")

    def _build_absolute_url(self, path):
        """Build absolute URL from relative path"""
        if path.startswith('http'):
            return path
        elif path.startswith('/'):
            return f"{self.base_url}{path}"
        else:
            return f"{self.base_url}/{path}"


def run_sourcemap_harvest(session, target, js_files, analyzer, output_dir=None):
    """
    Wrapper function to run source map harvesting and feed results
    into the existing analyzer pipeline. NON-INTRUSIVE.
    """
    engine = SourceMapEngine(session, target, output_dir=output_dir)
    extracted_files, found_maps = engine.harvest(js_files)

    # ── Fix 6: Store engine on analyzer so save_report can access TS catalog + dts_files ──
    if not hasattr(analyzer, '_sourcemap_engine'):
        analyzer._sourcemap_engine = engine
    else:
        # Merge catalog data from subsequent harvest passes
        existing = analyzer._sourcemap_engine
        existing.ts_source_catalog = (
            getattr(existing, 'ts_source_catalog', []) +
            getattr(engine, 'ts_source_catalog', [])
        )
        existing.dts_files = (
            getattr(existing, 'dts_files', []) +
            getattr(engine, 'dts_files', [])
        )
        existing.webpack_module_paths = (
            getattr(existing, 'webpack_module_paths', []) +
            getattr(engine, 'webpack_module_paths', [])
        )
        existing.source_map_urls = list(set(
            getattr(existing, 'source_map_urls', []) +
            getattr(engine, 'source_map_urls', [])
        ))
        existing.extracted_files = list(set(
            getattr(existing, 'extracted_files', []) +
            getattr(engine, 'extracted_files', [])
        ))
        # merge subapp_js_urls so Phase 1.85 sub-app discoveries
        # are not silently dropped when the engine is discarded.
        existing.subapp_js_urls = list(set(
            getattr(existing, 'subapp_js_urls', []) +
            getattr(engine, 'subapp_js_urls', [])
        ))

    # ── Fix 5: Fallback to cached extracted files ──
    # If no files were extracted (e.g. source maps returned HTML),
    # check the default 'sourcemaps/extracted/' directory for
    # previously cached files from a prior successful run.
    if not extracted_files and output_dir:
        _default_extracted = os.path.join("sourcemaps", "extracted")
        if os.path.isdir(_default_extracted):
            _cached = []
            for root, _dirs, files in os.walk(_default_extracted):
                for fname in files:
                    if fname.endswith(('.ts', '.tsx', '.jsx', '.js', '.mjs')):
                        _cached.append(os.path.join(root, fname))
            if _cached:
                print(f"\n[SOURCEMAP] No new extractions — reusing {len(_cached)} cached file(s) from {_default_extracted}")
                extracted_files = _cached

    if extracted_files:
        ts_registered = 0
        print(f"\n[SOURCEMAP] Feeding {len(extracted_files)} files into analyzer...")
        for filepath in extracted_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    code = f.read()
                # Register TypeScript/JSX source files with the parameter extractor
                # so later extract_params() calls can resolve interface types
                if hasattr(analyzer, '_ts_extractor'):
                    n = analyzer._ts_extractor.register_source_file(code, filepath)
                    ts_registered += n
                # Feed into endpoint analysis pipeline
                analyzer.analyze_code_from_dynamic(code, filepath)
                # GraphQL remap signal: scan sourcemap source content
                # for absolute GraphQL URLs matching the SPA host.
                # api-graphql.js.map source contains "http://localhost:3005/graphql"
                # → this is the definitive signal that the SPA hosts GraphQL at /graphql.
                # We store it on the analyzer so the remap decision can use it.
                if not hasattr(analyzer, 'sourcemap_gql_endpoints'):
                    analyzer.sourcemap_gql_endpoints = set()
                try:
                    _spa_base_sm = getattr(analyzer, 'base_url', '').rstrip('/')
                    if _spa_base_sm:
                        _abs_gql = re.findall(
                            re.escape(_spa_base_sm) + r'(/(?:graphql|gql)[/\w]*)',
                            code, re.IGNORECASE
                        )
                        for _gp in _abs_gql:
                            analyzer.sourcemap_gql_endpoints.add(
                                _spa_base_sm + _gp.rstrip('/')
                            )
                except Exception as _exc:
                    diagnostics.swallowed(__name__, _exc)
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)
        if ts_registered:
            print(f"[SOURCEMAP] Registered {ts_registered} TypeScript type(s) for parameter resolution")
        print("[SOURCEMAP] Integration complete")

    # ── SUB-APP JS BUNDLE ANALYSIS ──────────────────────────────────────
    # When source map URLs redirect to sub-app HTML pages (e.g. /ui_isolation/),
    # _download_maps extracts <script src> URLs. Fetch and analyze those bundles.
    subapp_js = getattr(engine, 'subapp_js_urls', [])
    if subapp_js:
        # Deduplicate against already-known JS files
        known = set(js_files)
        new_subapp_js = [u for u in subapp_js if u not in known]
        if new_subapp_js:
            print(f"\n[SUBAPP DISCOVERY] Analyzing {len(new_subapp_js)} sub-app JS bundle(s)...")
            _snap = len(analyzer.endpoints)
            for js_url in new_subapp_js:
                try:
                    r = session.get(js_url, timeout=15, verify=False)
                    if r.status_code != 200:
                        continue
                    ct = r.headers.get('content-type', '')
                    # Skip HTML responses (another redirect)
                    if 'html' in ct.lower() or r.text.strip().startswith('<'):
                        continue
                    code = r.text
                    if len(code) < 100:
                        continue
                    # use full analyze_code() pipeline (not the lighter
                    # analyze_code_from_dynamic) so Pattern E (webpack individual module
                    # assignments), Pattern 2b (this.X = this.Y + this.Z concatenation),
                    # Pattern 11 (this.http.get(this.A + this.B)), and
                    # EXTERNAL_SUBDOMAIN_LITERAL all fire on MFE main.js bundles.
                    analyzer.analyze_code(code, js_url)
                    print(f"    ✓ {js_url.split('/')[-1]} ({len(code):,} bytes)")
                except Exception as _exc:
                    diagnostics.swallowed(__name__, _exc)
            _new_count = len(analyzer.endpoints) - _snap
            if _new_count:
                print(f"[SUBAPP DISCOVERY] +{_new_count} endpoint(s) from sub-app bundles")
            # Also harvest source maps from sub-app bundles (recursive, 1 level)
            _sub_engine = SourceMapEngine(session, target, output_dir=output_dir)
            _sub_extracted, _sub_maps = _sub_engine.harvest(new_subapp_js)
            if _sub_extracted:
                print(f"[SUBAPP DISCOVERY] Feeding {len(_sub_extracted)} sub-app source files...")
                for filepath in _sub_extracted:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            code = f.read()
                        # full pipeline for extracted source files too
                        analyzer.analyze_code(code, filepath)
                    except Exception as _exc:
                        diagnostics.swallowed(__name__, _exc)
            # Merge sub-app engine data
            if hasattr(analyzer, '_sourcemap_engine'):
                existing = analyzer._sourcemap_engine
                existing.subapp_js_urls = list(set(
                    getattr(existing, 'subapp_js_urls', []) + new_subapp_js
                ))
                existing.source_map_urls = list(set(
                    getattr(existing, 'source_map_urls', []) +
                    getattr(_sub_engine, 'source_map_urls', [])
                ))
            # Return sub-app JS URLs so they feed into chunk harvester too
            found_maps = list(set((found_maps or []) + getattr(_sub_engine, 'source_map_urls', [])))
            js_files.extend(new_subapp_js)

    return extracted_files, found_maps
