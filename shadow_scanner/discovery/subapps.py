"""Phase 1.55/1.6: sub-application (micro-frontend) bundle discovery."""
import re
import urllib.parse

from bs4 import BeautifulSoup
def _discover_subapp_bundles_postanalysis(session, target, static_endpoints, known_js_files):
    """
    After Phase 2 static analysis, mine discovered endpoints for sub-app paths
    (FRONTEND_ROUTE, WINDOW_OPEN_ROUTE) and statically fetch each sub-app's
    index.html to collect its JS bundles.
    Returns list of new JS URLs not already in known_js_files.
    """
    parsed_target = urllib.parse.urlparse(target)
    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    domain = parsed_target.netloc

    # Extract sub-app paths from FRONTEND_ROUTE / WINDOW_OPEN_ROUTE endpoints
    subapp_paths = set()
    for ep in static_endpoints:
        if ep.get('classification') not in ('FRONTEND_ROUTE',) and \
           ep.get('type') not in ('WINDOW_OPEN_ROUTE', 'LOCATION_ORIGIN', 'HASH_ROUTE'):
            continue
        url = ep.get('endpoint', '')
        try:
            ep_parsed = urllib.parse.urlparse(url)
            if ep_parsed.netloc and ep_parsed.netloc != domain:
                continue
            parts = ep_parsed.path.strip('/').split('/')
            if parts and len(parts[0]) > 3:
                seg = parts[0]
                if not any(seg.startswith(x) for x in ('api', 'assets', 'login', 'static')):
                    subapp_paths.add(seg)
        except Exception:
            pass

    if not subapp_paths:
        return []

    print(f"  [1.6] Probing {len(subapp_paths)} sub-app path(s): {sorted(subapp_paths)}")
    new_js = []
    for path in sorted(subapp_paths):
        sub_url = urllib.parse.urljoin(base_url + '/', path + '/')
        try:
            r = session.get(sub_url, timeout=10, verify=False, allow_redirects=True)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, 'html.parser')
            found = 0
            for s in soup.find_all('script', src=True):
                js_url = urllib.parse.urljoin(sub_url, s['src'])
                if js_url not in known_js_files and js_url not in new_js:
                    new_js.append(js_url)
                    known_js_files.add(js_url)
                    found += 1
            if found:
                print(f"  [1.6] /{path}/: +{found} new JS bundle(s)")
        except Exception:
            pass

    return new_js


def _discover_subapp_index_pages(session, target, analyzer, known_js_files):
    """
    Discover sub-application JS bundles by mining fetched JS content for
    sub-app base path patterns (e.g. ui_rc_permit, ui_isolation) and probing
    those paths as index HTML pages to extract their <script> bundles.

    These sub-apps are independent Angular/React applications deployed at
    separate base paths on the same origin (e.g. /ui_rc_permit/main.*.js).
    """
    parsed = urllib.parse.urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # ── Step 1: mine sub-app paths from fetched JS content ──────────────
    subapp_paths = set()
    js_contents = getattr(analyzer, 'js_contents', {})
    for url, code in js_contents.items():
        # Pattern: ui_<service_name> — Angular enterprise convention
        for m in re.finditer(r'["\'/](ui_[a-z][a-z0-9_]{2,30})["\'/]', code):
            subapp_paths.add(m.group(1))
        # Pattern: /app_<name>/ or /mod_<name>/
        for m in re.finditer(r'["\']((?:app|mod|module|portal)_[a-z][a-z0-9_]{2,30})["\'/]', code):
            subapp_paths.add(m.group(1))

    # ── Step 2: also mine from source map HTML redirects ────────────────
    if hasattr(analyzer, '_sourcemap_engine'):
        eng = analyzer._sourcemap_engine
        for js_url in getattr(eng, 'subapp_js_urls', []):
            # Extract the base path from sub-app JS URLs
            # e.g. https://rcow.ril.com/ui_isolation/main.*.js → ui_isolation
            path = urllib.parse.urlparse(js_url).path
            parts = path.strip('/').split('/')
            if len(parts) >= 2:
                candidate = parts[0]
                if re.match(r'^(?:ui|app|mod|module|portal)_[a-z]', candidate):
                    subapp_paths.add(candidate)

    # ── Step 3: also mine from endpoints already discovered ─────────────
    for ep in analyzer.endpoints:
        ep_url = ep.get('endpoint', '')
        try:
            ep_path = urllib.parse.urlparse(ep_url).path
            parts = ep_path.strip('/').split('/')
            if parts:
                seg = parts[0]
                if re.match(r'^(?:ui|app|mod|module|portal)_[a-z]', seg):
                    subapp_paths.add(seg)
        except Exception:
            pass

    if not subapp_paths:
        return []

    print(f"\n[SUBAPP INDEX] Probing {len(subapp_paths)} sub-app path(s): {sorted(subapp_paths)}")

    # ── Step 4: probe each sub-app path for an HTML index page ──────────
    _CDN_SKIP = ('googleapis.com', 'bootstrapcdn', 'fontawesome', 'jquery',
                 'cdnjs.', 'unpkg.', 'jsdelivr.', 'cloudflare')
    known = set(known_js_files)
    new_js = []

    for path in sorted(subapp_paths):
        sub_url = f"{origin}/{path}/"
        try:
            r = session.get(sub_url, timeout=10, verify=False, allow_redirects=True)
            if r.status_code != 200:
                continue
            html = r.text
            if '<html' not in html[:1000].lower() and '<!doctype' not in html[:1000].lower():
                continue

            # Extract <base href="..."> for resolving relative script paths
            base_m = re.search(r'<base\s+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if base_m:
                base_href = base_m.group(1)
                base_url = f"{origin}{base_href}"
            else:
                base_url = sub_url

            # Extract title for logging
            title_m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            title = title_m.group(1).strip() if title_m else path

            found = 0
            for m in re.finditer(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = m.group(1)
                if any(cdn in src for cdn in _CDN_SKIP):
                    continue
                if not src.endswith('.js'):
                    continue
                if src.startswith('http'):
                    js_url = src
                else:
                    js_url = urllib.parse.urljoin(base_url, src)
                if js_url not in known:
                    known.add(js_url)
                    new_js.append(js_url)
                    found += 1

            if found:
                print(f"  [SUBAPP INDEX] /{path}/ '{title}': +{found} JS bundle(s)")

        except Exception:
            pass

    if new_js:
        print(f"[SUBAPP INDEX] Total: {len(new_js)} new JS bundle(s) from sub-app index pages")
    else:
        print("[SUBAPP INDEX] No new JS bundles found")

    return new_js
