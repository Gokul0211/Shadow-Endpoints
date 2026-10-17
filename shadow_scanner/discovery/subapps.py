"""Phase 1.55/1.6: sub-application (micro-frontend) bundle discovery."""
import re
import urllib.parse

from bs4 import BeautifulSoup
from shadow_scanner.core import diagnostics
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
        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

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
        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

    return new_js


def _discover_subapp_index_pages(session, target, analyzer, known_js_files):
    """
    Find independently deployed sub-applications (micro-frontends served from their
    own directory of the same origin) and collect the <script> bundles of their
    index pages.

    Candidate directories come only from URLs the scan has already seen: the first
    path segment of every same-origin script that is served from a sub-directory
    (https://host/<dir>/main.js), including scripts that source maps pointed at.
    No directory names are guessed.
    """
    parsed = urllib.parse.urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Generic asset folders are not applications
    _ASSET_DIRS = {'static', 'assets', 'dist', 'build', 'js', 'scripts', 'chunks', 'vendor', 'public', 'lib'}
    subapp_paths = set()
    seen_scripts = set(known_js_files)
    engine = getattr(analyzer, '_sourcemap_engine', None)
    if engine is not None:
        seen_scripts.update(getattr(engine, 'subapp_js_urls', []))
    for js_url in seen_scripts:
        u = urllib.parse.urlparse(js_url)
        if u.netloc != parsed.netloc:
            continue
        parts = [p for p in u.path.split('/') if p]
        if len(parts) >= 2 and not parts[0].startswith(('_', '.')) and parts[0].lower() not in _ASSET_DIRS:
            subapp_paths.add(parts[0])

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

        except Exception as _exc:
            diagnostics.swallowed(__name__, _exc)

    if new_js:
        print(f"[SUBAPP INDEX] Total: {len(new_js)} new JS bundle(s) from sub-app index pages")
    else:
        print("[SUBAPP INDEX] No new JS bundles found")

    return new_js
