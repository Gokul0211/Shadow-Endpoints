"""Phase 1.75: service-worker / web-worker discovery and static analysis."""
import re

from shadow_scanner.config import logger
# ==============================================================================
# FEATURE 1: SERVICE WORKER ANALYZER
# ==============================================================================
class ServiceWorkerAnalyzer:
    """
    Discovers and statically analyzes service worker scripts.

    Detection strategy (in order of reliability):
      1. Parse HTML for  navigator.serviceWorker.register('<path>')  calls
      2. Try a fixed list of common registration paths
      3. Scan every already-discovered JS file for register() calls

    All discovered SWs are fetched once, deduped by URL, and then fed into
    the existing analyzer.analyze_code_from_dynamic() pipeline.
    """

    _CANDIDATE_PATHS = [
        '/sw.js', '/service-worker.js', '/serviceworker.js',
        '/sw-prod.js', '/sw-dev.js',
        '/assets/sw.js', '/assets/service-worker.js',
        '/static/sw.js', '/static/service-worker.js',
        '/js/sw.js', '/js/service-worker.js',
        '/dist/sw.js', '/dist/service-worker.js',
        '/public/sw.js', '/firebase-messaging-sw.js',
        '/workbox-sw.js',
        # FIX BUG-2: Common Web Worker paths NOT registered via serviceWorker.register().
        # Standalone workers spawned via new Worker('/path') -- these fire API calls
        # but are completely invisible to the HTML/SW registration scanner.
        '/worker.js', '/app.worker.js', '/background.worker.js',
        '/recommendation.worker.js', '/background-sync.worker.js',
        '/push.worker.js', '/cache.worker.js', '/sync.worker.js',
    ]

    _REGISTER_RE = re.compile(
        r'serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    # FIX BUG-2: Pattern to discover Web Worker files via new Worker('/path.js').
    # Covers both classic and module workers, and SharedWorker.
    _WEB_WORKER_RE = re.compile(
        r'new\s+(?:Worker|SharedWorker)\s*\(\s*["\']([\/][^"\' ]+\.(?:worker\.js|js))["\'\)]',
        re.IGNORECASE,
    )

    def __init__(self, session, base_url):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self._seen = set()

    def discover_and_analyze(self, html, js_contents, analyzer):
        """
        Full pipeline: collect SW candidates, fetch, validate, analyze.
        Returns list of SW URLs successfully processed.
        """
        print("\n[SW] Service Worker Analysis")

        candidate_urls = self._collect_candidates(html, js_contents)
        if not candidate_urls:
            print("  [-] No service worker candidates found")
            return []

        print(f"  [*] {len(candidate_urls)} candidate URL(s) to probe")
        processed = []

        for url in candidate_urls:
            code = self._fetch(url)
            if code is None:
                continue

            if not self._looks_like_service_worker(code):
                logger.debug(f"[SW] Skipping {url} - does not look like a SW")
                continue

            print(f"  [+] Analyzing SW: {url.split('/')[-1]} ({len(code):,} chars)")
            try:
                analyzer.analyze_code_from_dynamic(code, url)
            except Exception as exc:
                logger.debug(f"[SW] analyze error for {url}: {exc}")

            # ── Service Worker proxy rewrite extraction ────────────────────
            # Catches: fetch event handlers that rewrite /proxy/X → /api/X
            #   event.respondWith(fetch(event.request.url.replace('/proxy', '/api')))
            #   const newUrl = request.url.replace('old', 'new'); fetch(newUrl)
            # Also catches cache.addAll(['/api/data', '/api/config']) route lists.
            try:
                self._extract_sw_proxy_routes(code, url, analyzer)
            except Exception as exc:
                logger.debug(f"[SW] proxy extraction error for {url}: {exc}")

            processed.append(url)

        if processed:
            print(f"  [+] Processed {len(processed)} service worker(s)")
        else:
            print("  [-] No valid service workers found after fetching candidates")

        return processed

    def _extract_sw_proxy_routes(self, code, sw_url, analyzer):
        """
        Extract API routes exposed by Service Worker proxy/rewrite patterns.

        Handles:
          1. cache.addAll(['/api/data', '/api/config']) — explicit route lists
          2. url.replace('/proxy/', '/api/') — rewrite rules expose real backend paths
          3. respondWith(fetch('/api/...')) — direct fetch inside fetch event
        """
        base = self.base_url.rstrip('/')

        # Pattern 1: cache.addAll([...]) route lists
        for m in re.finditer(
            r'(?:cache\.addAll|precacheAndRoute|precache)\s*\(\s*\[([^\]]{4,2000})\]',
            code, re.IGNORECASE | re.DOTALL
        ):
            array_body = m.group(1)
            for path_m in re.finditer(r'[\'"`](/[a-zA-Z0-9/_\-\.]{3,200})[\'"`]', array_body):
                path = path_m.group(1)
                # Only API paths — skip static assets
                if re.search(r'/api[/_]|\.json$|/data[/_]|/config', path, re.IGNORECASE):
                    analyzer.add_endpoint(
                        f"{base}{path}", 'GET', [], 'SW_PRECACHE_ROUTE',
                        sw_url, 'BACKEND_API', 78
                    )

        # Pattern 2: URL rewrite rules — extract the target path suffix
        # e.g. url.replace('/proxy/', '/api/') → /api/ prefix is the real backend
        for m in re.finditer(
            r'\.replace\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]\s*\)',
            code, re.IGNORECASE
        ):
            old_prefix = m.group(1)
            new_prefix = m.group(2)
            if new_prefix.startswith('/api') or '/api' in new_prefix:
                # Record the rewrite target as a base — endpoints will be dynamic
                analyzer.resolver.global_scope[f'sw_rewrite:{old_prefix}'] = new_prefix
                logger.debug(f"[SW] Rewrite rule: {old_prefix} → {new_prefix}")

        # Pattern 3: respondWith(fetch('...')) inside fetch event handler
        for m in re.finditer(
            r'respondWith\s*\(\s*fetch\s*\(\s*[\'"`]([^\'"`]{4,200})[\'"`]',
            code, re.IGNORECASE
        ):
            path = m.group(1)
            if path.startswith('/') or path.startswith('http'):
                full = f"{base}{path}" if path.startswith('/') else path
                analyzer.add_endpoint(
                    full, 'GET', [], 'SW_RESPOND_WITH', sw_url, 'BACKEND_API', 80
                )

    def _collect_candidates(self, html, js_contents):
        urls = []

        # 1. Parse HTML source for register() calls
        for m in self._REGISTER_RE.finditer(html):
            urls.append(self._resolve(m.group(1)))

        # 2. Scan every JS bundle for register() calls AND new Worker() calls
        for _js_url, code in js_contents.items():
            for m in self._REGISTER_RE.finditer(code):
                urls.append(self._resolve(m.group(1)))
            # FIX BUG-2: Discover Web Workers spawned via new Worker('/path.js')
            # These are completely separate from ServiceWorker registrations but
            # often fire authenticated API calls on behalf of the main thread.
            for m in self._WEB_WORKER_RE.finditer(code):
                urls.append(self._resolve(m.group(1)))

        # 3. Fixed candidate paths (404s are silently ignored)
        for path in self._CANDIDATE_PATHS:
            urls.append(self.base_url + path)

        # Deduplicate while preserving order
        seen = set()
        result = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result

    def _resolve(self, path):
        if path.startswith('http'):
            return path
        if path.startswith('/'):
            return self.base_url + path
        return self.base_url + '/' + path

    def _fetch(self, url):
        if url in self._seen:
            return None
        self._seen.add(url)
        try:
            r = self.session.get(url, timeout=8, verify=False)
            if r.status_code == 200 and len(r.text) > 50:
                return r.text
            logger.debug(f"[SW] {url} -> HTTP {r.status_code}")
            return None
        except Exception as exc:
            logger.debug(f"[SW] fetch error {url}: {exc}")
            return None

    @staticmethod
    def _looks_like_service_worker(code):
        """
        Heuristic guard: a real SW or Web Worker will reference relevant signals.

        ServiceWorker signals (require 2+):
          self.addEventListener, caches., install, activate, skipWaiting, workbox

        Web Worker signals (require 1+):
          self.postMessage, postMessage, self.addEventListener('message')
          These workers fire fetch/XHR calls but have none of the SW cache APIs.

        FIX BUG-2: Accept Web Worker files that contain fetch() + postMessage
        even when they lack the traditional SW signals (caches, skipWaiting etc.)
        """
        sw_signals = ['caches.', 'install', 'activate', 'skipWaiting',
                      'clients.claim', 'workbox']
        sw_hits = sum(1 for s in sw_signals if s in code)
        if sw_hits >= 2:
            return True
        # Web Worker: must have fetch() or XHR AND postMessage communication
        if 'fetch(' in code and ('postMessage' in code or 'self.addEventListener' in code):
            return True
        # Minimal SW: self.addEventListener + fetch (bare-bones proxy workers)
        if 'self.addEventListener' in code and 'fetch' in code:
            return True
        return False
