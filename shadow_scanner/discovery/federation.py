"""Phase 1 discovery: HTML crawl, JS/JSON bundle discovery, Module Federation."""
import json
import re
import urllib.parse
from collections import deque

import requests
from bs4 import BeautifulSoup, Comment

from shadow_scanner.config import COMMON_ENDPOINTS, LOW_VALUE_JS, is_ignored_url
from shadow_scanner import config
class EnhancedFederationHunter:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.found_js_files = set()
        self.found_json_files = set()
        self.scan_queue = deque()
        self.raw_html = ""  # Stored by crawl_html() for ServiceWorkerAnalyzer

    def run(self):
        print("\n[PHASE 1] Discovery (JS + JSON)")

        self.check_config_files()
        self.crawl_html()

        print("  Deep scanning JavaScript files...")
        processed_files = set()
        scan_errors = 0

        while self.scan_queue:
            url = self.scan_queue.popleft()
            if url in processed_files:
                continue
            processed_files.add(url)

            if any(x in url.lower() for x in LOW_VALUE_JS):
                continue

            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    self.hunt_webpack_chunks(r.text, url)
                    self.hunt_config_references(r.text, url)
                    if hasattr(self, 'ext_link_extractor'):
                        self.ext_link_extractor.feed_js(r.text, source=url)
                elif r.status_code == 403:
                    print(f"\n  [!] 403 Forbidden on {url.split('/')[-1]} - Site may be blocking scraper")
                    scan_errors += 1
            except requests.exceptions.Timeout:
                scan_errors += 1
            except Exception as e:
                if scan_errors < 3:  # Only show first few errors
                    print(f"\n  [!] Error fetching {url.split('/')[-1]}: {type(e).__name__}")
                scan_errors += 1

        if scan_errors > 0:
            print(f"  [!] {scan_errors} files failed to download")

        # ⭐ IMPROVEMENT 1: Forced endpoint probing for common API paths
        if config.PROBING_ENABLED:          # --no-probe disables the path wordlist
            self._probe_common_endpoints()

        print(f"  [+] JS: {len(self.found_js_files)}, JSON: {len(self.found_json_files)}")
        return list(self.found_js_files), list(self.found_json_files)

    def _probe_common_endpoints(self):
        """⭐ IMPROVEMENT 1: Probe common API endpoints that may not be linked"""
        print(f"  Probing {len(COMMON_ENDPOINTS)} common endpoints...")

        found_count = 0
        for endpoint in COMMON_ENDPOINTS:
            test_url = self.base_url + endpoint
            try:
                response = self.session.get(test_url, timeout=5, verify=False)

                # Consider 200, 401, 403 as "exists" (endpoint is present even if blocked)
                if response.status_code in [200, 401, 403]:
                    found_count += 1
                    if found_count <= 5:  # Only print first 5 to avoid spam
                        print(f"    • Found: {endpoint} (Status: {response.status_code})")
                    # FIX Issue 10: Actually record the discovered endpoint.
                    # Previously, found endpoints were counted but never stored anywhere,
                    # so they never appeared in the final report.
                    self.found_json_files.add(test_url)
            except Exception:
                pass  # Endpoint doesn't exist, continue

        if found_count > 0:
            print(f"  [+] Probing discovered {found_count} active endpoints")
        else:
            print("  [-] No common endpoints found via probing")

    def check_config_files(self):
        """Check common config file locations"""
        config_paths = [
            '/assets/config/environment.json',
            '/assets/config/config.json',
            '/config/environment.json',
            '/environment.json',
            '/config.json',
        ]

        for path in config_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        r.json()
                        self.found_json_files.add(url)
                        print(f"  [*] Found config: {path}")
                    except json.JSONDecodeError:
                        pass  # Not valid JSON
            except requests.exceptions.Timeout:
                pass  # Config file doesn't exist, timeout is expected
            except Exception as e:
                # Only print unexpected errors
                if "404" not in str(e) and "Connection" not in str(e):
                    print(f"  [!] Error checking {path}: {e}")

    def hunt_config_references(self, code, source_url):
        """Extract JSON file references from JS code"""
        json_refs = re.findall(r'["\']([^"\']+\.json)["\']', code)
        base = source_url.rsplit('/', 1)[0] + '/'

        for ref in json_refs:
            if any(x in ref.lower() for x in ['sourcemap', 'webpack']):
                continue

            if ref.startswith('http'):
                full_url = ref
            elif ref.startswith('/'):
                full_url = urllib.parse.urljoin(self.base_url, ref)
            else:
                full_url = urllib.parse.urljoin(base, ref.lstrip('./'))

            if self.base_url in full_url and full_url not in self.found_json_files:
                try:
                    r = self.session.get(full_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        try:
                            r.json()
                            self.found_json_files.add(full_url)
                        except json.JSONDecodeError:
                            pass
                except requests.exceptions.Timeout:
                    pass
                except Exception:
                    pass

    def crawl_html(self):
        """Crawl HTML for script tags"""
        print(f"  [*] Fetching HTML from {self.target_url}...")
        try:
            # Add verify=False to handle self-signed certs
            r = self.session.get(self.target_url, timeout=15, verify=False)
            print(f"  [*] Status Code: {r.status_code}")

            if r.status_code != 200:
                print(f"  [!] Non-200 status code. Content length: {len(r.text)}")
                # Still try to parse even with non-200 status

            self.raw_html = r.text  # Store for ServiceWorkerAnalyzer
            if hasattr(self, 'ext_link_extractor'):
                self.ext_link_extractor.feed_html(r.text, source='HTML')
            soup = BeautifulSoup(r.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            print(f"  [*] Found {len(scripts)} script tags in HTML")

            if len(scripts) == 0:
                print("  [!] WARNING: No <script> tags found. This might be a dynamic SPA.")
                print("  [!] HTML preview (first 500 chars):")
                print(f"      {r.text[:500]}")

            for s in scripts:
                url = urllib.parse.urljoin(self.target_url, s['src'])
                if not is_ignored_url(url):
                    if url not in self.found_js_files:
                        self.found_js_files.add(url)
                        self.scan_queue.append(url)

            # ════════════════════════════════════════════════════════════════
            # DEEP JS DISCOVERY — 6 techniques beyond <script src>
            # These catch JS references that every other tool misses.
            # ════════════════════════════════════════════════════════════════
            _before = len(self.found_js_files)

            # ── TECHNIQUE 1: Broad HTML attribute scan ─────────────────────
            _js_attr_re = re.compile(
                r'''(?:src|href|data-main|data-src|ng-include|ui-sref'''
                r'''|formaction|dynsrc|action|code|codebase|archive)'''
                r'''\s*=\s*["']([^"']*?\.js(?:\?[^"']*)?)["']''',
                re.IGNORECASE
            )
            for m in _js_attr_re.finditer(r.text):
                _js_ref = m.group(1).strip()
                if not _js_ref or len(_js_ref) < 3:
                    continue
                _url = urllib.parse.urljoin(self.target_url, _js_ref)
                if not is_ignored_url(_url):
                    if _url not in self.found_js_files:
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)

            # Event handler attributes with JS loading patterns
            _event_js_re = re.compile(
                r'''(?:onclick|onload|onerror|onmouseover|onfocus)'''
                r'''\s*=\s*["'][^"']*?(?:loadScript|getScript|import|require)'''
                r'''\s*\(\s*["']([^"']+\.js(?:\?[^"']*)?)["']''',
                re.IGNORECASE
            )
            for m in _event_js_re.finditer(r.text):
                _url = urllib.parse.urljoin(self.target_url, m.group(1).strip())
                if _url not in self.found_js_files and not is_ignored_url(_url):
                    self.found_js_files.add(_url)
                    self.scan_queue.append(_url)

            # ── TECHNIQUE 2: Link preload / prefetch / modulepreload ───────
            for link in soup.find_all('link', href=True):
                rel = ' '.join(link.get('rel', []))
                as_type = link.get('as', '')
                href = link['href']
                if any(x in rel for x in ['preload', 'prefetch', 'modulepreload']):
                    if as_type == 'script' or href.endswith('.js') or '.js?' in href:
                        _url = urllib.parse.urljoin(self.target_url, href)
                        if _url not in self.found_js_files and not is_ignored_url(_url):
                            self.found_js_files.add(_url)
                            self.scan_queue.append(_url)

            # ── TECHNIQUE 3: Inline <script> block analysis ────────────────
            for s in soup.find_all('script', src=False):
                inline_code = s.string or ''
                if len(inline_code) < 10:
                    continue
                # Dynamic import() calls
                for m in re.finditer(r'''import\s*\(\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']\s*\)''', inline_code):
                    _url = urllib.parse.urljoin(self.target_url, m.group(1))
                    if _url not in self.found_js_files and not is_ignored_url(_url):
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)
                # document.createElement('script'); ...src = '...'
                for m in re.finditer(r'''\.src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']''', inline_code):
                    _url = urllib.parse.urljoin(self.target_url, m.group(1))
                    if _url not in self.found_js_files and not is_ignored_url(_url):
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)
                # SystemJS.import / System.import
                for m in re.finditer(r'''(?:SystemJS|System)\.import\s*\(\s*["']([^"']+\.js(?:\?[^"']*)?)["']''', inline_code):
                    _url = urllib.parse.urljoin(self.target_url, m.group(1))
                    if _url not in self.found_js_files and not is_ignored_url(_url):
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)

            # ── TECHNIQUE 4: Web Worker / SharedWorker / ServiceWorker ─────
            _worker_re = re.compile(
                r'''(?:new\s+(?:Worker|SharedWorker)|navigator\.serviceWorker\.register)'''
                r'''\s*\(\s*["']([^"']+\.js(?:\?[^"']*)?)["']''',
                re.IGNORECASE
            )
            for m in _worker_re.finditer(r.text):
                _url = urllib.parse.urljoin(self.target_url, m.group(1))
                if _url not in self.found_js_files and not is_ignored_url(_url):
                    self.found_js_files.add(_url)
                    self.scan_queue.append(_url)

            # ── TECHNIQUE 5: <noscript> fallback JS references ─────────────
            for ns in soup.find_all('noscript'):
                ns_text = str(ns)
                for m in re.finditer(r'''(?:src|href)\s*=\s*["']([^"']*?\.js(?:\?[^"']*)?)["']''', ns_text, re.IGNORECASE):
                    _url = urllib.parse.urljoin(self.target_url, m.group(1))
                    if _url not in self.found_js_files and not is_ignored_url(_url):
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)

            # ── TECHNIQUE 6: HTML comment JS references ────────────────────
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                for m in re.finditer(r'''(?:src|href)\s*=\s*["']([^"']*?\.js(?:\?[^"']*)?)["']''', str(comment), re.IGNORECASE):
                    _url = urllib.parse.urljoin(self.target_url, m.group(1))
                    if _url not in self.found_js_files and not is_ignored_url(_url):
                        self.found_js_files.add(_url)
                        self.scan_queue.append(_url)

            _deep_found = len(self.found_js_files) - _before
            if _deep_found:
                print(f"  [+] Deep HTML scan found {_deep_found} additional JS file(s)")

        except requests.exceptions.SSLError as e:
            print(f"  [!] SSL Error: {e}")
            print("  [!] Try adding verify=False or check SSL certificate")
        except requests.exceptions.ConnectionError as e:
            print(f"  [!] Connection Error: {e}")
            print("  [!] Cannot reach target. Check internet connection.")
        except Exception as e:
            print(f"  [!] CRITICAL ERROR in crawl_html: {type(e).__name__}: {e}")

    def hunt_webpack_chunks(self, code, source_url):
        """Hunt for webpack chunk patterns"""
        suffix_match = re.search(r'\)\s*\+\s*["\']([^"\']+\.js)["\']', code)
        if suffix_match:
            suffix = suffix_match.group(1)
            candidates = re.finditer(r'["\']([\w-]+)["\']\s*:\s*["\']([^"\']+)["\']', code)
            base_url = source_url.rsplit('/', 1)[0] + '/'

            for match in candidates:
                val = match.group(2)
                if len(val) < 2 or len(val) > 100 or ' ' in val:
                    continue
                clean_val = val.lstrip('./')
                if clean_val.startswith('/'):
                    full_chunk_url = urllib.parse.urljoin(self.base_url, clean_val + suffix)
                else:
                    full_chunk_url = urllib.parse.urljoin(base_url, clean_val + suffix)

                if full_chunk_url not in self.found_js_files:
                    self.found_js_files.add(full_chunk_url)
                    self.scan_queue.append(full_chunk_url)
