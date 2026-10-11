"""Authentication automation: Bearer injection, form login, browser login, TOTP MFA."""
import json
import re
import urllib.parse

import requests
from bs4 import BeautifulSoup

from shadow_scanner.config import PLAYWRIGHT_AVAILABLE
# ==============================================================================
# AUTH ENGINE — Login automation + token extraction
# ==============================================================================
class AuthEngine:
    """
    Automated authentication for endpoint scanning.

    Supports four strategies, tried in order of specificity:
      1. --login-url + --username + --password  →  form-based POST login (requests)
      2. --login-url + --username + --password + Playwright  →  browser-based login
         (handles JS-rendered login forms, SPAs, CSRF tokens, 2-step flows)
      3. --bearer  →  raw Bearer / JWT token injected directly into session headers
      4. --cookies (existing)  →  pre-captured cookie string (unchanged behaviour)

    After a successful login the engine exposes:
      .cookies   dict  – ready for requests.Session and Playwright context
      .headers   dict  – Authorization / CSRF / custom headers to inject
      .tokens    dict  – named tokens extracted from responses (jwt, csrf, api_key …)
    """

    # Common field-name candidates for username / password inputs
    _USER_FIELDS  = ['username', 'email', 'user', 'login', 'identifier', 'name', 'account']
    _PASS_FIELDS  = ['password', 'pass', 'passwd', 'secret', 'pwd', 'credential']

    # Patterns used to fish tokens out of JSON responses / HTML / JS globals
    _TOKEN_PATTERNS = [
        # Bearer / JWT
        (re.compile(r'(?:access_token|accessToken|id_token|idToken|jwt|token)\s*[=:]\s*["\']?([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*)'), 'bearer'),
        # Short-lived API keys / session tokens (alphanum, 20-200 chars)
        (re.compile(r'(?:api_?key|apiKey|sessionToken|session_token|auth_token|authToken)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,200})["\']'), 'api_key'),
        # CSRF / XSRF tokens
        (re.compile(r'(?:csrf_?token|xsrf_?token|_csrf|csrfmiddlewaretoken)\s*[=:]\s*["\']([A-Za-z0-9\-_+/=]{10,200})["\']', re.IGNORECASE), 'csrf'),
        # Laravel / Django / Rails session values in JSON
        (re.compile(r'"(?:token|auth)"\s*:\s*"([A-Za-z0-9\-_.+/=]{20,})"'), 'generic'),
    ]

    def __init__(self, session: requests.Session, target_url: str):
        self.session     = session
        self.target_url  = target_url.rstrip('/')
        self.base_url    = urllib.parse.urlparse(target_url).scheme + '://' + urllib.parse.urlparse(target_url).netloc
        self.cookies: dict = {}
        self.headers: dict = {}
        self.tokens:  dict = {}
        self._auth_ok = False

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def login_with_bearer(self, token: str) -> bool:
        """Inject a raw Bearer token (JWT or opaque) into the session."""
        token = token.strip()
        # Auto-detect JWT vs opaque token
        prefix = 'Bearer'
        self.headers['Authorization'] = f'{prefix} {token}'
        self.session.headers.update({'Authorization': f'{prefix} {token}'})
        self.tokens['bearer'] = token
        print(f"[AUTH] ✓ Bearer token injected ({len(token)} chars)")
        self._auth_ok = True
        return True

    def login_with_form(self, login_url: str, username: str, password: str,
                        username_field: str = None, password_field: str = None,
                        extra_fields: dict = None) -> bool:
        """
        HTTP POST form login via requests.
        - Auto-detects field names from the login page HTML if not supplied.
        - Extracts CSRF tokens automatically.
        - Extracts Bearer / API tokens from the JSON or HTML response.
        Returns True if login appears successful.
        """
        print(f"\n[AUTH] Form-based login → {login_url}")

        # 1. GET the login page to harvest CSRF / field names
        try:
            get_resp = self.session.get(login_url, timeout=15, verify=False)
        except Exception as e:
            print(f"[AUTH] ✗ Could not fetch login page: {e}")
            return False

        soup = BeautifulSoup(get_resp.text, 'html.parser')
        csrf_value = self._extract_csrf_from_html(soup)

        # Auto-detect field names if not provided
        if not username_field:
            username_field = self._detect_field(soup, self._USER_FIELDS) or 'username'
        if not password_field:
            password_field = self._detect_field(soup, self._PASS_FIELDS) or 'password'

        print(f"[AUTH]   Field names  → user: '{username_field}', pass: '{password_field}'")
        if csrf_value:
            print(f"[AUTH]   CSRF token   → found ({csrf_value[:12]}…)")

        # 2. Build POST payload
        payload = {username_field: username, password_field: password}
        if csrf_value:
            # Try common CSRF field names
            for csrf_name in ['csrf_token', 'csrfmiddlewaretoken', '_csrf', 'csrfToken', '_token']:
                if soup.find('input', {'name': csrf_name}):
                    payload[csrf_name] = csrf_value
                    break
            else:
                payload['csrf_token'] = csrf_value  # fallback

        if extra_fields:
            payload.update(extra_fields)

        # 3. POST login
        try:
            post_resp = self.session.post(
                login_url, data=payload,
                allow_redirects=True, timeout=15, verify=False
            )
        except Exception as e:
            print(f"[AUTH] ✗ POST failed: {e}")
            return False

        # 4. Evaluate success
        success = self._evaluate_login_response(post_resp, username)
        if success:
            self._harvest_tokens_from_response(post_resp)
            self._sync_session_cookies()
            print(f"[AUTH] ✓ Login successful (status {post_resp.status_code})")
        else:
            print(f"[AUTH] ✗ Login may have failed (status {post_resp.status_code})")
            print("[AUTH]   Hint: try --browser-login for JS-rendered login pages")

        # FIX RC9: 405 means POST was sent to a static file server (SPA route).
        # Auto-construct API backend candidates and retry.
        if not success and post_resp.status_code == 405:
            print("[AUTH]   405 detected — frontend SPA route, not an API endpoint.")
            api_login_candidates = [
                login_url.replace('/login', '/api/auth/login'),
                login_url.replace('/login', '/api/login'),
                login_url.replace('/login', '/auth/login'),
            ]
            for candidate in api_login_candidates:
                if candidate == login_url:
                    continue
                print(f"[AUTH]   Trying: {candidate}")
                try:
                    retry_resp = self.session.post(
                        candidate, data=payload,
                        allow_redirects=True, timeout=15, verify=False
                    )
                    if self._evaluate_login_response(retry_resp, username):
                        print(f"[AUTH] ✓ Login successful via: {candidate}")
                        self._harvest_tokens_from_response(retry_resp)
                        self._sync_session_cookies()
                        success = True
                        break
                    print(f"[AUTH]   {candidate} → {retry_resp.status_code}")
                except Exception as e:
                    print(f"[AUTH]   {candidate} → error: {e}")

        self._auth_ok = success
        return success

    def login_with_browser(self, login_url: str, username: str, password: str,
                           username_field: str = None, password_field: str = None,
                           mfa_secret: str = None) -> bool:
        """
        Playwright-based login for SPAs / JS-rendered forms / OAuth flows.
        Handles: React/Vue/Angular login pages, CSRF auto-refresh, MFA (TOTP).
        After login, syncs cookies & tokens back to the requests session.
        Returns True if login appears successful.
        """
        if not PLAYWRIGHT_AVAILABLE:
            print("[AUTH] ✗ Browser login requires Playwright.")
            print("[AUTH]   Install: pip install playwright && python -m playwright install chromium")
            return False

        print(f"\n[AUTH] Browser-based login → {login_url}")

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page    = context.new_page()

                # Navigate to login page and wait for it to settle
                page.goto(login_url, wait_until='networkidle', timeout=20000)
                print(f"[AUTH]   Page loaded: {page.url}")

                # ── Detect & fill username ──────────────────────────────
                user_sel = self._browser_detect_field(page, self._USER_FIELDS, username_field)
                if not user_sel:
                    print("[AUTH] ✗ Could not find username field on login page")
                    browser.close()
                    return False

                page.fill(user_sel, username)
                print(f"[AUTH]   Filled username into: {user_sel}")

                # ── Tab to / click password field and fill ──────────────
                pass_sel = self._browser_detect_field(page, self._PASS_FIELDS, password_field)
                if not pass_sel:
                    print("[AUTH] ✗ Could not find password field on login page")
                    browser.close()
                    return False

                page.fill(pass_sel, password)
                print(f"[AUTH]   Filled password into: {pass_sel}")

                # ── Submit ──────────────────────────────────────────────
                submitted = False
                for submit_sel in [
                    'button[type="submit"]', 'input[type="submit"]',
                    'button:has-text("Login")', 'button:has-text("Sign in")',
                    'button:has-text("Log in")', 'button:has-text("Continue")',
                    '[data-testid="login-button"]', '.login-btn', '.signin-btn',
                ]:
                    try:
                        page.click(submit_sel, timeout=2000)
                        submitted = True
                        print(f"[AUTH]   Clicked submit: {submit_sel}")
                        break
                    except Exception:
                        pass

                if not submitted:
                    # Last resort: press Enter in the password field
                    page.press(pass_sel, 'Enter')
                    print("[AUTH]   Submitted via Enter key")

                # ── Wait for navigation after submit ────────────────────
                try:
                    page.wait_for_load_state('networkidle', timeout=10000)
                except Exception:
                    pass

                # ── MFA / TOTP handling ─────────────────────────────────
                if mfa_secret:
                    self._handle_mfa(page, mfa_secret)

                # ── Check success ───────────────────────────────────────
                current_url = page.url
                page_text   = page.content()
                success     = self._evaluate_browser_login(current_url, page_text, login_url)

                if success:
                    print(f"[AUTH] ✓ Browser login successful → {current_url}")
                else:
                    print(f"[AUTH] ✗ Login may have failed → {current_url}")

                # ── Harvest tokens from page globals / localStorage ─────
                self._harvest_tokens_from_browser(page)

                # ── Sync browser cookies → requests.Session ────────────
                browser_cookies = context.cookies()
                for c in browser_cookies:
                    self.cookies[c['name']] = c['value']
                self._sync_session_cookies()
                print(f"[AUTH]   Synced {len(browser_cookies)} cookies to requests session")

                browser.close()
                self._auth_ok = success
                return success

        except Exception as e:
            print(f"[AUTH] ✗ Browser login error: {e}")
            return False

    # ------------------------------------------------------------------
    # Token harvesting helpers
    # ------------------------------------------------------------------

    def _harvest_tokens_from_response(self, response: requests.Response):
        """Extract auth tokens from an HTTP response (JSON body + headers + cookies)."""
        # 1. JSON body
        try:
            body = response.json()
            self._extract_tokens_from_dict(body)
        except Exception:
            pass

        # 2. Raw text (covers HTML pages that inline a token)
        self._extract_tokens_from_text(response.text)

        # 3. Response headers
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            self.tokens['bearer'] = token
            self.headers['Authorization'] = auth_header
            self.session.headers['Authorization'] = auth_header
            print(f"[AUTH]   Token extracted from Authorization header ({len(token)} chars)")

        x_token = response.headers.get('X-Auth-Token') or response.headers.get('X-Access-Token')
        if x_token:
            self.tokens['x_auth_token'] = x_token
            self.headers['X-Auth-Token'] = x_token
            self.session.headers['X-Auth-Token'] = x_token
            print("[AUTH]   Token extracted from X-Auth-Token header")

    def _harvest_tokens_from_browser(self, page):
        """Extract tokens from browser localStorage, sessionStorage, and window globals."""
        # localStorage / sessionStorage
        for storage_name in ['localStorage', 'sessionStorage']:
            try:
                raw = page.evaluate(f'() => JSON.stringify(Object.entries({storage_name}))')
                entries = json.loads(raw)
                for key, value in entries:
                    self._check_and_store_token(key, value)
            except Exception:
                pass

        # Common window globals where SPAs stash tokens
        for global_var in [
            'window.__AUTH_TOKEN__', 'window.__token', 'window.authToken',
            'window.accessToken', 'window.jwt', 'window.token',
            'window.__INITIAL_STATE__', 'window.__store__',
        ]:
            try:
                val = page.evaluate(f'() => {{ try {{ return JSON.stringify({global_var}) }} catch(e) {{ return null }} }}')
                if val and val != 'null':
                    self._extract_tokens_from_text(val)
            except Exception:
                pass

        if self.tokens:
            for name, value in self.tokens.items():
                display = value[:16] + '…' if len(value) > 16 else value
                print(f"[AUTH]   Token '{name}' → {display}")
            # Auto-inject bearer if found
            if 'bearer' in self.tokens:
                token = self.tokens['bearer']
                self.headers['Authorization'] = f'Bearer {token}'
                self.session.headers['Authorization'] = f'Bearer {token}'
        else:
            print("[AUTH]   No tokens found in browser storage")

    def _extract_tokens_from_dict(self, data: dict, depth: int = 0):
        """Recursively walk a JSON dict looking for auth tokens."""
        if depth > 5:
            return
        for key, value in data.items():
            if isinstance(value, str):
                self._check_and_store_token(key, value)
            elif isinstance(value, dict):
                self._extract_tokens_from_dict(value, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_tokens_from_dict(item, depth + 1)

    def _extract_tokens_from_text(self, text: str):
        """Scan raw text for token patterns using compiled regexes."""
        for pattern, token_type in self._TOKEN_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(1)
                if len(candidate) >= 10:
                    self.tokens[token_type] = candidate
                    if token_type == 'bearer':
                        self.headers['Authorization'] = f'Bearer {candidate}'
                        self.session.headers['Authorization'] = f'Bearer {candidate}'
                    elif token_type == 'csrf':
                        self.headers['X-CSRFToken'] = candidate
                        self.session.headers['X-CSRFToken'] = candidate

    def _check_and_store_token(self, key: str, value: str):
        """Decide if a key/value pair is an auth token and store it."""
        if not isinstance(value, str) or len(value) < 10:
            return
        key_lower = key.lower()
        # JWT detection (three base64 segments)
        if value.count('.') == 2 and len(value) > 40:
            self.tokens['bearer'] = value
            self.headers['Authorization'] = f'Bearer {value}'
            self.session.headers['Authorization'] = f'Bearer {value}'
            return
        for indicator in ['token', 'jwt', 'auth', 'bearer', 'access', 'session', 'csrf', 'xsrf', 'api_key', 'apikey']:
            if indicator in key_lower:
                self.tokens[key_lower] = value
                return

    # ------------------------------------------------------------------
    # Login evaluation helpers
    # ------------------------------------------------------------------

    def _evaluate_login_response(self, response: requests.Response, username: str) -> bool:
        """Heuristic: did the form login actually work?"""
        text = response.text.lower()
        url  = response.url.lower()

        # Strong failure signals
        failure_signals = [
            'invalid password', 'invalid credentials', 'incorrect password',
            'login failed', 'authentication failed', 'wrong password',
            'invalid username', 'account not found', 'bad credentials',
        ]
        for sig in failure_signals:
            if sig in text:
                return False

        # Strong success signals
        success_signals = [
            'dashboard', 'logout', 'sign out', 'welcome', 'profile',
            'my account', 'overview', username.lower(),
        ]
        for sig in success_signals:
            if sig in text or sig in url:
                return True

        # Redirect away from login page = usually success
        if 'login' not in url and 'signin' not in url:
            return True

        return response.status_code in (200, 302)

    def _evaluate_browser_login(self, current_url: str, page_html: str, login_url: str) -> bool:
        """Heuristic: did the browser login work?"""
        cu  = current_url.lower()
        txt = page_html.lower()

        failure_signals = ['invalid', 'incorrect', 'wrong password', 'error', 'failed']
        for sig in failure_signals:
            if '<p' in txt and sig in txt:
                # FIX Issue 11: Actually detect failure instead of silently passing.
                # Previously this was `pass`, making the entire failure detection dead code.
                return False

        # Redirected away from the login page? Almost always means success
        login_host_path = urllib.parse.urlparse(login_url).path.lower()
        current_path    = urllib.parse.urlparse(current_url).path.lower()
        if current_path != login_host_path and 'login' not in cu and 'signin' not in cu:
            return True

        # Still on login page = failure
        return False

    # ------------------------------------------------------------------
    # HTML / browser field detection helpers
    # ------------------------------------------------------------------

    def _detect_field(self, soup, candidates: list) -> str:
        """Find an input field name from an HTML soup object."""
        for name in candidates:
            tag = (soup.find('input', {'name': name}) or
                   soup.find('input', {'id': name}) or
                   soup.find('input', attrs={'placeholder': re.compile(name, re.I)}))
            if tag:
                return tag.get('name') or tag.get('id') or name
        # Fallback: first text/email input for user, first password input for pass
        if candidates == self._USER_FIELDS:
            tag = soup.find('input', {'type': ['text', 'email']})
            if tag:
                return tag.get('name') or tag.get('id') or 'username'
        if candidates == self._PASS_FIELDS:
            tag = soup.find('input', {'type': 'password'})
            if tag:
                return tag.get('name') or tag.get('id') or 'password'
        return None

    def _browser_detect_field(self, page, candidates: list, override: str = None) -> str:
        """Return a CSS selector for an input field on the current Playwright page."""
        if override:
            # If caller specified exact selector / field name
            for sel in [override, f'[name="{override}"]', f'[id="{override}"]']:
                try:
                    if page.query_selector(sel):
                        return sel
                except Exception:
                    pass

        is_password = (candidates == self._PASS_FIELDS)
        if is_password:
            for sel in ['input[type="password"]', 'input[name*="pass"]', 'input[id*="pass"]']:
                try:
                    if page.query_selector(sel):
                        return sel
                except Exception:
                    pass
        else:
            for sel in ['input[type="email"]', 'input[type="text"]', 'input[name*="user"]',
                        'input[name*="email"]', 'input[id*="user"]', 'input[id*="email"]']:
                try:
                    if page.query_selector(sel):
                        return sel
                except Exception:
                    pass

        for name in candidates:
            for sel in [f'input[name="{name}"]', f'input[id="{name}"]',
                        f'input[placeholder*="{name}"]']:
                try:
                    if page.query_selector(sel):
                        return sel
                except Exception:
                    pass
        return None

    def _extract_csrf_from_html(self, soup) -> str:
        """Pull CSRF token value from HTML meta tags or hidden inputs."""
        # <meta name="csrf-token" content="...">
        for meta_name in ['csrf-token', 'csrfToken', '_csrf', 'csrf_token']:
            tag = soup.find('meta', {'name': meta_name})
            if tag and tag.get('content'):
                return tag['content']
        # <input type="hidden" name="csrf...">
        for input_tag in soup.find_all('input', {'type': 'hidden'}):
            name = (input_tag.get('name') or '').lower()
            if 'csrf' in name or 'xsrf' in name or '_token' in name:
                return input_tag.get('value', '')
        return ''

    def _handle_mfa(self, page, mfa_secret: str):
        """Handle TOTP MFA step if a code field appears after login."""
        try:
            import hmac, hashlib, struct, base64, time as _time

            def _totp(secret):
                """Minimal RFC 6238 TOTP implementation (no pyotp dependency)."""
                key      = base64.b32decode(secret.upper().replace(' ', ''))
                counter  = int(_time.time()) // 30
                msg      = struct.pack('>Q', counter)
                h        = hmac.new(key, msg, hashlib.sha1).digest()
                offset   = h[-1] & 0x0F
                code     = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
                return str(code % 1_000_000).zfill(6)

            # Wait up to 5 s for an MFA field to appear
            for mfa_sel in ['input[name*="otp"]', 'input[name*="mfa"]',
                            'input[name*="code"]', 'input[name*="token"]',
                            'input[placeholder*="code"]', 'input[placeholder*="OTP"]']:
                try:
                    page.wait_for_selector(mfa_sel, timeout=5000)
                    code = _totp(mfa_secret)
                    page.fill(mfa_sel, code)
                    page.press(mfa_sel, 'Enter')
                    print(f"[AUTH]   MFA code submitted: {code}")
                    page.wait_for_load_state('networkidle', timeout=8000)
                    return
                except Exception:
                    pass
        except Exception as e:
            print(f"[AUTH]   MFA handling error: {e}")

    # ------------------------------------------------------------------
    # Session sync
    # ------------------------------------------------------------------

    def _sync_session_cookies(self):
        """Push self.cookies into the requests.Session."""
        self.session.cookies.update(self.cookies)

    def summary(self):
        print("\n[AUTH] Authentication summary:")
        print(f"  Authenticated : {self._auth_ok}")
        print(f"  Cookies       : {list(self.cookies.keys())}")
        print(f"  Tokens        : {list(self.tokens.keys())}")
        print(f"  Extra headers : {list(self.headers.keys())}")
