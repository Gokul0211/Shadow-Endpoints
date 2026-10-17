"""
One HTTP layer for the whole scanner.

HttpClient wraps a requests.Session (or any object with the same get/post
methods) and adds, for every request made through it:

  * rate limiting and retry/back-off on 429/503 (core.rate_limiter.RateLimiter);
  * a budget: maximum number of requests and maximum response bytes;
  * counters per phase (requests, bytes, status classes, errors);
  * optional TLS verification override;
  * an optional JSON-lines request log: method, URL (secret-looking query
    values masked), status, size, seconds, phase - never headers or bodies.

It is drop-in: attributes it does not define (headers, cookies, ...) are the
wrapped session's, so code written for requests.Session keeps working.
"""
import json
import re
import threading
import time
import urllib.parse

import requests

from shadow_scanner.config import logger
from shadow_scanner.core.rate_limiter import RateLimiter
from shadow_scanner.core.scope import OutOfScope, Scope

_SECRET_QUERY = re.compile(r'pass|secret|token|key|auth|sig|session|code', re.I)


class BudgetExceeded(requests.exceptions.RequestException):
    """The request or byte budget is used up; no further requests are sent."""


def mask_url(url):
    """URL with the values of secret-looking query parameters replaced by '***'."""
    try:
        p = urllib.parse.urlsplit(url)
        if not p.query:
            return url
        q = [(k, '***' if _SECRET_QUERY.search(k) else v)
             for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(q), p.fragment))
    except Exception:
        return url


class HttpClient:
    def __init__(self, session, rate_limiter=None, max_requests=None, max_bytes=None,
                 verify=None, retries=2, log_path=None, scope=None):
        self._session = session
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.verify = verify            # None = leave each call's own setting
        self.retries = retries
        self.phase = '-'
        self.scope = scope              # core.scope.Scope: credential isolation / --scope-strict
        self._lock = threading.Lock()
        self._requests = 0
        self._bytes = 0
        self._errors = 0
        self._budget_hit = False
        self._by_phase = {}
        self._status = {}
        self._log = open(log_path, 'a', encoding='utf-8') if log_path else None

    # -- session passthrough -------------------------------------------------
    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return getattr(self._session, name)

    def set_phase(self, name):
        self.phase = name

    # -- accounting ----------------------------------------------------------
    def _charge(self):
        with self._lock:
            if self.max_requests is not None and self._requests >= self.max_requests:
                self._budget_exhausted('request')
            if self.max_bytes is not None and self._bytes >= self.max_bytes:
                self._budget_exhausted('byte')
            self._requests += 1
            ph = self._by_phase.setdefault(self.phase, {'requests': 0, 'bytes': 0, 'errors': 0})
            ph['requests'] += 1
            return ph

    def _budget_exhausted(self, kind):
        if not self._budget_hit:
            self._budget_hit = True
            logger.warning(f"[http] {kind} budget exhausted - no further requests will be sent")
        raise BudgetExceeded(f'{kind} budget exhausted')

    def _record(self, ph, method, url, status, size, seconds, error=None):
        with self._lock:
            self._bytes += size
            ph['bytes'] += size
            if error:
                self._errors += 1
                ph['errors'] += 1
            if status is not None:
                k = f'{status // 100}xx'
                self._status[k] = self._status.get(k, 0) + 1
            if self._log:
                self._log.write(json.dumps({
                    't': round(time.time(), 3), 'phase': self.phase, 'method': method,
                    'url': mask_url(url), 'status': status, 'bytes': size,
                    'seconds': round(seconds, 3), 'error': error}) + '\n')
                self._log.flush()

    # -- requests ------------------------------------------------------------
    def _send(self, method, url, kwargs):
        """One attempt. Credentials go only to first-party hosts: for any other host the request is made
        without the session's Authorization/Cookie headers and without its cookie jar."""
        sc = self.scope
        if sc is not None and not sc.credentials_ok(url) and isinstance(self._session, requests.Session):
            sc.credentials_withheld += 1
            headers = sc.safe_headers(dict(self._session.headers))
            headers.update(sc.safe_headers(kwargs.pop('headers', None)))
            return requests.request(method, url, headers=headers, **kwargs)
        return getattr(self._session, method.lower())(url, **kwargs)

    def request(self, method, url, **kwargs):
        if self.verify is not None:
            kwargs['verify'] = self.verify
        if self.scope is not None and not self.scope.allows(url):
            self.scope.blocked += 1
            with self._lock:
                self._by_phase.setdefault(self.phase, {'requests': 0, 'bytes': 0, 'errors': 0})
            raise OutOfScope(f'{url} is outside the declared scope (--scope-strict)')
        ph = self._charge()
        last_exc = None
        for attempt in range(self.retries + 1):
            self.rate_limiter.wait()
            t0 = time.time()
            try:
                resp = self._send(method, url, kwargs)
            except BudgetExceeded:
                raise
            except Exception as exc:
                last_exc = exc
                self._record(ph, method, url, None, 0, time.time() - t0, error=type(exc).__name__)
                if isinstance(exc, requests.exceptions.Timeout) or attempt == self.retries:
                    raise
                continue
            status = getattr(resp, 'status_code', None)
            if status is not None:
                self.rate_limiter.handle_response(status)
            size = len(getattr(resp, 'content', b'') or b'')
            self._record(ph, method, url, status, size, time.time() - t0)
            if status in (429, 503) and attempt < self.retries:
                continue
            return resp
        raise last_exc  # pragma: no cover

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def note_browser_request(self):
        """Count one request made by the browser against the same budget; False once it is used up."""
        prev = self.phase
        self.phase = 'browser'
        try:
            self._charge()
            return True
        except BudgetExceeded:
            return False
        finally:
            self.phase = prev

    # -- reporting -----------------------------------------------------------
    def stats(self):
        with self._lock:
            return {
                'requests': self._requests,
                'bytes': self._bytes,
                'errors': self._errors,
                'status_classes': dict(sorted(self._status.items())),
                'by_phase': {k: dict(v) for k, v in sorted(self._by_phase.items())},
                'budget': {'max_requests': self.max_requests, 'max_bytes': self.max_bytes,
                           'exhausted': self._budget_hit},
                'scope': self.scope.summary() if self.scope is not None else None,
            }

    def close(self):
        if self._log:
            self._log.close()
            self._log = None
