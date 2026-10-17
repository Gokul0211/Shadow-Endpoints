"""Thread-safe rate limiter with exponential backoff on HTTP 429/503."""
import random
import threading
import time

import requests

from shadow_scanner.config import logger
class RateLimiter:
    """
    Thread-safe rate limiter with exponential backoff.

    Usage:
        limiter = RateLimiter(delay=0.0)          # no delay by default
        limiter = RateLimiter(delay=0.5)          # 500 ms between requests
        limiter.wait()                             # call before each request
        limiter.handle_response(status_code)       # call after; backs off on 429/503
    """

    MAX_BACKOFF   = 60.0   # seconds
    BACKOFF_BASE  = 2.0    # exponential base

    def __init__(self, delay: float = 0.0):
        self.delay         = delay          # base inter-request delay (seconds)
        self._lock         = threading.Lock()
        self._last_request = 0.0
        self._backoff      = 0.0            # current extra delay due to throttling
        self._retry_count  = 0

    def wait(self):
        """Block until it is safe to issue the next request."""
        with self._lock:
            now     = time.time()
            gap     = self.delay + self._backoff
            elapsed = now - self._last_request
            if elapsed < gap:
                time.sleep(gap - elapsed + random.uniform(0, 0.05))
            self._last_request = time.time()

    def handle_response(self, status_code: int):
        """
        Inspect the status code and adjust backoff accordingly.
        429 Too Many Requests / 503 Service Unavailable → back off.
        2xx / 3xx → reset backoff.
        """
        with self._lock:
            if status_code in (429, 503):
                self._retry_count += 1
                self._backoff = min(
                    self.MAX_BACKOFF,
                    (self.BACKOFF_BASE ** self._retry_count) + random.uniform(0, 1)
                )
                logger.debug(f"[RateLimit] HTTP {status_code} — backing off {self._backoff:.1f}s")
            elif status_code < 400:
                # Successful response — slowly relax backoff
                self._retry_count = max(0, self._retry_count - 1)
                self._backoff     = max(0.0, self._backoff / 2)

    def throttled_get(self, session: requests.Session, url: str, **kwargs) -> requests.Response:
        """
        Drop-in wrapper around session.get() that applies rate limiting
        and handles 429/503 with automatic retry (up to 3 attempts).
        """
        if hasattr(session, 'rate_limiter') and hasattr(session, 'stats'):
            # HttpClient already rate-limits, retries and counts this request
            return session.get(url, **kwargs)
        max_attempts = 3
        resp = None
        for attempt in range(max_attempts):
            self.wait()
            try:
                resp = session.get(url, **kwargs)
                self.handle_response(resp.status_code)
                if resp.status_code in (429, 503) and attempt < max_attempts - 1:
                    logger.debug(f"[RateLimit] Retrying {url} (attempt {attempt + 2})")
                    continue
                return resp
            except requests.exceptions.Timeout:
                logger.debug(f"[RateLimit] Timeout on {url}")
                raise
            except Exception as exc:
                logger.debug(f"[RateLimit] Request error on {url}: {exc}")
                raise
        return resp  # return last response even if still throttled after all attempts
