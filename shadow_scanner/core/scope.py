"""
Scope and credential isolation.

A scan has a *target* (the URL given on the command line). Two separate rules follow from it:

  1. Credentials (Authorization / Cookie / API-key headers, session cookies, the bearer token injected into the
     browser) are sent ONLY to first-party hosts: the target's host (any port), subdomains of its site, hosts named
     with --scope, and the host of an explicit login URL. A script fetched from a public CDN or an analytics host
     never receives them (earlier versions attached the token to every request).
  2. With --scope-strict, requests to any other host are not sent at all (HttpClient raises OutOfScope; the
     browser aborts them). Without it they are still allowed (public scripts and sibling resources are read by
     many scans) but go out without credentials.
"""
import urllib.parse

from shadow_scanner.config import is_first_party

CREDENTIAL_HEADERS = frozenset({
    'authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-access-token',
    'x-csrf-token', 'x-csrftoken', 'x-xsrf-token',
})


class OutOfScope(Exception):
    """A request to a host outside the declared scope was refused (--scope-strict)."""


def _host(url):
    try:
        return (urllib.parse.urlparse(url).hostname or '').lower()
    except ValueError:
        return ''


class Scope:
    def __init__(self, target, extra_hosts=(), strict=False):
        self.target = target
        self.strict = bool(strict)
        self.extra = set()
        for h in extra_hosts or ():
            self.add(h)
        self.blocked = 0
        self.credentials_withheld = 0

    def add(self, host_or_url):
        """Allow a host (or the host of a URL) as first-party."""
        h = host_or_url if '/' not in host_or_url else _host(host_or_url)
        h = h.lower().split(':')[0].strip('.')
        if h:
            self.extra.add(h)

    def first_party(self, url):
        h = _host(url)
        if not h:
            return False
        if is_first_party(url, self.target):
            return True
        return any(h == e or h.endswith('.' + e) for e in self.extra)

    def allows(self, url):
        """May a request to this URL be sent at all?"""
        if not self.strict:
            return True
        scheme = urllib.parse.urlparse(url).scheme
        if scheme not in ('http', 'https', 'ws', 'wss'):
            return True
        return self.first_party(url)

    def credentials_ok(self, url):
        return self.first_party(url)

    def safe_headers(self, headers):
        """A copy of `headers` without credential-bearing entries."""
        return {k: v for k, v in (headers or {}).items() if k.lower() not in CREDENTIAL_HEADERS}

    def summary(self):
        return {'target_host': _host(self.target), 'extra_hosts': sorted(self.extra), 'strict': self.strict,
                'requests_blocked': self.blocked, 'requests_sent_without_credentials': self.credentials_withheld}
