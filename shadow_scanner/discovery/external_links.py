"""External link collection + classification (subdomains, SSO, partner APIs...)."""
import re
import urllib.parse
# ==============================================================================
# EXTERNAL LINK EXTRACTOR
# Collects all valuable external URLs found during the scan — subdomains,
# partner APIs, SSO endpoints, redirect targets — classified by relationship
# to the target domain. Kept separate from endpoint results so noise filters
# don't accidentally drop legitimate external references.
# ==============================================================================

class ExternalLinkExtractor:
    """
    Collects external URLs from HTML, JS, JSON, and live browser traffic.
    Classifies them into tiers so the report is immediately actionable:
      - INTERNAL_SUBDOMAIN : same org, different subdomain (high value)
      - SSO_AUTH           : login/auth/oauth endpoints (high value)
      - PARTNER_API        : external APIs the app integrates with (medium)
      - CDN_ASSET          : pure asset delivery, low security value
      - ANALYTICS          : tracking/monitoring, informational only
      - OTHER_EXTERNAL     : everything else external
    """

    # Domains that are pure noise — vendor libs, schemas, browser internals.
    # These are NOT added to external_links at all.
    _NOISE_DOMAINS = {
        'w3.org', 'xmlns.com', 'schema.org', 'openxmlformats.org',
        'schemas.microsoft.com', 'mozilla.org', 'purl.org',
        'reactjs.org', 'react.dev', 'angular.io',
        'vimeo.com', 'vzaar.com',
        'gstatic.com', 'bootstrapcdn.com', 'fontawesome.com',
        'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
        'google-analytics.com', 'googletagmanager.com',
        'googlefonts.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
    }

    # Domain fragments that signal SSO / auth infrastructure
    _SSO_SIGNALS = ['sso', 'login', 'auth', 'oauth', 'saml', 'oidc', 'identity',
                    'accounts.', 'signin', 'adfs', 'microsoftonline', 'okta',
                    'onelogin', 'ping', 'keycloak']

    # Domain fragments that signal CDN / pure asset delivery
    _CDN_SIGNALS = ['cdn', 'static', 'assets', 'media', 'images', 'img',
                    'cloudfront', 'akamai', 'fastly', 'cloudflare']

    # Domain fragments that signal analytics / monitoring
    _ANALYTICS_SIGNALS = ['sentry', 'datadog', 'newrelic', 'hotjar', 'segment',
                          'mixpanel', 'amplitude', 'heap', 'fullstory', 'logrocket',
                          'intercom', 'analytics', 'tracking', 'telemetry', 'apmrum']

    def __init__(self, target_url: str):
        parsed       = urllib.parse.urlparse(target_url)
        self.target_host = parsed.netloc.lower()
        # Extract root domain (last two parts): rcow.ril.com -> ril.com
        parts = self.target_host.split('.')
        self.root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else self.target_host

        self._seen: dict = {}   # url -> entry dict (dedup key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed_html(self, html: str, source: str = 'HTML'):
        """Extract from raw HTML — href, src, action, data-* attributes."""
        if not html:
            return
        # All quoted URLs in attributes
        for m in re.finditer(r"""(?:href|src|action|data-url|data-href|content)=["']([^"']{8,})["']""", html, re.IGNORECASE):
            self._add(m.group(1), source)
        # meta refresh / og:url
        for m in re.finditer(r"""<meta[^>]+content=["']([^"']{8,})["']""", html, re.IGNORECASE):
            val = m.group(1)
            if val.startswith('http'):
                self._add(val, source)

    def feed_js(self, code: str, source: str = 'JS'):
        """Extract from JavaScript source — string literals that look like URLs."""
        if not code:
            return
        # Full https:// URLs inside string literals
        for m in re.finditer(r'(https?://[^\s"\'<>}{,\)\]]{10,})', code):
            self._add(m.group(1), source)
        # window.open / location.href patterns
        for m in re.finditer(r'(?:window\.open|location\.href|location\.replace)\s*\(\s*["\'](https?[^"\']+)["\'\)]', code):
            self._add(m.group(1), source)
        # redirect / returnUrl / callbackUrl patterns
        for m in re.finditer(r'(?:redirect|returnUrl|callbackUrl)\s*[=:]\s*["\'](https?[^"\']{6,})["\'\)]', code, re.IGNORECASE):
            self._add(m.group(1), source)

    def feed_json(self, data, source: str = 'JSON', _depth: int = 0):
        """Recursively extract URLs from JSON config values."""
        if _depth > 6:
            return
        if isinstance(data, dict):
            for v in data.values():
                self.feed_json(v, source, _depth + 1)
        elif isinstance(data, list):
            for item in data:
                self.feed_json(item, source, _depth + 1)
        elif isinstance(data, str) and data.startswith('http'):
            self._add(data, source)

    def feed_request_url(self, url: str, source: str = 'Browser_Request'):
        """Add a URL seen in live browser network traffic."""
        self._add(url, source)

    def get_results(self) -> list:
        """Return sorted, deduplicated external link entries."""
        results = [v for v in self._seen.values()
                   if v['tier'] not in ('NOISE', 'SAME_HOST')]
        # Sort: INTERNAL_SUBDOMAIN first, then SSO_AUTH, then rest
        tier_order = {
            'INTERNAL_SUBDOMAIN': 0,
            'SSO_AUTH': 1,
            'PARTNER_API': 2,
            'CDN_ASSET': 4,
            'ANALYTICS': 5,
            'OTHER_EXTERNAL': 3,
        }
        results.sort(key=lambda x: (tier_order.get(x['tier'], 9), x['url']))
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(self, raw_url: str, source: str):
        """Classify and store a URL if it's external and non-noise."""
        # Basic cleanup
        url = raw_url.strip().split('\n')[0].split('\r')[0]
        # Must be a proper URL
        if not url.startswith('http'):
            return
        try:
            parsed = urllib.parse.urlparse(url)
            host   = parsed.netloc.lower()
        except Exception:
            return
        if not host:
            return

        # Skip same host
        if host == self.target_host:
            return

        # Noise domains — silent drop
        if any(nd in host for nd in self._NOISE_DOMAINS):
            return

        # Strip query+fragment for dedup key, but keep path
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
        if not clean_url or clean_url in self._seen:
            return

        tier = self._classify(host, url)
        if tier == 'NOISE':
            return

        self._seen[clean_url] = {
            'url':    clean_url,
            'host':   host,
            'tier':   tier,
            'source': source,
        }

    def _classify(self, host: str, url: str) -> str:
        h = host.lower()
        u = url.lower()

        # Same root org domain but different subdomain = INTERNAL_SUBDOMAIN
        if self.root_domain and self.root_domain in h and h != self.target_host:
            return 'INTERNAL_SUBDOMAIN'

        # SSO / auth
        if any(s in h or s in u for s in self._SSO_SIGNALS):
            return 'SSO_AUTH'

        # Analytics / monitoring
        if any(s in h for s in self._ANALYTICS_SIGNALS):
            return 'ANALYTICS'

        # CDN / assets
        if any(s in h for s in self._CDN_SIGNALS):
            return 'CDN_ASSET'

        # Anything else that hit noise list
        if any(nd in h for nd in self._NOISE_DOMAINS):
            return 'NOISE'

        return 'PARTNER_API'
