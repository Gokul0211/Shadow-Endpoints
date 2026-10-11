"""
Global configuration shared by every module of the scanner.

Contents
--------
* logging setup (single ``stoic`` logger used everywhere)
* optional-dependency flags (esprima / pandas / playwright)
* the UNIFIED BLOCKLIST - the single source of truth for noise filtering
* small constant tables (API indicators, hash-route patterns, low-value JS,
  forced-probe endpoints)

Add new vendor/library noise to ``_BLOCKED_KEYWORDS`` / ``_BLOCKED_PATTERNS``
here - never introduce a second list elsewhere.
"""
import logging
import re

import urllib3
# ==============================================================================
# LOGGING — single source of truth for all output
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',   # keep clean for non-debug; debug adds prefix below
)
logger = logging.getLogger('stoic')

# Optional dependencies -- every feature that needs one degrades gracefully.
try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    esprima = None
    ESPRIMA_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

# Suppress SSL warnings (every request in the scanner uses verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Third-party hosts (analytics, monitoring, public CDNs, social widgets, XML /
# schema namespaces). Matched as a host or a subdomain of it — never as a
# substring of the URL, which used to drop first-party traffic on
# *.azurewebsites.net, CloudFront-hosted bundles and Firebase (googleapis.com).
IGNORED_DOMAINS = [
    # analytics / ads / tag managers
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "googlesyndication.com", "google.com", "gstatic.com",
    "fonts.googleapis.com", "maps.googleapis.com",
    "facebook.com", "facebook.net", "twitter.com", "linkedin.com",
    "hotjar.com", "hotjar.io", "optimizely.com", "segment.com", "segment.io",
    # monitoring / support widgets
    "sentry.io", "sentry-cdn.com", "datadoghq.com", "datadoghq.eu", "newrelic.com", "nr-data.net",
    "intercom.io", "intercomcdn.com", "cloudflareinsights.com",
    # public CDNs / library hosts / media
    "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "bootstrapcdn.com", "fontawesome.com",
    "tiny.cloud", "tinymce.com", "vimeo.com", "vzaar.com", "opencagedata.com",
    # identity provider login pages (reported as SSO links, not app endpoints)
    "login.microsoftonline.com",
    # XML / schema namespaces and documentation sites
    "w3.org", "schema.org", "openxmlformats.org", "schemas.microsoft.com", "xmlns.com", "purl.org",
    "mozilla.org", "reactjs.org", "react.dev",
]


def is_ignored_host(host: str) -> bool:
    """True if host is one of IGNORED_DOMAINS or a subdomain of one."""
    h = (host or '').lower().split(':')[0].strip('.')
    return any(h == d or h.endswith('.' + d) for d in IGNORED_DOMAINS)


# Well-known-path probing (COMMON_ENDPOINTS, OpenAPI/Actuator/Next.js paths,
# GraphQL paths, service-worker names, .d.ts guesses). --no-probe sets this to
# False; URLs the target's own code references are still fetched.
PROBING_ENABLED = True


def site_of(host: str) -> str:
    """Registrable-domain approximation: last two labels (whole host for IPs / localhost)."""
    h = (host or '').lower().split(':')[0].strip('.')
    labels = h.split('.')
    if len(labels) < 2 or re.fullmatch(r'[\d.]+', h):
        return h
    return '.'.join(labels[-2:])


def is_first_party(url: str, target: str) -> bool:
    """Same host as the target (any port) or a subdomain of the target's site."""
    import urllib.parse
    try:
        h = (urllib.parse.urlparse(url).hostname or '').lower()
        t = (urllib.parse.urlparse(target).hostname or '').lower()
    except ValueError:
        return False
    if not h or not t:
        return False
    site = site_of(t)
    return h == t or h == site or h.endswith('.' + site)


def is_ignored_url(url: str) -> bool:
    """True if the URL's host is a third-party host (see is_ignored_host)."""
    import urllib.parse
    try:
        return is_ignored_host(urllib.parse.urlparse(url if '//' in (url or '') else '//' + (url or '')).hostname or '')
    except ValueError:
        return False

# ==============================================================================
# UNIFIED BLOCKLIST — single source of truth for all noise filtering.
# Previously duplicated across NOISE_KEYWORDS, BASE_URL_BLACKLIST,
# STRICT_BLOCKS, and FALSE_POSITIVE_PATTERNS.  Everything references
# the helpers is_blocked_keyword() / is_blocked_pattern() below.
# ==============================================================================

_BLOCKED_KEYWORDS: list[str] = [
    # Font / CSS noise
    'helvetica', 'arial', 'courier', 'times', 'verdana',
    '__html2canvas__', '_pseudoelement_',
    # Obvious garbage strings
    'klmnopqrstuvwxyz',
    'expressionchangedafterithasbeenchecked',
    # Angular internals
    'ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef',
    # Build / tooling noise
    'node_modules', 'sourcemap', 'webpack', '__webpack',
    # Template / CSS literal leakage
    'animation-timing-function', 'sheet ${', 'sheet,', 'sheet[',
    # Error message fragments
    'caused by:', 'valid digit info',
    ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup',
    # Framework file names
    'on_property', 'template.html',
    # Excel / OOXML internals (SheetJS bundles)
    '/xl/worksheets/', 'SummaryInformation', 'DocumentSummaryInformation',
    'EncryptionInfo', 'EncryptedPackage', '!DataSpaces',
    'a:styleSheet', 'a:sheets', 'a:dimension', 'a:cellXfs', 'a:numFmts', 'a:cellStyleXfs',
    # Crypto polyfill package names (browserify / webpack)
    'elliptic', 'browserify-sign', 'create-ecdh', 'browserify-cipher',
    'public-encrypt', 'diffie-hellman', 'create-hmac',
    'pbkdf2', 'randombytes', 'randomfill',
]

_BLOCKED_PATTERNS: list[str] = [
    # Protocol / URL noise
    r'^https?:$', r'^http:-', r'^http:/[^/]', r'^https?:px',
    r'^https?://[^/]*$',
    # XML / schema namespaces
    r'w3\.org', r'xmlns', r'/1999/xhtml', r'/2000/svg',
    # Known Angular error string
    r'ExpressionChangedAfterItHasBeenCheckedError',
    # Garbage alphabet string
    r'klmnopqrstuvwxyz',
    # Template literal syntax that was not resolved
    r'\$\{', r'\{\{',
    # JS primitives that leaked into paths
    r'undefined', r'\bnull\b',
    # Excel worksheet paths
    r'/xl/worksheets/',
    # Whitespace in URL
    r'\s',
    # jQuery / Angular expression fragments
    r'\(\$', r'\?\$', r'\(!',
    # CSS units at end of path
    r'(?:^|/)(?:px|ms|em|rem|vh|vw)$',
    # Template query string fragments
    r'\?id=\$\{', r':\$\{',
    # Array accessor at end (not a real path)
    r'\[\w+\]$',
    # Sheet expression leakage
    r'/sheet\s', r'sheet\$', r'sheet,', r'sheet\[', r'sheet\(',
    # Trailing comment
    r'//\s*$',
    # Escaped newlines in path
    r':\\n', r'\}\\n',
    # Binary / unicode escape sequences (xlsx/crypto bundles)
    r'\\x[0-9a-fA-F]{2}', r'\\u[0-9a-fA-F]{4}',
    # Developer local absolute paths from source maps
    r'/(?:Users|home|Documents|Desktop|Downloads|AppData)/[A-Za-z]',
    r'^[A-Z]:[/\\]',
    # Single lowercase letter at end of path (pure noise)
    r'/[a-z]$',
    # Error messages in path
    r'caused by:', r'valid digit info', r'animation-timing-function',
    # Case-sensitive (scoped (?-i:…) so is_blocked_pattern's IGNORECASE does not apply):
    # Angular lazy-load strings whose last segment is an NgModule class name,
    # e.g. "./admin/admin.module#AdminModule" resolved to …/admin/AdminModule
    r'(?-i:/[A-Z][A-Za-z0-9]*Module)$',
]

# Pre-compile for performance — used by the helpers below
_BLOCKED_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in _BLOCKED_PATTERNS]


def is_blocked_keyword(text: str) -> bool:
    """Return True if text contains any unified blocked keyword (case-insensitive)."""
    t = text.lower()
    return any(kw in t for kw in _BLOCKED_KEYWORDS)


def is_blocked_pattern(text: str) -> bool:
    """Return True if text matches any unified blocked pattern."""
    return any(p.search(text) for p in _BLOCKED_PATTERNS_COMPILED)


def is_noise(text: str) -> bool:
    """Single entry-point noise check used everywhere in the codebase."""
    return is_blocked_keyword(text) or is_blocked_pattern(text)

# Legacy aliases — kept so existing call-sites don't need changing
NOISE_KEYWORDS        = _BLOCKED_KEYWORDS          # read-only reference
BASE_URL_BLACKLIST    = [r'w3\.org', r'xmlns', r'2000/svg', r'1999/xhtml',
                         r'ExpressionChangedAfterItHasBeenCheckedError', r'klmnopqrstuvwxyz']
STRICT_BLOCKS         = [kw for kw in _BLOCKED_KEYWORDS if not kw.startswith(' ')]
FALSE_POSITIVE_PATTERNS = [r'^https?:$', r'w3\.org', r'xmlns', r'/1999/xhtml',
                            r'/2000/svg', r'ExpressionChangedAfterItHasBeenCheckedError',
                            r'klmnopqrstuvwxyz']


# Every regex that used to be appended here was already present in
# _BLOCKED_PATTERNS (verified during the refactor), so the old 33-entry
# extension list was pure duplication.  Behaviour is identical: callers only
# ever test any(re.search(p, ...) for p in NOISE_PATTERNS).
NOISE_PATTERNS = list(_BLOCKED_PATTERNS)
API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/odata/', r'/rest/', r'/graphql',
    r'\.json$', r'/endpoint', r'/service', r'/rpc',
    r'/fetch(?:[/_?]|$)', r'/get(?:[/_?]|$)', r'/post(?:[/_?]|$)',
    r'/update(?:[/_?]|$)', r'/delete(?:[/_?]|$)',
    r'/pdf', r'/export', r'/data',
    r'/admin', r'/user', r'/auth',
    r'/dashboard', r'/master', r'/project',
    r'^#/', r'^/#/',
]

HASH_ROUTE_PATTERNS = [
    r'["\'](/[^/]+/#/[^"\']+)["\']',
    r'["\'](#/[^"\']+)["\']',
    r'["\'](/#/[^"\']+)["\']',
]

LOW_VALUE_JS = [
    'polyfill', 'polyfills', 'core-js', 'zone.js',
    'es2015', 'es5', 'babel', 'tslib'
]

# ⭐ IMPROVEMENT 1: Common endpoints for forced probing
COMMON_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/admin",
    "/api/internal",
    "/api/private",
    "/api/debug",
    "/admin",
    "/internal",
    "/private",
    "/graphql",
    "/rest",
    "/v1",
    "/v2",
    "/v3",
    "/odata",
    "/rpc",
    "/service",
    "/services",
    "/endpoint",
    "/endpoints",
]
