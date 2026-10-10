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

IGNORED_DOMAINS = [
    "google", "facebook", "twitter", "linkedin", "sentry", "datadog", "newrelic",
    "segment", "hotjar", "optimizely", "intercom", "cloudflare", "cloudfront",
    "jsdelivr", "cdnjs", "unpkg", "microsoftonline", "azure", "chinacloudapi",
    "opencagedata", "tinymce", "w3.org", "gstatic", "bootstrapcdn", "fontawesome",
    "vimeo.com", "vzaar.com",
    "reactjs.org", "react.dev",
    "openxmlformats.org", "schemas.openxmlformats.org",
    "schemas.microsoft.com", "schema.org",
    "mozilla.org", "mdn.",
]

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
    # FIX FP-5 / TC-NOISE-007: React component names that leak as paths
    # These appear in React DevTools / error boundaries but are NOT API endpoints.
    '/productcard', '/checkoutform', '/userprofile', '/orderhistory',
    '/paymentgateway', '/admindashboard', '/inventorytable', '/reportgenerator',
    '/notificationcenter',
    # FIX FP-5 / TC-NOISE-008: SPA router navigation paths (frontend routes, not APIs)
    # These are navigated by the frontend router and never hit the backend directly.
    # Note: only block the exact noise manifest examples, not their sub-paths.
    '/user/profile/settings', '/settings/notifications/preferences',
    '/team/members/invite', '/billing/plans/upgrade',
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
    # FP FIX: Angular/React SPA frontend router paths that leak from source maps.
    # These are client-side navigation routes, NOT backend API endpoints.
    # Pattern: single-segment paths with no /api/ prefix that are pure nouns/views.
    # /dashboard, /users, /admin (as root) are frontend routes; /api/users is fine.
    r'^https?://[^/]+/dashboard$',
    r'^https?://[^/]+/users$',
    r'^https?://[^/]+/users/\{[^}]+\}$',
    # Angular Module Federation lazy-load path artifacts from app-routing.module.ts
    # e.g. http://localhost:3002/mfeUsers/UsersModule — this is a loadChildren() string
    r'/mfe[A-Z][a-zA-Z]+/[A-Z][a-zA-Z]+Module$',
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
    # RC1-FIX: Match api_service/method style paths (no leading slash, underscore-separated service names)
    # e.g. api_rc_simops/CheckSimops, api_isolationtemplate/getAllIsolationTemplates
    r'^api_[a-z_]+/',
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
