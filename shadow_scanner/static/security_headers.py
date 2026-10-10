"""Security-relevant HTTP header mining (client-set secrets + server-read trust headers)."""
import re

from shadow_scanner.config import logger
# ==============================================================================
# SECURITY HEADER EXTRACTOR
# ------------------------------------------------------------------------------
# Mines security-relevant HTTP headers from JS bundles and source-map-recovered
# frontend/backend source. Two directions matter to a pentester:
#
#   1. CLIENT-SET  — headers the frontend attaches to its own API calls.
#      Leaks secrets (API keys, bearer tokens) and reveals which custom headers
#      the backend expects (an oracle for what to forge).
#        headers:{'X-Api-Key':'...'}, xhr.setRequestHeader(), new Headers(),
#        HttpHeaders().set(), axios.defaults.headers.common[...]
#
#   2. SERVER-READ — headers the backend TRUSTS as input. This is the gold:
#      the real-world case that motivated this feature was a leaked
#      `X-Internal-IP` that ~2 microservices trusted for a fast-path, letting
#      an attacker forge it and bypass access control.
#        req.headers['x-internal-ip'], request.headers.get('X-Foo'),
#        req.get('X-Foo'), ctx.req.headers[...]
#
# Everything is regex-based and self-contained (no esprima dependency) so it
# runs on minified bundles and recovered .ts alike. Findings are deduped by
# (name, direction) and classified by pentest relevance + severity.
# ==============================================================================
class SecurityHeaderExtractor:
    # Known header name (lower-case) -> (category, base_severity, note).
    # Severity: CRITICAL > HIGH > MEDIUM > LOW. Escalated below when a header is
    # SERVER-READ (trusted input) or carries a hardcoded secret value.
    CATALOG = {
        # ── IP / trust spoofing — forge these to appear internal/allow-listed ──
        'x-forwarded-for':      ('ip_trust_spoof', 'HIGH',   'Client-controlled source IP; often trusted for allow-listing.'),
        'x-real-ip':            ('ip_trust_spoof', 'HIGH',   'Client-controlled source IP.'),
        'x-client-ip':          ('ip_trust_spoof', 'HIGH',   'Client-controlled source IP.'),
        'x-originating-ip':     ('ip_trust_spoof', 'HIGH',   'Client-controlled source IP.'),
        'x-remote-ip':          ('ip_trust_spoof', 'HIGH',   'Client-controlled source IP.'),
        'x-internal-ip':        ('ip_trust_spoof', 'HIGH',   'Internal-IP trust header; forgeable fast-path / ACL bypass.'),
        'x-forwarded-host':     ('ip_trust_spoof', 'HIGH',   'Host override; can poison links, cache, and routing.'),
        'x-forwarded-server':   ('ip_trust_spoof', 'MEDIUM', 'Upstream server name; trust boundary hint.'),
        'cf-connecting-ip':     ('ip_trust_spoof', 'HIGH',   'Cloudflare real-IP header; forgeable if origin exposed.'),
        'true-client-ip':       ('ip_trust_spoof', 'HIGH',   'Akamai/Cloudflare real-IP header; forgeable.'),
        'fastly-client-ip':     ('ip_trust_spoof', 'HIGH',   'Fastly real-IP header; forgeable.'),
        'x-envoy-internal':     ('ip_trust_spoof', 'HIGH',   'Envoy internal-traffic marker; forge to appear internal.'),
        'x-envoy-external-address': ('ip_trust_spoof', 'MEDIUM', 'Envoy client address.'),
        'forwarded':            ('ip_trust_spoof', 'MEDIUM', 'RFC 7239 forwarded chain; client-controlled.'),
        # ── URL / path override — classic ACL & routing bypass ─────────────────
        'x-original-url':       ('auth_bypass',    'CRITICAL', 'Path override; bypasses front-proxy path-based access rules.'),
        'x-rewrite-url':        ('auth_bypass',    'CRITICAL', 'Path rewrite; bypasses path-based ACLs.'),
        'x-override-url':       ('auth_bypass',    'HIGH',     'Path override.'),
        'x-forwarded-path':     ('auth_bypass',    'HIGH',     'Path override.'),
        # ── HTTP method override — turn a GET into a DELETE past a WAF/ACL ──────
        'x-http-method-override': ('method_override', 'HIGH', 'Overrides HTTP verb; bypass method-based restrictions.'),
        'x-http-method':        ('method_override', 'HIGH',   'Overrides HTTP verb.'),
        'x-method-override':    ('method_override', 'HIGH',   'Overrides HTTP verb.'),
        # ── Auth / secrets — hardcoded values here are an immediate finding ─────
        'authorization':        ('auth_secret',    'HIGH',   'Auth credential header; check for hardcoded token.'),
        'proxy-authorization':  ('auth_secret',    'HIGH',   'Proxy auth credential.'),
        'x-api-key':            ('auth_secret',    'HIGH',   'API key header; check for hardcoded key.'),
        'api-key':              ('auth_secret',    'HIGH',   'API key header.'),
        'apikey':               ('auth_secret',    'HIGH',   'API key header.'),
        'x-auth-token':         ('auth_secret',    'HIGH',   'Auth token header.'),
        'x-access-token':       ('auth_secret',    'HIGH',   'Access token header.'),
        'x-session-token':      ('auth_secret',    'HIGH',   'Session token header.'),
        'x-secret':             ('auth_secret',    'HIGH',   'Secret header.'),
        'x-secret-key':         ('auth_secret',    'HIGH',   'Secret key header.'),
        'x-app-key':            ('auth_secret',    'MEDIUM', 'Application key header.'),
        'x-client-secret':      ('auth_secret',    'HIGH',   'OAuth client secret header.'),
        # ── Privilege / tenant — forge to escalate or cross tenants ─────────────
        'x-user-id':            ('privilege_tenant', 'HIGH',   'Caller identity as a header; forge for horizontal escalation.'),
        'x-user-role':          ('privilege_tenant', 'HIGH',   'Role asserted by header; forge for vertical escalation.'),
        'x-roles':              ('privilege_tenant', 'HIGH',   'Roles asserted by header.'),
        'x-admin':              ('privilege_tenant', 'HIGH',   'Admin flag header; forge to gain admin.'),
        'x-is-admin':           ('privilege_tenant', 'HIGH',   'Admin flag header.'),
        'x-impersonate':        ('privilege_tenant', 'HIGH',   'Impersonation header.'),
        'x-impersonate-user':   ('privilege_tenant', 'HIGH',   'Impersonation header.'),
        'x-sudo':               ('privilege_tenant', 'HIGH',   'Privilege elevation header.'),
        'x-tenant-id':          ('privilege_tenant', 'HIGH',   'Tenant selector; forge to cross tenants (IDOR).'),
        'x-account-id':         ('privilege_tenant', 'MEDIUM', 'Account selector; possible IDOR.'),
        'x-org-id':             ('privilege_tenant', 'MEDIUM', 'Org selector; possible IDOR.'),
        'x-organization-id':    ('privilege_tenant', 'MEDIUM', 'Org selector; possible IDOR.'),
        'x-workspace-id':       ('privilege_tenant', 'MEDIUM', 'Workspace selector; possible IDOR.'),
        # ── CSRF ───────────────────────────────────────────────────────────────
        'x-csrf-token':         ('csrf',            'MEDIUM', 'CSRF token header.'),
        'x-xsrf-token':         ('csrf',            'MEDIUM', 'CSRF token header.'),
        'x-csrftoken':          ('csrf',            'MEDIUM', 'CSRF token header.'),
        # ── Debug / internal routing — recon into backend topology ─────────────
        'x-debug':              ('debug_internal',  'MEDIUM', 'Debug toggle header; may enable verbose/insecure mode.'),
        'x-debug-token':        ('debug_internal',  'MEDIUM', 'Symfony debug token header.'),
        'x-internal':           ('debug_internal',  'MEDIUM', 'Internal-request marker; forge to reach internal-only logic.'),
        'x-internal-request':   ('debug_internal',  'HIGH',   'Internal-request marker; forge to bypass external checks.'),
        'x-internal-secret':    ('auth_secret',     'HIGH',   'Internal shared secret between services.'),
        'x-backend':            ('debug_internal',  'MEDIUM', 'Backend selector; routing/SSRF hint.'),
        'x-backend-server':     ('debug_internal',  'MEDIUM', 'Backend server hint.'),
        'x-gateway-secret':     ('auth_secret',     'HIGH',   'Gateway->service shared secret.'),
        # ── Cloud / infra provider secrets & trust (SSRF + creds jackpot) ──────
        'x-amz-security-token': ('auth_secret',     'HIGH',   'AWS STS session token.'),
        'x-amz-date':           ('debug_internal',  'LOW',    'AWS SigV4 date; signing recon.'),
        'x-amz-content-sha256': ('debug_internal',  'LOW',    'AWS SigV4 payload hash.'),
        'x-goog-api-key':       ('auth_secret',     'HIGH',   'Google Cloud API key.'),
        'x-goog-authenticated-user-email': ('privilege_tenant', 'HIGH', 'GCP IAP identity header; forge to spoof user.'),
        'x-firebase-appcheck':  ('auth_secret',     'MEDIUM', 'Firebase App Check token.'),
        'x-hasura-admin-secret':('auth_secret',     'CRITICAL','Hasura admin secret; full GraphQL admin if leaked.'),
        'x-hasura-role':        ('privilege_tenant', 'HIGH',   'Hasura role header; forge for escalation.'),
        'x-hasura-user-id':     ('privilege_tenant', 'HIGH',   'Hasura user id; forge for horizontal escalation.'),
        'x-vault-token':        ('auth_secret',     'CRITICAL','HashiCorp Vault token; secret-store access.'),
        'x-forwarded-proto':    ('ip_trust_spoof',  'MEDIUM', 'Scheme override; can bypass https-only checks.'),
        'x-forwarded-port':     ('ip_trust_spoof',  'LOW',    'Port override; routing hint.'),
        'x-forwarded-prefix':   ('auth_bypass',     'MEDIUM', 'Path-prefix override; routing/ACL bypass.'),
        'x-akamai-edgescape':   ('debug_internal',  'LOW',    'Akamai geo/edge metadata.'),
        'x-b3-traceid':         ('debug_internal',  'LOW',    'Zipkin/B3 trace id; infra recon.'),
    }

    # Custom/vendor header prefixes worth reporting even if not in the catalog —
    # this is what catches the *unknown* interesting header (the whole point).
    _CUSTOM_PREFIX_RE = re.compile(r'^(?:x-|sec-|proxy-|cf-|fastly-|akamai-|true-client-|x-envoy-)', re.I)

    # Header tokens are almost always hyphenated (X-Api-Key, Content-Type). This
    # keeps us from matching every JS identifier. Single-word headers
    # (Authorization, Cookie) are matched explicitly via the catalog.
    _HYPHENATED = r'[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+'

    # Boring headers we never want to report (pure content negotiation / caching,
    # plus standard defensive/CORS/transport response headers that are noise for
    # a *forgeable-trust* header hunt — they can't be abused as trust inputs).
    _IGNORE = {
        'content-type', 'content-length', 'accept', 'accept-encoding',
        'accept-language', 'accept-charset', 'cache-control', 'user-agent',
        'content-encoding', 'content-disposition', 'if-none-match',
        'if-modified-since', 'last-modified', 'content-language', 'x-requested-with',
        # ── defensive response headers (report is about *offensive* trust inputs) ──
        'x-content-type-options', 'x-frame-options', 'x-xss-protection',
        'strict-transport-security', 'content-security-policy',
        'content-security-policy-report-only', 'referrer-policy',
        'x-permitted-cross-domain-policies', 'cross-origin-opener-policy',
        'cross-origin-embedder-policy', 'cross-origin-resource-policy',
        'x-dns-prefetch-control', 'x-download-options',
        # ── CORS negotiation (not a trust input the client can forge server-side) ──
        'access-control-allow-origin', 'access-control-allow-methods',
        'access-control-allow-headers', 'access-control-allow-credentials',
        'access-control-expose-headers', 'access-control-max-age',
        'access-control-request-method', 'access-control-request-headers',
        'origin', 'vary', 'date', 'etag', 'age', 'expires', 'connection',
        'keep-alive', 'transfer-encoding', 'sec-fetch-site', 'sec-fetch-mode',
        'sec-fetch-dest', 'sec-fetch-user', 'sec-ch-ua', 'sec-ch-ua-mobile',
        'sec-ch-ua-platform', 'accept-ranges', 'content-range',
    }

    def __init__(self):
        # Keyed by (name_lower, direction) so the same header from many files
        # collapses to one finding but client-set vs server-read stay distinct.
        self._found = {}

    # ── public API ────────────────────────────────────────────────────────────
    def extract(self, code, source):
        """Scan one blob of code; accumulate findings. Safe on any input."""
        try:
            self._scan_client_set(code, source)
            self._scan_server_read(code, source)
        except Exception as _exc:
            logger.debug(f"[SecurityHeader] suppressed: {_exc}")

    def extract_live_headers(self, headers, source, direction):
        """
        Feed real headers observed on the wire (Playwright request/response) into
        the same finding store as static analysis.

        This is the highest-fidelity source: unlike static code, live headers carry
        the ACTUAL VALUE the client sent (so hardcoded secrets are concrete, not
        templated) and reveal headers that only appear after minification/env
        substitution.  `direction` is 'client_set' (what the SPA sent) or
        'server_read' (reflected/echoed by the server — treated as a trust-input
        signal so IP/role/tenant headers escalate exactly like req.headers[...]).

        `headers` is a dict (Playwright `request.all_headers()` /
        `response.all_headers()`). Never raises.
        """
        try:
            if not headers:
                return
            src = source or 'live'
            for name, value in headers.items():
                if not name:
                    continue
                # Playwright lower-cases header names; that's fine — _classify()
                # keys on lower-case anyway, and _record() re-lowers.
                self._record(str(name), direction, src,
                             value=str(value) if value is not None else None)
        except Exception as _exc:
            logger.debug(f"[SecurityHeader] live suppressed: {_exc}")

    def results(self):
        """Return findings sorted by severity (critical first)."""
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        return sorted(self._found.values(),
                      key=lambda f: (order.get(f['severity'], 9), f['name']))

    # ── classification ────────────────────────────────────────────────────────
    def _classify(self, name_lower):
        """Return (category, severity, note) or None if the header is noise."""
        if name_lower in self._IGNORE:
            return None
        if name_lower in self.CATALOG:
            return self.CATALOG[name_lower]
        if self._CUSTOM_PREFIX_RE.match(name_lower):
            # Unknown custom header — report at LOW; direction/value may escalate.
            return ('custom_unknown', 'LOW',
                    'Non-standard custom header; inspect for trust/secret usage.')
        return None

    def _record(self, name, direction, source, value=None):
        name_lower = name.lower()
        meta = self._classify(name_lower)
        if not meta:
            return
        category, severity, note = meta

        # ── severity escalation ────────────────────────────────────────────────
        # A SERVER-READ trust/privilege/IP header is the forgeable-input jackpot:
        # bump it up a notch (the X-Internal-IP bypass lives here).
        if direction == 'server_read' and category in (
                'ip_trust_spoof', 'privilege_tenant', 'auth_bypass',
                'method_override', 'debug_internal', 'custom_unknown'):
            severity = self._bump(severity)
        # A hardcoded, non-templated secret value is an immediate finding.
        leaked = self._looks_like_secret_value(value) if value else False
        if leaked and category in ('auth_secret',):
            severity = 'CRITICAL'

        key = (name_lower, direction)
        prior = self._found.get(key)
        if prior:
            # Keep the highest severity + remember a concrete value if we got one.
            if self._sev_rank(severity) < self._sev_rank(prior['severity']):
                prior['severity'] = severity
            if leaked and not prior.get('leaked_value'):
                prior['leaked_value'] = value
                prior['note'] = prior['note'] + ' Hardcoded value present.'
            if source and source not in prior['sources']:
                prior['sources'].append(source)
            return

        finding = {
            'name':        name,
            'direction':   direction,          # 'client_set' | 'server_read'
            'category':    category,
            'severity':    severity,
            'note':        note,
            'sources':     [source] if source else [],
        }
        if leaked:
            finding['leaked_value'] = value
            finding['note'] = note + ' Hardcoded value present.'
        self._found[key] = finding

    # ── client-set detection ──────────────────────────────────────────────────
    def _scan_client_set(self, code, source):
        # (a) object-literal keys:  'X-Api-Key': <val>   or   "X-Foo": <val>
        #     capture an optional following string literal as the value.
        obj_re = re.compile(
            r'''(['"]?)(''' + self._HYPHENATED + r''')\1\s*:\s*'''
            r'''(?:(['"`])([^'"`]{0,160})\3)?''',
            re.IGNORECASE)
        for m in obj_re.finditer(code):
            self._record(m.group(2), 'client_set', source, value=m.group(4))

        # (b) single-word catalog headers as object keys (Authorization/Cookie…)
        for hdr in ('authorization', 'cookie', 'apikey'):
            for m in re.finditer(
                r'''(['"]?)(''' + re.escape(hdr) + r''')\1\s*:\s*'''
                r'''(?:(['"`])([^'"`]{0,160})\3)?''',
                code, re.IGNORECASE):
                self._record(m.group(2), 'client_set', source, value=m.group(4))

        # (c) imperative setters:
        #     xhr.setRequestHeader('X-Foo', v) | headers.append/set('X-Foo', v)
        #     new HttpHeaders().set('X-Foo', v) | headers.set('X-Foo', v)
        setter_re = re.compile(
            r'''\.(?:setRequestHeader|append|set)\s*\(\s*'''
            r'''(['"`])([A-Za-z][\w-]+)\1\s*,\s*'''
            r'''(?:(['"`])([^'"`]{0,160})\3)?''',
            re.IGNORECASE)
        for m in setter_re.finditer(code):
            self._record(m.group(2), 'client_set', source, value=m.group(4))

        # (d) axios/global defaults:  axios.defaults.headers.common['X-Foo'] = v
        default_re = re.compile(
            r'''headers(?:\.\w+)?\s*\[\s*(['"`])([A-Za-z][\w-]+)\1\s*\]\s*=\s*'''
            r'''(?:(['"`])([^'"`]{0,160})\3)?''',
            re.IGNORECASE)
        for m in default_re.finditer(code):
            self._record(m.group(2), 'client_set', source, value=m.group(4))

    # ── server-read detection ─────────────────────────────────────────────────
    def _scan_server_read(self, code, source):
        # req.headers['x-foo'] | request.headers["x-foo"] | ctx.req.headers[...]
        bracket_re = re.compile(
            r'''\bheaders\s*\[\s*(['"`])([A-Za-z][\w-]+)\1\s*\]''',
            re.IGNORECASE)
        for m in bracket_re.finditer(code):
            self._record(m.group(2), 'server_read', source)

        # req.headers.get('X-Foo') | request.headers.get("x-foo")
        get_re = re.compile(
            r'''\bheaders\s*\.\s*get\s*\(\s*(['"`])([A-Za-z][\w-]+)\1''',
            re.IGNORECASE)
        for m in get_re.finditer(code):
            self._record(m.group(2), 'server_read', source)

        # Express: req.get('X-Foo') | req.header('X-Foo')
        express_re = re.compile(
            r'''\breq(?:uest)?\s*\.\s*(?:get|header)\s*\(\s*(['"`])([A-Za-z][\w-]+)\1''',
            re.IGNORECASE)
        for m in express_re.finditer(code):
            self._record(m.group(2), 'server_read', source)

        # Dotted access to a hyphen-free header: req.headers.authorization
        for hdr in ('authorization', 'cookie'):
            for m in re.finditer(
                r'\bheaders\s*\.\s*(' + re.escape(hdr) + r')\b',
                code, re.IGNORECASE):
                self._record(m.group(1), 'server_read', source)

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _sev_rank(sev):
        return {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(sev, 9)

    @staticmethod
    def _bump(sev):
        return {'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL',
                'CRITICAL': 'CRITICAL'}.get(sev, sev)

    @staticmethod
    def _looks_like_secret_value(value):
        """True if a captured value is a concrete secret, not a template/var."""
        if not value or len(value) < 8:
            return False
        # Templated / interpolated values are runtime, not leaked constants.
        if any(t in value for t in ('${', '{{', '" +', "' +", '`+', '+ ', 'process.env', 'import.meta')):
            return False
        v = value.strip()
        # Bearer <token>, long base64/hex, JWT-looking triples.
        if re.match(r'(?i)bearer\s+[\w.\-]{10,}', v):
            return True
        # Well-known secret prefixes — high confidence regardless of length/charset.
        # AWS access key, GitHub PAT/OAuth, OpenAI/Anthropic keys, Stripe, Slack,
        # Google API, generic sk-/pk_/rk_.
        if re.match(r'(?i)^(?:AKIA|ASIA|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|'
                    r'sk-|sk_live_|sk_test_|pk_live_|rk_live_|xox[baprs]-|'
                    r'AIza|ya29\.|glpat-|shpat_|shpss_|hf_)[\w.\-]{6,}', v):
            return True
        # Padded base64 secret (e.g. "aGVsbG8gd29ybGQ=" style, 20+ chars).
        if len(v) >= 20 and re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', v):
            return True
        if re.match(r'^[A-Za-z0-9_\-]{16,}$', v):
            return True
        if v.count('.') == 2 and re.match(r'^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$', v):
            return True
        return False
