"""
Command-line entry point.

    python main.py --target http://localhost:3001 --output results.json

Responsible only for setup (arguments, connectivity check, HTTP session,
authentication, logging, rate limiting, cache) - the scan itself is
pipeline.run_scan().
"""
import argparse
import contextlib
import logging
import os
import sys

import requests

from shadow_scanner.auth import AuthEngine
from shadow_scanner.core.rate_limiter import RateLimiter
from shadow_scanner.core.scan_cache import ScanCache
from shadow_scanner.pipeline import run_scan
from shadow_scanner.reporting.report import save_report
from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Endpoint Scanner - Enhanced Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scanner.py --target https://example.com
  
  # Scan with pre-captured cookies
  python scanner.py --target https://example.com --cookies "session=abc123; csrf=xyz"

  # Automated form login (requests-based, fast)
  python scanner.py --target https://example.com --login-url https://example.com/login --username admin --password secret

  # Automated browser login (Playwright, handles JS-rendered forms + MFA)
  python scanner.py --target https://example.com --login-url https://example.com/login --username admin --password secret --browser-login

  # Automated browser login with TOTP MFA
  python scanner.py --target https://example.com --login-url https://example.com/login --username admin --password secret --browser-login --mfa-secret JBSWY3DPEHPK3PXP

  # Bearer / JWT token injection
  python scanner.py --target https://example.com --bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  # Deep scan with more routes and depth
  python scanner.py --target https://example.com --max-routes 50 --max-depth 5
  
  # Quick scan (fewer routes, less depth)
  python scanner.py --target https://example.com --max-routes 10 --max-depth 2 --no-cookies
        """
    )

    parser.add_argument('--target', type=str,
                        help='Target URL (omit to be prompted interactively)')
    parser.add_argument('--no-cookies', action='store_true', help='Skip cookie input')
    parser.add_argument('--cookies', type=str, help='Cookies for authenticated scanning (format: "name=value; name2=value2")', default=None)
    parser.add_argument('--output', type=str, default=None, metavar='FILE',
                        help='Also save a copy of the JSON report to FILE (the report is always '
                             'written to output/<domain>/json/<domain>_<timestamp>.json)')
    parser.add_argument('--max-routes', type=int, default=30, help='Max routes to visit per depth (default: 30)')
    parser.add_argument('--max-depth', type=int, default=5, help='Max navigation depth (default: 5)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress scan progress output; only the result paths are printed')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose/debug logging (shows suppressed errors, cache hits, rate-limit events)')
    parser.add_argument('--delay', type=float, default=0.0, metavar='SECONDS',
                        help='Fixed delay between HTTP requests in seconds (default: 0). '
                             'Increase to avoid WAF rate-limiting. Exponential backoff on 429/503 '
                             'is applied automatically regardless of this setting.')
    parser.add_argument('--workers', type=int, default=None, metavar='N',
                        help='Number of parallel fetch workers (default: 15). '
                             'Lower this value if the target WAF rate-limits aggressively.')
    parser.add_argument('--timeout', type=float, default=30.0, metavar='SECONDS',
                        help='HTTP request timeout in seconds (default: 30). '
                             'Applied to all JS/JSON fetches.')
    parser.add_argument('--cache', type=str, default=None, metavar='FILE',
                        help='Path to scan cache file (default: no cache). Enables resume support. '
                             'Note: file content is not persisted to disk, so --resume skips re-fetching '
                             'only for files already in memory from the current session.')
    parser.add_argument('--no-probe', action='store_true',
                        help='Do not request well-known paths that nothing references (common API '
                             'paths, OpenAPI/Actuator/WSDL/Next.js/GraphQL locations, service-worker '
                             'names, .d.ts guesses). URLs the target\'s code references are still '
                             'fetched. Probe-derived findings are always tagged as such in the report.')
    parser.add_argument('--resume', action='store_true',
                        help='Resume a previous scan using the cache file specified by --cache. '
                             'Skips already-fetched JS files. Requires --cache.')

    # ── Authentication automation ──────────────────────────────────────────────
    auth_group = parser.add_argument_group('Authentication Automation')
    auth_group.add_argument('--login-url',       type=str, default=None,
                            help='Login page URL for automated login')
    auth_group.add_argument('--username',         type=str, default=None,
                            help='Username / email for login')
    auth_group.add_argument('--password',         type=str, default=None,
                            help='Password for login')
    auth_group.add_argument('--username-field',   type=str, default=None,
                            help='HTML field name for username (auto-detected if omitted)')
    auth_group.add_argument('--password-field',   type=str, default=None,
                            help='HTML field name for password (auto-detected if omitted)')
    auth_group.add_argument('--browser-login',    action='store_true',
                            help='Use Playwright for login (required for JS-rendered / SPA login pages)')
    auth_group.add_argument('--mfa-secret',       type=str, default=None,
                            help='TOTP MFA secret (base32) for automated 2FA handling')
    auth_group.add_argument('--bearer',           type=str, default=None,
                            help='Inject a Bearer / JWT token directly (skips login flow)')
    auth_group.add_argument('--api-login-url', type=str, default=None,
                            help='Direct API login endpoint. Use when --login-url is a '
                                 'SPA frontend route that returns 405 on POST. '
                                 'Example: https://api.example.com/api/auth/login')

    return parser.parse_args()


def _resolve_target(args):
    """Target URL from --target or an interactive prompt (https:// added if missing)."""
    # Get target URL
    if args.target:
        target = args.target
        print(f"Target: {target}")
    else:
        target = input("Target URL: ").strip()
        if not target:
            print("[X] No URL provided")
            sys.exit(1)

    if not target.startswith("http"):
        target = "https://" + target
    return target


def _check_connectivity(target):
    """Fail fast if the target is unreachable; warn on 403 / SSL problems."""
    # DEBUG: Test connection BEFORE starting scan
    print(f"\n[DEBUG] Testing connection to {target}...")
    try:
        test_resp = requests.get(target, timeout=10, verify=False)
        print(f"[DEBUG] ✓ Connection successful (Status: {test_resp.status_code})")
        if test_resp.status_code == 403:
            print("[!] WARNING: Got 403 Forbidden. Site may block python-requests.")
            print("[!] Consider using different User-Agent or checking for WAF/Cloudflare.")
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL Error: {e}")
        print("[!] Continuing with verify=False...")
    except requests.exceptions.ConnectionError as e:
        print(f"[X] FATAL: Cannot connect to target: {e}")
        print("[X] Check your internet connection or if the site is down.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Connection test error: {e}")
        print("[!] Attempting to continue anyway...")


def _build_session():
    """requests.Session with a realistic browser User-Agent."""
    # Setup session with realistic User-Agent
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    return session


def _authenticate(args, session, target):
    """Bearer token, automated login, --cookies, or interactive cookie prompt.

    Returns (cookies, auth_headers) - both are reused by the Playwright phase.
    """
    # ==================================================================
    # AUTHENTICATION — priority order:
    #   1. --bearer          (direct token injection)
    #   2. --login-url       (automated login, browser or requests)
    #   3. --cookies         (pre-captured cookie string)
    #   4. interactive       (prompt, existing behaviour)
    # ==================================================================
    cookies = {}
    auth_engine = AuthEngine(session, target)
    auth_headers = {}

    if args.bearer:
        # ── Strategy 1: Raw Bearer / JWT token ───────────────────────
        auth_engine.login_with_bearer(args.bearer)
        auth_headers = auth_engine.headers

    elif (args.login_url or getattr(args, 'api_login_url', None)) and args.username and args.password:
        # ── Strategy 2: Automated login ──────────────────────────────
        # FIX RC9: if --api-login-url is provided, use it directly as POST target
        _effective_login = getattr(args, 'api_login_url', None) or args.login_url
        if _effective_login != args.login_url:
            print(f"[AUTH] Using explicit API login URL: {_effective_login}")

        if args.browser_login:
            success = auth_engine.login_with_browser(
                login_url      = args.login_url,   # browser navigates to frontend route
                username       = args.username,
                password       = args.password,
                username_field = args.username_field,
                password_field = args.password_field,
                mfa_secret     = args.mfa_secret,
            )
        else:
            success = auth_engine.login_with_form(
                login_url      = _effective_login,  # POST to API endpoint
                username       = args.username,
                password       = args.password,
                username_field = args.username_field,
                password_field = args.password_field,
            )

        cookies     = auth_engine.cookies
        auth_headers = auth_engine.headers
        auth_engine.summary()

        if not success:
            print("\n[!] Login failed — scan will continue without authentication")

    elif args.cookies:
        # ── Strategy 3: Pre-captured cookie string ───────────────────
        print("\n[COOKIES] Using cookies from command line")
        for cookie_pair in args.cookies.split(';'):
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                name, value = cookie_pair.split('=', 1)
                cookies[name.strip()] = value.strip()
                print(f"  • {name.strip()}")
        session.cookies.update(cookies)

    elif not args.no_cookies:
        # ── Strategy 4: Interactive cookie prompt (original behaviour) ─
        cookie_choice = input("\nAdd cookies? (y/n): ").strip().lower()
        if cookie_choice == 'y':
            print("Enter cookies (press Enter with empty name to finish):")
            while True:
                name = input("  Cookie name: ").strip()
                if not name:
                    break
                value = input("  Cookie value: ").strip()
                cookies[name] = value
        session.cookies.update(cookies)
    return cookies, auth_headers


def _configure_verbose_logging(args):
    """--verbose switches the root logger to DEBUG."""
    # ── Verbose / debug logging ────────────────────────────────────────────
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(levelname)s %(message)s',
        )
        print("[*] Verbose mode enabled — debug output active")


def _build_rate_limiter(args):
    """Fixed --delay plus automatic exponential backoff on 429/503."""
    # ── Rate limiter ───────────────────────────────────────────────────────
    rate_limiter = RateLimiter(delay=args.delay)
    if args.delay > 0:
        print(f"[*] Rate limiting: {args.delay}s between requests + exponential backoff on 429/503")
    else:
        print("[*] Rate limiting: exponential backoff on 429/503 (use --delay N to add fixed delay)")
    return rate_limiter


def _report_worker_config(args):
    """Print the effective fetch-worker count and timeout."""
    # ── Worker / timeout config ────────────────────────────────────────────
    _effective_workers = args.workers if args.workers is not None else EnhancedStaticAnalyzer.MAX_FETCH_WORKERS
    print(f"[*] Fetch workers : {_effective_workers} (override with --workers N)")
    print(f"[*] Fetch timeout : {args.timeout}s (override with --timeout N)")


def _build_scan_cache(args):
    """--cache / --resume support (None when no cache file is given)."""
    # ── Scan cache / resume ────────────────────────────────────────────────
    scan_cache = None
    if args.cache:
        scan_cache = ScanCache(path=args.cache)
        stats = scan_cache.stats()
        if args.resume and stats['entries'] > 0:
            print(f"[*] Resuming scan — cache has {stats['entries']} entries from {args.cache}")
        else:
            print(f"[*] Scan cache enabled → {args.cache}")
    elif args.resume:
        print("[!] --resume requires --cache <file>. Ignoring --resume.")
    return scan_cache


def _run_scan_quietly(args, target, session, cookies, auth_headers, rate_limiter, scan_cache):
    """--quiet: run the scan with stdout silenced, then print only where the results went.

    Setup (prompts, login) has already run with normal output, so interactive
    prompts are never hidden. Errors still surface: stdout is restored before
    main() prints them.
    """
    with open(os.devnull, 'w', encoding='utf-8') as devnull, contextlib.redirect_stdout(devnull):
        run_scan(args, target, session, cookies, auth_headers, rate_limiter, scan_cache)
    json_path = getattr(save_report, '_last_json_path', None)
    if json_path:
        print(f"[RESULTS] JSON  → {os.path.abspath(json_path)}")
    if args.output:
        print(f"[RESULTS] Copy  → {os.path.abspath(args.output)}")


def main():
    """Run the scanner from the command line."""
    print("=" * 70)
    print("ADVANCED ENDPOINT SCANNER - ENHANCED EDITION")
    print("Recursive lazy-loading discovery for modern SPAs")
    print("=" * 70 + "\n")

    try:
        # Parse command-line arguments
        args = parse_args()
        if args.no_probe:
            from shadow_scanner import config
            config.PROBING_ENABLED = False
            print("[*] Probing disabled (--no-probe)")
        target = _resolve_target(args)
        _check_connectivity(target)
        session = _build_session()
        cookies, auth_headers = _authenticate(args, session, target)
        _configure_verbose_logging(args)
        rate_limiter = _build_rate_limiter(args)
        _report_worker_config(args)
        scan_cache = _build_scan_cache(args)

        if args.quiet:
            _run_scan_quietly(args, target, session, cookies, auth_headers, rate_limiter, scan_cache)
        else:
            run_scan(args, target, session, cookies, auth_headers, rate_limiter, scan_cache)

    except KeyboardInterrupt:
        print("\n\n[X] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[X] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
