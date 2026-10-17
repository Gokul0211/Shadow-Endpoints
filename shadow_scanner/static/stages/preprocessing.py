"""Pre-processing: comment stripping, FP neutralisation, de-obfuscation."""
import re
import urllib.parse
from shadow_scanner.core import diagnostics
class PreprocessingMixin:
    """Source pre-processing applied before any extractor runs."""

    def _preprocess_code(self, code):
        """Strip comment lines, neutralise false-positive constructs, decode obfuscation.

        Returns the transformed code that every later extractor sees.
        """
        # ── FP FIX 1: Strip ONLY inline double-slash comments on non-URL lines ──
        # Prevents: // fetch('/api/old') from emitting endpoints.
        # IMPORTANT: Does NOT strip JSDoc block comments (/** ... */) because
        # Real codebases embed valid endpoint hints in JSDoc.
        # Only removes single-line // comments where the comment itself is the
        # entire meaningful content of the line (i.e. the // is not inside a string).
        # We use a line-by-line approach to avoid stripping JSDoc blocks.
        def _strip_inline_comments(src: str) -> str:
            """Strip // comments but preserve JSDoc and block comments."""
            lines = []
            for line in src.split('\n'):
                stripped = line.strip()
                # Skip lines that are pure comments (start with //)
                # but NOT lines inside JSDoc-style block comments (starting with *)
                if stripped.startswith('//') and not stripped.startswith('///'):
                    lines.append('')  # blank the comment line
                else:
                    lines.append(line)
            return '\n'.join(lines)

        code = _strip_inline_comments(code)

        # ── FP FIX 2: Neutralize TypeScript type union declarations ───────────
        # Prevents: type ApiPath = '/api/users' | '/api/orders';
        # These are compile-time types and should never emit endpoints.
        # Only targets 'type X = ...' at statement level (with semicolon ending).
        code = re.sub(
            r'\btype\s+[A-Za-z_$][A-Za-z0-9_$<>,\s]*\s*=\s*[^;{]{1,300};',
            ' ',
            code
        )

        # ── FP FIX 3: Neutralize test-framework patterns ──────────────────────
        # describe('/api/users', () => ...) is a test label, not an API call.
        # Replace the function name so downstream patterns don't match the string arg.
        code = re.sub(
            r'\b(describe|it|test|expect|beforeEach|afterEach|beforeAll|afterAll)\s*\(\s*([\'"`])',
            r'__TEST__(\2',
            code
        )

        # ── FP FIX 4: Route-map object keys are config, not API calls ─────────
        # const routes = { '/api/users': 'UsersPage' } or { '/api/users': UsersPage }
        # — key is a router config path. Neutralize both quoted and unquoted values.
        code = re.sub(
            r'([{,])\s*([\'"`])(/(?:api|v\d)[^\'"`]+)\2\s*:\s*(?:[\'"`][^\'"`]*[\'"`]|[A-Z][A-Za-z0-9_$]*)',
            r'\1 __ROUTE_MAP_KEY__: null',
            code
        )

        # ── UPGRADE: Obfuscation decoder pre-pass ─────────────────────────
        # Decodes common obfuscation patterns BEFORE AST / regex analysis so
        # hidden endpoint strings become visible to all downstream extractors.
        #
        # Patterns handled:
        #   atob("L2FwaS91c2Vycw==")           → "/api/users"
        #   String.fromCharCode(47,97,112,105)  → "/api"
        #   "\x2f\x61\x70\x69"                 → "/api"
        #   unescape("%2Fapi%2Fusers")          → "/api/users"
        code = self._decode_obfuscated(code)

        return code

    def _decode_obfuscated(self, code: str) -> str:
        """
        Pre-process JavaScript to decode common obfuscation patterns that
        hide API endpoints from static analysis.

        Returns the original code with decoded strings APPENDED as synthetic
        const assignments — visible to every regex extractor that follows.

        Patterns handled:
          1. atob("L2FwaS91c2Vycw==")
          2. String.fromCharCode(47,97,112,105)
          3. "\x2f\x61\x70\x69" hex escapes
          4. unescape("%2Fapi%2Fusers") / decodeURIComponent
          5. eval("literal string")
          6. "sresu/ipa/".split("").reverse().join("")
          7. GAP 3: eval(userDecodeFunc(encoded)) — user-defined thin wrappers
        """
        import base64 as _b64
        decoded_fragments = []

        # ── 1. atob() — Base64 encoded strings ────────────────────────────
        for m in re.finditer(r'\batob\s*\(\s*["\']([A-Za-z0-9+/=]{4,300})["\']', code):
            try:
                decoded = _b64.b64decode(m.group(1) + '==').decode('utf-8', errors='ignore')
                if decoded and ('/' in decoded or 'api' in decoded.lower()):
                    decoded_fragments.append(f'"{decoded}"')
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        # ── 2. String.fromCharCode() ───────────────────────────────────────
        for m in re.finditer(r'String\.fromCharCode\s*\(([0-9,\s]{3,200})\)', code):
            try:
                chars = [int(c.strip()) for c in m.group(1).split(',') if c.strip().isdigit()]
                decoded = ''.join(chr(c) for c in chars if 32 <= c < 128)
                if decoded and ('/' in decoded or 'api' in decoded.lower()):
                    decoded_fragments.append(f'"{decoded}"')
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        # ── 3. Hex escape sequences in string literals ─────────────────────
        for m in re.finditer(r'["\'](?:\\x[0-9a-fA-F]{2}){2,50}["\']', code):
            try:
                raw = m.group(0).strip('"\'')
                decoded = raw.encode('raw_unicode_escape').decode('unicode_escape')
                if decoded and ('/' in decoded or 'api' in decoded.lower()):
                    decoded_fragments.append(f'"{decoded}"')
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        # ── 4. unescape() / decodeURIComponent() ──────────────────────────
        for m in re.finditer(
            r'(?:unescape|decodeURIComponent)\s*\(\s*["\']([^"\']{4,300})["\']', code
        ):
            raw = m.group(1)
            if '%' not in raw and not raw.startswith('/'):
                continue
            try:
                decoded = urllib.parse.unquote(raw)
                if decoded and ('/' in decoded or 'api' in decoded.lower()):
                    decoded_fragments.append(f'"{decoded}"')
            except Exception as _exc:
                diagnostics.swallowed(__name__, _exc)

        # ── 5. eval() with direct string literal ──────────────────────────
        for m in re.finditer(r'\beval\s*\(\s*["\']([^"\']{4,200})["\']', code):
            inner = m.group(1)
            if '/' in inner and len(inner) < 200:
                decoded_fragments.append(f'"{inner}"')

        # ── 6. Reversed string literals ───────────────────────────────────
        for m in re.finditer(
            r'["\']([a-zA-Z0-9/._\-]{5,100})["\']'
            r'\s*\.split\s*\(["\']["\'\s]*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(["\']["\'\s]*\)',
            code
        ):
            candidate = m.group(1)[::-1]
            if candidate.startswith('/') or 'api' in candidate.lower():
                decoded_fragments.append(f'"{candidate}"')

        # ── 7. GAP 3 FIX: eval(userDefinedDecodeFunc(encoded)) ────────────
        #
        # Real-world obfuscators define a thin wrapper like:
        #   function _0x3f2a(enc){ return atob(enc) }          // atob wrapper
        #   function decode(s){ return s.split('').reverse().join('') }
        #   const dec = (s) => unescape(s)
        #   const _x = (s) => String.fromCharCode(...s.split(',').map(Number))
        #
        # Then use it: eval(_0x3f2a("L2FwaS9vcmRlcnM="))
        #
        # Strategy:
        #   Pass 1 — build a registry: funcName → decoder_type
        #   Pass 2 — scan for eval(funcName(encoded)) and apply the decoder

        # Pass 1: detect thin decode wrappers
        _decoder_registry: dict[str, str] = {}  # name → 'atob'|'reverse'|'unescape'|'charcode'

        # Pattern A: function name(s){ return atob(s) }
        for m in re.finditer(
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\s*\([^)]{0,20}\)\s*\{'
            r'[^}]{0,120}\breturn\s+atob\s*\(',
            code, re.DOTALL
        ):
            _decoder_registry[m.group(1)] = 'atob'

        # Pattern B: const name = (s) => atob(s)  /  const name = s => atob(s)
        for m in re.finditer(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\s*=\s*'
            r'(?:\([^)]{0,20}\)|[a-zA-Z_$][a-zA-Z0-9_$]{0,20})\s*=>\s*atob\s*\(',
            code
        ):
            _decoder_registry[m.group(1)] = 'atob'

        # Pattern C: reverse wrapper — function name(s){ return s.split('').reverse().join('') }
        for m in re.finditer(
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\s*\([^)]{0,20}\)\s*\{'
            r'[^}]{0,120}\.split\s*\(["\']["\'\s]*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(',
            code, re.DOTALL
        ):
            _decoder_registry[m.group(1)] = 'reverse'

        # Pattern D: unescape wrapper
        for m in re.finditer(
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\s*\([^)]{0,20}\)\s*\{'
            r'[^}]{0,120}\breturn\s+(?:unescape|decodeURIComponent)\s*\(',
            code, re.DOTALL
        ):
            _decoder_registry[m.group(1)] = 'unescape'

        # Pattern E: charcode wrapper — return String.fromCharCode(...s.split(',').map(Number))
        for m in re.finditer(
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\s*\([^)]{0,20}\)\s*\{'
            r'[^}]{0,200}String\.fromCharCode',
            code, re.DOTALL
        ):
            _decoder_registry[m.group(1)] = 'charcode'

        # Pass 2: scan for eval(decoderFunc(encoded_string))
        if _decoder_registry:
            _func_names_pat = '|'.join(re.escape(fn) for fn in _decoder_registry)
            _eval_wrap_re = re.compile(
                r'\beval\s*\(\s*(?:' + _func_names_pat + r')\s*\(\s*["\']([^"\']{4,600})["\']',
                re.IGNORECASE
            )
            for m in _eval_wrap_re.finditer(code):
                func_name = re.search(_func_names_pat, code[m.start():m.start()+80], re.I)
                if not func_name:
                    continue
                decoder_type = _decoder_registry.get(func_name.group(0))
                encoded = m.group(1)
                decoded_val = None
                try:
                    if decoder_type == 'atob':
                        decoded_val = _b64.b64decode(encoded + '==').decode('utf-8', errors='ignore')
                    elif decoder_type == 'reverse':
                        decoded_val = encoded[::-1]
                    elif decoder_type == 'unescape':
                        decoded_val = urllib.parse.unquote(encoded)
                    elif decoder_type == 'charcode':
                        # encoded is comma-separated char codes: "47,97,112,105"
                        chars = [int(c.strip()) for c in encoded.split(',')
                                 if c.strip().isdigit()]
                        decoded_val = ''.join(chr(c) for c in chars if 32 <= c < 128)
                except Exception as _exc:
                    diagnostics.swallowed(__name__, _exc)
                if decoded_val and ('/' in decoded_val or 'api' in decoded_val.lower()):
                    decoded_fragments.append(f'"{decoded_val}"')

        # ── Append decoded fragments as synthetic const declarations ───────
        # Synthetic consts are visible to ALL regex + AST extractors that follow.
        if decoded_fragments:
            synthetic = '\n'.join(
                f'const __decoded_{i}__ = {frag};'
                for i, frag in enumerate(decoded_fragments)
            )
            code = code + '\n/* DECODED_OBFUSCATION */\n' + synthetic

        return code
