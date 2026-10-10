"""Lazy-chunk discovery: queue dynamically imported JS for a second pass."""
import re
import urllib.parse
class DynamicImportsMixin:
    """Collects lazy-loaded chunk URLs into self._dynamic_imports (fetched later by scan())."""

    def _queue_dynamic_imports(self, code, source):
        """import() / require.ensure / __webpack_require__ / dynamic() call sites."""
        # ── GAP 2 FIX: Extract ALL dynamic import() forms ─────────────────
        # Patterns:
        #   import('./orders.module.js')
        #   import(/* webpackChunkName */ './admin/main')
        #   require.ensure([], fn, './payments')
        #   __webpack_require__.e(n).then(() => __webpack_require__('./lazy'))
        #   dynamic('./feature/index')
        _DYN_IMPORT_RE = re.compile(
            r'import\s*\(\s*(?:/\*[^*]*\*/\s*)?[\'"`]([^\'"`\s]{2,200})[\'"`]\s*\)',
            re.IGNORECASE,
        )
        for _m in _DYN_IMPORT_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1), source)

        _REQUIRE_ENSURE_RE = re.compile(
            r'require\.ensure\s*\(\s*\[[^\]]*\]\s*,\s*[^,]+,\s*[\'"`]([^\'"`\s]{2,200})[\'"`]',
            re.IGNORECASE,
        )
        for _m in _REQUIRE_ENSURE_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1), source)

        _WPK_LAZY_RE = re.compile(
            r'__webpack_require__\s*\(\s*[\'"`]([^\'"`\s]{2,200})[\'"`]\s*\)',
            re.IGNORECASE,
        )
        for _m in _WPK_LAZY_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1), source)

        # FIX: __webpack_require__.bind(null, "./module.js") — HOC binding pattern
        # Used in: chunk.then(__webpack_require__.bind(null, "./orders.module.js"))
        _WPK_BIND_RE = re.compile(
            r'__webpack_require__\s*\.\s*bind\s*\(\s*\w+\s*,\s*[\'"`]([^\'"`\s]{2,200})[\'"`]',
            re.IGNORECASE,
        )
        for _m in _WPK_BIND_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1), source)

        # __webpack_require__.e(chunkId).then(r => r("./mod.js")) variant
        _WPK_THEN_RE = re.compile(
            r'__webpack_require__\.e\s*\([^)]+\)\s*\.then\s*\([^)]{0,80}[\'"`]([^\'"`\s]{3,200}\.[jt]s(?:x?)[\'"`])',
            re.IGNORECASE,
        )
        for _m in _WPK_THEN_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1).strip('"\'`'), source)

        _DYNAMIC_FN_RE = re.compile(
            r'\bdynamic\s*\(\s*[\'"`]([^\'"`\s]{2,200})[\'"`]\s*[,)]',
            re.IGNORECASE,
        )
        for _m in _DYNAMIC_FN_RE.finditer(code):
            self._enqueue_dynamic_import(_m.group(1), source)

        # ── GAP 2 FIX: Dynamic import() graph traversal ───────────────────────
        # Captures ALL forms of code-splitting entry points and enqueues them for
        # a second-pass fetch+analysis so endpoints in lazy-loaded chunks are found.
        #
        # Form 1: import('./orders.module')  /  import('/chunks/payments.js')
        for m in re.finditer(
            r'\bimport\s*\(\s*[\'"`]([^\'"`\s]{3,200})[\'"`]\s*\)',
            code, re.IGNORECASE
        ):
            self._enqueue_dynamic_import(m.group(1), source)

        # Form 2: require.ensure([], callback, './admin.module')
        for m in re.finditer(
            r'\brequire\.ensure\s*\([^,)]*,[^,)]*,\s*[\'"`]([^\'"`\s]{3,200})[\'"`]',
            code, re.IGNORECASE
        ):
            self._enqueue_dynamic_import(m.group(1), source)

        # Form 3: __webpack_require__.e(chunkId) → chunk file name in comment or map
        # We can't resolve the chunkId→filename without the runtime map, but we
        # capture adjacent string literals that look like chunk filenames.
        for m in re.finditer(
            r'__webpack_require__\.e\s*\([^)]+\)[^"\'`]{0,120}[\'"`]([^\'"`\s]{3,200}\.js)[\'"`]',
            code, re.IGNORECASE
        ):
            self._enqueue_dynamic_import(m.group(1), source)

        # Form 4: dynamic('./feature/dashboard.module')  — generic dynamic() wrappers
        for m in re.finditer(
            r'\bdynamic\s*\(\s*[\'"`]([^\'"`\s]{3,200})[\'"`]\s*[,)]',
            code, re.IGNORECASE
        ):
            self._enqueue_dynamic_import(m.group(1), source)

    def _queue_lazy_chunk_paths(self, code, source):
        """Chunk paths with a JS/TS extension, resolved relative to the source file."""
        # ── GAP 2 FIX: Dynamic import() / require.ensure / webpack lazy chunk ──
        # Collects all statically-known chunk URLs for post-scan analysis.
        # Four forms:
        #   import('./orders.module.js')
        #   require.ensure(['./auth'], cb)
        #   __webpack_require__.e(chunkId)     → chunk URL resolved by harvester
        #   dynamic('./payments.bundle.js')
        #
        # We store resolved absolute URLs in self._dynamic_imports so that
        # EnhancedStaticAnalyzer.scan() can fetch & re-analyze them after the
        # primary sweep (same pipeline as Phase-1.85 external JS crawl).
        for m in re.finditer(
            r'(?:import\s*\(\s*|require\.ensure\s*\(\s*\[\s*|dynamic\s*\(\s*)'
            r'[\'"`]([^\'"`]{3,200}\.(?:js|mjs|cjs|ts|jsx|tsx))[\'"`]',
            code, re.IGNORECASE
        ):
            chunk_path = m.group(1)
            # Resolve relative paths against the source file URL
            try:
                abs_url = urllib.parse.urljoin(source, chunk_path)
            except Exception:
                abs_url = chunk_path
            if abs_url and abs_url not in self.analyzed_js_files:
                self._dynamic_imports.add(abs_url)

        # Also catch bare string paths inside webpack lazy chunk arrays:
        # require.ensure(['./admin/dashboard', './admin/users'], callback)
        for m in re.finditer(
            r'require\.ensure\s*\(\s*\[([^\]]{0,400})\]',
            code, re.IGNORECASE
        ):
            for path_m in re.finditer(r'[\'"`]([^\'"`]{3,200}\.(?:js|mjs|jsx))[\'"`]', m.group(1)):
                chunk_path = path_m.group(1)
                try:
                    abs_url = urllib.parse.urljoin(source, chunk_path)
                except Exception:
                    abs_url = chunk_path
                if abs_url and abs_url not in self.analyzed_js_files:
                    self._dynamic_imports.add(abs_url)

    def _queue_import_expressions(self, code, source):
        """import()/require.ensure/next dynamic() + webpack chunk-hash maps."""
        # ── GAP 2 FIX: Dynamic import() static URL extraction ─────────────
        # Collects all four forms that webpack/bundlers use to declare lazy routes:
        #
        #   1. import('./orders.module.js')
        #   2. require.ensure(['./payments'], ...)
        #   3. __webpack_require__.e(chunkId)  — chunk IDs resolved via chunk map
        #   4. dynamic(() => import('./admin/page'))  (Next.js dynamic)
        #
        # Discovered .js URLs are stored in self._dynamic_imports; the scan()
        # loop runs a second pass to fetch+analyze them, surfacing any endpoints
        # that live exclusively in lazy-loaded bundles.
        # ─────────────────────────────────────────────────────────────────────
        _base_origin = urllib.parse.urlparse(self.normalizer.base_url)
        _base_prefix = f"{_base_origin.scheme}://{_base_origin.netloc}"

        def _resolve_import_path(raw: str) -> str | None:
            """Resolve a relative import path to an absolute URL."""
            raw = raw.strip()
            if not raw:
                return None
            if raw.startswith('http'):
                return raw
            if raw.startswith('./') or raw.startswith('../'):
                # Resolve relative to the source file's directory
                src_dir = '/'.join(source.split('/')[:-1]) if '/' in source else _base_prefix
                try:
                    return urllib.parse.urljoin(src_dir + '/', raw)
                except Exception:
                    return None
            if raw.startswith('/'):
                return _base_prefix + raw
            return None

        # Form 1: import("./chunk") — dynamic import expression
        for m in re.finditer(
            r'\bimport\s*\(\s*[\'"`]([^\'"`\s]{3,200})[\'"`]\s*\)',
            code, re.IGNORECASE
        ):
            resolved = _resolve_import_path(m.group(1))
            if resolved and (resolved.endswith('.js') or '.js?' in resolved):
                self._dynamic_imports.add(resolved)
            elif resolved:
                # Non-JS lazy import (e.g. CSS module, JSON) — skip
                pass

        # Form 2: require.ensure(["./module"], callback)
        for m in re.finditer(
            r'require\.ensure\s*\(\s*\[\s*[\'"`]([^\'"`\s]{3,200})[\'"`]',
            code, re.IGNORECASE
        ):
            resolved = _resolve_import_path(m.group(1))
            if resolved:
                self._dynamic_imports.add(resolved)

        # Form 3: Next.js dynamic(() => import('./page'))
        for m in re.finditer(
            r'dynamic\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*import\s*\(\s*[\'"`]([^\'"`\s]{3,200})[\'"`]',
            code, re.IGNORECASE
        ):
            resolved = _resolve_import_path(m.group(1))
            if resolved:
                self._dynamic_imports.add(resolved)

        # Form 4: __webpack_require__.e(chunkId) — resolve via chunk filename map
        # We don't have the runtime chunk map here, but we can harvest filenames from
        # any chunkId→filename object literals in the same bundle, e.g.:
        #   {0: "a1b2c3", 1: "d4e5f6"}  combined with publicPath
        _pub_path = self.resolver.global_scope.get('publicPath', '') or ''
        if not _pub_path:
            _pub_path_m = re.search(r'__webpack_require__\.p\s*=\s*[\'"`]([^\'"`]+)[\'"`]', code)
            if _pub_path_m:
                _pub_path = _pub_path_m.group(1)
        if _pub_path:
            # Harvest chunk hash map: {chunkId: "hexhash", ...}
            for cm in re.finditer(
                r'\{\s*(?:\d+\s*:\s*[\'"`][a-f0-9]{6,20}[\'"`]\s*,?\s*){2,}\}',
                code
            ):
                chunk_pairs = re.findall(r'(\d+)\s*:\s*[\'"`]([a-f0-9]{6,20})[\'"`]', cm.group(0))
                for cid, chash in chunk_pairs[:30]:  # cap at 30 to avoid runaway
                    chunk_url = urllib.parse.urljoin(
                        _base_prefix + '/' + _pub_path.lstrip('/'),
                        f"{cid}.{chash}.chunk.js"
                    )
                    self._dynamic_imports.add(chunk_url)

    def _enqueue_dynamic_import(self, raw_path: str, referrer_url: str):
        """
        GAP 2 FIX — Dynamic import() graph traversal.
        Resolves a raw import path to an absolute URL and enqueues it for
        analysis.  Called from analyze_code whenever any of the four
        dynamic-import forms is detected:
          • import('./orders.module.js')
          • require.ensure(['./chunk'], cb)
          • __webpack_require__.e(chunkId)          ← chunk id only, skip
          • dynamic('./lazy.js') / loadChildren(...)
        """
        if not raw_path:
            return
        raw = raw_path.strip().strip('"\'`')
        if not raw or len(raw) < 3:
            return
        # Skip bare chunk IDs (webpack numeric IDs like "42")
        if re.match(r'^\d+$', raw):
            return
        # Skip non-JS assets
        if raw.endswith(('.css', '.png', '.svg', '.json')):
            return
        # Resolve to absolute URL
        if raw.startswith('http://') or raw.startswith('https://'):
            abs_url = raw
        else:
            try:
                base = referrer_url or self.base_url
                abs_url = urllib.parse.urljoin(base, raw)
            except Exception:
                return
        # Only enqueue same-origin or explicitly set JS files
        try:
            ref_host = urllib.parse.urlparse(self.base_url).netloc
            imp_host = urllib.parse.urlparse(abs_url).netloc
            if imp_host and imp_host != ref_host:
                return
        except Exception:
            return
        if abs_url not in self.analyzed_js_files and abs_url not in self._dynamic_imports:
            self._dynamic_imports.add(abs_url)
