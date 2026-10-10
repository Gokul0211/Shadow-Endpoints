"""Static webpack bundle splitter: analyze every module body individually."""
import re
from typing import TYPE_CHECKING

from shadow_scanner.config import logger

if TYPE_CHECKING:                       # type hint only - avoids a circular import
    from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer
class StaticWebpackModuleAnalyzer:
    """
    UPGRADE: Static webpack module body analyzer.

    When a webpack bundle is available as a JS file (not in the browser),
    this class extracts every individual module function from the bundle and
    feeds each one through the endpoint analyzer separately.

    This catches endpoints that are in modules which never execute during
    normal page navigation — e.g. admin panels, dead code, feature-flagged
    modules, and lazy routes that are never triggered.

    Supports webpack 4/5 bundle formats:
      • webpack 5 : (self.__webpack_modules__ = {id: function(...){...}})
      • webpack 4 : webpackJsonp([chunkId], {id: function(...){...}})
      • IIFE       : (function(modules){...})([function(){...}])

    False-positive risk: LOW — each module body passes through the full
    analyze_code() pipeline including Bayesian scoring and noise filtering.
    """

    # Maximum module source size to analyze (avoid slow analysis of huge vendor modules)
    MAX_MODULE_SIZE = 200_000  # 200 KB

    def __init__(self, analyzer: 'EnhancedStaticAnalyzer'):
        self.analyzer = analyzer

    def analyze_bundle(self, code: str, source_url: str) -> int:
        """
        Extract all webpack modules from a bundle and analyze each one.
        Returns count of new endpoints discovered.
        """
        if not re.search(r'__webpack_require__|webpackChunk|webpackJsonp|webpack_modules', code):
            return 0

        before = len(self.analyzer.endpoints)
        modules = self._extract_modules(code, source_url)

        processed = 0
        for module_id, module_src in modules.items():
            if len(module_src) < 80 or len(module_src) > self.MAX_MODULE_SIZE:
                continue
            if self._is_vendor_only(module_src):
                continue
            label = f"{source_url}::module_{module_id}"
            try:
                self.analyzer.analyze_code_from_dynamic(module_src, label)
                processed += 1
            except Exception:
                pass

        after    = len(self.analyzer.endpoints)
        new_eps  = after - before
        if new_eps > 0:
            logger.debug(f"[WPK-STATIC] {processed} modules → {new_eps} new endpoints from {source_url}")
        return new_eps

    def _extract_modules(self, code: str, source_url: str) -> dict:
        """Extract module ID → source body map from webpack bundle."""
        modules = {}

        # ── Pattern A: webpack 5 __webpack_modules__ ───────────────────────
        # (self.__webpack_modules__ = {"id": (function(__unused_module, exports, __webpack_require__) { ... })})
        wp5_match = re.search(
            r'(?:self\.__webpack_modules__|__webpack_modules__)\s*=\s*\{',
            code
        )
        if wp5_match:
            start = code.index('{', wp5_match.start())
            block = self._extract_brace_block(code, start)
            modules.update(self._parse_module_map(block))

        # ── Pattern B: webpack 5 webpackChunk.push ──────────────────────────
        # webpackChunk.push([[chunkId], {moduleId: function(){...}}])
        for m in re.finditer(r'webpackChunk\w*\.push\s*\(\s*\[', code):
            try:
                chunk_start = m.end()
                # Find the module map object — second element of the array
                obj_start = code.find('{', chunk_start)
                if obj_start == -1:
                    continue
                block = self._extract_brace_block(code, obj_start)
                modules.update(self._parse_module_map(block))
            except Exception:
                pass

        # ── Pattern C: webpack 4 webpackJsonp ──────────────────────────────
        # webpackJsonp([chunkId], {moduleId: function(module, exports, req){...}})
        for m in re.finditer(r'webpackJsonp\s*\(\s*\[[^\]]*\]\s*,\s*\{', code):
            try:
                obj_start = code.rindex('{', m.start(), m.end() + 1)
                block = self._extract_brace_block(code, obj_start)
                modules.update(self._parse_module_map(block))
            except Exception:
                pass

        # ── Pattern D: IIFE module array ────────────────────────────────────
        # (function(modules){...}([function(module,exports){...}, ...]))
        iife_m = re.search(r'\(function\s*\(\s*modules\s*\)', code)
        if iife_m and not modules:
            # Extract each element from the module array
            arr_m = re.search(r'\(\s*\[', code[iife_m.start():iife_m.start() + 200])
            if arr_m:
                abs_start = iife_m.start() + arr_m.end()
                depth = 1
                func_bodies = []
                i = abs_start
                func_start = abs_start
                while i < len(code) and i < abs_start + 5_000_000:
                    ch = code[i]
                    if ch == '[':   depth += 1
                    elif ch == ']':
                        depth -= 1
                        if depth == 0:
                            break
                    elif ch == ',' and depth == 1:
                        func_bodies.append(code[func_start:i].strip())
                        func_start = i + 1
                    i += 1
                for idx, body in enumerate(func_bodies[:500]):
                    if len(body) > 80:
                        modules[f'iife_{idx}'] = body

        # ── Pattern E: post-init individual assignments ─────────────────────
        # Handles: __webpack_modules__[847]=function(m,e,r){...}
        # This pattern occurs when the bundle initialises __webpack_modules__={}
        # (empty) then assigns each module separately, so Pattern A gets an
        # empty block and misses all module bodies.
        # Also catches minified aliases like: __[847]=function(m,e,r){...}
        # Always runs (also when patterns A-D already found modules).
        for m in re.finditer(
            r'(?:__webpack_modules__|__)\s*\[(\d+)\]\s*=\s*function\s*\(',
            code
        ):
            mod_id = m.group(1)
            if mod_id in modules:
                continue  # already harvested by an earlier pattern
            # Find the opening brace of the function body
            brace_pos = code.find('{', m.end())
            if brace_pos == -1:
                continue
            try:
                body = self._extract_brace_block(code, brace_pos)
                if len(body) > 80:
                    modules[f'wp_assign_{mod_id}'] = body
            except Exception:
                pass

        return modules

    def _extract_brace_block(self, code: str, start: int) -> str:
        """Extract a balanced {…} block starting at position start."""
        depth = 0
        end   = start
        for i, ch in enumerate(code[start:], start=start):
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        return code[start: end + 1]

    def _parse_module_map(self, block: str) -> dict:
        """
        Parse a webpack module map {id: function(){...}, id2: function(){...}}
        and return {module_id: source_body}.
        """
        modules = {}
        # Find each key: value pair where value starts with 'function' or '('
        for m in re.finditer(
            r'(?:"([^"]+)"|\'([^\']+)\'|(\d+))\s*:\s*(?:function|\()',
            block
        ):
            mod_id = m.group(1) or m.group(2) or m.group(3)
            body_start = m.end() - 1  # points to 'f' of function or '('
            # Extract to the matching closing brace
            try:
                # Find the opening brace of the function body
                ob_pos = block.index('{', body_start)
                body = self._extract_brace_block(block, ob_pos)
                # Lower threshold: 40 chars — even short modules may have an endpoint
                if len(body) > 40:
                    modules[mod_id] = body
            except (ValueError, IndexError):
                pass
        return modules

    @staticmethod
    def _is_vendor_only(source: str) -> bool:
        """
        Return True if the module looks like pure vendor/polyfill code.

        GAP 5 FIX: threshold lowered to 40 chars (matches _parse_module_map).
        Any module containing a URL-like string is never filtered — even if short.
        """
        # Never filter modules that contain actual URL/API strings
        if re.search(r'["\'][/][a-zA-Z]|https?://', source):
            return False
        if len(source) < 40:
            return True
        # No path-like strings → check for vendor signals
        vendor_signals = ['__esModule', 'Object.defineProperty(exports',
                          'use strict', 'core-js', 'regenerator']
        hits = sum(1 for sig in vendor_signals if sig in source)
        if hits >= 3:
            return True
        return False
