"""Phase 3: live webpack module-registry extraction from the running page."""
import re

from shadow_scanner.config import logger
# ==============================================================================
# FEATURE 2: WEBPACK MODULE GRAPH RECONSTRUCTOR
# ------------------------------------------------------------------------------
# Webpack stores every module function (loaded AND lazy) inside a live registry:
#
#   window.__webpack_require__.m   (webpack 4/5)
#   window.webpackJsonp              (webpack 3 / older)
#
# This class injects a script into the running page AFTER navigation, calls
# .toString() on every module function in the registry, and feeds the raw
# source through the static analysis pipeline.
#
# Result: endpoints in lazy-loaded, never-navigated modules surface without
# any user interaction or navigation.
#
# False-positive risk: VERY LOW - extracted source is real JS, analysed by
# the same pipeline that handles every other JS file.
# ==============================================================================
class WebpackModuleGraphReconstructor:
    """
    Extracts and analyses every module from webpack live module registry.

    Works with webpack 4/5 (__webpack_require__.m), webpack 3 (webpackJsonp),
    and Rspack/Turbopack (same __webpack_require__ interface).

    Called from _navigate_routes_with_feedback() after the first page load.
    """

    _EXTRACT_SCRIPT = """
    (() => {
        const results = [];
        const seen = new Set();

        const tryModuleRegistry = (req) => {
            if (!req || typeof req.m !== 'object') return;
            for (const id in req.m) {
                try {
                    const src = req.m[id].toString();
                    if (src.length > 80 && !seen.has(src.slice(0, 64))) {
                        seen.add(src.slice(0, 64));
                        results.push({ id: String(id), source: src, via: 'require.m' });
                    }
                } catch (_) {}
            }
        };

        for (const key of Object.getOwnPropertyNames(window)) {
            try {
                const val = window[key];
                if (typeof val === 'function' && val.m && typeof val.m === 'object') {
                    tryModuleRegistry(val);
                }
            } catch (_) {}
        }

        if (Array.isArray(window.webpackJsonp)) {
            for (const chunk of window.webpackJsonp) {
                const moduleMap = chunk[1];
                if (moduleMap && typeof moduleMap === 'object') {
                    for (const id in moduleMap) {
                        try {
                            const src = moduleMap[id].toString();
                            if (src.length > 80 && !seen.has(src.slice(0, 64))) {
                                seen.add(src.slice(0, 64));
                                results.push({ id: String(id), source: src, via: 'jsonp' });
                            }
                        } catch (_) {}
                    }
                }
            }
        }

        return results;
    })()
    """

    _MIN_MODULE_LEN = 120

    def __init__(self, domain):
        self.domain = domain

    def extract_from_page(self, page, analyzer):
        """
        Run extraction on the current Playwright page.
        Returns count of new endpoints discovered.
        """
        before = len(analyzer.endpoints)

        try:
            modules = page.evaluate(self._EXTRACT_SCRIPT)
        except Exception as exc:
            logger.debug(f"[WPK] Module extraction script failed: {exc}")
            return 0

        if not modules:
            logger.debug("[WPK] No webpack modules found in page")
            return 0

        logger.debug(f"[WPK] Raw module count: {len(modules)}")

        processed = 0
        for mod in modules:
            source = mod.get('source', '')
            mod_id = mod.get('id', '?')
            via    = mod.get('via', '?')

            if len(source) < self._MIN_MODULE_LEN:
                continue

            if self._is_vendor_stub(source):
                continue

            label = f"webpack_module_{mod_id}[{via}]"
            try:
                analyzer.analyze_code_from_dynamic(source, label)
                processed += 1
            except Exception as exc:
                logger.debug(f"[WPK] analyze error module {mod_id}: {exc}")

        after   = len(analyzer.endpoints)
        new_eps = after - before
        if processed > 0:
            print(f"      [WPK] Processed {processed} webpack modules -> {new_eps} new endpoints")
        logger.debug(f"[WPK] Processed {processed} modules -> {new_eps} new endpoints")
        return new_eps

    @staticmethod
    def _is_vendor_stub(source):
        """Quick vendor check on raw module source."""
        if len(source) < 200:
            return True
        lines = [l.strip() for l in source.splitlines() if l.strip()]
        if len(lines) < 5:
            return True
        # Only flag as vendor stub if module has NO path-looking strings at all
        has_path = bool(re.search(r'["\'][/][a-zA-Z]', source))
        if not has_path:
            vendor_signals = ['This is a placeholder', '__esModule']
            for sig in vendor_signals:
                if sig in source:
                    return True
        return False
