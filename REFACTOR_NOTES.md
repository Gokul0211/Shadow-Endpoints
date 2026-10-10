# Refactor notes

Source: `../main.py` (15,354 lines, working-tree version including the
uncommitted header-extraction changes). The original file is untouched.

## What changed structurally

| Original | Now |
|---|---|
| one 15,354-line file | 50 modules; largest file 1,165 lines |
| `analyze_code()`, 1,710 lines | orchestrator + ~35 named stages in `static/stages/*.py` |
| `scan()`, 609 lines | orchestrator + 11 steps in `static/stages/scan_steps.py` |
| `save_report()`, 533 lines | orchestrator + 8 helpers in `reporting/report.py` |
| `if __name__ == "__main__":` block, 625 lines | `cli.py` (setup) + `pipeline.py` (one function per phase) |
| `_navigate_routes_with_feedback()`, 389 lines | 177 lines + 3 helpers; injected JS moved to `dynamic/browser_scripts.py` (byte-identical) |

All extraction code was moved by slicing exact line ranges out of `main.py`, not
retyped. Comments (including the `FIX EP-*` / `TC-*` / `FP-*` markers) are kept.
Cosmetic only: trailing whitespace stripped, 74 `f"..."` strings without
placeholders turned into plain strings, over-indented one-line `except` bodies
re-indented. All of these are AST-neutral and were checked.

## Dead code removed

Each item below either can never execute or has a result nothing reads.
Removing it cannot change scan output (confirmed by the differential tests).

**Never-called methods**
- `EndpointClassifier.score_and_classify` (a shim that forwarded to `BayesianConfidenceScorer.score`)
- `EnhancedVariableResolver.resolve`, `EnhancedVariableResolver.get_all_service_properties`
- `EndpointProvenanceGraph.all_urls`, `EndpointProvenanceGraph.multi_source_urls`
- `EnhancedStaticAnalyzer._fetch_dynamic_imports` (`scan()` has its own inline loop)
- `AuthEngine.is_authenticated`, `BackendFileHunter.get_findings`

**Overridden duplicates**
- `EnhancedStaticAnalyzer._enqueue_dynamic_import` was defined twice. Python
  only ever used the second one (main.py line 7823); the first (6042) is gone.
- `EnhancedFederationHunter.hunt_webpack_chunks` was defined twice (identical).

**Values computed but never read**
- `EnhancedVariableResolver.obfuscated_strings` + `_extract_obfuscated_strings()`, `.file_variables`
- `analyzer.sourcemap_code_cache` (its comment referred to a function that does not exist)
- `save_report._domain_slug / _output_root / _sourcemaps_dir / _backend_dir`
  (`_last_json_path` / `_last_excel_path` are still set; the CLI reads them)
- `GraphQLIntrospector.graphql_endpoints`, `._apq_found` and a no-op `if ...: pass`
- `AliasResolver._dirty`, `ASTExtractionLayer.logger`
- Class constants never referenced: `EndpointClassifier.BLOCKED_DOMAINS` / `POLYFILL_NAMES`,
  `URLNormalizer._PARAM_COLON_RE` / `_PARAM_TMPL_RE` / `_NUMERIC_SEG_RE`,
  `IndexedDBExtractor._API_KEY_PATTERNS`, `BackendFileHunter.SEVERITY`
- Unused locals: `_INTERPROCEDURAL_NAME`, `_ENV_SECONDARY_KEYS`, `tier_order`,
  `closure_params`, `result_var`, `import math`, `_new_chunks_set`, `_snap16a`,
  and the unused halves of `run_sourcemap_harvest(...)` tuples (now `_`)
- A `for ... : pass` loop in the Nuxt extractor
- `page.evaluate("window.__beacon_urls")` in Phase 3 (result unused; beacons are
  already captured through `window.__api_calls`)

**Unreachable branches / always-true conditions**
- `BranchLogicExtractor._try_extract_string`: a second `BinaryExpression` branch
  shadowed by an identical earlier one
- `if not modules or True:` (webpack module extraction), plus two
  `if hasattr(self, 'resolver')` guards that are always true
- A nested `if _ext_js_urls:` inside an identical outer `if`
- `getattr(analyzer, '_js_cache', {})`: `_js_cache` is never set anywhere, so
  the lookup always missed
- `save_report` fallback `getattr(static, '_header_extractor')`: `static` is always a list
- `json_to_excel`'s `except ImportError` fallback for openpyxl: unreachable,
  because `ExcelWriter(engine='openpyxl')` already requires openpyxl
- `try: from bs4 import ...` in `_discover_subapp_bundles_postanalysis`: bs4 is
  a hard import at the top of the program anyway
- Duplicated entries in `NOISE_PATTERNS`: all 33 extra regexes were already in
  `_BLOCKED_PATTERNS`, so it is now `list(_BLOCKED_PATTERNS)`

**Non-functional Phase-3 lazy-chunk harvest** (`DynamicInterceptor`)
- It read `window.__lazy_chunks`, which the injected script initialises to `[]`
  and never fills, then called `analyzer._analyze_js_content()`, a method that
  does not exist (the `AttributeError` was swallowed). The `session` argument
  and attribute that existed only for this block were removed too. This is
  item T2 in `SCANNER_IMPROVEMENT_PLAN.md`. If you implement T2, re-add the
  harvest in `DynamicInterceptor._navigate_routes_with_feedback`, right after
  `self._harvest_sse_urls(page)`, calling `analyze_code_from_dynamic`.

**One reorder (provably safe):** the two groups of dynamic-import regexes in
`analyze_code` now run back to back, before the AST stage instead of on either
side of it. Both only add to `_dynamic_imports`, which the AST stage never reads.

## Bugs fixed (after the behaviour-identical refactor was verified)

All six exist in the original `main.py` and are fixed only in this package.
None of them is triggered by the SPABench apps, so the SPABench differential
test still gives identical results after the fixes. Each fix has its own
offline check.

1. **Crash: RPC pattern 8 used a non-existent `self.normalizer`.**
   `EnhancedRPCExtractor.extract_rpc_patterns` (`static/rpc_extractor.py`,
   "Pattern 8 ... RC4-FIX") raised `AttributeError` whenever a bundle contained
   `postDataFromUrl('api_...')` / `getDataFromUrl('/api...')` etc. In `scan()`
   step 2 that was uncaught, so **the whole scan aborted with "Fatal error"**.
   Fix: return the path with a leading slash; every caller already normalizes it
   to a full URL (e.g. `http://host/api_rc_simops/CheckSimops`).
2. **Phase-3 WebSocket capture never recorded anything.**
   `WebSocketDiscovery.intercept_playwright_websockets` injected its hook with
   `page.evaluate()` before `page.goto()`, and navigation wiped it (plan item T3.1).
   Fix: the hook (`WebSocketDiscovery._WS_HOOK_SCRIPT`) is registered with
   `page.add_init_script()`. Because it now really takes effect, it was also made
   safe for the page: it keeps `WebSocket.prototype` (`instanceof`) and the
   `CONNECTING/OPEN/CLOSING/CLOSED` constants, never throws inside `send()`, and
   patches only once per document.
3. **`webpack_module_paths` in the JSON report was always `[]`.**
   Fix: `SourceMapEngine._extract_single_map` records every application
   `webpack://` source path (de-duplicated; `node_modules` and webpack internals
   excluded by the existing `_sanitize_source_path` filter).
4. **APQ detection was print-only** (plan item T6.1).
   Fix: `GraphQLIntrospector.apq_endpoints` collects APQ-confirmed endpoints, and
   the analyzer's GraphQL step adds the ones that introspection didn't already add,
   as `GRAPHQL_APQ_ENDPOINT`. It is mapped to the scorer's existing but previously
   unused `apq_persisted` signal (LR 5.0).
5. **`--output` had no effect.** `save_report()` only used that filename when no
   target URL was available, which never happens from the CLI.
   Fix: `--output FILE` saves a copy of the JSON report to FILE (default: no copy,
   so plain runs don't create extra files). The report is still always written to
   `output/<domain>/json/<domain>_<timestamp>.json`.
6. **`--quiet` had no effect** (parsed, never read).
   Fix: `cli._run_scan_quietly` silences stdout for the scan and then prints the
   result paths. Setup prompts and error messages are still shown.

Not changed (documented limitation, not a bug): `--cache/--resume` only writes
URL metadata to disk, not file contents, so a resumed run still re-fetches JS.
The `--cache` help text says so.

## README

`README.md` is based on `Burp-extension-main/README.md`, updated for the
package layout and corrected wherever it disagreed with the code:
- 47 likelihood-ratio signals (not 36) and 20 Swagger paths (not 18); check these against the paper.
- TOTP is built in; `pyotp` is not used. `openpyxl` is required for the Excel export.
- Phase 3 does not fill forms; it clicks, hovers and scrolls.
- The output location and JSON entry format match what the code actually writes.
- The pipeline section follows the real execution order and names each module.
- `--cache/--resume`, `--output` and `--quiet` are described as they actually behave.
