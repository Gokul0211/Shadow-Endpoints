# Shadow Endpoints

**Hybrid Static–Dynamic Discovery of Hidden API Surfaces in Obfuscated Single-Page Applications**

Modern SPAs don't put their API URLs in the HTML. They assemble them at runtime from variable chains, template literals, lazy-loaded chunks, and GraphQL schemas, none of which a tool sees if it only greps strings out of JavaScript. Shadow Endpoints was built to work at the abstraction level where modern SPAs actually operate.

> **This folder is the refactored code base.** The original single 15,354-line `main.py` has been split into the `shadow_scanner/` package (50 focused modules): same CLI, same pipeline, same JSON report. The split itself was verified to produce **identical results**. Six bugs found along the way were then fixed (see [Fixed bugs](#fixed-bugs)). See [Code Layout](#code-layout) and [Refactor & Verification](#refactor--verification). The full list of removed dead code is in [`REFACTOR_NOTES.md`](REFACTOR_NOTES.md).

---

## What It Does

Shadow Endpoints runs a multi-phase pipeline across every available evidence layer: static AST analysis, source map decompilation, dynamic browser instrumentation, GraphQL introspection, WebSocket discovery and automated authentication. It scores every candidate with a Bayesian confidence model. The result is a ranked, tiered endpoint list with full provenance for each finding.

Evaluation results are being re-measured on SPABench v3.0.0 with the benchmark-specific rules removed from the scanner (see "Benchmark de-tuning" in `REFACTOR_NOTES.md`). Numbers will be added here only when produced by the benchmark's runner scripts.

---

## Key Features

- **Inter-procedural variable resolution**: traces `this.baseUrl` through 3+ files of constructor injection to rebuild full URLs that single-pass tools can't see
- **Source map decompilation**: recovers original TypeScript `.service.ts` files, `environment.ts` configs, OAuth endpoints and staging server URLs from `.map` files
- **Recursive lazy-loading feedback loop**: JS files discovered dynamically are fed back into the static phase, catching endpoints in chunks Phase 1 couldn't predict
- **GraphQL introspection**: enumerates all queries, mutations and subscriptions, plus APQ (Automatic Persisted Query) detection
- **WebSocket discovery**: static extraction, plus runtime monkey-patching of the native `WebSocket` constructor
- **Bayesian confidence scoring**: 49 hand-set likelihood-ratio signals combined into a continuous score (0–100), plus the evidence the score rests on; learned weights are the next step (see `vibe/scanner-plan.md`, Phase E)
- **Security-relevant header mining**: client-set secrets (API keys, hard-coded bearer tokens) and server-read trust headers (`X-Internal-IP`, `X-User-Role`, `X-Tenant-Id`…), from JS, recovered source and live browser traffic
- **De-obfuscation pre-pass**: `atob()`, `String.fromCharCode()`, hex escapes, `unescape()`, reversed strings and `eval(decoder(...))` wrappers are decoded before extraction
- **Authentication automation**: form login, Playwright browser login, built-in TOTP MFA, Bearer token injection
- **Vendor fingerprinting**: suppresses 65–80% of false positives from third-party library noise before scoring
- **Scan cache**: SHA-256-keyed cache of fetched JS (see the note under `--cache` for its resume limitation)
- **Multi-threaded static analysis**: 5–10x speedup via `ThreadPoolExecutor`; configurable worker count
- **Excel export**: optional filterable spreadsheet alongside the JSON report

---

## How It Works — The Pipeline

`shadow_scanner/pipeline.py` → `run_scan()` executes the phases **in this order**. The phase numbers are the labels used in the paper and console output, which is why Phases 1.55–1.85 run after Phase 2.

| Order | Phase | Function in `pipeline.py` | Main module(s) |
|---|---|---|---|
| 1 | **1** Federation discovery | `phase1_discovery` | `discovery/federation.py` |
| 2 | **1.5** Source map intelligence (+ Next.js hidden chunks) | `phase1_5_sourcemaps` | `discovery/sourcemaps.py`, `discovery/chunks.py` |
| 3 | **2** Static program analysis (+ GraphQL introspection) | `phase2_static_analysis` | `static/analyzer.py`, `static/stages/*` |
| 4 | **1.55** Sub-app index pages (recursive) | `phase1_55_subapp_index_pages` | `discovery/subapps.py` |
| 5 | **1.6** Webpack chunk harvester + sub-app bundles | `phase1_6_bundle_discovery` | `discovery/chunks.py`, `discovery/subapps.py` |
| 6 | **1.75** Service / web workers | `phase1_75_service_workers` | `discovery/service_worker.py` |
| 7 | **1.8** Exposed API intelligence | `phase1_8_backend_intel` | `discovery/backend_intel.py` |
| 8 | **1.85** Module Federation remotes | `phase1_85_external_js` | `pipeline.py` |
| 9 | **3** Dynamic browser instrumentation | `phase3_dynamic` | `dynamic/*` |
| 10 | **1.5b** Source maps for Phase-3-only bundles | `phase1_5b_phase3_sourcemaps` | `discovery/sourcemaps.py` |
| 11 | **4 / 5** Report + Excel | `_write_report` | `reporting/*` |

Bayesian scoring is not a separate pass. Every candidate is scored the moment it is added (`add_endpoint()`), and `save_report()` applies the final filter.

### Phase 1: Federation Discovery
*`discovery/federation.py` → `EnhancedFederationHunter`*

Finds every JavaScript bundle the target serves. Goes beyond `<script src>` tags to cover: `link rel="preload"` / `prefetch` / `modulepreload`, inline `import()` dynamic imports, `SystemJS.import`, `new Worker()` / `serviceWorker.register()`, `<noscript>` blocks, HTML comments, and webpack chunk-name maps. Also checks common config files (`/assets/config/environment.json`, …) and force-probes 22 common API roots (`/api`, `/graphql`, `/v1`, …).

### Phase 1.5: Source Map Intelligence
*`discovery/sourcemaps.py` → `SourceMapEngine`, `run_sourcemap_harvest`*

For every JS bundle found, it checks manifest files, parses `//# sourceMappingURL=` directives, derives likely `.map` URLs, and decodes inline base64 maps. It decompiles the source maps back to TypeScript. That recovers `.service.ts` files (HTTP call signatures, type annotations), `environment.ts` (API base URLs, OAuth endpoints, staging server URLs) and `auth.service.ts`. Every original source path is catalogued, and `.d.ts` declaration files are probed. Recovered sources go through the full Phase-2 pipeline. On Target-A from the evaluation, this phase alone found 150 exclusive endpoints (35.6% of total), none of which any competing tool found.

Related phases:
- **Phase 1.5a: Next.js hidden chunk enumeration** probes `/_next/static/chunks/` for API-route and resolver bundles that HTML never links to (`discovery/chunks.py`).
- **Phase 1.55: Sub-app index page discovery** scans fetched JS for sub-app base paths (`ui_*`, `app_*`, …). It probes them as independent HTML entry points with their own bundles, and runs twice to catch nested sub-apps (`discovery/subapps.py`).
- **Phase 1.6: Webpack chunk harvester** reads chunk maps from webpack 4/5 runtimes and Vite/asset manifests deterministically, then falls back to heuristic sub-app bundle discovery (`discovery/chunks.py`).
- **Phase 1.85: Module Federation remotes** fetches `remoteEntry.js` (including same-host remotes), follows it to the sibling `main.js`, and harvests that bundle's source map.
- **Phase 1.5b** harvests source maps for bundles that were first seen during Phase 3.

### Phase 2: Static Program Analysis
*`static/analyzer.py` → `EnhancedStaticAnalyzer.scan()`*

The core static layer, running on all bundles including those discovered in Phases 1.5/1.55/1.6. `scan()` performs these steps, from `static/stages/scan_steps.py`:
1. Fetch every bundle in parallel and extract variables.
2. Resolve DI chains across files (up to 5 passes).
3. Extract RPC and array-harvested endpoints.
4. Extract service-property endpoints.
5. Run `analyze_code()` on every bundle in parallel.
6. Analyze each webpack module body individually.
7. Extract static WebSocket URLs.
8. Make two rounds of lazy dynamic-import fetching.
9. Apply the confidence filter.
10. Run **GraphQL introspection**.

**EnhancedVariableResolver** (`static/variable_resolver.py`) does inter-procedural constant propagation, tracking:
- `var`/`let`/`const` declarations
- `this.prop = value` assignments and cross-file DI chain resolution
- Object literal property paths (`cfg.method`, `VERSIONS.prod`, `api.baseUrl`)
- Array element indexing (`arr[0]` → `arr.0`)
- Method return values (`getApiBase()` returning a base URL), environment-object keys
- `this.X = this.Y + this.Z` concatenation with both operands resolved

**EnhancedRPCExtractor** (`static/rpc_extractor.py`) reconstructs endpoints from string concatenation driven by the resolver. Examples: `this.prop = this.getBase() + "path"`, `base + "/users/" + id + "/status"`, custom wrappers like `postDataFromUrl(...)`, and `this.http.get(this.apiBase + this.endpoint)`.

**`analyze_code()`** runs ~35 extraction stages in a **fixed order** (order matters: on equal confidence, de-duplication keeps the first finding). Each stage family lives in its own mixin under `static/stages/`:
- **HTTP clients** (`http_clients.py`): Angular `HttpClient` and injected service wrappers, named axios instances, `fetch()`, Vue 3 / Nuxt `useFetch` / `useAsyncData` / `$fetch`, React `useEffect + fetch`, `new URL()`, URL-builder helpers, promise chains, axios interceptors, SOAP bridge calls
- **Framework conventions** (`frameworks.py`): Next.js API routes (route comments and `pages/api` files), tRPC procedures (flat and nested), Nuxt 3 `server/api` routes, `gql` tagged GraphQL operations, Tanstack/React Router routes, JSDoc `@openapi` annotations, RTK Query, React Query, SWR, Apollo mutations
- **Inter-procedural** (`interprocedural.py`): a regex-level registry of URL-builder functions evaluated at call sites, SSA-style propagation (`const url = buildUrl("x"); fetch(url)`), and `{version}` expansion
- **Literal sweeps** (`literals.py`): hard-coded private IPs, `process.env` / `import.meta.env` fallbacks, WebSocket literals, template literals with `${VAR}` resolution, `/api/...` and `api_<svc>/<Method>` literals, external API hosts, and a LinkFinder-style sweep with false-positive filters
- **Routes** (`routes.py`): router / history / hash-route / `location.origin` navigation (scored as front-end routes)
- **Dynamic imports** (`dynamic_imports.py`): `import()`, `require.ensure`, `__webpack_require__`, Next.js `dynamic()` and chunk-hash maps, all queued for a second fetch pass
- **AST layer** (`static/ast_engine/`, Esprima): `AliasResolver` scope building, `ComputedPropertyExtractor` (`api["get"]("/path")`), `TemplateLiteralExtractor`, **BranchLogicExtractor** (feature-flag ternaries, switch/if branches), `ObjectExpressionExtractor`, and two call-graph engines. **ASTCallGraphExtractor** handles class, object-literal and prototype methods with `this`-scope, HOFs and IIFEs. **ASTCallGraph** resolves pure function chains. Together they are the highest-confidence static signal (`ast_call_graph`, LR = 7.5).

**TypeScriptParameterExtractor** (`static/ts_params.py`) recovers request parameters using 7 techniques without a TypeScript compiler: interface/type-alias registries, generic type annotations on HTTP calls, `HttpParams` chains, backward taint from adjacent object literals, `URLSearchParams` constructors, `FormGroup` field declarations, and forward object scanning.

**SecurityHeaderExtractor** (`static/security_headers.py`) mines security-relevant headers from every analyzed file:
- **client-set** headers carrying secrets: `headers: {...}`, `setRequestHeader`, `HttpHeaders().set`, `axios.defaults.headers`
- **server-read** trust headers: `req.headers['x-internal-ip']`, `request.headers.get(...)`, Express `req.get(...)`

There are 72 catalogued headers, and severity escalates for server-read trust headers and hard-coded secret values.

### Phase 2.5: URL value-flow analysis

Runs after every bundle, sub-app and source map has been fetched (and once more if the browser phase brought new code).
All client code the scan has seen (bundles and the TypeScript/JSX sources embedded in source maps) is handed to a
Babel-based Node.js sidecar (`analysis/`, see `analysis/src/*.js`). It parses every file (TypeScript, JSX, modern syntax),
builds the module graph (ES imports, CommonJS `require`, webpack module tables) and evaluates the URL that reaches each
**HTTP sink** as a set of *templates*: literal text plus typed holes (`param`, `unknown`, `origin`, `env`, `runtime`).
Config objects, class fields, getters, `this.x`, services injected by TypeScript type, function calls and
`axios.create({baseURL})` instances are followed across modules. A function whose parameter reaches a sink is detected as a
wrapper automatically and its call sites (in any file) are analysed with the arguments substituted; data arguments stay
`{param}` (so `/api/users/{id}`, not `/api/users/5`). The method comes from the sink (`axios.post`, `fetch(url, {method})`,
`xhr.open`), not from nearby text.

Sinks: `fetch`/`Request`, `XMLHttpRequest.open`, `WebSocket`, `EventSource`, `sendBeacon`, imported HTTP libraries and their
`.get/.post/...` calls, `HttpClient`-typed receivers, `$http`/jQuery, and (URL-shaped first argument only) unknown receivers.
GraphQL resolver maps, decorators and SDL are recognised as operations. Each finding is evidence of type `VALUEFLOW_SINK`
with the sink kind, wrapper chain and hole classes under `evidence[].detail`. `--disable-extractor value_flow` or
`--disable-phase 2.5` switches it off.

### Phase 1.75: Service Workers
*`discovery/service_worker.py` → `ServiceWorkerAnalyzer`*

Finds service workers and web workers: `serviceWorker.register()` and `new Worker()` in HTML and JS, plus 24 common paths. Runs them through the analyzer, and extracts `cache.addAll` precache routes, URL-rewrite rules and `respondWith(fetch(...))` intercepts.

### Phase 1.8: Exposed API Intelligence
*`discovery/backend_intel.py` → `BackendFileHunter`*

Probes for server-side artifacts and parses them straight into the endpoint pool:
- **backend source maps** (`dist/*.js.map` with full backend TypeScript)
- **OpenAPI/Swagger specs** (20 standard paths, JSON/YAML/embedded Redoc-Scalar, `$ref` resolution)
- **Spring Boot Actuator** `/actuator/mappings`
- **SOAP WSDL** operations (15 paths, with bridge-path verification against cross-app contamination)
- **Next.js** `pages-manifest.json` / API routes

A catch-all SPA fingerprint stops index.html fallbacks being counted as hits.

### Phase 3: Dynamic Browser Instrumentation
*`dynamic/interceptor.py` → `DynamicInterceptor`*

Headless Chromium (via Playwright) navigates discovered routes at increasing depth while it:
- Intercepts XHR and `fetch` requests at the network level, and patches `fetch` / `XMLHttpRequest` / `EventSource` / `sendBeacon` / axios / GraphQL-over-fetch at the prototype level. The injected script is in `dynamic/browser_scripts.py`.
- Reads the webpack module registry directly through JavaScript evaluation to harvest modules that were never navigated to (**WebpackModuleGraphReconstructor**, `dynamic/webpack_runtime.py`).
- Crawls actively: clicks admin/settings links, buttons, submit buttons, tabs, selects and hover targets, scrolls, and collects internal links for the next depth.
- Mines `localStorage`/`sessionStorage` for API base URLs and inspects every IndexedDB store (**IndexedDBExtractor**, `dynamic/indexeddb.py`).
- Runs **WebSocketDiscovery**, which monkey-patches the native `WebSocket` constructor (registered with `add_init_script`, so it survives navigation) to capture `ws://`/`wss://` connections and sampled messages.
- Feeds live request and response headers to the security-header miner.
- Sends every newly discovered JS file back into the Phase-2 analyzer. This is the **feedback loop** that enables lazy-loaded chunk discovery.

With an auth token, it injects the token into browser storage and re-visits common routes in a second pass.

### Phase 4: Protocol Expansion
*`protocols/graphql.py`, `protocols/websockets.py`*

**GraphQLIntrospector** runs at the end of Phase 2. It detects GraphQL endpoints through path heuristics, common paths and API hosts from the resolver, sends a standard introspection query, and parses the full schema. Every query, mutation and subscription becomes an endpoint (`…/graphql#OperationName`). It also detects SPA-proxied GraphQL, and probes for APQ: a fake-hash probe, `/.well-known/apollo/persisted-queries`, and query maps.

### Phase 4/5: Bayesian Confidence Scoring & Report
*`core/scoring.py` → `BayesianConfidenceScorer`; `reporting/report.py` → `save_report()`*

Every candidate passes through `BayesianConfidenceScorer.score()`:

```
P(API | signals) = [ P(API) × ∏ LRᵢ ] / [ P(API) × ∏ LRᵢ + (1 − P(API)) ]
```

The prior is `P(API) = 0.35`. There are 49 signals, each with a (hand-set, provisional) likelihood ratio, and 79 extraction types mapped to them. The score maps to a tier:

| Score | Tier | Use case |
|-------|------|---------|
| ≥ 85 | `HIGH_CONFIDENCE` | Strong static or spec evidence (not observed at runtime) |
| 55–84 | `BACKEND_API` | Penetration testing: verified list, minimal triage |
| 30–54 | `LOW_CONFIDENCE` | Bug bounty: maximum reach, includes partial paths |
| < 30 | `NOISE_CANDIDATE` | Filtered from output |

`VERIFIED_API` is reserved for requests **observed in browser traffic** (runtime evidence): such an endpoint is scored 100. Nothing else may carry that label; spec-declared routes (OpenAPI, Actuator, WSDL, Next.js manifest, GraphQL introspection) are a separate evidence kind. Vendor source paths get an LR penalty of 0.2 before scoring. **EndpointProvenanceGraph** (`core/provenance.py`) adds up to +30 when independent categories (RUNTIME, SCHEMA, CONFIG, SOURCEMAP, STATIC, STORAGE, PROBE) confirm the same URL; endpoints supported only by inference (INFERRED, e.g. a `pages/api/<file>` route guessed from a file name) are left out of the report unless `--include-inferred` is given.

The scorer also implements `calibrate_from_labels()`: MLE-based LR calibration from labeled ground truth, with Laplace smoothing (Jeffreys prior α = 0.5). It computes Wilson 95% CIs for per-tier precision reporting.

`save_report()` then:
1. Merges static and dynamic results, de-duplicating on URL.
2. Applies the final noise filter.
3. Writes the JSON report and prints the console summary.

`json_to_excel()` then writes the spreadsheet.

---

## Installation

### Requirements

- Python 3.10+

### Install core dependencies

```bash
pip install -e .            # exact versions are pinned in pyproject.toml
# or: pip install requests beautifulsoup4 urllib3 esprima openpyxl
```

### Install the value-flow sidecar (recommended)

The URL value-flow analysis runs in a small Node.js program (`analysis/`, Babel parser). It needs Node 20.19+ and one command; without it the scanner still runs, the `value_flow` extractor just logs a warning and does nothing.

```bash
cd analysis && npm ci --ignore-scripts
```

`SHADOW_ANALYSIS_DIR` points the scanner at a different location of that folder.

### Install Playwright (required for Phase 3 dynamic analysis)

```bash
pip install playwright
python -m playwright install chromium
```

TOTP MFA needs **no extra package**. A minimal RFC 6238 implementation is built in (`auth.py`).

---

## Usage

Run from inside this `refactored/` folder. Output folders are created relative to the directory you run from.

```bash
python main.py --target https://example.com
# equivalent:
python -m shadow_scanner --target https://example.com
```

### Authenticated scan — form login

```bash
python main.py --target https://example.com \
  --login-url https://example.com/login \
  --username admin --password secret
```

### Authenticated scan — browser login (JS-rendered forms, SPAs)

```bash
python main.py --target https://example.com \
  --login-url https://example.com/login \
  --username admin --password secret \
  --browser-login
```

### With TOTP MFA

```bash
python main.py --target https://example.com \
  --login-url https://example.com/login \
  --username admin --password secret \
  --browser-login --mfa-secret JBSWY3DPEHPK3PXP
```

### Login API differs from the login page

```bash
python main.py --target http://localhost:3001 \
  --login-url http://localhost:3001/login \
  --api-login-url http://localhost:4001/api/auth/login \
  --username admin --password secret
```

### Bearer / JWT token injection

```bash
python main.py --target https://example.com \
  --bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Pre-captured cookies

```bash
python main.py --target https://example.com \
  --cookies "session=abc123; csrf=xyz789"
```

### With scan cache

```bash
python main.py --target https://example.com --cache scan.json
python main.py --target https://example.com --cache scan.json --resume
```

### Rate limiting (for WAF-protected targets)

```bash
python main.py --target https://example.com --delay 0.5 --workers 5
```

Exponential backoff on HTTP 429/503 is applied automatically regardless of `--delay`.

### Custom depth and breadth

```bash
# Deep scan
python main.py --target https://example.com --max-routes 50 --max-depth 5

# Fast scan
python main.py --target https://example.com --max-routes 10 --max-depth 2 --no-cookies
```

---

## All CLI Options

`python main.py --help` prints the same help text as the original single-file version.

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | *(interactive prompt)* | Target URL to scan (`https://` is added if missing) |
| `--output` | *(none)* | Also save a copy of the JSON report to this path, e.g. `--output results.json` for `evaluate.py --tool-output results.json`. The report is always written to `output/<domain>/json/` as well (see [Output](#output)) |
| `--max-routes` | 30 | Max routes to visit per depth in Phase 3 |
| `--max-depth` | 5 | Max browser navigation depth (`0` skips route navigation) |
| `--delay` | 0.0 | Fixed inter-request delay in seconds |
| `--workers` | 15 | Parallel fetch workers for Phase 2 |
| `--timeout` | 30.0 | Timeout for Phase-2 JS fetches in seconds (other probes use fixed 4–15 s timeouts) |
| `--cache` | *(none)* | Scan cache file path |
| `--resume` | false | Resume using the cache file (requires `--cache`). Only URL metadata is written to disk, not file contents, so a resumed run still re-fetches JS |
| `--cookies` | *(none)* | Pre-captured cookie string (`name=value; name2=value2`) |
| `--no-cookies` | false | Skip the interactive cookie prompt |
| `--bearer` | *(none)* | Bearer/JWT token, injected directly (skips the login flow) |
| `--login-url` | *(none)* | Login page URL |
| `--username` | *(none)* | Login username or email |
| `--password` | *(none)* | Login password |
| `--username-field` | *(auto-detect)* | HTML `name` attribute for the username input |
| `--password-field` | *(auto-detect)* | HTML `name` attribute for the password input |
| `--browser-login` | false | Use Playwright for login (JS-rendered / SPA login pages) |
| `--mfa-secret` | *(none)* | TOTP MFA secret (base32 string) |
| `--api-login-url` | *(none)* | Direct API POST endpoint, for when `--login-url` is a SPA front-end route that returns 405 on POST |
| `--verbose` / `-v` | false | Enable debug logging (cache hits, rate-limit events, suppressed errors) |
| `--quiet` | false | Hide scan progress output and print only the result paths. Setup prompts and errors are still shown |
| `--include-inferred` | false | Also report endpoints supported only by inference (e.g. `pages/api` routes guessed from file names) |
| `--no-probe` | false | Do not request well-known paths nothing references (common API paths, OpenAPI/Actuator/WSDL/Next.js/GraphQL locations, service-worker names, `.d.ts` guesses) |
| `--scope HOST` | - | Treat HOST (and subdomains) as first-party besides the target's own site; repeatable. Credentials (tokens, cookies, API keys) are sent only to first-party hosts |
| `--scope-strict` | false | Send no request (HTTP or browser) to hosts outside the scope; without it such requests are made but carry no credentials |
| `--seed` | 0 | Seed for the scanner's own randomness |
| `--openapi FILE` | - | Also write the discovered surface as an OpenAPI 3.0 JSON document (scores and evidence kinds as `x-` extensions; nothing invented) |
| `--postman FILE` | - | Also write a Postman v2.1 collection |
| `--export-min-score N` | 0 | Leave endpoints scoring below N out of the two exports |
| `--max-requests` / `--max-bytes` | unlimited | Request / response-byte budget; once used up no further request is sent |
| `--request-log` | *(none)* | JSON-lines log of every request (method, URL with secret-looking query values masked, status, bytes, seconds, phase). Headers and bodies are never logged |
| `--verify-tls` | false | Verify TLS certificates (off by default, as in earlier versions) |
| `--disable-phase` | *(none)* | Skip a pipeline phase (repeatable): `1.5 2 1.55 1.6 1.75 1.8 1.85 3 1.5b`. Phase 1 always runs |
| `--disable-extractor` / `--only-extractor` | *(none)* | Switch extractors off / run only the named ones (repeatable), for ablations. `--list-extractors` prints the names |

**Credentials.** `--password`, `--bearer`, `--cookies` and `--mfa-secret` can be supplied through the environment
instead (`SHADOW_PASSWORD`, `SHADOW_BEARER`, `SHADOW_COOKIES`, `SHADOW_MFA_SECRET`) so they stay out of shell history.
They are never written to the report: the `run.args` block shows them as `<redacted>`.

**Run metadata.** Every report has a `run` block: scanner git SHA and dirty flag, Python and package versions, a hash
of the result-relevant configuration, arguments (secrets redacted), wall time and request counts per phase, HTTP
totals, per-extractor sightings and error counts, and `swallowed_errors` (errors the scanner survived, by module).

**Tests and offline benchmark.** `python -m unittest discover -s tests` runs the unit tests and the offline SPABench
regression tests (needs the SPABench checkout next to this repository, or `SPABENCH_DIR`; they are skipped otherwise).
`python tools/offline_bench.py [--disable-extractor NAME ...]` runs the static phase on SPABench's own files with no
network and scores it with `evaluate.py`.

---

## Output

Every run is non-destructive and writes to a per-target folder:

```
output/<domain>/
├── json/<domain>_<YYYYmmdd_HHMMSS>.json     ← the report
├── excel/<domain>_<YYYYmmdd_HHMMSS>.xlsx    ← same endpoints as a spreadsheet
├── sourcemaps/{maps,extracted}/              ← downloaded .map files + recovered sources
└── backend/                                  ← saved OpenAPI / actuator / backend-map artifacts
```

Each endpoint entry carries full provenance (real example from SPABench):

```json
{
  "endpoint": "http://localhost:3002/api/admin/users/",
  "method": "PATCH",
  "parameters": ["generateReport", "getMonthlyReport", "role"],
  "type": "RPC_HTTP_CALL_DYNAMIC",
  "source": "main.js",
  "classification": "VERIFIED_API",
  "confidence_score": 100,
  "auth_required": true,
  "auth_method": "bearer",
  "origin": {
    "is_vendor": false,
    "extraction_type": "RPC_HTTP_CALL_DYNAMIC",
    "provenance": ["RUNTIME"],
    "provenance_sources": 1
  },
  "tags": ["verified_dynamic", "api_path", "non_get_method"]
}
```

The `tags` array holds the Bayesian signals that fired, and shows exactly why an endpoint got its score. Look at the tags on any endpoint and you'll see why it landed at that confidence level. You can then decide whether to trust it without re-running the scan. `type` is the extraction technique, and `origin.provenance` lists the independent evidence categories.

The report's top-level sections:

| Key | Contents |
|---|---|
| `scan_metadata` | scanner version, timestamp, target, capabilities, Phase-3 status, Bayesian scorer configuration |
| `summary` | endpoint count per classification |
| `tier_statistics` | per-tier counts with Wilson 95% CI support (`BayesianConfidenceScorer.tier_statistics()`) |
| `endpoints` | all endpoints, sorted by confidence. GraphQL operations appear as `…/graphql#OperationName` |
| `security_findings` | admin panels, auth / debug endpoints, staging URLs, internal IPs, WebSockets, exposed GraphQL, plus HIGH/CRITICAL header findings |
| `security_headers` | every security-relevant header: direction (`client_set` / `server_read`), category, severity, sources, leaked value |
| `provenance_summary` | multi-source confirmed / runtime-verified / schema-discovered counts |
| `external_links` | external URLs classified as INTERNAL_SUBDOMAIN, SSO_AUTH, PARTNER_API, CDN_ASSET, ANALYTICS |
| `discovered_source_maps`, `ts_architecture_catalog`, `ts_declaration_files`, `webpack_module_paths` | source-map intelligence |
| `backend_intelligence` | Swagger specs, backend maps and actuator routes found in Phase 1.8 |

The format is unchanged by the refactor; SPABench's `evaluate.py` reads it with `--format spabench-v1`.

---

## Selected Likelihood Ratios

The full table is `BayesianConfidenceScorer.LR` in `shadow_scanner/core/scoring.py`.

| Signal | LR | What it means |
|--------|-----|---------------|
| `verified_dynamic` | ∞ (capped 10⁹) | Directly observed in live browser traffic |
| `ts_service_file` | 8.0 | From decompiled TypeScript `.service.ts` |
| `ast_call_graph` | 7.5 | Full Esprima AST call graph resolution |
| `httpclient_angular` | 7.0 | Angular `HttpClient` call pattern |
| `nuxt_server_route` | 6.5 | Nuxt 3 server/api filesystem route |
| `jsdoc_openapi` | 6.0 | JSDoc `@openapi` annotation |
| `rtk_query` | 5.5 | RTK Query / React Query / SWR hook |
| `multi_source` | 5.0 | Confirmed by two or more independent phases |
| `non_get_method` | 2.5 | POST / PUT / DELETE / PATCH detected |
| `api_path` | 2.0 | URL contains `/api/`, `/v1/`, `/v2/`, etc. |
| `vendor_source` | 0.2 | Path comes from third-party vendor code |
| `frontend_route_nav` | 0.05 | Router navigation call (client-side route, not API) |
| `library_artifact` | 0.05 | Bundled library artifact (Moment.js, etc.) |

---

## Noise Filtering

The **unified blocklist** in `shadow_scanner/config.py` (67 keywords, 44 regex patterns) is the single source of truth. It covers:
- Font/CSS noise (`helvetica`, `animation-timing-function`)
- Angular internals (`ngDirectiveDef`, `ngModuleDef`)
- Build/tooling artifacts (`node_modules`, webpack internals)
- Excel/OOXML internals (SheetJS bundle strings)
- Crypto polyfill package names (`elliptic`, `browserify-sign`, `pbkdf2`)
- Binary/unicode escape sequences from xlsx/crypto bundles
- Developer local absolute paths from source maps (`/Users/...`, `C:\...`)
- XML/HTML schema namespaces (`w3.org`, `xmlns`)
- Unresolved template literals (`${`, `{{`)
- Angular Module Federation lazy-load path artifacts
- SPA front-end router paths (pure client-side navigation, no backend call)

`LibraryFingerprint` (`core/scoring.py`) also identifies vendor code through path indicators (`node_modules`), library name signatures and file-hash patterns, and applies an aggressive LR penalty before scoring. This module alone suppresses 65–80% of the false positives that regex-based extractors produce on production targets. Before any extractor runs, a pre-processing stage (`static/stages/preprocessing.py`) neutralises comment lines, TypeScript type unions, test-framework labels and route-map keys.

---

## Supported Frameworks

| Framework | Static | Dynamic | Source Maps |
|-----------|--------|---------|-------------|
| Angular 8–17 | ✅ | ✅ | ✅ |
| Angular Module Federation | ✅ | ✅ | ✅ |
| React 16–19 | ✅ | ✅ | ✅ |
| Vue 3 / Nuxt | ✅ | ✅ | ✅ (when available) |
| Next.js | ✅ | ✅ | ✅ |
| tRPC | ✅ | — | — |
| RTK Query / React Query / SWR | ✅ | — | — |
| GraphQL (any backend) | ✅ | ✅ | ✅ |
| WebSocket (any) | ✅ | ✅ | — |
| SOAP/WSDL | — | ✅ | — |
| Spring Boot Actuator | ✅ | — | — |
| OpenAPI / Swagger | ✅ | — | — |

---

## Authentication Support

*`shadow_scanner/auth.py` → `AuthEngine`; wired up in `cli.py`*

| Method | How |
|--------|-----|
| Form login | `requests`-based POST to the login endpoint: fast, no browser. Auto-detects field names and CSRF tokens; on HTTP 405 it retries common API login paths |
| Browser login | Playwright fills and submits the login form; handles JS-rendered SPAs |
| TOTP MFA | Built-in RFC 6238 TOTP code generation during browser login (no `pyotp` needed) |
| Bearer token | Injects `Authorization: Bearer <token>` into all requests and into browser storage for Phase 3 |
| Pre-captured cookies | Parses a `name=value; name2=value2` string into session cookies |
| Interactive | Prompts for cookie name/value pairs at runtime |

Tokens are harvested automatically from login responses, `localStorage`/`sessionStorage` and common `window` globals.

**Current limitation:** Full SAML 2.0 and OIDC assertion workflows are not yet supported. Endpoints behind these auth walls are still found by static analysis, because Phase 2 reads publicly served JS regardless of auth state. Only Phase 3 dynamic navigation is restricted.

---

## Performance

*These timings come from earlier measurements on production targets and are not regenerated by a script; treat them as indicative. Per-phase wall time and request counts of every scan are now recorded in the report's `run` block.*

Benchmarked on MacBook Pro M2, 16 GB RAM, 100 Mbps connection:

| Target | Total Time | Phase 3 Time | Notes |
|--------|------------|-------------|-------|
| Angular 8 SPA (9.4 MB bundle) | ~25 min | ~18 min | 26 source maps |
| Angular 17 Module Federation (~60 MB) | ~43 min | ~32 min | 4 source maps, 24 micro-frontends |

Phase 3 dominates runtime. Phase 2 scales linearly with total bundle size. Memory use during Phase 2 peaks at ~1.1 GB on the larger target because of concurrent AST representations. Bundles over 15 MB skip AST parsing; the regex extractors still run.

**Speed-up options:**
- `--workers N`: more parallel fetch workers (default 15)
- Static-only: Phase 3 is skipped automatically when Playwright isn't installed, and `--max-depth 0` skips route navigation. Static-only finishes in under 6 minutes on a 9.4 MB target, with ~36% less coverage
- `--max-routes` / `--max-depth`: trade coverage for time in Phase 3

---

## Code Layout

```
refactored/
├── main.py                       entry point: python main.py --target ...
├── README.md                     this file
├── REFACTOR_NOTES.md             what changed vs the single-file version
├── pyproject.toml  Dockerfile    packaging (pinned versions), image with Node + Playwright
├── analysis/                     Node.js value-flow sidecar (Babel): src/*.js, test/*.test.js
├── tools/offline_bench.py        static phase vs SPABench's own files, no network/Docker
├── tests/                        Python unit + offline-benchmark regression tests
└── shadow_scanner/
    ├── __main__.py               python -m shadow_scanner
    ├── cli.py                    argument parsing, connectivity check, session, auth, main()
    ├── pipeline.py               run_scan(): every phase in execution order   ← start reading here
    ├── config.py                 logging, optional deps, UNIFIED BLOCKLIST, constant tables
    ├── auth.py                   AuthEngine
    │
    ├── core/                     cross-cutting building blocks
    │   ├── scoring.py            BayesianConfidenceScorer, LibraryFingerprint, EndpointClassifier
    │   ├── provenance.py         EndpointProvenanceGraph
    │   ├── url_normalizer.py     URLNormalizer (must stay consistent with evaluate.py)
    │   ├── rate_limiter.py       RateLimiter
    │   └── scan_cache.py         ScanCache
    │
    ├── discovery/                Phases 1, 1.5, 1.55, 1.6, 1.75, 1.8
    │   ├── federation.py         EnhancedFederationHunter
    │   ├── external_links.py     ExternalLinkExtractor
    │   ├── sourcemaps.py         SourceMapEngine, run_sourcemap_harvest
    │   ├── chunks.py             WebpackChunkHarvester, Next.js hidden chunks
    │   ├── subapps.py            sub-app / micro-frontend bundle discovery
    │   ├── service_worker.py     ServiceWorkerAnalyzer
    │   └── backend_intel.py      BackendFileHunter
    │
    ├── static/                   Phase 2
    │   ├── analyzer.py           EnhancedStaticAnalyzer (state + scan()/analyze_code() orchestrators)
    │   ├── stages/               the analyzer's mixins, one per technique family
    │   │   ├── scan_steps.py         the steps of scan(), incl. GraphQL introspection
    │   │   ├── preprocessing.py      comment/FP neutralisation + de-obfuscation
    │   │   ├── dynamic_imports.py    lazy-chunk discovery
    │   │   ├── http_clients.py       Angular / axios / fetch / hooks / SOAP ...
    │   │   ├── frameworks.py         Next.js / tRPC / Nuxt / gql / RTK Query ...
    │   │   ├── interprocedural.py    URL-builder evaluation + SSA propagation
    │   │   ├── routes.py             front-end navigation
    │   │   ├── literals.py           literal sweeps, LinkFinder sweep
    │   │   ├── endpoint_store.py     process() / add_endpoint(): validate, score, de-duplicate
    │   │   └── json_config.py        JSON config files
    │   ├── ast_engine/           Esprima: walker, AliasResolver, node extractors, call graphs, layer
    │   ├── variable_resolver.py  EnhancedVariableResolver
    │   ├── rpc_extractor.py      EnhancedRPCExtractor
    │   ├── ts_params.py          TypeScriptParameterExtractor
    │   ├── security_headers.py   SecurityHeaderExtractor
    │   └── webpack_static.py     StaticWebpackModuleAnalyzer
    │
    ├── protocols/
    │   ├── graphql.py            GraphQLIntrospector
    │   └── websockets.py         WebSocketDiscovery
    │
    ├── dynamic/                  Phase 3
    │   ├── interceptor.py        DynamicInterceptor
    │   ├── browser_scripts.py    JS injected into every page
    │   ├── webpack_runtime.py    WebpackModuleGraphReconstructor
    │   └── indexeddb.py          IndexedDBExtractor
    │
    └── reporting/                Phases 4/5
        ├── report.py             save_report() + its helpers
        └── excel.py              json_to_excel
```

### Class → file

| Class / function | File | Role |
|-------|------|------|
| `BayesianConfidenceScorer` | `core/scoring.py` | Posterior scoring, LR calibration, Wilson CI, tier statistics |
| `LibraryFingerprint` | `core/scoring.py` | Vendor code identification for noise suppression |
| `EndpointClassifier` | `core/scoring.py` | Hard-garbage gate (XML/binary/unresolved base variables) |
| `EndpointProvenanceGraph` | `core/provenance.py` | Which phase/technique found each endpoint; multi-source boost |
| `URLNormalizer` | `core/url_normalizer.py` | Absolute URLs, `:param` / `${var}` → `{param}` |
| `RateLimiter` | `core/rate_limiter.py` | Adaptive delay + exponential backoff on 429/503 |
| `ScanCache` | `core/scan_cache.py` | SHA-256-keyed JS content cache |
| `EnhancedStaticAnalyzer` | `static/analyzer.py` (+ `static/stages/`) | Orchestrates Phase 2: threading, de-duplication, provenance |
| `EnhancedVariableResolver` | `static/variable_resolver.py` | Inter-procedural variable and method return-value resolution |
| `EnhancedRPCExtractor` | `static/rpc_extractor.py` | Concatenation / custom-wrapper endpoint reconstruction |
| `TypeScriptParameterExtractor` | `static/ts_params.py` | Request parameter mining (7 techniques) |
| `SecurityHeaderExtractor` | `static/security_headers.py` | Client-set secret / server-read trust header mining |
| `StaticWebpackModuleAnalyzer` | `static/webpack_static.py` | Per-module analysis of webpack bundles |
| `ASTExtractionLayer` | `static/ast_engine/layer.py` | Parses with Esprima and runs every AST extractor |
| `AliasResolver` | `static/ast_engine/alias_resolver.py` | SSA-style variable alias tracking |
| `ComputedPropertyExtractor`, `TemplateLiteralExtractor`, `BranchLogicExtractor`, `ObjectExpressionExtractor` | `static/ast_engine/node_extractors.py` | Single-pass AST extractors |
| `ASTCallGraphExtractor`, `ASTCallGraph` | `static/ast_engine/call_graph.py` | Multi-level function-chain resolution |
| `EnhancedFederationHunter` | `discovery/federation.py` | Phase 1 bundle discovery including Module Federation |
| `ExternalLinkExtractor` | `discovery/external_links.py` | External domain link tracking |
| `SourceMapEngine`, `run_sourcemap_harvest` | `discovery/sourcemaps.py` | Source map decompilation (Phase 1.5) |
| `WebpackChunkHarvester` | `discovery/chunks.py` | Deterministic chunk map extraction (Phase 1.6) |
| `ServiceWorkerAnalyzer` | `discovery/service_worker.py` | Service worker precache / respondWith routes |
| `BackendFileHunter` | `discovery/backend_intel.py` | OpenAPI / Actuator / WSDL / backend source maps (Phase 1.8) |
| `GraphQLIntrospector` | `protocols/graphql.py` | Schema introspection + APQ detection |
| `WebSocketDiscovery` | `protocols/websockets.py` | Static extraction + runtime WebSocket interception |
| `DynamicInterceptor` | `dynamic/interceptor.py` | Phase 3 Playwright orchestration + feedback loop |
| `WebpackModuleGraphReconstructor` | `dynamic/webpack_runtime.py` | Live webpack registry harvest |
| `IndexedDBExtractor` | `dynamic/indexeddb.py` | IndexedDB / storage URL inspection |
| `AuthEngine` | `auth.py` | Form login, browser login, TOTP MFA, Bearer token injection |
| `save_report`, `json_to_excel` | `reporting/` | JSON report, console summary, Excel |

### Where to make changes

- **New extraction technique:** add a method to the matching `static/stages/*.py` mixin and call it from `EnhancedStaticAnalyzer.analyze_code()` in `static/analyzer.py`. Mind the stage order.
- **New noise / vendor filter:** `_BLOCKED_KEYWORDS` / `_BLOCKED_PATTERNS` in `config.py`. Never add a second blocklist.
- **New confidence signal:** `BayesianConfidenceScorer.LR` / `_ET_MAP` in `core/scoring.py`. Never add a competing scorer.
- **New scan phase:** a function in `pipeline.py`, called from `run_scan()`.
- **Report fields:** `_build_report()` in `reporting/report.py` (keep `evaluate.py` compatibility).

Benchmark test-case IDs (`EP-…`, `TC-…`) were removed from the comments together with the benchmark-specific rules they marked; the remaining `FIX FP-n` tags are internal false-positive fix numbers. Do not add rules that encode a particular benchmark's ports, file names or paths.

---

## Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `requests` | ✅ | HTTP fetching for all phases |
| `beautifulsoup4` | ✅ | HTML parsing (Phase 1, login forms, sub-apps) |
| `urllib3` | ✅ | SSL warning suppression |
| `esprima` | Recommended | AST extractors and call graphs. Without it the AST stage is skipped and the regex extractors still run |
| `playwright` | Recommended | Phase 3 dynamic instrumentation, browser login, WebSocket capture |
| `pandas` + `openpyxl` | Optional | Excel report export |

---

## Limitations

**Authentication ceiling:** SAML 2.0 and full OIDC federation workflows are not yet supported. The static phases still analyze publicly served JS; only Phase 3 navigation is blocked by these flows.

**Heavy obfuscation:** Standard minification and variable renaming are fully handled. Build-time encrypted configurations, WebAssembly-based routing paths, and control-flow flattening with rotation-shifted string arrays need deobfuscation beyond the current Phase 2 scope.

**Source map dependency:** when source maps are exposed, the original TypeScript/JSX sources become analysable (this is where the value-flow analysis gains most). Targets that restrict `.map` access get less coverage from this phase; every other phase runs normally.

**Framework coverage:** results exist only for SPABench v3 (Angular, React, Vue, Next.js), which is a *development* set for this scanner. Svelte, SvelteKit, Remix and Astro have not been evaluated; held-out evaluation is planned (`vibe/remaining-work.md`).

**No production false-positive rate is claimed.** Earlier versions of this document quoted a `<1%` rate from 50-endpoint spot checks; the interval was miscomputed (the 95% Wilson upper bound for 0/50 is 7.1%, not 5.8%) and the targets were also used while developing the scanner, so the figure is withdrawn. Evaluation is on SPABench and on held-out applications with ground truth.

### Fixed bugs

These were found during the refactor and are **fixed in this version**. They are still present in the original single-file `main.py`. Details are in [`REFACTOR_NOTES.md`](REFACTOR_NOTES.md).

1. **RPC "pattern 8" crash.** `EnhancedRPCExtractor` referenced a `self.normalizer` that doesn't exist. Any bundle containing `postDataFromUrl('api_...')`-style wrapper calls raised `AttributeError` and aborted the whole scan in Phase 2. Those calls are now extracted as endpoints.
2. **Phase-3 WebSocket capture recorded nothing.** The `WebSocket` hook was injected with `page.evaluate()` before `page.goto()`, so navigation wiped it. It is now registered with `page.add_init_script()`, and keeps `instanceof WebSocket` and `WebSocket.OPEN` working for the page.
3. **`webpack_module_paths` was always empty.** It now lists the application's `webpack://` module paths from source maps (excluding `node_modules` and webpack internals).
4. **APQ endpoints were print-only.** GraphQL endpoints that confirm Automatic Persisted Queries but have introspection disabled are now added to the results (type `GRAPHQL_APQ_ENDPOINT`, scored with the previously unused `apq_persisted` signal).
5. **`--output` had no effect.** It now saves a copy of the JSON report to the given path.
6. **`--quiet` had no effect.** It now hides scan progress and prints only where the results went.

---

## Refactor & Verification

The refactor split `main.py` along its existing boundaries:
- Each class went to its own module.
- `analyze_code()` (1,710 lines) became about 35 named stages, called in the original order.
- `scan()` (609 lines), `save_report()` (533 lines) and the 625-line `__main__` block became small orchestrators plus named helpers.
- The code was moved by slicing exact line ranges out of the original, not retyped.
- Only provably dead code was removed (unused methods, overridden duplicates, values nothing reads, unreachable branches). The full list is in `REFACTOR_NOTES.md`.

Equivalence was verified offline, without network or Docker:

1. **AST comparison:** 258 of the original functions/methods are AST-identical. The four decomposed functions were re-assembled by inlining the new helpers and diffed statement by statement against the original. The only differences are the documented dead-code removals.
2. **Runtime differential test:** all 125 JS/TS files under `SPA-Bench-main/apps` (built bundles and sources) were fed to the original and refactored analyzers, per file and cumulatively, for two base URLs. That covered 1,122 endpoints plus resolver state, lazy-import queues, security headers and provenance. All are **identical**, including order.
3. **Report test:** `save_report()` on the same results produces an identical JSON report and identical console output.
4. `--help` output is identical, and `pyflakes` reports nothing.

---

## Paper & Benchmark

This scanner is the system described in:

> *Shadow Endpoints: Hybrid Static–Dynamic Discovery of Hidden API Surfaces in Obfuscated Single-Page Applications*
> Gokul Iyer
> DOI: 10.5281/zenodo.XXXXXXX *(to be assigned)*

The SPABench controlled evaluation benchmark is available separately at:
**[github.com/Gokul0211/SPA-Bench](https://github.com/Gokul0211/SPA-Bench)**

---

## License

MIT License. See `LICENSE` for details.
