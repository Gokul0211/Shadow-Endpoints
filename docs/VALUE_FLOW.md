# URL value-flow analysis

Specification of the analysis in `analysis/` (Node.js sidecar, Babel parser) as implemented. Everything below is
what the code does today; the "limits" section says what it cannot do. Source files are named in brackets.

## 1. Problem

Client code rarely contains an endpoint as one string literal. The URL a request goes to is assembled from a base
read from a config object, a path from a helper, a resource name passed by the caller and an id:

```ts
this.http.get(`${environment.api}/orders/${id}`)
fetch(this.reportsBase + 'generate/' + type)
api.get('permits')            // api.get(path) { return this.http.get(this.getBase() + path) }
```

The analysis computes, for the URL argument of every HTTP *sink*, a finite set of **templates**: literal text
interleaved with **holes** for the parts that cannot be known statically. It does this over the whole program
(all bundles and all source-map sources the scanner fetched), across module boundaries, without running it.

## 2. Abstract domain [`values.js`]

* A **part** is `lit(s)` or `hole(cls, name)`. Hole classes say *why* a piece is unknown:
  `param` (a function parameter; may be substituted at call sites), `unknown` (unresolved name/property/call),
  `origin` (the page origin: `location.origin`, `document.baseURI`), `env` (build-time environment:
  `process.env.X`, `import.meta.env.X`), `runtime` (data that exists only while running: storage, DOM).
* A **template** is a sequence of parts, normalised (adjacent literals merged, empty literals dropped).
* An **abstract value (AV)** is a set of at most `K = 8` templates plus a set of *references* to non-string
  things the analysis follows: object literals, array literals, functions, classes, class instances, module
  namespaces, constructor-function instances, and native objects (libraries, `location`, `process.env`, HTTP-client
  types). When a set would exceed `K` further templates are dropped and the value is flagged `widened`.
* Join is set union (templates deduplicated by structure); concatenation is the cross product of the operands'
  templates (a non-string operand contributes an `unknown` hole named after it).

## 3. Evaluation [`evaluator.js`]

Flow-insensitive: the value of a variable is the union of everything assigned to it, so the result over-approximates
the strings that can occur. Context-sensitive only for calls.

| Expression | Value |
|---|---|
| string / number / boolean literal | that text |
| template literal, `a + b` on strings | concatenation of the parts |
| `a \|\| b`, `a ?? b`, `a && b`, `c ? a : b` | join of the branches |
| identifier | join of: the declarator's initialiser, every later `=`, `+=` (concatenation), `\|\|=`/`??=` assignment, a destructuring path (`const {a, b: {c}} = init`), a function/class declaration |
| function parameter | `hole(param, name, fn, index)`, or the argument value when evaluated under a call; a TypeScript type annotation naming a class adds an instance of that class |
| `obj.p`, `obj["p"]` | property `p` of every object the receiver may be: object-literal properties (including spreads, getters), properties assigned later (`obj.p = v`), array elements by index |
| `obj[k]`, key unknown | every value the object or array holds |
| `this.p` | in a class: fields, getters, constructor parameter properties (`constructor(private http: HttpClient)`), every `this.p = v` in the class, then the superclass; in an ES5 constructor function: `this.p = v` in the function and `F.prototype.m = fn` |
| `f(args)`, `o.m(args)` | the callee's `return` expressions evaluated with the parameters bound to the argument values (depth ≤ 5, memoised per `(function, arguments)`, recursion yields an `unknown` hole) |
| `new C(...)` | an instance of `C` (class) or of the constructor function |
| `import {x} from './m'`, `require('./m')`, webpack `__webpack_require__(id)` | the module's export `x` (ES named/default/`export *`/re-export, CommonJS `exports.x` / `module.exports`, webpack `exports.x`, `r.d(exports, {x: () => v})`, `Object.defineProperty(exports, 'x', {get})`) |
| Angular compiled DI | `Cls.ɵfac = function (t) { return new (t \|\| Cls)(ɵɵinject(A), ...) }`: constructor parameter *i* is an instance of the *i*-th injected class |
| `location.origin`, `document.baseURI` | `origin` hole |
| `process.env.X`, `import.meta.env.X` | `env` hole named `X` |
| `localStorage.getItem(k)` | `runtime` hole |
| `axios.create({baseURL})`, `ky.create({prefixUrl})` | a client instance carrying the base |
| `s.concat`, `trim`, `toString`, `String(x)`, `encodeURIComponent(x)`, `[..].join(sep)`, `s.replace(lit, lit)` | applied exactly when the operands are known; otherwise `unknown` |

**Modules.** Import specifiers resolve among the input files by relative path (with extensions and `index`), then
by unique suffix (path aliases, `baseUrl`), preferring the file closest to the importer. A webpack bundle is
recognised by its module table (an object or array of functions with `(module, exports, require)` parameters, or
`__webpack_modules__[id] = fn` assignments) and each function is analysed as a module; `require(id)` resolves to
the module function with that key in the same table, else to the unique one across all tables [`modules.js`].

## 4. Sinks and methods [`sinks.js`]

A fixed list; nothing is recognised by the name of a variable.

| Sink | Method |
|---|---|
| `fetch(url, init)`, `new Request(url, init)`, `window.fetch` | `init.method`, else GET |
| `x.open(method, url)` | the first argument, which must evaluate to HTTP verbs |
| `new WebSocket(url)` / `new EventSource(url)` / `navigator.sendBeacon(url)` | WS / GET / POST |
| a function imported from an HTTP package (axios, ky, got, superagent, ofetch, …), and `.get/.post/.put/.patch/.delete/.head/.options/.request` on it | the verb, or `config.method` |
| the same verbs on a value typed `HttpClient`, `Http`, `AxiosInstance`, …, on `$http`, `$`/`jQuery`, on an `axios.create()` instance (base URL prepended) | the verb |
| `$.ajax(config)`, `axios(config)`, `http.request(config)` | `config.method` / `config.type` |
| `useSWR(url)`, `useFetch(url)`, `$fetch(url, opts)` (Nuxt) | GET / `opts.method` |
| the same verbs on a receiver of **unknown type** | accepted only when the first argument is URL-shaped (starts with `/` or a scheme, or a hole followed by a `/path`); `map.get('key')` is not a sink |

Separate passes recognise operations the code *declares*: GraphQL resolver maps (`{Query: {name() {}}}`), `@Query` /
`@Mutation` decorators and SDL text [`graphql.js`]; RTK Query `createApi` endpoints (`baseUrl` joined with the
`query()` result) [`rtk.js`]; and Next.js route files (`app/**/route.ts`, `pages/api/**`) whose URL comes from
the file path by convention and are therefore flagged *inferred* [`nextroutes.js`].

## 5. Wrappers [`sinks.js`]

If a template contains a `param` hole of the enclosing function *F*, *F* is a derived sink: its call sites are
looked up (callee name index, then confirmed by evaluating the callee to *F*), the arguments are evaluated and
substituted for the holes, and the result is processed as a new sink hit; if it still holds a parameter of the
caller the chain continues (depth ≤ 4, ≤ 40 call sites per function).

* **Substitution rule.** An argument is substituted only if it supplies structure: not a hole, not a number, not a
  UUID. Data arguments stay holes, so `getUser(5)` yields `/api/users/{id}`, not `/api/users/5`.
* **Uncalled wrappers** are reported with their holes (`uncalled: true`), because the function is still something
  the client can do, **except generic request helpers**: a URL that is exactly a *configured base* (a URL literal
  in an object property, class field or variable initialiser) followed by a bare parameter says nothing about an
  endpoint and is dropped (`genericWrappers` in the statistics).
* **Partial URLs.** `{unresolved}{id}/x` (two holes before the first literal) is dropped: which hole is the base
  cannot be told. A single leading hole followed by `/path` is reported with `base` set.

## 6. Output

One finding per (sink, method, URL template): file, line, column, sink kind, `method` (null = unknown), `url`
(holes rendered `{name}`), `base` (the unresolved leading piece, if any), hole classes, whether the sink is a known
HTTP API or only URL-shaped, library, wrapper chain (`via`), `uncalled`, request parameter names (keys of the body,
`params` option, `HttpParams`/`URLSearchParams` chains, `JSON.stringify` argument), and `auth` (an
Authorization-style header at the sink). The scanner records each as evidence of type `VALUEFLOW_SINK`.

## 7. Soundness, precision and limits

* **Not sound.** Unresolvable by construction: `eval`/`new Function`, reflection and computed property *writes*,
  URLs fetched from the server at run time, calls through arrays of functions or higher-order plumbing deeper
  than the call-depth bound, values that depend on user input. These become holes (or are missed).
* **Bounded.** `K = 8` templates per value; call depth 5; wrapper chain depth 4; 40 call sites per wrapper;
  expression depth 350; a per-run time budget (default 600 s) after which the run stops and says so.
* **Imprecise.** Flow-insensitive (a later assignment is a possible value everywhere); fields are
  context-insensitive; webpack `require` of a key present in several tables resolves only when unique; object
  mutation through aliases is not tracked beyond `obj.p = v` on the same binding and `this.p = v`.
* **Type information is read, not computed.** Dependency injection is followed through TypeScript annotations and
  Angular's compiled factory; other DI containers are not modelled.
* **Findings are evidence, not verdicts.** Each carries `known` (an HTTP API was recognised) or *shape-only*,
  and the hole classes; the scanner's scorer decides what to report.

## 8. Complexity and determinism

Parsing and indexing are linear in the input. Binding values are memoised per binding and call results per
(function, argument values); the caps above bound the rest. Measured on a 5.8 MB library bundle: 1.5 s to
parse and analyse. Iteration order follows source order and insertion order only, so a run is deterministic
(the offline regression test compares output across `PYTHONHASHSEED` values). Results are cached by content
(`SHADOW_VF_CACHE`).

## 9. Tests and measured effect

`analysis/test/analyze.test.js` (30 fixtures: each evaluation rule, each sink family, wrappers across files,
webpack tables, compiled Angular DI, GraphQL, RTK Query, Next routes, parameters and auth, deep chains, time
budget); `tests/test_valueflow.py` (bridge, cache, missing sidecar); the offline SPABench regression tests.
On SPABench v3 (a **development** set for this scanner), removing the analysis costs 0.19 recall and 0.26 method
recall (macro over the five apps, leave-one-out ablation); every older regex extractor is individually dispensable
there. These are development-set numbers, not an evaluation.
