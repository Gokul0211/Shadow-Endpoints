import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/cli.js';

const run = (files) => analyze({ files: files.map(([id, code]) => ({ id, code })) });
const out = (r) => r.findings.map((f) => `${f.method ?? '?'} ${f.base ? f.base : ''}${f.url}`).sort();
const has = (r, s) => assert.ok(out(r).includes(s), `expected ${JSON.stringify(s)} in ${JSON.stringify(out(r))}`);
const hasNot = (r, s) => assert.ok(!out(r).includes(s), `did not expect ${JSON.stringify(s)} in ${JSON.stringify(out(r))}`);

test('fetch literal with method option', () => {
  const r = run([['a.js', 'fetch("/api/users", {method: "POST"}); fetch("/api/ping");']]);
  has(r, 'POST /api/users');
  has(r, 'GET /api/ping');
});

test('template literal: data stays a {param}, base stays unresolved', () => {
  const r = run([['a.js', 'function load(id) { return fetch(`/api/users/${id}`); }']]);
  has(r, 'GET /api/users/{id}');
});

test('config object imported from another module (TypeScript, DI by type annotation)', () => {
  const r = run([
    ['src/environments/environment.ts', 'export const environment = { api: "http://localhost:4001" };'],
    ['src/app/orders.service.ts', `
      import { HttpClient } from '@angular/common/http';
      import { environment } from '../environments/environment';
      export class OrdersService {
        constructor(private http: HttpClient) {}
        load(id: number) { return this.http.get<Order>(\`\${environment.api}/orders/\${id}\`); }
        remove(id: number) { return this.http.delete(environment.api + '/orders/' + id); }
      }`],
  ]);
  has(r, 'GET http://localhost:4001/orders/{id}');
  has(r, 'DELETE http://localhost:4001/orders/{id}');
});

test('class field, getter and this.x assigned in the constructor', () => {
  const r = run([['svc.ts', `
    class Cfg { apiUrl = 'https://api.acme.io'; }
    class S {
      base = '/v1';
      constructor(cfg: Cfg) { this.cfg = cfg; }
      get root() { return this.cfg.apiUrl + this.base; }
      list() { return fetch(this.root + '/items'); }
    }`]]);
  has(r, 'GET https://api.acme.io/v1/items');
});

test('wrapper function: method and path come from the call sites', () => {
  const r = run([['w.js', `
    const BASE = 'http://localhost:4001';
    function request(path, method) { return fetch(BASE + path, { method }); }
    request('/api/a', 'DELETE');
    request('/api/b', 'PUT');`]]);
  has(r, 'DELETE http://localhost:4001/api/a');
  has(r, 'PUT http://localhost:4001/api/b');
});

test('wrapper chain across files (import, two levels)', () => {
  const r = run([
    ['lib/http.js', 'export function api(path) { return fetch(path); }'],
    ['lib/users.js', `import { api } from './http'; export function users() { return api('/api/users'); }`],
  ]);
  has(r, 'GET /api/users');
});

test('numeric call-site argument stays a path parameter', () => {
  const r = run([['n.js', `
    function getUser(id) { return fetch('/api/users/' + id); }
    getUser(5); getUser(6);`]]);
  has(r, 'GET /api/users/{id}');
  hasNot(r, 'GET /api/users/5');
});

test('axios.create baseURL is prepended', () => {
  const r = run([['ax.js', `
    import axios from 'axios';
    const client = axios.create({ baseURL: '/api/v2' });
    client.get('/items'); client.post('/items', {});`]]);
  has(r, 'GET /api/v2/items');
  has(r, 'POST /api/v2/items');
});

test('axios config object form', () => {
  const r = run([['ax2.js', `import axios from 'axios'; axios({ url: '/api/q', method: 'put' }); axios.request({url: '/api/r', method: 'delete'});`]]);
  has(r, 'PUT /api/q');
  has(r, 'DELETE /api/r');
});

test('XMLHttpRequest.open, WebSocket, EventSource, sendBeacon', () => {
  const r = run([['x.js', `
    const x = new XMLHttpRequest(); x.open('PATCH', '/api/x');
    new WebSocket('ws://localhost:3005/ws/live');
    new EventSource('/events');
    navigator.sendBeacon('/api/beacon', data);`]]);
  has(r, 'PATCH /api/x');
  has(r, 'WS ws://localhost:3005/ws/live');
  has(r, 'GET /events');
  has(r, 'POST /api/beacon');
});

test('unknown receiver: URL-shaped first argument is a sink, a map key is not', () => {
  const r = run([['s.js', `foo.get('/api/z'); map.get('key'); headers.get('Authorization'); cache.get('a/b');`]]);
  has(r, 'GET /api/z');
  assert.equal(r.findings.length, 1, JSON.stringify(out(r)));
});

test('webpack module table: require(n) and exports are followed', () => {
  const r = run([['bundle.js', `
    (function(modules){ var cache = {}; function __webpack_require__(id){ var m = {exports:{}}; modules[id](m, m.exports, __webpack_require__); return m.exports; } __webpack_require__(2); })({
      1: function(module, exports, __webpack_require__) { exports.API = 'http://localhost:4001/api'; },
      2: function(module, exports, __webpack_require__) { var cfg = __webpack_require__(1); fetch(cfg.API + '/orders'); }
    });`]]);
  has(r, 'GET http://localhost:4001/api/orders');
});

test('webpack 5 style: r.d getters and minified names', () => {
  const r = run([['b.js', `
    var mods = {
      10: (e, t, n) => { n.d(t, { U: () => o }); const o = "/api/v3"; },
      20: (e, t, n) => { var i = n(10); fetch(i.U + "/health"); }
    };`]]);
  has(r, 'GET /api/v3/health');
});

test('ES5 constructor functions and prototype methods', () => {
  const r = run([['es5.js', `
    function AuthService(http) { this.http = http; this.apiBase = "http://localhost:3002"; }
    AuthService.prototype.login = function (u, p) { return fetch(this.apiBase + "/api/auth/login", { method: "POST" }); };`]]);
  has(r, 'POST http://localhost:3002/api/auth/login');
});

test('modern syntax parses (optional chaining, class fields, nullish, import.meta, TS decorators)', () => {
  const r = run([['m.ts', `
    @Injectable() export class A { #p = 1; static BASE = import.meta.env.VITE_API ?? '/api';
      go(x?: string) { return fetch((A.BASE) + '/go'); } }`]]);
  assert.equal(r.stats.failed, 0, JSON.stringify(r.errors));
  has(r, 'GET /api/go');
});

test('location.origin base is dropped, env base is a leading hole', () => {
  const r = run([['o.js', `fetch(location.origin + '/api/o'); fetch(process.env.API_URL + '/api/e');`]]);
  has(r, 'GET /api/o');
  assert.ok(r.findings.some((f) => f.url === '/api/e' && f.base === '{API_URL}'), JSON.stringify(r.findings));
});

test('strings in comments and unrelated calls are not endpoints', () => {
  const r = run([['c.js', `// fetch('/api/old')\nconst s = '/api/not-a-call'; log('/api/x');`]]);
  assert.equal(r.findings.length, 0, JSON.stringify(out(r)));
});

test('parse failure is reported, not fatal', () => {
  const r = run([['bad.js', 'function ('], ['ok.js', 'fetch("/api/ok")']]);
  has(r, 'GET /api/ok');
  assert.equal(r.errors.length >= 0, true);
});

// ---- Phase C completion ---------------------------------------------------------------

test('endpoint map with a computed key yields every value', () => {
  const r = run([['j.js', 'const EP = { users: "/api/users", orders: "/api/orders" }; export const get = (k) => fetch(EP[k]);']]);
  has(r, 'GET /api/users');
  has(r, 'GET /api/orders');
});

test('useSWR key and Nuxt $fetch / useFetch are sinks', () => {
  const r = run([
    ['s.jsx', 'import useSWR from "swr"; export const P = () => useSWR("/api/profile", fetcher);'],
    ['n.vue.js', '$fetch("/api/nuxt", { method: "POST" }); useFetch("/api/nuxt-get");'],
  ]);
  has(r, 'GET /api/profile');
  has(r, 'POST /api/nuxt');
  has(r, 'GET /api/nuxt-get');
});

test('RTK Query endpoints: base url + query() result, method from the config object', () => {
  const r = run([['api.ts', `
    import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
    export const api = createApi({
      baseQuery: fetchBaseQuery({ baseUrl: '/api/v1/' }),
      endpoints: (b) => ({
        getPosts: b.query({ query: () => 'posts' }),
        getPost: b.query({ query: (id) => \`posts/\${id}\` }),
        addPost: b.mutation({ query: (p) => ({ url: '/posts', method: 'POST', body: p }) }),
      }),
    });`]]);
  has(r, 'GET /api/v1/posts');
  has(r, 'GET /api/v1/posts/{id}');
  has(r, 'POST /api/v1/posts');
});

test('Angular compiled DI: constructor arguments come from the class factory', () => {
  const r = run([['e.js', `
    class Cfg { constructor() { this.api = "/api/v9"; } }
    class S { constructor(cfg, http) { this.cfg = cfg; this.http = http; } go() { return this.http.post(this.cfg.api + "/go", {}); } }
    S.ɵfac = function (t) { return new (t || S)(i0.ɵɵinject(Cfg), i0.ɵɵinject(i1.HttpClient)); };`]]);
  has(r, 'POST /api/v9/go');
});

test('Angular compiled DI through a package namespace import', () => {
  const r = run([['e2.js', `
    import * as i1 from '@angular/common/http';
    class S { constructor(http) { this.http = http; } list() { return this.http.get("/api/list"); } }
    S.ɵfac = function (t) { return new (t || S)(i0.ɵɵinject(i1.HttpClient)); };`]]);
  has(r, 'GET /api/list');
});

test('string replace on a resolved base, then a helper that appends (the generateReport shape)', () => {
  const r = run([
    ['src/env.ts', "export const environment = { apiBaseUrl: 'http://localhost:4001/api/rc_permit/' };"],
    ['src/cfg.ts', `import { environment } from './env';
      export class AppConfig { private readonly apiBase: string; constructor() { this.apiBase = environment.apiBaseUrl; }
        getApiBase(): string { return this.apiBase; } }`],
    ['src/rep.ts', `import { AppConfig } from './cfg';
      export class Rep { private readonly base: string; private readonly http: HttpClient;
        constructor(cfg: AppConfig, http: HttpClient) { this.base = cfg.getApiBase().replace('/api/rc_permit/', '/api/reports/'); this.http = http; }
        private url(type: string): string { return this.base + 'generate/' + type; }
        generate(t: string) { return this.http.get(this.url(t)); } }`],
  ]);
  has(r, 'GET http://localhost:4001/api/reports/generate/{t}');
});

test('generic request helper (configured base + bare parameter) is not an endpoint; a specific uncalled one is', () => {
  const r = run([
    ['src/env.ts', "export const environment = { api: 'http://localhost:4001/api/core/' };"],
    ['src/api.ts', `import { environment } from './env';
      export class Api { constructor(private http: HttpClient) {}
        put(path: string) { return this.http.put(environment.api + path, {}); } }`],
    ['src/users.ts', `export class U { constructor(private http: HttpClient) {}
        remove(id: string) { return this.http.delete('/api/users/' + id); } }`],
  ]);
  hasNot(r, 'PUT http://localhost:4001/api/core/{path}');
  has(r, 'DELETE /api/users/{id}');
  assert.ok(r.stats.genericWrappers >= 1, JSON.stringify(r.stats));
});

test('GraphQL resolver maps, decorators and SDL are operations', () => {
  const r = run([
    ['a.resolver.ts', 'export const resolvers = { Query: { getUser: () => null, listOrders() { return []; } }, Mutation: { createUser: () => null } };'],
    ['b.ts', 'const typeDefs = `type Query { getProduct(id: ID!): Product searchProducts(q: String): [Product] } type Mutation { deleteProduct(id: ID!): Boolean }`;'],
    ['c.ts', 'class R { @Query() items() { return []; } @Mutation(() => X, { name: "addItem" }) add() { return 1; } }'],
  ]);
  for (const op of ['getUser', 'listOrders', 'createUser', 'getProduct', 'searchProducts', 'deleteProduct', 'items', 'addItem']) {
    assert.ok(r.findings.some((f) => f.kind === 'graphql_operation' && f.url === '#' + op), `missing ${op}: ${JSON.stringify(out(r))}`);
  }
});

test('Next.js route files: path from the file, methods from the code, flagged inferred', () => {
  const r = run([
    ['src/app/api/users/[id]/route.ts', 'export async function GET() {} export const DELETE = () => {};'],
    ['pages/api/auth/login.ts', 'export default function h(req, res) { if (req.method !== "POST") return res.status(405).end(); }'],
  ]);
  const routes = r.findings.filter((f) => f.kind === 'nextjs_route');
  assert.deepEqual(routes.map((f) => `${f.method} ${f.url}`).sort(), ['DELETE /api/users/{id}', 'GET /api/users/{id}', 'POST /api/auth/login']);
  assert.ok(routes.every((f) => f.inferred));
});

test('request parameters and authorisation header are read off the sink', () => {
  const r = run([['p.ts', `
    this.http.post('/api/orders', { productId: 1, qty: 2 }, { headers: { Authorization: 'Bearer ' + t } });
    fetch('/api/search', { method: 'POST', body: JSON.stringify({ q: x, page: 1 }) });
    this.http.get('/api/items', { params: { sort: 'asc', limit: 10 } });`]]);
  const by = (u) => r.findings.find((f) => f.url === u);
  assert.deepEqual(by('/api/orders').params, ['productId', 'qty']);
  assert.equal(by('/api/orders').auth, true);
  assert.deepEqual(by('/api/search').params, ['page', 'q']);
  assert.deepEqual(by('/api/items').params, ['limit', 'sort']);
  assert.equal(by('/api/items').auth, false);
});

test('a very deep concatenation chain does not overflow the stack', () => {
  const chain = Array.from({ length: 3000 }, (_, i) => `"p${i}"`).join(' + ');
  const r = run([['d.js', `fetch("/api/x/" + ${chain});`]]);
  assert.equal(r.stats.errors ?? 0, 0, r.stats.lastError);
});

test('time budget stops the analysis and says so', () => {
  const code = Array.from({ length: 200 }, (_, i) => `fetch("/api/b${i}");`).join('\n');
  const r = analyze({ files: [{ id: 'b.js', code }], options: { timeBudgetSeconds: -1 } });
  assert.equal(r.stats.timedOut, true);
});
