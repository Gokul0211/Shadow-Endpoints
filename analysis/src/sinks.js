// Sinks: the places where a value becomes an outgoing request.
//
// Fixed, documented list (nothing is recognised by the *name* of a variable):
//
//   fetch(url, {method})            window.fetch, node-fetch style imports
//   new Request(url, {method})
//   x.open(method, url)             XMLHttpRequest  (method must evaluate to an HTTP verb)
//   new WebSocket(url)              method WS
//   new EventSource(url)            method GET
//   navigator.sendBeacon(url)       method POST
//   <lib>(url|config)               axios, ky, got, superagent, ofetch, ... imported from the package
//   <lib>.get|post|put|patch|delete|head|options|request(url|config)
//                                   where the receiver is a known HTTP client:
//                                   an imported library, an axios.create()/ky.create() instance,
//                                   a value typed HttpClient/Http/AxiosInstance, $http, jQuery/$
//   <anything>.get|post|...(url)    receiver of unknown type: accepted only when the first
//                                   argument evaluates to a URL-shaped value ("shape" sinks)
//
// Wrappers are found automatically: when the URL value contains a parameter of
// the enclosing function, that function becomes a derived sink and its call
// sites (in any file) are analysed with the arguments substituted.
import { AV, hole, renderTemplate, substitute, templateHoles } from './values.js';
import { graphqlOperations } from './graphql.js';
import { cleanKeys, configKeys, keysOf, paramFlows, requestInfo } from './request_info.js';
import { rtkEndpoints } from './rtk.js';
import { nextRoutes } from './nextroutes.js';

const HTTP_LIBS = new Set([
  'axios', 'ky', 'got', 'superagent', 'ofetch', 'node-fetch', 'cross-fetch', 'isomorphic-fetch', 'wretch',
  'redaxios', 'whatwg-fetch', 'unfetch', 'request', 'needle', 'undici', 'ky-universal', '@angular/common/http',
  '@angular/http', 'vue-resource', 'axios-retry', 'umi-request',
]);
const HTTP_TYPES = new Set(['HttpClient', 'Http', 'AxiosInstance', 'Axios', 'KyInstance', 'Ky', 'SuperAgent', 'HttpService', 'XhrFactory']);
const VERBS = new Map([
  ['get', 'GET'], ['post', 'POST'], ['put', 'PUT'], ['patch', 'PATCH'], ['delete', 'DELETE'], ['del', 'DELETE'],
  ['head', 'HEAD'], ['options', 'OPTIONS'], ['getJSON', 'GET'], ['jsonp', 'GET'],
]);
const VERB_SET = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const MAX_CHAIN = 4;
// data-fetching hooks whose first argument is the URL: package -> exported names
const HOOK_LIBS = { swr: ['default', 'useSWR'], 'swr/immutable': ['default'], '@vueuse/core': ['useFetch'] };

const isAbs = (s) => /^(https?|wss?):\/\//i.test(s);

function firstLit(t) {
  return t.length && t[0].k === 'lit' ? t[0].s : null;
}

export class Sinks {
  constructor(ev, units, opts = {}) {
    this.ev = ev;
    this.units = units;
    this.deadline = opts.deadline ?? Infinity;
    this.findings = [];
    this.stats = { sinks: 0, byKind: {}, wrappers: 0, derived: 0, uncalled: 0, shapeRejected: 0 };
    this.seen = new Set();
    this.fnByKey = new Map();
    this.callsByName = new Map();
    for (const u of units) {
      for (const f of u.functions) this.fnByKey.set(u.key(f.node), f);
      for (const c of u.calls) {
        const n = this.calleeName(c);
        if (n) {
          if (!this.callsByName.has(n)) this.callsByName.set(n, []);
          this.callsByName.get(n).push(c);
        }
      }
    }
  }

  calleeName(call) {
    const c = call.node.callee;
    if (c.type === 'Identifier') return c.name;
    if (c.type === 'MemberExpression' || c.type === 'OptionalMemberExpression') return this.ev._propName(c);
    return null;
  }

  // names a function can be called by
  fnNames(fnPath) {
    const names = new Set();
    const n = fnPath.node;
    if (n.id?.name) names.add(n.id.name);
    if (n.key && !n.computed) names.add(n.key.name ?? n.key.value);
    const p = fnPath.parentPath;
    if (p?.isVariableDeclarator() && p.node.id.type === 'Identifier') names.add(p.node.id.name);
    if (p?.isObjectProperty() && p.node.key) names.add(p.node.key.name ?? p.node.key.value);
    if (p?.isClassProperty?.() && p.node.key) names.add(p.node.key.name);
    if (p?.isAssignmentExpression() && p.node.left.type === 'MemberExpression') names.add(this.ev._propName(p.node.left));
    if (p?.isExportDefaultDeclaration()) names.add('default');
    names.delete(null);
    names.delete(undefined);
    return names;
  }

  // ---- classification -----------------------------------------------------
  // A forwarding proxy `function (f, a, b) { return f(a, b); }` (control-flow obfuscators route calls through
  // such helpers): the call is the call of its first argument with the remaining ones.
  proxyCall(call, ctx) {
    if (call.node.type === 'NewExpression') return null;
    let v;
    try { v = this.ev.eval(call.get('callee'), ctx); } catch (e) { return null; }
    const fns = v.refs.filter((r) => r.kind === 'fn');
    if (fns.length !== 1) return null;
    const node = fns[0].path.node;
    if (!node.params.length || node.params.some((p) => p.type !== 'Identifier')) return null;
    const body = node.body;
    const ret = body.type === 'BlockStatement'
      ? (body.body.length === 1 && body.body[0].type === 'ReturnStatement' ? body.body[0].argument : null)
      : body;
    if (!ret || ret.type !== 'CallExpression' || ret.callee.type !== 'Identifier') return null;
    const k = node.params.findIndex((p) => p.name === ret.callee.name);
    if (k < 0) return null;
    const rest = node.params.filter((_, i) => i !== k).map((p) => p.name);
    if (ret.arguments.length !== rest.length || ret.arguments.some((a, i) => a.type !== 'Identifier' || a.name !== rest[i])) return null;
    const callArgs = call.get('arguments');
    if (callArgs.length <= k) return null;
    return { callee: callArgs[k], args: callArgs.filter((_, i) => i !== k) };
  }

  classify(call, ctx, override) {
    const n = call.node;
    const callee = override ? override.callee : call.get('callee');
    const args = override ? override.args : call.get('arguments');
    const ev = this.ev;
    if (n.type === 'NewExpression') {
      if (callee.isIdentifier() && !callee.scope.getBinding(callee.node.name)) {
        const name = callee.node.name;
        if (name === 'WebSocket') return { kind: 'websocket', method: 'WS', url: args[0], known: true };
        if (name === 'EventSource') return { kind: 'eventsource', method: 'GET', url: args[0], known: true };
        if (name === 'Request') return { kind: 'fetch', url: args[0], opts: args[1], known: true };
      }
      return null;
    }
    // plain call: fetch(...), axios(...), $http(...)
    if (callee.isIdentifier()) {
      const name = callee.node.name;
      const b = callee.scope.getBinding(name);
      if (!b && name === 'fetch') return { kind: 'fetch', url: args[0], opts: args[1], known: true };
      if (!b && name === '$http') return { kind: 'http', configArg: args[0], known: true };
      if (!b && (name === '$fetch' || name === 'useFetch' || name === 'useLazyFetch')) {
        return { kind: 'fetch', url: args[0], opts: args[1], known: true, lib: 'nuxt' };
      }
      const v = ev.eval(callee, ctx);
      const lib = v.refs.find((r) => r.kind === 'native' && r.lib === 'lib' && HTTP_LIBS.has(r.pkg));
      if (lib) {
        if (/fetch/.test(lib.pkg)) return { kind: 'fetch', url: args[0], opts: args[1], known: true };
        return { kind: 'http', url: args[0], opts: args[1], configArg: args[0], base: lib.base, known: true, lib: lib.pkg };
      }
      const hook = v.refs.find((r) => r.kind === 'native' && r.lib === 'lib' && (HOOK_LIBS[r.pkg] || []).includes(r.name));
      if (hook) return { kind: 'fetch', url: args[0], opts: args[1], known: true, lib: hook.pkg };
      return null;
    }
    if (callee.node.type !== 'MemberExpression' && callee.node.type !== 'OptionalMemberExpression') return null;
    const m = ev._propName(callee.node);
    if (m === null) return null;
    const objPath = callee.get('object');
    // window.fetch(...)
    if (m === 'fetch' && objPath.isIdentifier() && /^(window|self|globalThis|global)$/.test(objPath.node.name) && !objPath.scope.getBinding(objPath.node.name)) {
      return { kind: 'fetch', url: args[0], opts: args[1], known: true };
    }
    if (m === 'sendBeacon' && objPath.isIdentifier() && objPath.node.name === 'navigator') {
      return { kind: 'beacon', method: 'POST', url: args[0], known: true };
    }
    // XMLHttpRequest.open(method, url)
    if (m === 'open' && args.length >= 2) {
      const mv = ev.eval(args[0], ctx);
      const verbs = mv.t.map((t) => (t.length === 1 && t[0].k === 'lit' ? t[0].s.toUpperCase() : null));
      if (verbs.length && verbs.every((v) => v && VERB_SET.has(v))) return { kind: 'xhr', methodAV: mv, url: args[1], known: true };
      return null;
    }
    const isAjax = m === 'ajax' || m === 'request';
    if (!VERBS.has(m) && !isAjax) return null;
    // receiver
    const recv = ev.eval(objPath, ctx);
    let known = false;
    let base = null;
    let lib = null;
    for (const r of recv.refs) {
      if (r.kind === 'native' && r.lib === 'lib' && (HTTP_LIBS.has(r.pkg) || r.name === 'instance')) { known = true; base = r.base ?? base; lib = r.pkg; }
      else if (r.kind === 'native' && r.lib === 'type' && HTTP_TYPES.has(r.name)) { known = true; lib = r.name; }
    }
    if (objPath.isIdentifier() && !objPath.scope.getBinding(objPath.node.name) && /^(\$http|\$|jQuery)$/.test(objPath.node.name)) known = true;
    const sink = { kind: 'http', known, base, lib, recv: objPath };
    if (m === 'ajax' || (m === 'request' && args.length === 1)) {
      return { ...sink, configArg: args[0] };
    }
    if (m === 'request') {
      // http.request("GET", url)
      const mv = ev.eval(args[0], ctx);
      const verbs = mv.t.map((t) => (t.length === 1 && t[0].k === 'lit' ? t[0].s.toUpperCase() : null));
      if (verbs.length && verbs.every((v) => v && VERB_SET.has(v)) && args[1]) return { ...sink, methodAV: mv, url: args[1], opts: args[2] };
      return { ...sink, configArg: args[0] };
    }
    if (!args[0]) return null;
    return { ...sink, method: VERBS.get(m), url: args[0], opts: args[1], configArg: args[0] };
  }

  // ---- URL / method values -------------------------------------------------
  urlOf(sink, ctx) {
    const ev = this.ev;
    let urlAV = null;
    let methodAV = sink.methodAV ?? (sink.method ? AV.str(sink.method) : null);
    const fromConfig = (cfgPath) => {
      const cv = ev.eval(cfgPath, ctx);
      const urls = new AV();
      const methods = new AV();
      for (const r of cv.refs) {
        if (r.kind !== 'obj' && r.kind !== 'ns') continue;
        const u = ev.getProp(r, 'url', ctx);
        if (!u.isEmpty && !(u.t.length === 1 && u.t[0].length === 1 && u.t[0][0].k === 'hole' && u.t[0][0].name === 'url' && u.t[0][0].cls === 'unknown')) urls.merge(u);
        for (const key of ['method', 'type']) methods.merge(ev.getProp(r, key, ctx));
      }
      return { urls, methods };
    };
    if (sink.url) {
      const first = ev.eval(sink.url, ctx);
      // axios.get(config) / fetch(new Request(...)) style: first arg may itself be a config object
      if (first.refs.some((r) => r.kind === 'obj') && first.t.every((t) => t.every((p) => p.k === 'hole'))) {
        const c = fromConfig(sink.url);
        if (!c.urls.isEmpty) { urlAV = c.urls; if (!methodAV && !c.methods.isEmpty) methodAV = c.methods; }
      }
      if (!urlAV) urlAV = first;
    } else if (sink.configArg) {
      const c = fromConfig(sink.configArg);
      urlAV = c.urls;
      if (!c.methods.isEmpty) methodAV = c.methods;
      else if (!methodAV) methodAV = null;
    }
    if (!methodAV && sink.opts) {
      const ov = ev.eval(sink.opts, ctx);
      const m = new AV();
      for (const r of ov.refs) if (r.kind === 'obj') m.merge(ev.getProp(r, 'method', ctx));
      if (!m.isEmpty) methodAV = m; // may hold a parameter: substituted from the call sites
    }
    if (!methodAV && sink.kind === 'fetch') methodAV = AV.str('GET'); // fetch default
    if (!urlAV) return null;
    // instance base URL (axios.create({baseURL}))
    if (sink.base && !sink.base.isEmpty) {
      const withBase = new AV();
      for (const t of urlAV.t) {
        const f = firstLit(t);
        if (f !== null && isAbs(f)) withBase.addTemplate(t);
        else for (const bt of sink.base.t) withBase.addTemplate([...bt, ...t]);
      }
      if (!withBase.isEmpty) urlAV = withBase;
    }
    return { urlAV, methodAV };
  }

  // String literals that sit in a configuration position: an object property value, a class field or a
  // variable initialiser, and look like a URL base (absolute, or a path). A helper whose URL is exactly
  // such a base followed by a bare parameter is a generic request helper, not an endpoint.
  collectConfigLiterals() {
    const set = new Set();
    for (const unit of this.units) {
      if (!unit.program) continue;
      unit.program.traverse({
        StringLiteral(p) {
          const par = p.parentPath;
          const v = p.node.value;
          if (!/^(https?:\/\/|\/)[^\s]*$/.test(v)) return;
          if ((par.isObjectProperty() && par.node.value === p.node) ||
              (par.isClassProperty() && par.node.value === p.node) ||
              (par.isVariableDeclarator() && par.node.init === p.node)) set.add(v);
        },
      });
    }
    return set;
  }

  // template = <literal prefix><bare parameter>, and the prefix is a configured base
  isGenericHelper(template) {
    const last = template[template.length - 1];
    if (!last || last.k !== 'hole' || last.cls !== 'param') return false;
    let parts = template.slice(0, -1);
    if (parts.length && parts[0].k === 'hole') parts = parts.slice(1);
    if (parts.some((p) => p.k === 'hole')) return false;
    const prefix = parts.map((p) => p.s).join('');
    if (!prefix) return true; // nothing but a parameter
    if (!this._config) this._config = this.collectConfigLiterals();
    return this._config.has(prefix);
  }

  urlShaped(t) {
    const f = firstLit(t);
    if (f !== null) return /^\/[^\s/]/.test(f) || isAbs(f) || /^[a-z]+:\/\//i.test(f);
    // {base}/path
    return t.length >= 2 && t[0].k === 'hole' && t[1].k === 'lit' && /^\/[^\s/]/.test(t[1].s);
  }

  // ---- main loop -------------------------------------------------------------
  run() {
    const queue = [];
    for (const unit of this.units) {
      if (!unit.program) continue;
      for (const call of unit.calls) {
        if (Date.now() > this.deadline) { this.stats.timedOut = true; break; }
        let sink;
        const ctx = this.ev.newCtx();
        try {
          sink = this.classify(call, ctx);
          if (!sink) {
            const px = this.proxyCall(call, ctx);
            if (px) { sink = this.classify(call, ctx, px); if (sink) sink.args = px.args; }
          }
          if (!sink) continue;
          const uv = this.urlOf(sink, ctx);
          if (!uv) continue;
          this.stats.sinks++;
          this.stats.byKind[sink.kind] = (this.stats.byKind[sink.kind] || 0) + 1;
          let info = { params: [], auth: false };
          try { info = requestInfo(this.ev, sink, call, ctx); } catch (e) { this.stats.infoErrors = (this.stats.infoErrors || 0) + 1; }
          queue.push({ unit, call, sink, urlAV: uv.urlAV, methodAV: uv.methodAV, via: [], depth: 0, info });
        } catch (e) {
          this.stats.errors = (this.stats.errors || 0) + 1;
          this.stats.lastError = String(e && e.stack ? e.stack : e).slice(0, 300);
        }
      }
    }
    while (queue.length) {
      if (Date.now() > this.deadline) { this.stats.timedOut = true; break; }
      const item = queue.shift();
      try {
        this.process(item, queue);
      } catch (e) {
        this.stats.errors = (this.stats.errors || 0) + 1;
        this.stats.lastError = String(e && e.stack ? e.stack : e).slice(0, 300);
      }
    }
    for (const pass of [graphqlOperations, rtkEndpoints, nextRoutes]) {
      try {
        if (pass === graphqlOperations || pass === nextRoutes) pass(this.units, this);
        else pass(this.units, this.ev, this);
      } catch (e) {
        this.stats.errors = (this.stats.errors || 0) + 1;
        this.stats.lastError = String(e && e.stack ? e.stack : e).slice(0, 300);
      }
    }
    return this.findings;
  }

  process(item, queue) {
    const { sink } = item;
    const direct = [];
    const wrapped = new Map(); // fnKey -> templates
    for (const t of item.urlAV.t) {
      const ph = templateHoles(t).find((h) => h.cls === 'param' && h.idx >= 0);
      if (ph) {
        if (!wrapped.has(ph.fn)) wrapped.set(ph.fn, []);
        wrapped.get(ph.fn).push(t);
      } else direct.push(t);
    }
    for (const t of direct) this.emit(item, t, item.methodAV, false);
    for (const [fnKey, templates] of wrapped) {
      this.stats.wrappers++;
      const sites = item.depth < MAX_CHAIN ? this.callSites(fnKey) : [];
      if (!sites.length) {
        this.stats.uncalled++;
        for (const t of templates) {
          if (this.isGenericHelper(t)) { this.stats.genericWrappers = (this.stats.genericWrappers || 0) + 1; continue; }
          this.emit(item, t, item.methodAV, true);
        }
        continue;
      }
      const fnPath = this.fnByKey.get(fnKey);
      for (const site of sites) {
        const args = new Map();
        site.call.node.arguments.forEach((a, i) => {
          if (a.type === 'SpreadElement') return;
          args.set(i, site.args[i]);
        });
        const usable = new Map();
        for (const [i, av] of args) if (this.substitutable(av)) usable.set(i, av);
        const urls = new AV();
        for (const t of templates) for (const r of substitute(t, fnKey, usable)) urls.addTemplate(r);
        let methodAV = item.methodAV;
        if (methodAV) {
          const m2 = new AV();
          for (const t of methodAV.t) for (const r of substitute(t, fnKey, usable)) m2.addTemplate(r);
          methodAV = m2;
        }
        this.stats.derived++;
        const name = [...this.fnNames(fnPath)][0] || '(anonymous)';
        queue.push({
          unit: site.unit, call: site.call, sink, urlAV: urls, methodAV, info: this.carryInfo(item.info, fnKey, site),
          via: [...item.via, { fn: name, file: site.unit.id, ...site.unit.loc(site.call.node) }],
          depth: item.depth + 1,
        });
      }
    }
  }

  // The request info of a wrapper's sink, completed with what this call site passes for the parameters that
  // flow into the body / query / config (the wrapper itself cannot know them).
  carryInfo(info, fnKey, site) {
    const mine = (info.flows || []).filter((f) => f.fn === fnKey);
    if (!mine.length) return info;
    const params = new Set(info.params);
    const flows = (info.flows || []).filter((f) => f.fn !== fnKey);
    const callArgs = site.call.get('arguments');
    for (const f of mine) {
      const argPath = callArgs[f.idx];
      if (!argPath || argPath.isSpreadElement()) continue;
      const ctx = this.ev.newCtx();
      try {
        const keys = f.mode === 'cfg' ? configKeys(this.ev, argPath, ctx) : keysOf(this.ev, argPath, ctx);
        for (const k of keys) params.add(k);
        for (const nf of paramFlows(this.ev, argPath, ctx, f.mode)) {
          if (!flows.some((x) => x.fn === nf.fn && x.idx === nf.idx && x.mode === nf.mode)) flows.push(nf);
        }
      } catch (e) { this.stats.infoErrors = (this.stats.infoErrors || 0) + 1; }
    }
    return { params: cleanKeys(params), auth: info.auth, flows };
  }

  // Which argument values are substituted into a wrapper's URL template? Values
  // that only fill a path segment with data (a hole, a number, an id) stay as a
  // {param}: /api/users/{id} is the endpoint, not /api/users/5.
  substitutable(av) {
    if (!av || av.isEmpty) return false;
    if (!av.t.length) return false;
    return av.t.every((t) => {
      if (t.some((p) => p.k === 'hole' && (p.cls === 'param' || p.cls === 'runtime' || p.cls === 'unknown') && t.length === 1)) return false;
      const text = t.filter((p) => p.k === 'lit').map((p) => p.s).join('');
      if (!text) return false;
      if (/^\d+$/.test(text)) return false; // numeric id
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(text)) return false; // uuid
      return true;
    });
  }

  callSites(fnKey) {
    if (!this._sites) this._sites = new Map();
    if (this._sites.has(fnKey)) return this._sites.get(fnKey);
    const fnPath = this.fnByKey.get(fnKey);
    const out = [];
    this._sites.set(fnKey, out);
    if (!fnPath) return out;
    const names = this.fnNames(fnPath);
    const seen = new Set();
    for (const name of names) {
      for (const call of this.callsByName.get(name) || []) {
        if (call.node.type === 'NewExpression') continue;
        const unit = this.ev.unitOf(call);
        const ck = unit.key(call.node);
        if (seen.has(ck)) continue;
        seen.add(ck);
        const ctx = this.ev.newCtx();
        let ok = false;
        try {
          const fv = this.ev.eval(call.get('callee'), ctx);
          ok = fv.refs.some((r) => r.kind === 'fn' && r.path.node === fnPath.node);
        } catch (e) { ok = false; }
        if (!ok) continue;
        const args = call.get('arguments').map((a) => (a.isSpreadElement() ? null : this.ev.eval(a, this.ev.newCtx())));
        out.push({ unit, call, args });
        if (out.length >= 40) return out;
      }
    }
    return out;
  }

  // ---- output ----------------------------------------------------------------
  emit(item, template, methodAV, uncalled) {
    const { unit, call, sink } = item;
    const holes = templateHoles(template).map((h) => ({ cls: h.cls, name: h.name }));
    const lit = template.filter((p) => p.k === 'lit').map((p) => p.s).join('');
    if (!lit) return; // nothing known about this URL
    if (!sink.known && !this.urlShaped(template)) { this.stats.shapeRejected++; return; }
    // base: leading unresolved piece before a path
    let parts = template;
    let base = null;
    if (parts.length && parts[0].k === 'hole') {
      if (parts[0].cls === 'origin') parts = parts.slice(1);
      else if (parts.length > 1 && parts[1].k === 'lit' && /^\//.test(parts[1].s)) {
        base = `{${parts[0].name || 'base'}}`;
        parts = parts.slice(1);
      } else {
        // {unresolvedCall}{id}/x: which hole is the base and which is data cannot be told
        this.stats.partial = (this.stats.partial || 0) + 1;
        return;
      }
    }
    const text = renderTemplate(parts);
    if (!text) return;
    const methods = new Set();
    if (methodAV) {
      for (const t of methodAV.t) {
        if (t.length === 1 && t[0].k === 'lit') {
          const m = t[0].s.toUpperCase();
          if (VERB_SET.has(m) || m === 'WS') methods.add(m);
        }
      }
    }
    if (sink.method && !methods.size) methods.add(sink.method);
    const list = methods.size ? [...methods].sort() : [null];
    for (const method of list) {
      const key = [unit.id, unit.key(call.node), text, method].join('|');
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      this.findings.push({
        file: unit.id, ...unit.loc(call.node), kind: sink.kind, method, url: text, base,
        holes, known: !!sink.known, lib: sink.lib || null, via: item.via, uncalled,
        widened: !!item.urlAV.widened, params: item.info?.params ?? [], auth: !!item.info?.auth,
      });
    }
  }
}
