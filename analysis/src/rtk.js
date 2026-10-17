// RTK Query: createApi({ baseQuery: fetchBaseQuery({ baseUrl }), endpoints: (b) => ({ name: b.query({ query }) }) })
// Every endpoint's `query` returns either a URL string or { url, method, ... }; the request goes to
// baseUrl + "/" + url (RTK joins them with exactly one slash).
import { AV, lit, normTemplate } from './values.js';

function keyOf(p) {
  if (!p.node.key || p.node.computed) return null;
  return p.node.key.name ?? p.node.key.value ?? null;
}

function join(baseT, urlT) {
  const b = baseT ? baseT.slice() : [];
  const u = urlT.slice();
  if (b.length && b[b.length - 1].k === 'lit') b[b.length - 1] = lit(b[b.length - 1].s.replace(/\/+$/, ''));
  if (u.length && u[0].k === 'lit') u[0] = lit(u[0].s.replace(/^\/+/, ''));
  return normTemplate([...b, lit('/'), ...u]);
}

export function rtkEndpoints(units, ev, sinks) {
  for (const unit of units) {
    if (!unit.program) continue;
    for (const call of unit.calls) {
      if (call.node.type !== 'CallExpression' || ev.hint(call.get('callee')) !== 'createApi') continue;
      const cfg = call.get('arguments.0');
      if (!cfg || !cfg.node || !cfg.isObjectExpression()) continue;
      const props = new Map();
      for (const p of cfg.get('properties')) if (p.isObjectProperty() || p.isObjectMethod()) props.set(keyOf(p), p);
      // baseUrl
      let base = null;
      const bq = props.get('baseQuery');
      if (bq && bq.isObjectProperty()) {
        const bqv = bq.get('value');
        if (bqv.isCallExpression() && bqv.get('arguments.0').node) {
          const cv = ev.eval(bqv.get('arguments.0'), ev.newCtx());
          const bAV = new AV();
          for (const r of cv.refs) bAV.merge(ev.getProp(r, 'baseUrl', ev.newCtx()));
          if (!bAV.isEmpty) base = bAV;
        }
      }
      // endpoints
      const ep = props.get('endpoints');
      const fn = ep && (ep.isObjectMethod() ? ep : ep.get('value'));
      if (!fn || !fn.node || !fn.isFunction()) continue;
      const built = ev.evalReturns(fn, ev.newCtx());
      for (const r of built.refs) {
        if (r.kind !== 'obj') continue;
        for (const e of r.path.get('properties')) {
          if (!e.isObjectProperty()) continue;
          const call2 = e.get('value');
          if (!call2.isCallExpression()) continue;
          const c = call2.node.callee;
          if (c.type !== 'MemberExpression' || !['query', 'mutation', 'infiniteQuery'].includes(c.property.name)) continue;
          const o = call2.get('arguments.0');
          if (!o || !o.node || !o.isObjectExpression()) continue;
          const q = o.get('properties').find((p) => (p.isObjectProperty() || p.isObjectMethod()) && keyOf(p) === 'query');
          if (!q) continue;
          const qfn = q.isObjectMethod() ? q : q.get('value');
          if (!qfn.isFunction()) continue;
          const ret = ev.evalReturns(qfn, ev.newCtx());
          const urls = new AV();
          const methods = new AV();
          for (const t of ret.t) urls.addTemplate(t);
          for (const rr of ret.refs) {
            if (rr.kind !== 'obj') continue;
            urls.merge(ev.getProp(rr, 'url', ev.newCtx()));
            methods.merge(ev.getProp(rr, 'method', ev.newCtx()));
          }
          const full = new AV();
          for (const t of urls.t) {
            const bases = base && base.t.length ? base.t : [null];
            for (const bt of bases) full.addTemplate(join(bt, t));
          }
          if (full.isEmpty) continue;
          const methodAV = methods.isEmpty ? AV.str('GET') : methods;
          sinks.stats.sinks++;
          sinks.stats.byKind['rtk-query'] = (sinks.stats.byKind['rtk-query'] || 0) + 1;
          const item = {
            unit, call: call2, sink: { kind: 'http', known: true, lib: 'rtk-query' }, urlAV: full, methodAV,
            via: [], depth: 0, info: { params: [], auth: false },
          };
          for (const t of full.t) sinks.emit(item, t, methodAV, false);
        }
      }
    }
  }
}
