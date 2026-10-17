// Abstract values for the URL value-flow analysis.
//
// A string value is a finite set (at most K) of TEMPLATES. A template is a
// sequence of parts, each a literal string or a hole:
//
//   lit(s)                      known text
//   hole(cls, name, extra)      an unknown piece; cls says why it is unknown:
//       param    a parameter of a function (substituted at call sites)
//       unknown  could not be resolved (identifier, property, call result)
//       origin   the page origin (location.origin, document.baseURI, ...)
//       env      build-time environment (process.env.X, import.meta.env.X)
//       runtime  data produced while running (storage, DOM, events)
//
// An abstract value (AV) also carries references to non-string things the
// analysis follows (objects, arrays, functions, classes, instances, modules,
// native library objects), because URLs are usually built from config objects
// and service methods rather than from string literals alone.

export const K = 8; // maximum templates per value; beyond that the value is widened

export const lit = (s) => ({ k: 'lit', s: String(s) });
export const hole = (cls, name = '', extra = null) => {
  const h = { k: 'hole', cls, name: cleanName(name) };
  if (extra) Object.assign(h, extra);
  return h;
};

function cleanName(n) {
  const s = String(n ?? '').replace(/[^A-Za-z0-9_$]/g, '');
  return s || '';
}

// ---- templates ----------------------------------------------------------

export function normTemplate(parts) {
  const out = [];
  for (const p of parts) {
    if (p.k === 'lit') {
      if (p.s === '') continue;
      const last = out[out.length - 1];
      if (last && last.k === 'lit') out[out.length - 1] = lit(last.s + p.s);
      else out.push(p);
    } else out.push(p);
  }
  return out;
}

export function templateKey(t) {
  return t.map((p) => (p.k === 'lit' ? 'L' + p.s : `H${p.cls}:${p.name}:${p.fn ?? ''}:${p.idx ?? ''}`)).join('\u0001');
}

// Text form: holes as {name}; nameless holes as {param}.
const MANGLED = /^_0x[0-9a-f]{3,}$/; // obfuscator-generated identifier: not a name worth showing
export function renderTemplate(t) {
  return t.map((p) => (p.k === 'lit' ? p.s : `{${p.name && !MANGLED.test(p.name) ? p.name : 'param'}}`)).join('');
}

export function templateHoles(t) {
  return t.filter((p) => p.k === 'hole');
}

// ---- abstract values ----------------------------------------------------

export class AV {
  constructor() {
    this.t = []; // templates
    this.refs = []; // non-string references
    this.widened = false;
    this._keys = new Set();
    this._refIds = new Set();
  }
  static ofTemplate(parts) {
    const v = new AV();
    v.addTemplate(parts);
    return v;
  }
  static ofRef(ref) {
    const v = new AV();
    v.addRef(ref);
    return v;
  }
  static str(s) {
    return AV.ofTemplate([lit(s)]);
  }
  static unknown(name = '', cls = 'unknown') {
    return AV.ofTemplate([hole(cls, name)]);
  }
  addTemplate(parts) {
    const t = normTemplate(parts);
    const key = templateKey(t);
    if (this._keys.has(key)) return;
    if (this.t.length >= K) {
      this.widened = true;
      return;
    }
    this._keys.add(key);
    this.t.push(t);
  }
  addRef(ref) {
    if (this._refIds.has(ref.id)) return;
    this._refIds.add(ref.id);
    this.refs.push(ref);
  }
  merge(other) {
    if (!other) return this;
    for (const t of other.t) this.addTemplate(t);
    for (const r of other.refs) this.addRef(r);
    if (other.widened) this.widened = true;
    return this;
  }
  get isEmpty() {
    return this.t.length === 0 && this.refs.length === 0;
  }
  // concatenation (JS `+` on strings): every template of a followed by every template of b
  static concat(a, b) {
    const out = new AV();
    const as = a.t.length ? a.t : [[hole('unknown', refName(a))]];
    const bs = b.t.length ? b.t : [[hole('unknown', refName(b))]];
    for (const x of as) for (const y of bs) out.addTemplate([...x, ...y]);
    if (a.widened || b.widened) out.widened = true;
    return out;
  }
}

function refName(v) {
  return v.refs.length ? v.refs[0].name || '' : '';
}

export function union(...vs) {
  const out = new AV();
  for (const v of vs) out.merge(v);
  return out;
}

// Replace param holes of function `fn` by the argument values (cartesian, capped).
export function substitute(template, fnKey, argsByIdx) {
  let results = [[]];
  for (const p of template) {
    if (p.k === 'hole' && p.cls === 'param' && p.fn === fnKey && argsByIdx.has(p.idx)) {
      const arg = argsByIdx.get(p.idx);
      const alts = arg.t.length ? arg.t : [[hole('unknown', p.name)]];
      const next = [];
      for (const r of results) for (const a of alts) next.push([...r, ...a]);
      results = next.slice(0, K * K);
    } else {
      for (const r of results) r.push(p);
    }
  }
  return results.map(normTemplate);
}
