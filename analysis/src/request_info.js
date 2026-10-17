// What a request carries, read off the sink call: parameter names (query / body keys) and whether an
// authorisation header is set. Names only: values are never evaluated into the report.

const AUTH_KEY = /^(authorization|x-api-key|x-auth-token|x-access-token|proxy-authorization)$/i;
const BUILDERS = new Set(['HttpParams', 'HttpHeaders', 'URLSearchParams', 'FormData']);
const CHAIN = new Set(['set', 'append']);

function keyName(node) {
  if (!node || node.computed) return null;
  const k = node.key;
  if (!k) return null;
  return k.type === 'Identifier' ? k.name : k.type === 'StringLiteral' ? k.value : null;
}

// names of the keys an expression (object literal, builder chain, JSON.stringify(x), variable) holds
export function keysOf(ev, path, ctx, depth = 0) {
  const keys = new Set();
  if (!path || !path.node || depth > 4) return keys;
  const n = path.node;
  switch (n.type) {
    case 'ObjectExpression':
      for (const p of path.get('properties')) {
        if (p.isObjectProperty() || p.isObjectMethod()) {
          const k = keyName(p.node);
          if (k) keys.add(k);
        }
      }
      return keys;
    case 'NewExpression': {
      const name = n.callee.type === 'Identifier' ? n.callee.name : null;
      if (name && BUILDERS.has(name) && n.arguments[0]) return keysOf(ev, path.get('arguments.0'), ctx, depth + 1);
      return keys;
    }
    case 'CallExpression': {
      const c = n.callee;
      // JSON.stringify(x)
      if (c.type === 'MemberExpression' && c.object.type === 'Identifier' && c.object.name === 'JSON' &&
          c.property.name === 'stringify' && n.arguments[0]) return keysOf(ev, path.get('arguments.0'), ctx, depth + 1);
      // params.set('k', v).append('j', w)
      if (c.type === 'MemberExpression' && !c.computed && CHAIN.has(c.property.name)) {
        const out = keysOf(ev, path.get('callee.object'), ctx, depth + 1);
        if (n.arguments[0] && n.arguments[0].type === 'StringLiteral') out.add(n.arguments[0].value);
        return out;
      }
      return keys;
    }
    case 'Identifier': case 'MemberExpression': {
      const v = ev.eval(path, ctx);
      for (const r of v.refs) if (r.kind === 'obj') for (const k of keysOf(ev, r.path, ctx, depth + 1)) keys.add(k);
      if (n.type === 'Identifier') {
        const b = path.scope.getBinding(n.name);
        // const params = new HttpParams().set('id', x)  /  const body = { a, b }
        if (b && b.constant && b.path.isVariableDeclarator() && b.path.node.init && !keys.size) {
          for (const k of keysOf(ev, b.path.get('init'), ctx, depth + 1)) keys.add(k);
        }
        // request: CreatePermitRequest - the members of the declared interface / type literal
        const ann = b && b.path.node && (b.path.node.typeAnnotation || b.path.node.id?.typeAnnotation);
        const ref = ann && ann.typeAnnotation;
        if (ref && ref.type === 'TSTypeReference' && ref.typeName.type === 'Identifier') {
          for (const k of typeKeys(ev, ref.typeName.name)) keys.add(k);
        }
      }
      return keys;
    }
    default:
      return keys;
  }
}

// member names of `interface Name {...}` / `type Name = {...}` anywhere in the analysed files
function typeKeys(ev, name) {
  if (!ev._typeIndex) {
    const idx = new Map();
    const members = (body) => {
      const out = [];
      for (const m of body || []) {
        if (m.type !== 'TSPropertySignature' || m.computed) continue;
        const k = m.key.type === 'Identifier' ? m.key.name : m.key.type === 'StringLiteral' ? m.key.value : null;
        if (k) out.push(k);
      }
      return out;
    };
    for (const unit of ev.units) {
      if (!unit.program) continue;
      unit.program.traverse({
        TSInterfaceDeclaration(p) {
          const cur = idx.get(p.node.id.name) || new Set();
          for (const k of members(p.node.body.body)) cur.add(k);
          idx.set(p.node.id.name, cur);
        },
        TSTypeAliasDeclaration(p) {
          if (p.node.typeAnnotation.type !== 'TSTypeLiteral') return;
          const cur = idx.get(p.node.id.name) || new Set();
          for (const k of members(p.node.typeAnnotation.members)) cur.add(k);
          idx.set(p.node.id.name, cur);
        },
      });
    }
    ev._typeIndex = idx;
  }
  return ev._typeIndex.get(name) || new Set();
}

// Parameters of the enclosing function that this expression is made of: [{fn, idx}]. When a request helper
// passes its own parameter on as the body / query object, the keys are only known at its call sites.
export function paramFlows(ev, path, ctx, mode) {
  const out = [];
  if (!path || !path.node) return out;
  let v;
  try { v = ev.eval(path, ctx); } catch (e) { return out; }
  for (const t of v.t) {
    if (t.length !== 1 || t[0].k !== 'hole' || t[0].cls !== 'param' || t[0].idx == null || t[0].idx < 0) continue;
    out.push({ fn: t[0].fn, idx: t[0].idx, mode });
  }
  return out;
}

// keys of the params / data / body properties of a request-config object
export function configKeys(ev, cfg, ctx) {
  const keys = new Set();
  for (const key of ['params', 'data', 'body']) {
    const p = propPath(ev, cfg, key, ctx);
    if (p) for (const k of keysOf(ev, p, ctx)) keys.add(k);
  }
  return keys;
}

export function cleanKeys(set) {
  return [...set].filter((k) => /^[A-Za-z_][A-Za-z0-9_.-]{0,40}$/.test(k)).sort().slice(0, 15);
}

function propPath(ev, objPath, name, ctx) {
  // the value expression of property `name` of an object (literal, or a variable holding one)
  let lit = objPath;
  if (!lit.isObjectExpression()) {
    const v = ev.eval(objPath, ctx);
    const r = v.refs.find((x) => x.kind === 'obj');
    if (!r) return null;
    lit = r.path;
  }
  for (const p of lit.get('properties')) {
    if (p.isObjectProperty() && keyName(p.node) === name) return p.get('value');
  }
  return null;
}

export function requestInfo(ev, sink, call, ctx) {
  const args = sink.args || call.get('arguments');
  const method = (sink.method || '').toUpperCase();
  const params = new Set();
  const flows = [];
  let auth = false;
  let cfg = null;
  if (sink.kind === 'fetch') cfg = args[1];
  else if (sink.kind === 'http') {
    if (sink.url) {
      const bodyLike = method === 'POST' || method === 'PUT' || method === 'PATCH';
      if (bodyLike && args[1]) {
        for (const k of keysOf(ev, args[1], ctx)) params.add(k);
        flows.push(...paramFlows(ev, args[1], ctx, 'keys'));
      }
      cfg = bodyLike ? args[2] : args[1];
    } else cfg = args[0]; // axios({ url, method, data, params, headers })
  }
  if (cfg && cfg.node) {
    for (const k of configKeys(ev, cfg, ctx)) params.add(k);
    for (const key of ['params', 'data', 'body']) {
      const p = propPath(ev, cfg, key, ctx);
      if (p) flows.push(...paramFlows(ev, p, ctx, 'keys'));
    }
    flows.push(...paramFlows(ev, cfg, ctx, 'cfg'));      // the whole config object is a parameter
    const h = propPath(ev, cfg, 'headers', ctx);
    if (h) for (const k of keysOf(ev, h, ctx)) if (AUTH_KEY.test(k)) auth = true;
  }
  return { params: cleanKeys(params), auth, flows };
}
