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
      return keys;
    }
    default:
      return keys;
  }
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
  const args = call.get('arguments');
  const method = (sink.method || '').toUpperCase();
  const params = new Set();
  let auth = false;
  let cfg = null;
  if (sink.kind === 'fetch') cfg = args[1];
  else if (sink.kind === 'http') {
    if (sink.url) {
      const bodyLike = method === 'POST' || method === 'PUT' || method === 'PATCH';
      if (bodyLike && args[1]) for (const k of keysOf(ev, args[1], ctx)) params.add(k);
      cfg = bodyLike ? args[2] : args[1];
    } else cfg = args[0]; // axios({ url, method, data, params, headers })
  }
  if (cfg && cfg.node) {
    for (const key of ['params', 'data', 'body']) {
      const p = propPath(ev, cfg, key, ctx);
      if (p) for (const k of keysOf(ev, p, ctx)) params.add(k);
    }
    const h = propPath(ev, cfg, 'headers', ctx);
    if (h) for (const k of keysOf(ev, h, ctx)) if (AUTH_KEY.test(k)) auth = true;
  }
  return { params: [...params].filter((k) => /^[A-Za-z_][A-Za-z0-9_.-]{0,40}$/.test(k)).sort().slice(0, 15), auth };
}
