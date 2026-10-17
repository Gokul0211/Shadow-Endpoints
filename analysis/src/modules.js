// Module graph: resolves import / require specifiers between the input files,
// builds each module's export table, and recognises webpack module tables
// (so a bundle is analysed as separate modules, not as one blob).

const EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];

function dirname(p) {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

function joinNorm(base, rel) {
  const parts = (base ? base.split('/') : []).concat(rel.split('/'));
  const out = [];
  for (const s of parts) {
    if (s === '' || s === '.') continue;
    if (s === '..') out.pop();
    else out.push(s);
  }
  return '/' + out.join('/');
}

const keyOf = (node) => {
  if (!node) return null;
  if (node.type === 'NumericLiteral') return String(node.value);
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'Identifier') return node.name;
  return null;
};

export class Modules {
  constructor(units) {
    this.units = units;
    this.byNorm = new Map();
    for (const u of units) this.byNorm.set(u.norm, u);
    this.tables = []; // {unit, container, entries: Map(key -> fnPath)}
    this.fnTable = new Map(); // fn node -> {table, key}
    this.exportsCache = new Map();
    this.resolveCache = new Map();
  }

  // ---- specifier resolution ------------------------------------------------
  resolve(spec, from) {
    const ck = from.id + '\u0001' + spec;
    if (this.resolveCache.has(ck)) return this.resolveCache.get(ck);
    const r = this._resolve(spec, from);
    this.resolveCache.set(ck, r);
    return r;
  }

  _candidates(path) {
    const c = [path];
    for (const e of EXTS) c.push(path + e);
    for (const e of EXTS) c.push(path + '/index' + e);
    return c;
  }

  _resolve(spec, from) {
    if (!spec) return null;
    const clean = spec.split('?')[0].replace(/^webpack:\/\/[^/]*\//, '').replace(/^~\//, '');
    if (clean.startsWith('./') || clean.startsWith('../')) {
      const target = joinNorm(dirname(from.norm), clean);
      for (const c of this._candidates(target)) if (this.byNorm.has(c)) return this.byNorm.get(c);
    }
    // aliases / baseUrl imports / bundler paths: unique suffix match
    const bare = clean.replace(/^(\.\/|\.\.\/)+/, '').replace(/^[@~]+[^/]*\//, (m) => (m.startsWith('@') && !clean.includes('/') ? m : ''));
    const tails = new Set([bare, clean.replace(/^(\.\/|\.\.\/)+/, '')]);
    let best = null;
    let bestCount = 0;
    for (const tail of tails) {
      if (!tail) continue;
      const found = [];
      for (const c of this._candidates('/' + tail)) {
        for (const [norm, unit] of this.byNorm) {
          if (norm === c || norm.endsWith(c)) found.push(unit);
        }
      }
      const uniq = [...new Set(found)];
      if (uniq.length === 1) return uniq[0];
      if (uniq.length > 1 && (best === null || uniq.length < bestCount)) {
        // ambiguous: prefer the file closest to the importer
        uniq.sort((a, b) => commonPrefix(b.norm, from.norm) - commonPrefix(a.norm, from.norm));
        best = uniq[0];
        bestCount = uniq.length;
      }
    }
    return best;
  }

  // ---- webpack module tables ----------------------------------------------
  detectTables() {
    for (const unit of this.units) {
      if (!unit.program) continue;
      const fingerprint = /__webpack_(?:modules|require)__|webpackChunk|webpackJsonp|webpack_modules/.test(unit.code);
      const groups = new Map(); // container node -> entries
      for (const fn of unit.functions) {
        const parent = fn.parentPath;
        if (!parent) continue;
        let container = null;
        let key = null;
        if (parent.isObjectProperty() && parent.node.value === fn.node) {
          const kt = parent.node.key.type;
          if (!parent.node.computed || kt === 'NumericLiteral' || kt === 'StringLiteral') {
            container = parent.parentPath?.node;
            key = keyOf(parent.node.key);
          }
        } else if (fn.isObjectMethod() && parent.isObjectExpression()) {
          container = parent.node;
          key = keyOf(fn.node.key);
        } else if (parent.isArrayExpression()) {
          container = parent.node;
          key = String(parent.node.elements.indexOf(fn.node));
        } else if (
          fingerprint &&
          parent.isAssignmentExpression() &&
          parent.node.right === fn.node &&
          parent.node.left.type === 'MemberExpression' &&
          parent.node.left.computed &&
          parent.node.left.object.type === 'Identifier'
        ) {
          // __webpack_modules__[10] = function (m, e, r) { ... }
          container = `${unit.id}:${parent.node.left.object.name}#assign`;
          key = keyOf(parent.node.left.property);
        }
        if (container === null || key === null) continue;
        if (fn.node.params.length > 3) continue;
        let g = groups.get(container);
        if (!g) groups.set(container, (g = []));
        g.push({ key, fn });
      }
      for (const [container, members] of groups) {
        const minMembers = fingerprint ? 1 : 2;
        if (members.length < minMembers) continue;
        if (!fingerprint && !members.some((m) => this._looksLikeModuleFn(m.fn))) continue;
        const entries = new Map();
        for (const m of members) entries.set(String(m.key), m.fn);
        const table = { unit, container, entries };
        this.tables.push(table);
        unit.tables.push(table);
        for (const [key, fn] of entries) this.fnTable.set(fn.node, { table, key });
      }
    }
  }

  // module functions assign to / read their exports parameter: (m, e, r) { e.X = ...; r(5) }
  _looksLikeModuleFn(fn) {
    const params = fn.node.params;
    if (params.length < 2 || params.length > 3) return false;
    let hit = false;
    fn.traverse({
      Function(p) {
        if (p.node !== fn.node) p.skip();
      },
      AssignmentExpression(p) {
        const l = p.node.left;
        if (l.type === 'MemberExpression' && l.object.type === 'Identifier' &&
            params.some((q) => q.type === 'Identifier' && q.name === l.object.name)) hit = true;
        if (l.type === 'MemberExpression' && l.object.type === 'Identifier' && l.object.name === 'module') hit = true;
      },
      CallExpression(p) {
        const c = p.node.callee;
        if (params[2]?.type === 'Identifier' && c.type === 'Identifier' && c.name === params[2].name) hit = true;
      },
    });
    return hit;
  }

  // `require(n)` inside a module function: returns the target module fn path, or null
  webpackTarget(callPath, binding) {
    // binding: the callee's binding; it must be the 3rd parameter of a module function
    const p = binding?.path;
    if (!p || p.listKey !== 'params' || p.key !== 2) return null;
    const info = this.fnTable.get(p.parentPath.node);
    if (!info) return null;
    const arg = callPath.node.arguments[0];
    const k = keyOf(arg);
    if (k === null) return null;
    const own = info.table.entries.get(String(k));
    if (own) return own;
    // other chunk: unique key across all tables
    let found = null;
    for (const t of this.tables) {
      const e = t.entries.get(String(k));
      if (e) {
        if (found) return null;
        found = e;
      }
    }
    return found;
  }

  // ---- export tables ------------------------------------------------------
  // result: {named: Map(name -> entry), stars: [spec], whole: path|null}
  // entry: {path} | {binding} | {getter: fnPath} | {reexport: spec, name}
  exportsOfUnit(unit) {
    const ck = 'u:' + unit.id;
    if (this.exportsCache.has(ck)) return this.exportsCache.get(ck);
    const ex = { named: new Map(), stars: [], whole: null, unit };
    this.exportsCache.set(ck, ex);
    if (!unit.program) return ex;
    const scope = unit.program.scope;
    for (const st of unit.program.get('body')) {
      if (st.isExportNamedDeclaration()) {
        const decl = st.get('declaration');
        if (decl.node) {
          if (decl.isVariableDeclaration()) {
            for (const d of decl.get('declarations')) {
              if (d.node.id.type === 'Identifier') ex.named.set(d.node.id.name, { binding: scope.getBinding(d.node.id.name) });
            }
          } else if (decl.node.id) {
            ex.named.set(decl.node.id.name, { binding: scope.getBinding(decl.node.id.name) });
          }
        }
        const src = st.node.source?.value;
        for (const sp of st.get('specifiers')) {
          if (sp.isExportSpecifier()) {
            const exported = keyOf(sp.node.exported);
            const local = sp.node.local.name;
            if (src) ex.named.set(exported, { reexport: src, name: local });
            else ex.named.set(exported, { binding: scope.getBinding(local) });
          } else if (sp.isExportNamespaceSpecifier() && src) {
            ex.named.set(keyOf(sp.node.exported), { reexport: src, name: '*' });
          }
        }
      } else if (st.isExportDefaultDeclaration()) {
        ex.named.set('default', { path: st.get('declaration') });
      } else if (st.isExportAllDeclaration()) {
        ex.stars.push(st.node.source.value);
      }
    }
    // CommonJS
    for (const a of unit.assigns) this._cjsAssign(a, ex, scope);
    return ex;
  }

  _cjsAssign(a, ex, scope) {
    const l = a.node.left;
    if (l.type !== 'MemberExpression' || a.node.operator !== '=') return;
    const isGlobal = (name) => !a.scope.getBinding(name);
    const prop = !l.computed && l.property.type === 'Identifier' ? l.property.name : keyOf(l.property);
    const right = a.get('right');
    if (l.object.type === 'Identifier' && l.object.name === 'exports' && isGlobal('exports') && prop) {
      ex.named.set(prop, { path: right });
    } else if (l.object.type === 'Identifier' && l.object.name === 'module' && isGlobal('module') && prop === 'exports') {
      ex.whole = right;
    } else if (
      l.object.type === 'MemberExpression' && l.object.object.type === 'Identifier' &&
      l.object.object.name === 'module' && isGlobal('module') && keyOf(l.object.property) === 'exports' && prop
    ) {
      ex.named.set(prop, { path: right });
    }
  }

  // exports of a webpack module function (params: module, exports, require)
  exportsOfWebpack(fnPath) {
    const cached = this.exportsCache.get(fnPath.node);
    if (cached) return cached;
    const ex = { named: new Map(), stars: [], whole: null, fn: fnPath };
    this.exportsCache.set(fnPath.node, ex);
    const params = fnPath.node.params.filter((p) => p.type === 'Identifier').map((p) => p.name);
    const [modName, expName, reqName] = [params[0], params[1], params[2]];
    const isParam = (id, name, path) => id.type === 'Identifier' && id.name === name &&
      path.scope.getBinding(name) === fnPath.scope.getBinding(name);
    fnPath.traverse({
      AssignmentExpression(p) {
        const l = p.node.left;
        if (l.type !== 'MemberExpression' || p.node.operator !== '=') return;
        const prop = l.computed ? keyOf(l.property) : l.property.type === 'Identifier' ? l.property.name : null;
        if (expName && isParam(l.object, expName, p) && prop) ex.named.set(prop, { path: p.get('right') });
        else if (modName && isParam(l.object, modName, p) && prop === 'exports') ex.whole = p.get('right');
        else if (modName && l.object.type === 'MemberExpression' && isParam(l.object.object, modName, p) &&
          keyOf(l.object.property) === 'exports' && prop) ex.named.set(prop, { path: p.get('right') });
      },
      CallExpression(p) {
        const c = p.node.callee;
        const args = p.node.arguments;
        // r.d(exports, { X: () => v, ... })   |   r.d(exports, "X", () => v)
        if (c.type === 'MemberExpression' && !c.computed && c.property.name === 'd' && args.length >= 2 &&
            expName && isParam(args[0], expName, p)) {
          if (args[1].type === 'ObjectExpression') {
            p.get('arguments.1.properties').forEach((pp) => {
              if (pp.isObjectProperty() && pp.get('value').isFunction()) ex.named.set(keyOf(pp.node.key), { getter: pp.get('value') });
              else if (pp.isObjectMethod()) ex.named.set(keyOf(pp.node.key), { getter: pp });
            });
          } else if (args[1].type === 'StringLiteral' && args[2]) {
            const g = p.get('arguments.2');
            if (g.isFunction()) ex.named.set(args[1].value, { getter: g });
          }
        }
        // Object.defineProperty(exports, "X", { get: function() { return v } })
        if (c.type === 'MemberExpression' && c.object.type === 'Identifier' && c.object.name === 'Object' &&
            c.property.name === 'defineProperty' && args.length === 3 && expName && isParam(args[0], expName, p) &&
            args[1].type === 'StringLiteral' && args[2].type === 'ObjectExpression') {
          for (const pp of p.get('arguments.2.properties')) {
            const k = keyOf(pp.node.key);
            if (k === 'get' && pp.isObjectProperty() && pp.get('value').isFunction()) ex.named.set(args[1].value, { getter: pp.get('value') });
            else if (k === 'get' && pp.isObjectMethod()) ex.named.set(args[1].value, { getter: pp });
            else if (k === 'value' && pp.isObjectProperty()) ex.named.set(args[1].value, { path: pp.get('value') });
          }
        }
      },
    });
    return ex;
  }
}

function commonPrefix(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

export { keyOf };
