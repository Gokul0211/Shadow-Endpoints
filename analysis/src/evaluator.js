// Abstract evaluation of expressions to values (see values.js).
//
// Flow-insensitive: a variable's value is the union of everything assigned to it.
// Context-sensitive for calls: a call evaluates the callee's return expressions
// with the parameters bound to the argument values (depth-limited, memoised,
// cycle-guarded). Properties of config objects, class fields, `this.x` and
// injected services (through TypeScript type annotations) are followed across
// modules (ES imports, CommonJS require, webpack module tables).
import { AV, hole, lit, union } from './values.js';
import { keyOf } from './modules.js';

const MAX_CALL_DEPTH = 5;
const MAX_DEFS = 24;
const MAX_EXPR_DEPTH = 350;
const WRAPPERS = new Set([
  'ParenthesizedExpression', 'TSAsExpression', 'TSNonNullExpression', 'TSTypeAssertion',
  'TSSatisfiesExpression', 'TypeCastExpression', 'AwaitExpression', 'TSInstantiationExpression',
]);
const IDENTITY_FNS = new Set(['String', 'encodeURIComponent', 'encodeURI', 'decodeURIComponent', 'decodeURI', 'escape', 'unescape']);
const IDENTITY_METHODS = new Set(['toString', 'trim', 'trimStart', 'trimEnd', 'valueOf', 'normalize']);

export class Evaluator {
  constructor(modules, units) {
    this.modules = modules;
    this.units = units;
    this.unitByProgram = new Map();
    for (const u of units) if (u.program) this.unitByProgram.set(u.program.node, u);
    this.memo = new Map();
    this.returnsCache = new Map();
    this.callMemo = new Map();
    this.refCache = new Map();
    this.classMembersCache = new Map();
    this.stats = { calls: 0, memoHits: 0, depthCut: 0, cycleCut: 0 };
    this.exprDepth = 0;
    this._index();
  }

  unitOf(path) {
    return this.unitByProgram.get(path.scope.getProgramParent().path.node);
  }

  // ---- prepass indexes ------------------------------------------------------
  _index() {
    this.thisAssign = new Map(); // owner key -> Map(prop -> [right paths])
    this.protoAssign = new Map(); // ctor fn key -> Map(prop -> [right paths])
    this.propAssign = new Map(); // binding uid + '.' + prop -> [right paths]
    this.facs = new Map(); // class binding uid -> factory function path (Angular compiled constructors)
    this.facArgsCache = new Map();
    for (const u of this.units) {
      for (const a of u.assigns) {
        const l = a.node.left;
        if (l.type !== 'MemberExpression' || a.node.operator !== '=') continue;
        const prop = this._propName(l);
        if (prop === null) continue;
        const right = a.get('right');
        if (l.object.type === 'ThisExpression') {
          const owner = this.thisOwner(a);
          if (owner) this._push(this.thisAssign, owner.key, prop, right);
        } else if (l.object.type === 'Identifier') {
          const b = a.scope.getBinding(l.object.name);
          if (b) this._push(this.propAssign, this.bindingUid(u, b), prop, right, true);
          if (b && prop === '\u0275fac') this.facs.set(this.bindingUid(u, b), right);
        } else if (
          l.object.type === 'MemberExpression' && !l.object.computed &&
          l.object.property.type === 'Identifier' && l.object.property.name === 'prototype' &&
          l.object.object.type === 'Identifier'
        ) {
          // F.prototype.m = ...
          const b = a.scope.getBinding(l.object.object.name);
          if (b) this._push(this.protoAssign, this.bindingUid(u, b), prop, right);
        }
      }
    }
  }

  _push(map, key, prop, path, flat = false) {
    if (flat) {
      const k = key + '.' + prop;
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(path);
      return;
    }
    if (!map.has(key)) map.set(key, new Map());
    const m = map.get(key);
    if (!m.has(prop)) m.set(prop, []);
    m.get(prop).push(path);
  }

  _propName(member) {
    if (!member.computed) return member.property.type === 'Identifier' ? member.property.name : member.property.type === 'PrivateName' ? '#' + member.property.id.name : null;
    const p = member.property;
    if (p.type === 'StringLiteral') return p.value;
    if (p.type === 'NumericLiteral') return String(p.value);
    return null;
  }

  bindingUid(unit, binding) {
    return `${unit.id}@${binding.identifier.start}`;
  }

  // ---- owners of `this` -----------------------------------------------------
  // returns {kind:'class', path, key} | {kind:'fclass', path(fn), key} | {kind:'obj', path, key} | null
  thisOwner(path) {
    let fp = path.findParent((p) => p.isFunction() && !p.isArrowFunctionExpression());
    const cls = path.findParent((p) => p.isClass());
    const unit = this.unitOf(path);
    if (fp && fp.isClassMethod?.() || fp?.isClassPrivateMethod?.()) {
      const c = fp.findParent((p) => p.isClass());
      if (c) return { kind: 'class', path: c, key: unit.key(c.node) };
    }
    if (fp && fp.isObjectMethod()) {
      return { kind: 'obj', path: fp.parentPath, key: unit.key(fp.parentPath.node) };
    }
    if (fp) {
      const par = fp.parentPath;
      // F.prototype.m = function () { this... }
      if (par.isAssignmentExpression() && par.node.left.type === 'MemberExpression') {
        const o = par.node.left.object;
        if (o.type === 'MemberExpression' && !o.computed && o.property.name === 'prototype' && o.object.type === 'Identifier') {
          const b = par.scope.getBinding(o.object.name);
          if (b) return { kind: 'fclass', binding: b, key: this.bindingUid(unit, b) };
        }
      }
      // function F() { this.x = ... }  (constructor function)
      if (fp.isFunctionDeclaration() && fp.node.id) {
        const b = fp.scope.parent?.getBinding(fp.node.id.name) ?? fp.scope.getBinding(fp.node.id.name);
        if (b) return { kind: 'fclass', binding: b, key: this.bindingUid(unit, b) };
      }
      if (par.isVariableDeclarator() && par.node.id.type === 'Identifier') {
        const b = par.scope.getBinding(par.node.id.name);
        if (b) return { kind: 'fclass', binding: b, key: this.bindingUid(unit, b) };
      }
      return null;
    }
    if (cls) return { kind: 'class', path: cls, key: unit.key(cls.node) };
    return null;
  }

  // ---- refs -----------------------------------------------------------------
  ref(kind, id, extra) {
    let r = this.refCache.get(id);
    if (!r) {
      r = { kind, id, ...extra };
      this.refCache.set(id, r);
    }
    return r;
  }
  fnRef(path) {
    const u = this.unitOf(path);
    const name = path.node.id?.name || path.node.key?.name || '';
    return this.ref('fn', 'fn:' + u.key(path.node), { path, unit: u, name });
  }
  classRef(path) {
    const u = this.unitOf(path);
    return this.ref('class', 'class:' + u.key(path.node), { path, unit: u, name: path.node.id?.name || '' });
  }
  instRef(owner) {
    if (owner.kind === 'class') {
      const c = this.classRef(owner.path);
      return this.ref('inst', 'inst:' + c.id, { cls: c, name: c.name });
    }
    if (owner.kind === 'fclass') {
      return this.ref('finst', 'finst:' + owner.key, { binding: owner.binding, key: owner.key, name: owner.binding.identifier.name });
    }
    return this.ref('obj', 'obj:' + owner.key, { path: owner.path, unit: this.unitOf(owner.path), name: '' });
  }
  native(lib, name = '', extra = null) {
    return this.ref('native', `native:${lib}:${name}:${extra?.baseKey ?? ''}`, { lib, name, ...(extra || {}) });
  }

  // ---- entry point ----------------------------------------------------------
  // Depth-guarded: minified bundles contain very deep `+` chains; past MAX_EXPR_DEPTH a value is unknown
  // instead of overflowing the JavaScript stack.
  eval(path, ctx) {
    if (this.exprDepth >= MAX_EXPR_DEPTH) {
      this.stats.depthCut++;
      return path && path.node ? AV.unknown(this.hint(path)) : new AV();
    }
    this.exprDepth++;
    try {
      return this._eval(path, ctx);
    } finally {
      this.exprDepth--;
    }
  }

  _eval(path, ctx) {
    if (!path || !path.node) return new AV();
    const t = path.node.type;
    if (WRAPPERS.has(t)) return this.eval(path.get('expression'), ctx);
    switch (t) {
      case 'StringLiteral': return AV.str(path.node.value);
      case 'NumericLiteral': case 'BigIntLiteral': case 'DecimalLiteral': return AV.str(String(path.node.value));
      case 'BooleanLiteral': return AV.str(String(path.node.value));
      case 'NullLiteral': case 'RegExpLiteral': return AV.unknown('');
      case 'TemplateLiteral': return this.evalTemplate(path, ctx);
      case 'BinaryExpression':
        if (path.node.operator === '+') return AV.concat(this.eval(path.get('left'), ctx), this.eval(path.get('right'), ctx));
        return AV.unknown('n');
      case 'LogicalExpression': return union(this.eval(path.get('left'), ctx), this.eval(path.get('right'), ctx));
      case 'ConditionalExpression': return union(this.eval(path.get('consequent'), ctx), this.eval(path.get('alternate'), ctx));
      case 'AssignmentExpression': return this.eval(path.get('right'), ctx);
      case 'SequenceExpression': { const e = path.get('expressions'); return this.eval(e[e.length - 1], ctx); }
      case 'UnaryExpression': return path.node.operator === 'void' ? new AV() : AV.unknown('');
      case 'Identifier': return this.evalIdentifier(path, ctx);
      case 'MemberExpression': case 'OptionalMemberExpression': return this.evalMember(path, ctx);
      case 'CallExpression': case 'OptionalCallExpression': return this.evalCall(path, ctx);
      case 'NewExpression': return this.evalNew(path, ctx);
      case 'ObjectExpression': return AV.ofRef(this.ref('obj', 'obj:' + this.unitOf(path).key(path.node), { path, unit: this.unitOf(path), name: '' }));
      case 'ArrayExpression': return AV.ofRef(this.ref('arr', 'arr:' + this.unitOf(path).key(path.node), { path, unit: this.unitOf(path), name: '' }));
      case 'ArrowFunctionExpression': case 'FunctionExpression': case 'FunctionDeclaration':
      case 'ObjectMethod': case 'ClassMethod': return AV.ofRef(this.fnRef(path));
      case 'ClassExpression': case 'ClassDeclaration': return AV.ofRef(this.classRef(path));
      case 'ThisExpression': {
        const o = this.thisOwner(path);
        return o ? AV.ofRef(this.instRef(o)) : AV.unknown('this');
      }
      case 'MetaProperty': return AV.ofRef(this.native('importmeta'));
      case 'TaggedTemplateExpression': return AV.unknown('');
      default: return AV.unknown(this.hint(path));
    }
  }

  hint(path) {
    const n = path.node;
    if (!n) return '';
    if (n.type === 'Identifier') return n.name;
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') return this._propName(n) ?? '';
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') return this.hint(path.get('callee'));
    if (WRAPPERS.has(n.type)) return this.hint(path.get('expression'));
    return '';
  }

  evalTemplate(path, ctx) {
    const quasis = path.node.quasis;
    const exprs = path.get('expressions');
    let v = AV.str(quasis[0].value.cooked ?? quasis[0].value.raw);
    for (let i = 0; i < exprs.length; i++) {
      v = AV.concat(v, this.eval(exprs[i], ctx));
      v = AV.concat(v, AV.str(quasis[i + 1].value.cooked ?? quasis[i + 1].value.raw));
    }
    return v;
  }

  // ---- identifiers & bindings ----------------------------------------------
  evalIdentifier(path, ctx) {
    const name = path.node.name;
    if (name === 'undefined') return new AV();
    const b = path.scope.getBinding(name);
    if (!b) return this.evalGlobal(name);
    return this.evalBinding(b, ctx, path);
  }

  evalGlobal(name) {
    switch (name) {
      case 'window': case 'self': case 'globalThis': case 'global': return AV.ofRef(this.native('global', 'window'));
      case 'location': return AV.ofRef(this.native('location'));
      case 'document': return AV.ofRef(this.native('document'));
      case 'process': return AV.ofRef(this.native('process'));
      case 'localStorage': case 'sessionStorage': return AV.ofRef(this.native('storage', name));
      default: return AV.unknown(name);
    }
  }

  evalBinding(binding, ctx, fromPath) {
    const unit = this.unitOf(binding.path);
    const uid = this.bindingUid(unit, binding);
    const useMemo = ctx.env.size === 0;
    if (useMemo && this.memo.has(uid)) {
      this.stats.memoHits++;
      return this.memo.get(uid);
    }
    if (ctx.stack.has(uid)) {
      this.stats.cycleCut++;
      return new AV();
    }
    ctx.stack.add(uid);
    let result;
    try {
      result = this._binding(binding, unit, ctx);
    } finally {
      ctx.stack.delete(uid);
    }
    if (useMemo) this.memo.set(uid, result);
    return result;
  }

  _binding(binding, unit, ctx) {
    const name = binding.identifier.name;
    // parameters
    let pp = binding.path;
    while (pp && pp.listKey !== 'params' && !pp.isFunction() && !pp.isProgram()) pp = pp.parentPath;
    if (pp && pp.listKey === 'params' && (binding.kind === 'param' || binding.path.listKey === 'params' || this._insideParam(binding.path, pp))) {
      return this.evalParam(binding, pp, unit, ctx);
    }
    if (binding.kind === 'module') return this.evalImport(binding, unit, ctx);
    const out = new AV();
    const bp = binding.path;
    let n = 0;
    if (bp.isFunctionDeclaration()) out.merge(AV.ofRef(this.fnRef(bp)));
    else if (bp.isClassDeclaration()) out.merge(AV.ofRef(this.classRef(bp)));
    else if (bp.isVariableDeclarator()) {
      if (bp.node.init) {
        if (bp.node.id.type === 'Identifier') out.merge(this.eval(bp.get('init'), ctx));
        else out.merge(this.evalPattern(bp, binding.identifier, ctx));
      } else if (bp.parentPath?.parentPath?.isForXStatement?.() ) out.merge(AV.unknown(name, 'unknown'));
    } else if (bp.isIdentifier() && bp.parentPath?.isCatchClause()) out.merge(AV.unknown(name));
    // later assignments
    for (const cv of binding.constantViolations) {
      if (++n > MAX_DEFS) break;
      if (cv.isAssignmentExpression()) {
        const l = cv.node.left;
        if (l.type === 'Identifier' && l.name === name) {
          const op = cv.node.operator;
          if (op === '=') out.merge(this.eval(cv.get('right'), ctx));
          else if (op === '+=') out.merge(AV.concat(out.isEmpty ? AV.unknown(name) : out, this.eval(cv.get('right'), ctx)));
          else if (op === '||=' || op === '??=' || op === '&&=') out.merge(this.eval(cv.get('right'), ctx));
        } else out.merge(this.evalPatternAssign(cv, binding.identifier, ctx));
      } else if (cv.isVariableDeclarator() && cv.node.init) {
        out.merge(this.eval(cv.get('init'), ctx));
      } else if (cv.isFunctionDeclaration()) {
        out.merge(AV.ofRef(this.fnRef(cv)));
      }
    }
    if (out.isEmpty) return AV.unknown(name);
    return out;
  }

  _insideParam(path, pp) {
    for (let p = path; p; p = p.parentPath) if (p === pp) return true; return false;
  }

  evalParam(binding, pp, unit, ctx) {
    const fnPath = pp.parentPath;
    const idx = pp.key;
    const fnKey = unit.key(fnPath.node);
    const node = pp.node.type === 'TSParameterProperty' ? pp.node.parameter : pp.node;
    const left = node.type === 'AssignmentPattern' ? node.left : node;
    const simple = left.type === 'Identifier' && left.name === binding.identifier.name;
    const pkey = `${fnKey}:${idx}`;
    if (simple && ctx.env.has(pkey)) return ctx.env.get(pkey);
    const out = new AV();
    if (simple) {
      out.addTemplate([hole('param', binding.identifier.name, { fn: fnKey, idx })]);
      // TypeScript annotation names a class: injected service, config object
      const ann = left.typeAnnotation?.typeAnnotation;
      if (ann?.type === 'TSTypeReference' && ann.typeName.type === 'Identifier') {
        const tb = pp.scope.getBinding(ann.typeName.name);
        if (tb) {
          const tv = this.evalBinding(tb, ctx);
          for (const r of tv.refs) {
            if (r.kind === 'class') out.addRef(this.instRef({ kind: 'class', path: r.path }));
            else if (r.kind === 'native') out.addRef(r);
          }
        } else out.addRef(this.native('type', ann.typeName.name));
      }
      if (node.type === 'AssignmentPattern') out.merge(this.eval(pp.get(pp.node.type === 'TSParameterProperty' ? 'parameter.right' : 'right'), ctx));
      const di = this.injectedFor(fnPath, idx, ctx);
      if (di) out.merge(di);
    } else {
      out.addTemplate([hole('param', binding.identifier.name, { fn: fnKey, idx: -1 })]);
    }
    return out;
  }

  // Angular compiled constructors get their dependencies from the class factory:
  //   Cls.ɵfac = function (t) { return new (t || Cls)(ɵɵinject(Dep0), ɵɵinject(Dep1)); }
  // so constructor parameter i is whatever the i-th inject(...) argument evaluates to.
  injectedFor(fnPath, idx, ctx) {
    let ownerBinding = null;
    const unit = this.unitOf(fnPath);
    if (fnPath.isClassMethod() && fnPath.node.kind === 'constructor') {
      const cls = fnPath.parentPath.parentPath;
      if (cls.node.id) ownerBinding = cls.parentPath.scope.getBinding(cls.node.id.name) ?? cls.scope.getBinding(cls.node.id.name);
      else if (cls.parentPath.isVariableDeclarator()) ownerBinding = cls.parentPath.scope.getBinding(cls.parentPath.node.id.name);
    } else if (fnPath.isFunctionDeclaration() && fnPath.node.id) {
      ownerBinding = fnPath.parentPath.scope.getBinding(fnPath.node.id.name);
    }
    if (!ownerBinding) return null;
    const uid = this.bindingUid(unit, ownerBinding);
    const fac = this.facs.get(uid);
    if (!fac) return null;
    let args = this.facArgsCache.get(uid);
    if (!args) {
      args = [];
      fac.traverse({
        Function(p) { if (p.node !== fac.node) p.skip(); },
        NewExpression(p) { if (!args.length) { args = p.get('arguments'); p.stop(); } },
      });
      this.facArgsCache.set(uid, args);
    }
    const a = args[idx];
    if (!a || !a.node) return null;
    return this.eval(a, { ...ctx, env: new Map() });
  }

  // ɵɵinject(Dep) / ɵɵdirectiveInject(Dep): an instance of Dep
  injectOf(v) {
    const out = new AV();
    for (const r of v.refs) {
      if (r.kind === 'class') out.addRef(this.instRef({ kind: 'class', path: r.path }));
      else if (r.kind === 'native') out.addRef(r);
    }
    return out;
  }

  // const {a, b: {c}} = init ;  const [x, y] = init
  evalPattern(declarator, identNode, ctx) {
    const chain = [];
    let cur = declarator.get('id');
    const find = (p) => {
      if (p.node === identNode) return true;
      if (p.isObjectPattern()) {
        for (const prop of p.get('properties')) {
          if (prop.isObjectProperty()) {
            const k = prop.node.computed ? null : keyOf(prop.node.key);
            chain.push({ obj: k });
            if (find(prop.get('value'))) return true;
            chain.pop();
          } else if (prop.isRestElement() && find(prop.get('argument'))) { chain.push({ rest: true }); return true; }
        }
      } else if (p.isArrayPattern()) {
        const els = p.get('elements');
        for (let i = 0; i < els.length; i++) {
          if (!els[i].node) continue;
          chain.push({ idx: i });
          if (find(els[i])) return true;
          chain.pop();
        }
      } else if (p.isAssignmentPattern()) {
        chain.push({ dflt: p.get('right') });
        if (find(p.get('left'))) return true;
        chain.pop();
      }
      return false;
    };
    if (!find(cur)) return AV.unknown(identNode.name);
    let v = this.eval(declarator.get('init'), ctx);
    const out = new AV();
    let dflt = null;
    for (const step of chain) {
      if (step.rest) return AV.unknown(identNode.name);
      if (step.dflt) { dflt = step.dflt; continue; }
      const key = step.obj ?? String(step.idx);
      if (key === null) return AV.unknown(identNode.name);
      const next = new AV();
      for (const r of v.refs) next.merge(this.getProp(r, key, ctx));
      if (next.isEmpty) next.merge(AV.unknown(key));
      v = next;
    }
    out.merge(v);
    if (dflt) out.merge(this.eval(dflt, ctx));
    return out;
  }

  evalPatternAssign(cv, identNode, ctx) {
    return AV.unknown(identNode.name);
  }

  // ---- imports / exports ----------------------------------------------------
  evalImport(binding, unit, ctx) {
    const sp = binding.path;
    const decl = sp.parentPath;
    if (!decl?.isImportDeclaration()) return AV.unknown(binding.identifier.name);
    const spec = decl.node.source.value;
    let name = 'default';
    if (sp.isImportSpecifier()) name = keyOf(sp.node.imported) ?? 'default';
    else if (sp.isImportNamespaceSpecifier()) name = '*';
    const target = this.modules.resolve(spec, unit);
    if (!target) return AV.ofRef(this.native('lib', name === '*' ? 'default' : name, { pkg: spec }));
    return this.exportAV(this.modules.exportsOfUnit(target), name, ctx, 0);
  }

  exportAV(ex, name, ctx, depth) {
    if (depth > 6) return AV.unknown(name);
    if (name === '*') return AV.ofRef(this.ref('ns', 'ns:' + (ex.unit?.id ?? ex.fn?.node.start), { ex, name: '' }));
    const entry = ex.named.get(name);
    if (entry) return this.evalEntry(entry, ex, ctx, depth);
    const out = new AV();
    for (const spec of ex.stars) {
      const from = ex.unit;
      const t = from && this.modules.resolve(spec, from);
      if (t) out.merge(this.exportAV(this.modules.exportsOfUnit(t), name, ctx, depth + 1));
    }
    if (ex.whole) {
      const w = this.eval(ex.whole, ctx);
      if (name === 'default') out.merge(w);
      for (const r of w.refs) out.merge(this.getProp(r, name, ctx));
    }
    return out.isEmpty ? AV.unknown(name) : out;
  }

  evalEntry(entry, ex, ctx, depth) {
    if (entry.path) return this.eval(entry.path, ctx);
    if (entry.binding) return this.evalBinding(entry.binding, ctx);
    if (entry.getter) return this.evalReturns(entry.getter, ctx);
    if (entry.reexport && ex.unit) {
      const t = this.modules.resolve(entry.reexport, ex.unit);
      if (!t) return AV.ofRef(this.native('lib', entry.name, { pkg: entry.reexport }));
      return this.exportAV(this.modules.exportsOfUnit(t), entry.name, ctx, depth + 1);
    }
    return AV.unknown('');
  }

  // ---- member access --------------------------------------------------------
  evalMember(path, ctx) {
    const n = path.node;
    let name = this._propName(n);
    if (name === null && n.computed) {
      const pv = this.eval(path.get('property'), ctx);
      if (pv.t.length === 1 && pv.t[0].every((p) => p.k === 'lit')) name = pv.t[0].map((p) => p.s).join('');
    }
    const objPath = path.get('object');
    const objV = this.eval(objPath, ctx);
    const out = new AV();
    if (name === null) {
      if (!n.computed) return AV.unknown('');
      // obj[key] with an unknown key: every value the object (or array) can hold
      for (const r of objV.refs) out.merge(this.allValues(r, ctx));
      return out.isEmpty ? AV.unknown('') : out;
    }
    for (const r of objV.refs) out.merge(this.getProp(r, name, ctx));
    // properties assigned later: cfg.api = "/x"
    if (objPath.isIdentifier()) {
      const b = objPath.scope.getBinding(objPath.node.name);
      if (b) {
        const lst = this.propAssign.get(this.bindingUid(this.unitOf(objPath), b) + '.' + name);
        if (lst) for (const rp of lst.slice(0, MAX_DEFS)) out.merge(this.eval(rp, ctx));
      }
    }
    if (out.isEmpty) return AV.unknown(name);
    return out;
  }

  getProp(ref, name, ctx, depth = 0) {
    if (depth > 6) return new AV();
    switch (ref.kind) {
      case 'obj': return this.objProp(ref, name, ctx, depth);
      case 'arr': return this.arrProp(ref, name, ctx);
      case 'ns': return this.nsProp(ref, name, ctx);
      case 'inst': return this.classProp(ref.cls, name, ctx, false, depth);
      case 'class': return this.classProp(ref, name, ctx, true, depth);
      case 'finst': return this.fclassProp(ref, name, ctx);
      case 'native': return this.nativeProp(ref, name, ctx);
      default: return new AV();
    }
  }

  // `const o = {}; o.k = v; o['k2'] = w;`: the values assigned to the properties of a local object literal,
  // by property name (flow-insensitive). Obfuscators build their proxy objects this way.
  objWrites(ref) {
    const unit = this.unitOf(ref.path);
    if (!unit._objWrites) {
      const idx = new Map();
      unit._objWrites = idx;
      for (const a of unit.assigns) {
        if (a.node.operator !== '=') continue;
        const l = a.get('left');
        if (!l.isMemberExpression() || !l.get('object').isIdentifier()) continue;
        const b = a.scope.getBinding(l.node.object.name);
        if (!b || !b.path.isVariableDeclarator()) continue;
        const init = b.path.get('init');
        if (!init.node || !init.isObjectExpression()) continue;
        let key = null;
        if (!l.node.computed && l.node.property.type === 'Identifier') key = l.node.property.name;
        else if (l.node.computed) {
          try {
            const kv = this.eval(l.get('property'), this.newCtx());
            if (kv.t.length === 1 && kv.t[0].length === 1 && kv.t[0][0].k === 'lit') key = kv.t[0][0].s;
          } catch (e) { key = null; }
        }
        if (key === null) continue;
        const nk = unit.key(init.node);
        if (!idx.has(nk)) idx.set(nk, new Map());
        const m = idx.get(nk);
        if (!m.has(key)) m.set(key, []);
        m.get(key).push(a.get('right'));
      }
    }
    return unit._objWrites.get(unit.key(ref.path.node)) || null;
  }

  objProp(ref, name, ctx, depth) {
    const out = new AV();
    const writes = this.objWrites(ref);
    if (writes && writes.has(name)) for (const rp of writes.get(name).slice(0, MAX_DEFS)) out.merge(this.eval(rp, ctx));
    for (const prop of ref.path.get('properties')) {
      if (prop.isObjectProperty()) {
        const k = prop.node.computed ? null : keyOf(prop.node.key);
        if (k === name) out.merge(this.eval(prop.get('value'), ctx));
      } else if (prop.isObjectMethod()) {
        const k = prop.node.computed ? null : keyOf(prop.node.key);
        if (k === name) {
          if (prop.node.kind === 'get') out.merge(this.evalReturns(prop, ctx));
          else out.merge(AV.ofRef(this.fnRef(prop)));
        }
      } else if (prop.isSpreadElement()) {
        const sv = this.eval(prop.get('argument'), ctx);
        for (const r of sv.refs) out.merge(this.getProp(r, name, ctx, depth + 1));
      }
    }
    return out;
  }

  // every value an object literal or array literal holds (used for obj[unknownKey])
  allValues(ref, ctx) {
    const out = new AV();
    if (ref.kind === 'obj') {
      for (const prop of ref.path.get('properties')) {
        if (prop.isObjectProperty()) out.merge(this.eval(prop.get('value'), ctx));
      }
      const writes = this.objWrites(ref);
      if (writes) for (const rps of writes.values()) for (const rp of rps.slice(0, MAX_DEFS)) out.merge(this.eval(rp, ctx));
    } else if (ref.kind === 'arr') {
      for (const el of ref.path.get('elements')) if (el.node) out.merge(this.eval(el, ctx));
    }
    return out;
  }

  arrProp(ref, name, ctx) {
    const out = new AV();
    if (/^\d+$/.test(name)) {
      const el = ref.path.get('elements')[Number(name)];
      if (el && el.node) out.merge(this.eval(el, ctx));
    }
    return out;
  }

  nsProp(ref, name, ctx) {
    return this.exportAV(ref.ex, name, ctx, 0);
  }

  // members of a class (instance or static), including superclasses
  classProp(clsRef, name, ctx, isStatic, depth) {
    const out = new AV();
    const cpath = clsRef.path;
    const unit = this.unitOf(cpath);
    for (const m of cpath.get('body.body')) {
      const staticMember = !!m.node.static;
      if (m.isClassMethod() || m.isClassPrivateMethod?.()) {
        const k = m.node.computed ? null : m.node.key.type === 'PrivateName' ? '#' + m.node.key.id.name : keyOf(m.node.key);
        if (m.node.kind === 'constructor') {
          if (!isStatic) {
            // constructor parameter properties: constructor(private http: HttpClient)
            for (const p of m.get('params')) {
              if (p.node.type === 'TSParameterProperty') {
                const inner = p.node.parameter.type === 'AssignmentPattern' ? p.node.parameter.left : p.node.parameter;
                if (inner.name === name) {
                  const b = m.scope.getBinding(name);
                  if (b) out.merge(this.evalBinding(b, ctx));
                  else out.merge(this.paramPropertyAV(m, p, inner, ctx)); // Babel registers no binding for these
                }
              }
            }
          }
          continue;
        }
        if (k !== name || staticMember !== isStatic) continue;
        if (m.node.kind === 'get') out.merge(this.evalReturns(m, ctx));
        else if (m.node.kind === 'method') out.merge(AV.ofRef(this.fnRef(m)));
      } else if (m.isClassProperty() || m.isClassPrivateProperty?.() || m.node.type === 'ClassAccessorProperty') {
        const k = m.node.key.type === 'PrivateName' ? '#' + m.node.key.id.name : m.node.computed ? null : keyOf(m.node.key);
        if (k !== name || staticMember !== isStatic) continue;
        if (m.node.value) out.merge(this.eval(m.get('value'), ctx));
        else {
          const ann = m.node.typeAnnotation?.typeAnnotation;
          if (ann?.type === 'TSTypeReference' && ann.typeName.type === 'Identifier') {
            const tb = m.scope.getBinding(ann.typeName.name);
            if (tb) for (const r of this.evalBinding(tb, ctx).refs) if (r.kind === 'class') out.addRef(this.instRef({ kind: 'class', path: r.path }));
          }
        }
      }
    }
    if (!isStatic) {
      // this.name = value, anywhere in the class
      const key = unit.key(cpath.node);
      const lst = this.thisAssign.get(key)?.get(name);
      if (lst) for (const rp of lst.slice(0, MAX_DEFS)) out.merge(this.eval(rp, { ...ctx, env: new Map() }));
    }
    // superclass
    if (out.isEmpty && cpath.node.superClass) {
      const sv = this.eval(cpath.get('superClass'), ctx);
      for (const r of sv.refs) if (r.kind === 'class' && r !== clsRef) out.merge(this.classProp(r, name, ctx, isStatic, depth + 1));
    }
    return out;
  }

  // `constructor(private api: Api)`: the property is whatever the annotation names (an injected service or a
  // native type), or the compiled factory's i-th dependency.
  paramPropertyAV(ctor, p, inner, ctx) {
    const out = new AV();
    const unit = this.unitOf(ctor);
    out.addTemplate([hole('param', inner.name, { fn: unit.key(ctor.node), idx: p.key })]);
    const ann = inner.typeAnnotation?.typeAnnotation;
    if (ann?.type === 'TSTypeReference' && ann.typeName.type === 'Identifier') {
      const tb = ctor.scope.getBinding(ann.typeName.name);
      if (tb) {
        for (const r of this.evalBinding(tb, ctx).refs) {
          if (r.kind === 'class') out.addRef(this.instRef({ kind: 'class', path: r.path }));
          else if (r.kind === 'native') out.addRef(r);
        }
      } else out.addRef(this.native('type', ann.typeName.name));
    }
    const di = this.injectedFor(ctor, p.key, ctx);
    if (di) out.merge(di);
    return out;
  }

  // ES5 constructor functions: this.x = v inside F, F.prototype.m = fn
  fclassProp(ref, name, ctx) {
    const out = new AV();
    const lst = this.thisAssign.get(ref.key)?.get(name);
    if (lst) for (const rp of lst.slice(0, MAX_DEFS)) out.merge(this.eval(rp, { ...ctx, env: new Map() }));
    const pl = this.protoAssign.get(ref.key)?.get(name);
    if (pl) for (const rp of pl.slice(0, MAX_DEFS)) out.merge(this.eval(rp, ctx));
    return out;
  }

  nativeProp(ref, name, ctx) {
    const lib = ref.lib;
    if (lib === 'location') {
      if (name === 'origin' || name === 'host' || name === 'hostname' || name === 'protocol' || name === 'href') return AV.unknown('origin', 'origin');
      return AV.unknown(name, 'runtime');
    }
    if (lib === 'document') {
      if (name === 'baseURI' || name === 'URL') return AV.unknown('origin', 'origin');
      if (name === 'location') return AV.ofRef(this.native('location'));
      return AV.unknown(name, 'runtime');
    }
    if (lib === 'global') {
      if (name === 'location') return AV.ofRef(this.native('location'));
      if (name === 'document') return AV.ofRef(this.native('document'));
      if (name === 'localStorage' || name === 'sessionStorage') return AV.ofRef(this.native('storage', name));
      return AV.unknown(name);
    }
    if (lib === 'importmeta' || lib === 'process') {
      if (name === 'env') return AV.ofRef(this.native('env'));
      return AV.unknown(name, 'env');
    }
    if (lib === 'env') return AV.unknown(name, 'env');
    if (lib === 'lib' && ref.pkg) return AV.ofRef(this.native('lib', name, { pkg: ref.pkg }));
    return AV.unknown(name);
  }

  // ---- calls ----------------------------------------------------------------
  evalCall(path, ctx) {
    const callee = path.get('callee');
    const cn = callee.node;
    const argPaths = path.get('arguments');
    const calleeHint = this.hint(callee);
    if ((calleeHint === '\u0275\u0275inject' || calleeHint === '\u0275\u0275directiveInject') && argPaths[0]) {
      const iv = this.injectOf(this.eval(argPaths[0], ctx));
      return iv.isEmpty ? AV.unknown('') : iv;
    }
    // require("./x") and webpack require(n)
    if (cn.type === 'Identifier') {
      const b = callee.scope.getBinding(cn.name);
      if (!b && cn.name === 'require' && argPaths[0]?.node?.type === 'StringLiteral') {
        const t = this.modules.resolve(argPaths[0].node.value, this.unitOf(path));
        if (!t) return AV.ofRef(this.native('lib', 'default', { pkg: argPaths[0].node.value }));
        return this.requireOf(this.modules.exportsOfUnit(t), ctx);
      }
      if (b) {
        const target = this.modules.webpackTarget(path, b);
        if (target) return this.requireOf(this.modules.exportsOfWebpack(target), ctx);
      }
      if (!b && IDENTITY_FNS.has(cn.name) && argPaths[0]) return this.eval(argPaths[0], ctx);
    }
    // method calls
    if ((cn.type === 'MemberExpression' || cn.type === 'OptionalMemberExpression')) {
      const mname = this._propName(cn);
      const objV = this.eval(callee.get('object'), ctx);
      const special = this.stringMethod(mname, objV, argPaths, ctx, callee);
      if (special) return special;
      const out = new AV();
      for (const r of objV.refs) {
        if (r.kind === 'native') {
          const nv = this.nativeCall(r, mname, argPaths, ctx);
          if (nv) { out.merge(nv); continue; }
        }
        const fv = mname !== null ? this.getProp(r, mname, ctx) : new AV();
        out.merge(this.applyFns(fv, argPaths, ctx, path));
      }
      if (out.isEmpty) return AV.unknown(mname ?? '');
      return out;
    }
    // plain call: f(...), IIFE, (0, f)(...)
    const fv = this.eval(callee, ctx);
    const out = this.applyFns(fv, argPaths, ctx, path);
    if (out.isEmpty) return AV.unknown(this.hint(callee));
    return out;
  }

  requireOf(ex, ctx) {
    if (ex.whole) return this.eval(ex.whole, ctx);
    return AV.ofRef(this.ref('ns', 'ns:' + (ex.unit?.id ?? ex.fn?.node.start), { ex, name: '' }));
  }

  stringMethod(name, objV, argPaths, ctx, callee) {
    if (name === null) return null;
    if (IDENTITY_METHODS.has(name) && objV.t.length) return objV;
    if (name === 'concat' && objV.t.length) {
      let v = objV;
      for (const a of argPaths) v = AV.concat(v, this.eval(a, ctx));
      return v;
    }
    if (name === 'join') {
      const arrs = objV.refs.filter((r) => r.kind === 'arr');
      if (!arrs.length) return null;
      const sepV = argPaths[0] ? this.eval(argPaths[0], ctx) : AV.str(',');
      const out = new AV();
      for (const r of arrs) {
        let v = null;
        for (const el of r.path.get('elements')) {
          if (!el.node) continue;
          const ev = this.eval(el, ctx);
          v = v === null ? ev : AV.concat(AV.concat(v, sepV), ev);
        }
        out.merge(v ?? AV.str(''));
      }
      return out;
    }
    if ((name === 'replace' || name === 'replaceAll') && objV.t.length && argPaths.length === 2) {
      const a = this.eval(argPaths[0], ctx);
      const b = this.eval(argPaths[1], ctx);
      const pure = (v) => v.t.length === 1 && v.t[0].every((p) => p.k === 'lit');
      if (pure(a) && pure(b)) {
        const find = a.t[0].map((p) => p.s).join('');
        const rep = b.t[0].map((p) => p.s).join('');
        const out = new AV();
        for (const t of objV.t) {
          const parts = t.map((p) => (p.k === 'lit' ? lit(name === 'replace' ? p.s.replace(find, rep) : p.s.split(find).join(rep)) : p));
          out.addTemplate(parts);
        }
        return out;
      }
      return AV.unknown('');
    }
    return null;
  }

  // calls on native objects
  nativeCall(ref, name, argPaths, ctx) {
    if (ref.lib === 'storage' && (name === 'getItem')) {
      const k = argPaths[0] ? this.eval(argPaths[0], ctx) : null;
      const kn = k && k.t.length === 1 && k.t[0].length === 1 && k.t[0][0].k === 'lit' ? k.t[0][0].s : '';
      return AV.unknown(kn, 'runtime');
    }
    if (ref.lib === 'lib' && (name === 'create')) {
      // axios.create({ baseURL }) / ky.create({ prefixUrl }) -> instance with a base
      const cfg = argPaths[0] ? this.eval(argPaths[0], ctx) : new AV();
      let base = null;
      for (const r of cfg.refs) {
        for (const k of ['baseURL', 'baseUrl', 'prefixUrl']) {
          const v = this.getProp(r, k, ctx);
          if (!v.isEmpty && !(v.t.length === 1 && v.t[0].length === 1 && v.t[0][0].k === 'hole' && v.t[0][0].cls === 'unknown')) { base = v; break; }
        }
        if (base) break;
      }
      const baseKey = base ? base.t.map((t) => JSON.stringify(t)).join('|') : '';
      return AV.ofRef(this.native('lib', 'instance', { pkg: ref.pkg, base, baseKey }));
    }
    return null;
  }

  applyFns(fv, argPaths, ctx, callPath) {
    const out = new AV();
    for (const r of fv.refs) {
      if (r.kind === 'fn') out.merge(this.callFn(r, argPaths, ctx, callPath));
    }
    return out;
  }

  callFn(fnRef, argPaths, ctx, callPath) {
    const fnPath = fnRef.path;
    const fnKey = this.unitOf(fnPath).key(fnPath.node);
    if (ctx.depth >= MAX_CALL_DEPTH) { this.stats.depthCut++; return AV.unknown(fnRef.name); }
    if (ctx.callStack.has(fnKey)) { this.stats.cycleCut++; return AV.unknown(fnRef.name); }
    const args = argPaths.map((a) => (a.isSpreadElement() ? null : this.eval(a, ctx)));
    const env = new Map(ctx.env);
    fnPath.node.params.forEach((p, i) => {
      const left = p.type === 'TSParameterProperty' ? p.parameter : p;
      const ident = left.type === 'AssignmentPattern' ? left.left : left;
      if (ident.type === 'Identifier' && args[i]) env.set(`${fnKey}:${i}`, args[i]);
    });
    const mkey = fnKey + '|' + args.map((a) => (a ? a.t.map((t) => JSON.stringify(t)).join(',') + a.refs.map((r) => r.id).join(',') : '-')).join(';') + '|' + [...ctx.env.keys()].length;
    if (ctx.env.size === 0 && this.callMemo.has(mkey)) { this.stats.memoHits++; return this.callMemo.get(mkey); }
    const callStack = new Set(ctx.callStack);
    callStack.add(fnKey);
    this.stats.calls++;
    const res = this.evalReturns(fnPath, { env, depth: ctx.depth + 1, stack: new Set(), callStack });
    if (ctx.env.size === 0) this.callMemo.set(mkey, res);
    return res;
  }

  evalReturns(fnPath, ctx) {
    let rets = this.returnsCache.get(fnPath.node);
    if (!rets) {
      rets = [];
      const body = fnPath.get('body');
      if (!body.isBlockStatement()) rets.push(body);
      else {
        body.traverse({
          Function(p) { p.skip(); },
          Class(p) { p.skip(); },
          ReturnStatement(p) { if (p.node.argument) rets.push(p.get('argument')); },
        });
      }
      this.returnsCache.set(fnPath.node, rets);
    }
    const out = new AV();
    for (const r of rets.slice(0, MAX_DEFS)) out.merge(this.eval(r, ctx));
    return out;
  }

  evalNew(path, ctx) {
    const cv = this.eval(path.get('callee'), ctx);
    const out = new AV();
    for (const r of cv.refs) {
      if (r.kind === 'class') out.addRef(this.instRef({ kind: 'class', path: r.path }));
      else if (r.kind === 'fn') {
        const b = r.path.isFunctionDeclaration() && r.path.node.id ? r.path.parentPath.scope.getBinding(r.path.node.id.name) : null;
        const unit = this.unitOf(r.path);
        if (b) out.addRef(this.instRef({ kind: 'fclass', binding: b, key: this.bindingUid(unit, b) }));
      } else if (r.kind === 'native') out.addRef(r);
    }
    if (out.isEmpty) return AV.unknown(this.hint(path.get('callee')));
    return out;
  }

  newCtx() {
    return { env: new Map(), depth: 0, stack: new Set(), callStack: new Set() };
  }
}
