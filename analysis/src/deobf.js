// String-array de-obfuscation (javascript-obfuscator and look-alikes), done by reading the code, never by running it.
//
// What those tools emit:
//   function A() { const a = ['x', 'y', ...]; A = function () { return a; }; return A(); }        string array
//   function D(i, key) { i = i - OFFSET; const a = A(); ...decode (none | base64 | rc4)...; return v; }   decoder
//   (function (get, target) { ... while (1) { try { const n = parseInt(w(0x1f))/1 + ...; if (n === target) break;
//                                          else arr.push(arr.shift()); } catch (e) { arr.push(arr.shift()); } } })(A, N)
//   function W(a, b, c, d) { return D(d - 0xea, c); }                                         wrappers (any depth)
//   const alias = D;   ... alias(0x15f) ...
// The pass finds the array, the decoder (offset and encoding), replays the rotation with a small integer evaluator
// (arithmetic, parseInt, calls to the decoder / wrappers - nothing else), then rewrites every call of the decoder, a
// wrapper or an alias whose arguments are constants into the string literal. The rest of the analysis then sees
// ordinary strings. Anything the pass does not recognise is left untouched.
import _traverse from '@babel/traverse';
import * as t from '@babel/types';

const traverse = _traverse.default ?? _traverse;
const B64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
const MAX_ROTATIONS = 200000;
const TIME_BUDGET_MS = 4000;     // per file, for the whole pass

// ---- decoders -----------------------------------------------------------------------------------

function b64decode(s) {
  let out = '';
  for (let bc = 0, bs = 0, buf, idx = 0; (buf = s.charAt(idx++)); ) {
    buf = B64.indexOf(buf);
    if (~buf && (bs % 4 ? (bc = bc * 64 + buf) : (bc = buf), bs++ % 4)) out += String.fromCharCode(255 & (bc >> ((-2 * bs) & 6)));
  }
  return out;
}

function utf8(s) {
  let enc = '';
  for (let i = 0; i < s.length; i++) enc += '%' + ('00' + s.charCodeAt(i).toString(16)).slice(-2);
  try { return decodeURIComponent(enc); } catch (e) { return s; }
}

function rc4(data, key) {
  const s = [];
  let j = 0;
  for (let i = 0; i < 256; i++) s[i] = i;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
    [s[i], s[j]] = [s[j], s[i]];
  }
  let i = 0;
  j = 0;
  let out = '';
  for (let y = 0; y < data.length; y++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
    out += String.fromCharCode(data.charCodeAt(y) ^ s[(s[i] + s[j]) % 256]);
  }
  return out;
}

function jsParseInt(v) {
  const m = /^\s*([+-]?\d+)/.exec(String(v));
  return m ? parseInt(m[1], 10) : NaN;
}

// ---- model ----------------------------------------------------------------------------------------

class StringArray {
  constructor(values) { this.values = values.slice(); }
  rotate() { this.values.push(this.values.shift()); }
}

class Decoder {
  constructor(fnPath, arr, offset, encoding) {
    this.fnPath = fnPath;
    this.arr = arr;
    this.offset = offset;
    this.encoding = encoding; // 'none' | 'base64' | 'rc4'
  }
  decode(index, key) {
    const raw = this.arr.values[index - this.offset];
    if (typeof raw !== 'string') return undefined;
    if (this.encoding === 'none') return raw;
    const text = utf8(b64decode(raw));
    if (this.encoding === 'base64') return text;
    return typeof key === 'string' ? rc4(text, key) : undefined;
  }
}

class Pass {
  constructor(program, code) {
    this.program = program;
    this.code = code;
    this.arrays = new Map(); // function node -> StringArray
    this.decoders = new Map(); // function node -> Decoder
    this.steps = 0;
    this.deadline = Date.now() + TIME_BUDGET_MS;
    this.stats = { arrays: 0, decoders: 0, rotations: 0, replaced: 0, unrotated: 0 };
  }

  // ---- discovery ----
  findArrays() {
    this.program.traverse({
      Function: (p) => {
        if (!p.isFunctionDeclaration() && !p.parentPath.isVariableDeclarator()) return;
        const body = p.node.body.body;
        const first = body && body[0];
        if (!first || first.type !== 'VariableDeclaration' || first.declarations.length !== 1) return;
        const init = first.declarations[0].init;
        if (!init || init.type !== 'ArrayExpression' || init.elements.length < 3) return;
        if (!init.elements.every((e) => e && e.type === 'StringLiteral')) return;
        // it replaces itself: NAME = function () { return arr; }
        const name = p.isFunctionDeclaration() ? p.node.id?.name : p.parentPath.node.id?.name;
        if (!name) return;
        let selfAssign = false;
        p.traverse({ AssignmentExpression(a) { if (a.node.left.type === 'Identifier' && a.node.left.name === name) selfAssign = true; } });
        if (!selfAssign) return;
        this.arrays.set(p.node, new StringArray(init.elements.map((e) => e.value)));
      },
    });
    this.stats.arrays = this.arrays.size;
  }

  fnSource(node) { return this.code.slice(node.start, node.end); }

  findDecoders() {
    this.program.traverse({
      Function: (p) => {
        if (this.arrays.has(p.node)) return;
        if (!p.isFunctionDeclaration() && !p.parentPath.isVariableDeclarator()) return;
        // calls one of the array functions
        let arr = null;
        p.traverse({
          CallExpression: (c) => {
            if (arr || c.node.callee.type !== 'Identifier') return;
            const target = this.resolveFunction(c.get('callee'));
            if (target && this.arrays.has(target.node)) arr = this.arrays.get(target.node);
          },
        });
        if (!arr) return;
        // offset: idx = idx - OFFSET (the parameter is reassigned, possibly inside a nested function)
        let offset = null;
        p.traverse({
          AssignmentExpression: (a) => {
            const n = a.node;
            if (offset !== null || n.operator !== '=' || n.left.type !== 'Identifier') return;
            const r = n.right;
            if (r.type === 'BinaryExpression' && r.operator === '-' && r.left.type === 'Identifier' && r.left.name === n.left.name) {
              const v = this.num(a.get('right.right'), new Map());
              if (typeof v === 'number' && Number.isFinite(v)) offset = v;
            }
          },
        });
        if (offset === null) return;
        const src = this.fnSource(p.node);
        let encoding = 'none';
        // numbers may have been rewritten as expressions, so RC4 is recognised by its xor, not by the constant 256
        if (src.includes(B64)) encoding = src.includes('^') ? 'rc4' : 'base64';
        this.decoders.set(p.node, new Decoder(p, arr, offset, encoding));
      },
    });
    this.stats.decoders = this.decoders.size;
  }

  // ---- name resolution ----
  // Follow aliases (const a = b), function declarations and function-valued constants to a function path.
  resolveFunction(idPath, depth = 0) {
    if (depth > 8 || !idPath.isIdentifier()) return null;
    const b = idPath.scope.getBinding(idPath.node.name);
    if (!b) return null;
    const bp = b.path;
    if (bp.isFunctionDeclaration()) return bp;
    if (bp.isVariableDeclarator()) {
      if (b.constantViolations.length) {
        // the array / decoder rewrite themselves (f = function () {...}): the declaration is still the function
        if (bp.node.init && (bp.node.init.type === 'FunctionExpression' || bp.node.init.type === 'ArrowFunctionExpression')) return bp.get('init');
        return null;
      }
      const init = bp.get('init');
      if (init.isIdentifier()) return this.resolveFunction(init, depth + 1);
      if (init.isFunctionExpression() || init.isArrowFunctionExpression()) return init;
    }
    if (bp.isFunctionDeclaration() === false && b.kind === 'hoisted') return null;
    return null;
  }

  // ---- integer / string evaluator ----
  // Returns a number or string, or undefined when the expression is not made of constants and known calls.
  num(path, env, depth = 0) {
    if (depth > 60 || (++this.steps & 0x3fff) === 0 && Date.now() > this.deadline) return undefined;
    const n = path.node;
    switch (n.type) {
      case 'NumericLiteral': return n.value;
      case 'StringLiteral': return n.value;
      case 'Identifier': return env.has(n.name) ? env.get(n.name) : undefined;
      case 'UnaryExpression': {
        const v = this.num(path.get('argument'), env, depth + 1);
        if (v === undefined) return undefined;
        if (n.operator === '-') return -v;
        if (n.operator === '+') return +v;
        if (n.operator === '!') return !v;
        return undefined;
      }
      case 'BinaryExpression': {
        const a = this.num(path.get('left'), env, depth + 1);
        const b = this.num(path.get('right'), env, depth + 1);
        if (a === undefined || b === undefined) return undefined;
        switch (n.operator) {
          case '+': return a + b;
          case '-': return a - b;
          case '*': return a * b;
          case '/': return a / b;
          case '%': return a % b;
          default: return undefined;
        }
      }
      case 'CallExpression': {
        const c = n.callee;
        if (c.type === 'Identifier' && c.name === 'parseInt' && !path.scope.getBinding('parseInt') && n.arguments.length >= 1) {
          const v = this.num(path.get('arguments.0'), env, depth + 1);
          return v === undefined ? undefined : jsParseInt(v);
        }
        if (c.type !== 'Identifier') return undefined;
        const fn = this.resolveFunction(path.get('callee'));
        if (!fn) return undefined;
        const args = path.get('arguments').map((a) => this.num(a, env, depth + 1));
        if (args.some((a) => a === undefined)) return undefined;
        return this.callFunction(fn, args, depth + 1);
      }
      default: return undefined;
    }
  }

  // decoder: decode; wrapper: a function whose body is `return <expr over its parameters>`
  callFunction(fn, args, depth) {
    const dec = this.decoders.get(fn.node);
    if (dec) return dec.decode(args[0], args[1]);
    const body = fn.isArrowFunctionExpression() && fn.node.body.type !== 'BlockStatement' ? null : fn.node.body.body;
    let ret = null;
    if (!body) ret = fn.get('body');
    else if (body.length === 1 && body[0].type === 'ReturnStatement' && body[0].argument) ret = fn.get('body.body.0.argument');
    else {
      // wrappers sometimes keep one local: const x = D; return x(...)  - only a single return is accepted
      return undefined;
    }
    const env = new Map();
    fn.node.params.forEach((p, i) => { if (p.type === 'Identifier') env.set(p.name, args[i]); });
    return this.num(ret, env, depth + 1);
  }

  // ---- rotation ----
  rotate() {
    this.program.traverse({
      CallExpression: (p) => {
        const c = p.node.callee;
        if (c.type !== 'FunctionExpression' || p.node.arguments.length !== 2) return;
        const a0 = p.get('arguments.0');
        if (!a0.isIdentifier()) return;
        const af = this.resolveFunction(a0);
        if (!af || !this.arrays.has(af.node)) return;
        const arr = this.arrays.get(af.node);
        const target = this.num(p.get('arguments.1'), new Map());
        if (typeof target !== 'number') return;
        // checksum: first variable initialiser inside the try block of the while loop
        let check = null;
        p.get('callee').traverse({
          WhileStatement: (w) => {
            w.traverse({
              TryStatement: (tr) => {
                if (check) return;
                const decl = tr.node.block.body.find((s) => s.type === 'VariableDeclaration');
                if (decl) check = tr.get('block.body.' + tr.node.block.body.indexOf(decl) + '.declarations.0.init');
              },
            });
          },
        });
        if (!check) return;
        // the loop reads the array through its own parameter: bind the parameter name to the array function
        for (let i = 0; i < MAX_ROTATIONS; i++) {
          let v;
          try { v = this.num(check, new Map()); } catch (e) { v = undefined; }
          if (v === target) { this.stats.rotations = Math.max(this.stats.rotations, i); return; }
          arr.rotate();
          if (Date.now() > this.deadline) break;
        }
        this.stats.unrotated++;
      },
    });
  }

  // ---- rewrite ----
  rewrite() {
    this.program.traverse({
      CallExpression: (p) => {
        if (p.node.callee.type !== 'Identifier') return;
        const fn = this.resolveFunction(p.get('callee'));
        if (!fn) return;
        const known = this.decoders.has(fn.node) || this.isWrapper(fn);
        if (!known) return;
        const args = p.get('arguments').map((a) => this.num(a, new Map()));
        if (args.some((a) => a === undefined)) return;
        const v = this.callFunction(fn, args, 0);
        if (typeof v === 'string') {
          p.replaceWith(t.stringLiteral(v));
          this.stats.replaced++;
        }
      },
    });
  }

  isWrapper(fn) {
    if (this.wrapperCache?.has(fn.node)) return this.wrapperCache.get(fn.node);
    if (!this.wrapperCache) this.wrapperCache = new Map();
    let ok = false;
    const body = fn.node.body;
    const ret = fn.isArrowFunctionExpression() && body.type !== 'BlockStatement' ? fn.get('body')
      : body.body && body.body.length === 1 && body.body[0].type === 'ReturnStatement' ? fn.get('body.body.0.argument') : null;
    if (ret && ret.node) {
      let calls = 0;
      let reachesDecoder = false;
      const visit = (path) => {
        if (path.isCallExpression() && path.node.callee.type === 'Identifier') {
          calls++;
          const f = this.resolveFunction(path.get('callee'));
          if (f && (this.decoders.has(f.node) || (f.node !== fn.node && this.isWrapper(f)))) reachesDecoder = true;
        }
      };
      visit(ret);
      ret.traverse({ CallExpression: visit });
      ok = reachesDecoder && calls >= 1;
    }
    this.wrapperCache.set(fn.node, ok);
    return ok;
  }
}

// Rewrites the AST in place; returns statistics (all zero when the file is not string-array obfuscated).
export function deobfuscate(ast, code) {
  const stats = { arrays: 0, decoders: 0, rotations: 0, replaced: 0, unrotated: 0 };
  if (!/\b_0x[0-9a-f]{3,}\b|parseInt\(/.test(code) || !code.includes("['push'](")) return stats;
  try {
    traverse(ast, {
      Program(program) {
        const pass = new Pass(program, code);
        pass.findArrays();
        if (!pass.arrays.size) { program.stop(); return; }
        pass.findDecoders();
        if (pass.decoders.size) {
          pass.rotate();
          pass.rewrite();
        }
        Object.assign(stats, pass.stats);
        program.stop();
      },
    });
  } catch (e) {
    stats.error = String(e && e.message ? e.message : e).slice(0, 160);
  }
  return stats;
}
