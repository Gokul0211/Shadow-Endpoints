// Parsing and per-file indexing. One Unit per input file.
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';

const traverse = _traverse.default ?? _traverse;

const BASE_PLUGINS = ['decorators-legacy', 'importAttributes', 'explicitResourceManagement'];

export function normPath(id) {
  let s = String(id).replace(/\\/g, '/').split('?')[0].split('#')[0];
  s = s.replace(/^[a-z]+:\/\/[^/]*/i, ''); // scheme://host
  return s.replace(/\/+/g, '/');
}

function pluginSets(id) {
  const ext = (normPath(id).match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase();
  if (ext === 'ts' || ext === 'mts' || ext === 'cts') return [['typescript'], ['jsx']];
  if (ext === 'tsx') return [['typescript', 'jsx'], ['jsx']];
  // plain JS (bundles, JSX): try JS+JSX first, then TypeScript syntax
  return [['jsx'], ['typescript', 'jsx'], ['flow', 'jsx']];
}

export function parseSource(id, code) {
  let lastErr = null;
  for (const plugins of pluginSets(id)) {
    try {
      return parse(code, {
        sourceType: 'unambiguous',
        plugins: [...BASE_PLUGINS, ...plugins],
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
      });
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

export class Unit {
  constructor(id, code) {
    this.id = id;
    this.norm = normPath(id);
    this.code = code;
    this.ast = null;
    this.program = null;
    this.calls = []; // CallExpression / OptionalCallExpression / NewExpression paths
    this.assigns = []; // AssignmentExpression paths
    this.functions = [];
    this.classes = [];
    this.tables = []; // webpack module tables (filled by modules.js)
    this.error = null;
  }

  parse() {
    try {
      this.ast = parseSource(this.id, this.code);
    } catch (e) {
      this.error = `${e.name}: ${String(e.message).slice(0, 160)}`;
      return false;
    }
    const unit = this;
    try {
      traverse(this.ast, {
        Program(path) {
          unit.program = path;
        },
        CallExpression(path) {
          unit.calls.push(path);
        },
        OptionalCallExpression(path) {
          unit.calls.push(path);
        },
        NewExpression(path) {
          unit.calls.push(path);
        },
        AssignmentExpression(path) {
          unit.assigns.push(path);
        },
        Function(path) {
          unit.functions.push(path);
        },
        Class(path) {
          unit.classes.push(path);
        },
      });
    } catch (e) {
      this.error = `traverse ${e.name}: ${String(e.message).slice(0, 160)}`;
      return false;
    }
    return true;
  }

  key(node) {
    return `${this.id}@${node.start}`;
  }
  loc(node) {
    const l = node.loc?.start;
    return l ? { line: l.line, col: l.column } : { line: 0, col: 0 };
  }
}
