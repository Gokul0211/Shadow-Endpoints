// Next.js server route files, when the server source is available (source maps, leaked sources):
//   app/**/route.ts   exports GET / POST / ... functions       -> /api/x/{id}
//   pages/api/**.ts   default handler, req.method comparisons  -> /api/x/{id}
// The URL is derived from the file's *path* by the framework's convention, so these findings are
// inferred (reported only with --include-inferred), but the methods are read from the code.

const VERBS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const APP_ROUTE = /(?:^|\/)app\/(.*?)\/?route\.[cm]?[jt]sx?$/;
const PAGES_API = /(?:^|\/)pages\/(api\/.+?)\.[cm]?[jt]sx?$/;

function segmentsToPath(raw) {
  const out = [];
  for (const seg of raw.split('/')) {
    if (!seg || /^\(.*\)$/.test(seg) || seg.startsWith('@')) continue; // route groups, parallel slots
    if (seg === 'index') continue;
    const m = seg.match(/^\[{1,2}(?:\.\.\.)?([A-Za-z0-9_]+)\]{1,2}$/);
    out.push(m ? `{${m[1]}}` : seg);
  }
  return '/' + out.join('/');
}

function exportedVerbs(unit) {
  const names = new Set();
  for (const st of unit.program.get('body')) {
    if (!st.isExportNamedDeclaration()) continue;
    const d = st.node.declaration;
    if (d && d.type === 'FunctionDeclaration' && d.id) names.add(d.id.name);
    if (d && d.type === 'VariableDeclaration') for (const x of d.declarations) if (x.id.type === 'Identifier') names.add(x.id.name);
    for (const sp of st.node.specifiers || []) if (sp.exported && sp.exported.name) names.add(sp.exported.name);
  }
  return [...names].filter((n) => VERBS.has(n)).sort();
}

function comparedVerbs(unit) {
  const verbs = new Set();
  const isMethod = (n) => n && n.type === 'MemberExpression' && !n.computed && n.property.name === 'method';
  unit.program.traverse({
    BinaryExpression(p) {
      if (!['===', '==', '!==', '!='].includes(p.node.operator)) return;
      const { left, right } = p.node;
      if (isMethod(left) && right.type === 'StringLiteral' && VERBS.has(right.value)) verbs.add(right.value);
      if (isMethod(right) && left.type === 'StringLiteral' && VERBS.has(left.value)) verbs.add(left.value);
    },
    SwitchStatement(p) {
      if (!isMethod(p.node.discriminant)) return;
      for (const c of p.node.cases) if (c.test && c.test.type === 'StringLiteral' && VERBS.has(c.test.value)) verbs.add(c.test.value);
    },
  });
  return [...verbs].sort();
}

export function nextRoutes(units, sinks) {
  for (const unit of units) {
    if (!unit.program) continue;
    let url = null;
    let verbs = [];
    let m = unit.norm.match(APP_ROUTE);
    if (m) {
      url = segmentsToPath(m[1]);
      verbs = exportedVerbs(unit);
    } else if ((m = unit.norm.match(PAGES_API))) {
      url = segmentsToPath(m[1]);
      verbs = comparedVerbs(unit);
    }
    if (!url || url === '/') continue;
    const node = unit.program.node;
    for (const method of verbs.length ? verbs : [null]) {
      const key = ['next', unit.id, url, method].join('|');
      if (sinks.seen.has(key)) continue;
      sinks.seen.add(key);
      sinks.stats.byKind.nextjs_route = (sinks.stats.byKind.nextjs_route || 0) + 1;
      sinks.findings.push({
        file: unit.id, ...unit.loc(node), kind: 'nextjs_route', method, url, base: null, holes: [], known: true,
        lib: null, via: [], uncalled: false, widened: false, inferred: true,
      });
    }
  }
}
