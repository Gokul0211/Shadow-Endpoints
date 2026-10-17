// GraphQL operations that the code itself declares:
//   resolver maps   { Query: { getUser() {...} }, Mutation: {...}, Subscription: {...} }
//   decorators      @Query() / @Mutation() / @Subscription() on class methods (NestJS style)
//   SDL text        type Query { getUser(id: ID!): User }   (string and template literals)
// The operation's URL is the GraphQL endpoint (chosen by the caller) plus "#name".

const TYPES = new Set(['Query', 'Mutation', 'Subscription']);
const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SDL_HINT = /\btype\s+(Query|Mutation|Subscription)\b/;
const SDL_BLOCK = /\b(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b[^{]*\{([^}]*(?:\([^)]*\)[^}]*)*)\}/g;
const SDL_FIELD = /(?:^|[\s,])([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|:)/g;

export function graphqlOperations(units, sinks) {
  const add = (unit, node, type, name) => {
    if (!NAME.test(name) || name.startsWith('__')) return;
    const key = ['gql', unit.id, type, name].join('|');
    if (sinks.seen.has(key)) return;
    sinks.seen.add(key);
    sinks.stats.byKind.graphql_operation = (sinks.stats.byKind.graphql_operation || 0) + 1;
    sinks.findings.push({
      file: unit.id, ...unit.loc(node), kind: 'graphql_operation', method: 'GRAPHQL', url: '#' + name, base: null,
      holes: [], known: true, lib: null, via: [], uncalled: false, widened: false,
      graphql: { type: type.toLowerCase(), name },
    });
  };

  const sdl = (unit, node, text) => {
    if (text.length < 15 || !SDL_HINT.test(text)) return;
    SDL_BLOCK.lastIndex = 0;
    let m;
    while ((m = SDL_BLOCK.exec(text))) {
      const body = m[2]
        .replace(/#[^\n]*/g, '')
        .replace(/"{3}[\s\S]*?"{3}/g, '')
        .replace(/\([^)]*\)/g, '(');
      for (const f of body.matchAll(SDL_FIELD)) add(unit, node, m[1], f[1]);
    }
  };

  for (const unit of units) {
    if (!unit.program) continue;
    unit.program.traverse({
      ObjectProperty(p) {
        const k = p.node.computed ? null : (p.node.key.name ?? p.node.key.value);
        if (!TYPES.has(k) || !p.get('value').isObjectExpression()) return;
        for (const m of p.get('value.properties')) {
          if (m.isSpreadElement()) continue;
          const name = m.node.computed ? null : (m.node.key.name ?? m.node.key.value);
          const isOp = m.isObjectMethod() ||
            (m.isObjectProperty() && (m.get('value').isFunction() || m.get('value').isObjectExpression()));
          if (name && isOp) add(unit, m.node, k, name);
        }
      },
      ClassMethod(p) {
        for (const d of p.node.decorators || []) {
          const e = d.expression;
          const callee = e.type === 'CallExpression' ? e.callee : e;
          if (callee.type !== 'Identifier' || !TYPES.has(callee.name) || p.node.key.type !== 'Identifier') continue;
          let name = p.node.key.name;
          if (e.type === 'CallExpression') {
            const opts = e.arguments.find((a) => a.type === 'ObjectExpression');
            const nm = opts?.properties.find((q) => q.key && q.key.name === 'name');
            if (nm && nm.value.type === 'StringLiteral') name = nm.value.value;
          }
          add(unit, p.node, callee.name, name);
        }
      },
      StringLiteral(p) {
        sdl(unit, p.node, p.node.value);
      },
      TemplateLiteral(p) {
        if (p.node.expressions.length === 0) sdl(unit, p.node, p.node.quasis.map((q) => q.value.cooked ?? q.value.raw).join(''));
      },
    });
  }
}
