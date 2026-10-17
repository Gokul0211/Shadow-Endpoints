// Sidecar entry point: JSON in on stdin, JSON out on stdout.
//   in : {"files":[{"id":"...","code":"..."}], "options":{"maxFileBytes":6000000}}
//   out: {"findings":[...], "stats":{...}, "errors":[{"file":"...","error":"..."}]}
import { Unit } from './units.js';
import { Modules } from './modules.js';
import { Evaluator } from './evaluator.js';
import { Sinks } from './sinks.js';

export function analyze(input) {
  const t0 = Date.now();
  const opts = input.options || {};
  const maxBytes = opts.maxFileBytes ?? 6_000_000;
  const errors = [];
  const units = [];
  for (const f of input.files || []) {
    if (typeof f.code !== 'string') continue;
    if (f.code.length > maxBytes) {
      errors.push({ file: f.id, error: `skipped: ${f.code.length} bytes exceeds ${maxBytes}` });
      continue;
    }
    const u = new Unit(f.id, f.code);
    if (u.parse()) units.push(u);
    else errors.push({ file: f.id, error: u.error });
  }
  const t1 = Date.now();
  const modules = new Modules(units);
  modules.detectTables();
  const ev = new Evaluator(modules, units);
  const budget = (opts.timeBudgetSeconds ?? 600) * 1000;
  const sinks = new Sinks(ev, units, { deadline: Date.now() + budget });
  const findings = sinks.run();
  const holeClasses = {};
  for (const f of findings) for (const h of f.holes) holeClasses[h.cls] = (holeClasses[h.cls] || 0) + 1;
  const stats = {
    files: (input.files || []).length,
    parsed: units.length,
    failed: errors.length,
    webpackTables: modules.tables.length,
    webpackModules: modules.tables.reduce((n, t) => n + t.entries.size, 0),
    ...sinks.stats,
    findings: findings.length,
    withHoles: findings.filter((f) => f.holes.length).length,
    holeClasses,
    eval: ev.stats,
    msParse: t1 - t0,
    msAnalyze: Date.now() - t1,
  };
  return { findings, stats, errors };
}

async function main() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  process.stdout.write(JSON.stringify(analyze(input)));
}

if (process.argv[1] && process.argv[1].endsWith('cli.js')) {
  main().catch((e) => {
    process.stderr.write(String(e && e.stack ? e.stack : e));
    process.exit(1);
  });
}
