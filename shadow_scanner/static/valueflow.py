"""
URL value-flow analysis (the Babel-based sidecar in refactored/analysis/).

The scanner hands the sidecar every piece of client code it has fetched (bundles
and source-map sources); the sidecar parses them with Babel (TypeScript, JSX,
modern syntax), builds the module graph and evaluates the URL given to every
HTTP sink as a set of templates with typed holes (see analysis/src/*.js and
vibe/scanner-plan.md, Phase C). Each finding becomes one evidence item of type
VALUEFLOW_SINK carrying the sink kind, the call chain through wrapper functions
and the classes of unresolved pieces.

If Node or the Babel packages are missing the extractor logs one warning and
does nothing; the rest of the scanner is unaffected.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

from shadow_scanner.config import logger
from shadow_scanner.core import diagnostics

# the sidecar lives next to the package (refactored/analysis); SHADOW_ANALYSIS_DIR overrides it
# (needed when the package is pip-installed, e.g. in the Docker image)
ANALYSIS_DIR = os.environ.get('SHADOW_ANALYSIS_DIR') or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'analysis')
MAX_FILE_BYTES = 6_000_000
MAX_TOTAL_BYTES = 120_000_000
TIMEOUT_SECONDS = 900
TIME_BUDGET_SECONDS = 600     # the sidecar stops analysing after this and reports stats.timedOut


def sidecar_available():
    """(ok, reason). Needs `node` on PATH and `npm ci` run once in refactored/analysis."""
    if not shutil.which('node'):
        return False, 'node is not on PATH'
    if not os.path.isfile(os.path.join(ANALYSIS_DIR, 'node_modules', '@babel', 'parser', 'package.json')):
        return False, f'Babel is not installed (run `npm ci` in {ANALYSIS_DIR})'
    return True, ''


def _version_hash():
    """Hash of the sidecar sources: a cached result is valid only for the code that produced it."""
    h = hashlib.sha256()
    src = os.path.join(ANALYSIS_DIR, 'src')
    for name in sorted(os.listdir(src)):
        with open(os.path.join(src, name), 'rb') as f:
            h.update(name.encode() + f.read())
    return h.hexdigest()[:16]


def _cache_path(payload):
    """Results are cached by content (set SHADOW_VF_CACHE=off to disable, or to a directory to relocate)."""
    where = os.environ.get('SHADOW_VF_CACHE', '')
    if where.lower() == 'off':
        return None
    root = where or os.path.join(tempfile.gettempdir(), 'shadow_vf_cache')
    key = hashlib.sha256(_version_hash().encode() + payload.encode('utf-8')).hexdigest()[:32]
    return os.path.join(root, key + '.json')


def analyze_corpus(files):
    """Run the sidecar on [{'id': label, 'code': text}]. Returns its JSON result."""
    ok, why = sidecar_available()
    if not ok:
        raise RuntimeError(why)
    payload = json.dumps({'files': files, 'options': {'maxFileBytes': MAX_FILE_BYTES,
                                                      'timeBudgetSeconds': TIME_BUDGET_SECONDS}})
    cache = _cache_path(payload)
    if cache and os.path.isfile(cache):
        with open(cache, encoding='utf-8') as f:
            result = json.load(f)
        result['stats']['cached'] = True
        return result
    proc = subprocess.run(
        ['node', os.path.join('src', 'cli.js')], input=payload.encode('utf-8'),
        capture_output=True, cwd=ANALYSIS_DIR, timeout=TIMEOUT_SECONDS)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode('utf-8', 'replace')[:500])
    result = json.loads(proc.stdout.decode('utf-8'))
    if cache and not result['stats'].get('timedOut'):
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, 'w', encoding='utf-8') as f:
            json.dump(result, f)
    return result


class ValueFlowMixin:
    """EnhancedStaticAnalyzer.run_value_flow(): feed the corpus to the sidecar, record the findings."""

    def run_value_flow(self):
        corpus = getattr(self, 'code_corpus', {})
        state = self.__dict__.setdefault('_vf_state', {'size': -1, 'keys': set(), 'warned': False, 'runs': 0})
        if len(corpus) == state['size']:
            return 0                                   # nothing new since the last run
        ok, why = sidecar_available()
        if not ok:
            if not state['warned']:
                logger.warning(f'[value_flow] skipped: {why}')
                state['warned'] = True
            self.value_flow_stats = {'skipped': why}
            return 0
        files, total = [], 0
        for label in sorted(corpus):
            code = corpus[label]
            total += len(code)
            if total > MAX_TOTAL_BYTES:
                break
            files.append({'id': label, 'code': code})
        try:
            result = analyze_corpus(files)
        except Exception as exc:
            logger.warning(f'[value_flow] sidecar failed: {type(exc).__name__}: {str(exc)[:200]}')
            diagnostics.swallowed(__name__, exc)
            self.value_flow_stats = {'failed': str(exc)[:200]}
            return 0
        state['size'] = len(corpus)
        state['runs'] += 1
        added = 0
        for f in result['findings']:
            key = (f['file'], f['line'], f['col'], f['url'], f['method'], f.get('base'))
            if key in state['keys']:
                continue
            state['keys'].add(key)
            if self._record_value_flow(f):
                added += 1
        stats = dict(result['stats'])
        stats['parse_errors'] = result['errors'][:20]
        stats['recorded'] = len(state['keys'])
        stats['runs'] = state['runs']
        self.value_flow_stats = stats
        print(f"  [value_flow] {stats['parsed']}/{stats['files']} files parsed, "
              f"{stats['sinks']} sinks, {stats['findings']} findings, {added} new")
        return added

    def _graphql_endpoint(self):
        """The GraphQL endpoint operations declared in the code belong to: one a source map or the
        introspection step already named, else <target>/graphql."""
        known = sorted(getattr(self, 'sourcemap_gql_endpoints', set()))
        if known:
            return known[0]
        for e in self.endpoints:
            if e.get('classification') == 'GRAPHQL_API' and '#' not in e['endpoint'] and e['endpoint'].rstrip('/').endswith('/graphql'):
                return e['endpoint'].rstrip('/')
        return self.base_url.rstrip('/') + '/graphql'

    def _record_value_flow(self, f):
        if f['kind'] == 'nextjs_route':
            # path derived from a file name by the framework's convention: inferred evidence
            n0 = len(self.endpoints)
            self.add_endpoint(self.normalizer.normalize(f['url']), f['method'] or 'REQUEST', [], 'NEXTJS_FILE_ROUTE',
                              f['file'], 'BACKEND_API', 78, evidence_extra={'detail': {'kind': 'nextjs_route', 'line': f['line']}})
            return len(self.endpoints) > n0
        if f['kind'] == 'graphql_operation':
            detail = {k: f[k] for k in ('kind', 'line', 'col', 'graphql') if k in f}
            n0 = len(self.endpoints)
            self.add_endpoint(self._graphql_endpoint() + f['url'], 'GRAPHQL', [], 'VALUEFLOW_SINK', f['file'],
                              'GRAPHQL_API', 88, evidence_extra={'detail': detail})
            return len(self.endpoints) > n0
        url = f['url']
        if not url.startswith(('http://', 'https://', 'ws://', 'wss://')):
            url = self.normalizer.normalize(url)
        method = f['method'] or 'REQUEST'          # REQUEST = unknown; the store treats it as a guess
        if f['kind'] == 'websocket':
            method, cls = 'WS', 'WEBSOCKET_ENDPOINT'
        else:
            cls = 'BACKEND_API'
        confidence = 90 if f['known'] and not f['uncalled'] else 82 if f['known'] else 70
        detail = {k: f[k] for k in ('kind', 'line', 'col', 'known', 'lib', 'via', 'holes', 'uncalled', 'base', 'auth') if k in f}
        n0 = len(self.endpoints)
        self.add_endpoint(url, method, f.get('params') or [], 'VALUEFLOW_SINK', f['file'], cls, confidence,
                          evidence_extra={'detail': detail})
        return len(self.endpoints) > n0
