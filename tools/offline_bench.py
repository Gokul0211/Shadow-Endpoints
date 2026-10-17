"""
Run the scanner's static analysis OFFLINE against SPABench's own files and score it.

No network, no Docker, no browser: a fake HTTP session answers every request from
the repository files of the benchmark (404 for anything else). Used by the
regression tests and for ablations.

    python tools/offline_bench.py [--app APP] [--disable-extractor NAME ...]
                                  [--only-extractor NAME ...] [--no-probe] [--json OUT]

The benchmark is found via $SPABENCH_DIR, else ../SPAbench/SPA-Bench-main.
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_ROOT = os.path.dirname(HERE)
sys.path.insert(0, SCANNER_ROOT)

APPS = ['angular-permit', 'angular-erp', 'react-ecommerce', 'vue-portal', 'nextjs-saas']


def bench_dir():
    d = os.environ.get('SPABENCH_DIR') or os.path.join(os.path.dirname(SCANNER_ROOT), 'SPAbench', 'SPA-Bench-main')
    return d if os.path.isfile(os.path.join(d, 'evaluate.py')) else None


class _Response:
    def __init__(self, url, path):
        self.url = url
        self.status_code = 200 if path else 404
        self.headers = {'Content-Type': ('application/javascript' if path and path.endswith('.js')
                                         else 'application/json' if path and path.endswith(('.json', '.map'))
                                         else 'text/html')}
        if path:
            with open(path, 'rb') as f:
                self.content = f.read()
        else:
            self.content = b''
        self.text = self.content.decode('utf-8', 'replace')

    def json(self):
        return json.loads(self.text)


class FakeSession:
    """Answers GETs from SPABench's served files; everything else is a 404."""

    def __init__(self, files):
        self.files = files
        self.headers = {}
        self.cookies = {}
        self.requests = []

    def get(self, url, **kw):
        self.requests.append(('GET', url))
        u = url.split('#')[0].split('?')[0]
        path = self.files.get(u) or self.files.get(u.rstrip('/') + '/index.html')
        return _Response(url, path)

    def post(self, url, **kw):
        self.requests.append(('POST', url))
        return _Response(url, None)

    def request(self, method, url, **kw):
        return self.get(url, **kw) if method.upper() == 'GET' else self.post(url, **kw)


def _load_bench():
    d = bench_dir()
    if not d:
        raise SystemExit('SPABench not found (set SPABENCH_DIR)')
    sys.path.insert(0, d)
    from spabench.artifacts import SERVED, served_files
    files = {}
    for app in APPS:
        for url, path in served_files(app):
            files[url.split('#')[0].split('?')[0]] = path
    return d, SERVED, served_files, files


def _feed_sourcemaps(an, app, served_files):
    """Like pipeline phase 1.5: analyse the source files embedded in the served .map files."""
    import re
    n = 0
    for url, path in served_files(app):
        if not path.endswith('.map'):
            continue
        with open(path, encoding='utf-8') as f:
            m = json.load(f)
        for src, content in zip(m.get('sources', []), m.get('sourcesContent') or []):
            label = re.sub(r'^(webpack|vite)://[^/]*/', '', src).lstrip('./')
            if not content or 'node_modules' in label or len(label) < 3:
                continue
            an.analyze_code_from_dynamic(content, 'sourcemap/' + app + '/' + label)
            n += 1
    return n


def run_static(app, disabled=(), only=None, no_probe=False, sourcemaps=False, value_flow=True):
    """Scanner phase 2 on one app. Returns the report entries (one per URL+method)."""
    from shadow_scanner import config
    from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer
    d, SERVED, served_files, files = _load_bench()
    saved = (config.DISABLED_EXTRACTORS, config.ONLY_EXTRACTORS, config.PROBING_ENABLED)
    config.DISABLED_EXTRACTORS, config.ONLY_EXTRACTORS = set(disabled), (set(only) if only else None)
    config.PROBING_ENABLED = not no_probe
    try:
        origin = next(iter(SERVED[app]))
        js = sorted(u for u, p in served_files(app) if p.endswith(('.js', '.mjs')))
        sess = FakeSession(files)
        an = EnhancedStaticAnalyzer(sess, origin.rstrip('/'), workers=4)
        with contextlib.redirect_stdout(io.StringIO()):
            an.scan(js, [])
            if sourcemaps:
                _feed_sourcemaps(an, app, served_files)
            if value_flow:
                an.run_extractor('value_flow', an.run_value_flow)
            rows = an.materialize()
        return rows, an
    finally:
        config.DISABLED_EXTRACTORS, config.ONLY_EXTRACTORS, config.PROBING_ENABLED = saved


def evaluate(app, rows):
    """SPABench evaluate.py (strict, path level and method level) for one app."""
    d, *_ = _load_bench()
    with tempfile.TemporaryDirectory() as tmp:
        tool = os.path.join(tmp, 'tool.json')
        rep = os.path.join(tmp, 'rep.json')
        with open(tool, 'w', encoding='utf-8') as f:
            json.dump({'endpoints': rows}, f)
        subprocess.run([sys.executable, 'evaluate.py', '--tool-output', tool, '--format', 'spabench-v1',
                        '--app', app, '--report', rep], cwd=d, capture_output=True, text=True, check=True)
        with open(rep, encoding='utf-8') as f:
            a = json.load(f)['apps'][0]
    p, m = a['path_level']['strict'], a['method_level']
    return {'rows': len(rows), 'precision': p['precision'], 'recall': p['recall'],
            'method_precision': m['precision'], 'method_recall': m['recall']}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--app', action='append')
    ap.add_argument('--disable-extractor', action='append', default=[])
    ap.add_argument('--only-extractor', action='append')
    ap.add_argument('--no-probe', action='store_true')
    ap.add_argument('--sourcemaps', action='store_true', help='also analyse the sources embedded in served .map files')
    ap.add_argument('--no-value-flow', action='store_true', help='skip the Phase C value-flow step')
    ap.add_argument('--json', help='write the results here')
    ap.add_argument('--dump-rows', help='write the scanner entries of the (single) --app here')
    a = ap.parse_args()
    out = {}
    print(f'{"app":16s} {"rows":>5s} {"P":>6s} {"R":>6s} {"mP":>6s} {"mR":>6s}')
    for app in a.app or APPS:
        rows, _ = run_static(app, a.disable_extractor, a.only_extractor, a.no_probe, a.sourcemaps, not a.no_value_flow)
        r = evaluate(app, rows)
        out[app] = r
        if a.dump_rows:
            with open(a.dump_rows, 'w', encoding='utf-8') as f:
                json.dump(rows, f, indent=1, sort_keys=True)
        print(f'{app:16s} {r["rows"]:5d} {r["precision"]:6.3f} {r["recall"]:6.3f} '
              f'{r["method_precision"]:6.3f} {r["method_recall"]:6.3f}')
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=1, sort_keys=True)


if __name__ == '__main__':
    main()
