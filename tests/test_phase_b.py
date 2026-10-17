"""Phase B: HTTP client, run metadata (credential redaction), extractor registry, extractor snippets."""
import argparse
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shadow_scanner import config  # noqa: E402
from shadow_scanner.core.http_client import BudgetExceeded, HttpClient, mask_url  # noqa: E402
from shadow_scanner.core.rate_limiter import RateLimiter  # noqa: E402
from shadow_scanner.core import run_meta  # noqa: E402
from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer  # noqa: E402
from shadow_scanner.static.registry import CODE_EXTRACTORS, PHASES, extractor_names  # noqa: E402

TARGET = 'http://app.example.com'


class _Resp:
    def __init__(self, status=200, body=b'x' * 10):
        self.status_code, self.content = status, body


class _Session:
    def __init__(self, statuses=(200,)):
        self.headers, self.cookies = {}, {}
        self.calls = []
        self._statuses = list(statuses)

    def get(self, url, **kw):
        self.calls.append(('GET', url, kw))
        return _Resp(self._statuses.pop(0) if len(self._statuses) > 1 else self._statuses[0])

    def post(self, url, **kw):
        self.calls.append(('POST', url, kw))
        return _Resp()


class HttpClientTests(unittest.TestCase):
    def client(self, **kw):
        return HttpClient(_Session(kw.pop('statuses', (200,))), rate_limiter=RateLimiter(0.0), **kw)

    def test_counts_per_phase(self):
        c = self.client()
        c.set_phase('2')
        c.get('http://h/a')
        c.set_phase('1.8')
        c.get('http://h/b')
        c.post('http://h/c')
        st = c.stats()
        self.assertEqual(st['requests'], 3)
        self.assertEqual(st['by_phase']['1.8']['requests'], 2)
        self.assertEqual(st['bytes'], 30)

    def test_request_budget(self):
        c = self.client(max_requests=2)
        c.get('http://h/1')
        c.get('http://h/2')
        with self.assertRaises(BudgetExceeded):
            c.get('http://h/3')
        self.assertTrue(c.stats()['budget']['exhausted'])
        self.assertEqual(len(c._session.calls), 2)

    def test_byte_budget(self):
        c = self.client(max_bytes=15)
        c.get('http://h/1')
        c.get('http://h/2')
        with self.assertRaises(BudgetExceeded):
            c.get('http://h/3')

    def test_retries_on_503(self):
        c = self.client(statuses=(503, 503, 200), retries=2)
        self.assertEqual(c.get('http://h/x').status_code, 200)
        self.assertEqual(len(c._session.calls), 3)

    def test_session_attributes_pass_through(self):
        c = self.client()
        c.headers['X-Test'] = '1'
        self.assertEqual(c._session.headers['X-Test'], '1')

    def test_verify_override(self):
        c = self.client(verify=True)
        c.get('http://h/x', verify=False)
        self.assertTrue(c._session.calls[0][2]['verify'])

    def test_log_masks_secrets_and_has_no_headers(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'req.jsonl')
            c = self.client(log_path=path)
            c.get('http://h/api?token=SECRET123&page=2', headers={'Authorization': 'Bearer ABC'})
            c.close()
            with open(path, encoding='utf-8') as f:
                text = f.read()
        self.assertNotIn('SECRET123', text)
        self.assertNotIn('Bearer ABC', text)
        self.assertIn('page=2', text)
        row = json.loads(text.splitlines()[0])
        self.assertEqual(row['status'], 200)

    def test_mask_url(self):
        self.assertEqual(mask_url('http://h/p'), 'http://h/p')
        self.assertIn('api_key=%2A%2A%2A', mask_url('http://h/p?api_key=abc'))


class RunMetaTests(unittest.TestCase):
    def args(self, **kw):
        base = dict(target='http://x', username='admin', password='hunter2', bearer='tok.en',
                    cookies='sid=abc', mfa_secret='JBSWY3DP', max_routes=30, workers=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_secrets_are_redacted(self):
        out = run_meta.redact_args(self.args())
        for k in ('password', 'bearer', 'cookies', 'mfa_secret'):
            self.assertEqual(out[k], '<redacted>', k)
        self.assertEqual(out['username'], 'admin')
        self.assertEqual(out['max_routes'], 30)
        blob = json.dumps(out)
        for secret in ('hunter2', 'tok.en', 'sid=abc', 'JBSWY3DP'):
            self.assertNotIn(secret, blob)

    def test_unset_secret_stays_none_and_private_attrs_skipped(self):
        a = self.args(password=None)
        a._recorder = object()
        out = run_meta.redact_args(a)
        self.assertIsNone(out['password'])
        self.assertNotIn('_recorder', out)

    def test_future_secret_like_option_is_redacted(self):
        out = run_meta.redact_args(self.args(client_secret='zzz', api_token='ttt'))
        self.assertEqual((out['client_secret'], out['api_token']), ('<redacted>', '<redacted>'))

    def test_env_secrets(self):
        a = argparse.Namespace(password=None, bearer=None, cookies=None, mfa_secret=None)
        os.environ['SHADOW_PASSWORD'] = 'from-env'
        try:
            run_meta.apply_env_secrets(a)
        finally:
            del os.environ['SHADOW_PASSWORD']
        self.assertEqual(a.password, 'from-env')
        self.assertEqual(run_meta.redact_args(a)['password'], '<redacted>')

    def test_recorder_build_contains_no_secret(self):
        rec = run_meta.RunRecorder()
        rec.start_phase('2')
        meta = rec.build(self.args(), config)
        self.assertIn('2', meta['phases'])
        self.assertEqual(len(meta['config_hash']), 16)
        self.assertNotIn('hunter2', json.dumps(meta, default=str))


class RegistryTests(unittest.TestCase):
    CODE = ('class S { load(){ return this.http.get("/api/orders"); } '
            'del(id){ return this.http.delete("/api/orders/" + id); } }')

    def run_scan_on(self, **cfg):
        saved = (config.DISABLED_EXTRACTORS, config.ONLY_EXTRACTORS)
        config.DISABLED_EXTRACTORS = set(cfg.get('disabled', ()))
        config.ONLY_EXTRACTORS = set(cfg['only']) if cfg.get('only') else None
        try:
            an = EnhancedStaticAnalyzer(None, TARGET)
            an.analyze_code(self.CODE, TARGET + '/main.js')
            return an
        finally:
            config.DISABLED_EXTRACTORS, config.ONLY_EXTRACTORS = saved

    def test_names_are_unique_and_known(self):
        names = extractor_names()
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('angular_http', names)
        self.assertEqual(PHASES[-1], '1.5b')
        for _, method in CODE_EXTRACTORS:
            self.assertTrue(hasattr(EnhancedStaticAnalyzer, method), method)

    def test_baseline_finds_endpoints_and_records_extractor(self):
        an = self.run_scan_on()
        urls = {e['endpoint'] for e in an.materialize()}
        self.assertIn(TARGET + '/api/orders', urls)
        names = {ev['extractor'] for e in an.materialize() for ev in e['evidence']}
        self.assertIn('angular_http', names)
        self.assertGreater(an.extractor_stats['angular_http']['sightings'], 0)

    def test_disabling_an_extractor_removes_its_evidence(self):
        an = self.run_scan_on(disabled=['angular_http'])
        names = {ev['extractor'] for e in an.materialize() for ev in e['evidence']}
        self.assertNotIn('angular_http', names)

    def test_only_runs_just_the_named_extractor(self):
        an = self.run_scan_on(only=['angular_http'])
        names = {ev['extractor'] for e in an.materialize() for ev in e['evidence']}
        self.assertEqual(names, {'angular_http'})

    def test_failing_extractor_is_counted_and_others_still_run(self):
        an = EnhancedStaticAnalyzer(None, TARGET)

        def boom(code, source):
            raise ValueError('boom')
        an._extract_angular_http_calls = boom
        an.analyze_code(self.CODE, TARGET + '/main.js')
        self.assertEqual(an.extractor_stats['angular_http']['errors'], 1)
        self.assertTrue(any(e['endpoint'].endswith('/api/orders') for e in an.materialize()))


class ExtractorSnippets(unittest.TestCase):
    """JS snippet -> expected endpoint (method, path). One case per technique family."""

    def endpoints(self, code):
        an = EnhancedStaticAnalyzer(None, TARGET)
        an.analyze_code(code, TARGET + '/main.js')
        return {(e['method'], e['endpoint'].replace(TARGET, '')) for e in an.materialize()}

    def test_angular_http_methods(self):
        got = self.endpoints('this.http.post("/api/users", body); this.http.delete("/api/users/1");')
        self.assertIn(('POST', '/api/users'), got)
        self.assertTrue(any(m == 'DELETE' and p.startswith('/api/users') for m, p in got))

    def test_fetch_method_option(self):
        self.assertIn(('PUT', '/api/items'), self.endpoints('fetch("/api/items", {method: "PUT"});'))

    def test_axios_named_instance(self):
        got = self.endpoints('const apiClient = axios.create({baseURL: "/api"}); apiClient.get("/api/cart");')
        self.assertIn(('GET', '/api/cart'), got)

    def test_template_literal_param(self):
        got = self.endpoints('fetch(`/api/orders/${id}/status`);')
        self.assertTrue(any(p.startswith('/api/orders/') and p.endswith('/status') for _, p in got))

    def test_websocket_literal_not_verified(self):
        an = EnhancedStaticAnalyzer(None, TARGET)
        an.analyze_code('const s = new WebSocket("ws://api.acme-shop.io/ws/live");', TARGET + '/main.js')
        rows = [e for e in an.materialize() if e['endpoint'].startswith('ws://')]
        self.assertTrue(rows)
        self.assertTrue(all(e['classification'] != 'VERIFIED_API' for e in rows))

    def test_comment_is_not_an_endpoint(self):
        got = self.endpoints('// fetch("/api/old")\nfetch("/api/new");')
        paths = {p for _, p in got}
        self.assertIn('/api/new', paths)
        self.assertNotIn('/api/old', paths)


if __name__ == '__main__':
    unittest.main()
