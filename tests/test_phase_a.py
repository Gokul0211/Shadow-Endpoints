"""Phase A behaviour: evidence kinds, scoring, the evidence store, method handling, domains, clicks.

    python -m unittest discover -s tests        (from refactored/)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shadow_scanner import config  # noqa: E402
from shadow_scanner.core.evidence import evidence_kind  # noqa: E402
from shadow_scanner.core.scoring import BayesianConfidenceScorer as B  # noqa: E402
from shadow_scanner.core.url_normalizer import URLNormalizer  # noqa: E402
from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer  # noqa: E402

TARGET = 'http://app.example.com'


def store():
    return EnhancedStaticAnalyzer(session=None, base_url=TARGET)


def entries(an, url):
    return [e for e in an.materialize() if e['endpoint'].rstrip('/') == url.rstrip('/')]


class EvidenceKinds(unittest.TestCase):
    def test_kinds_are_exact(self):
        self.assertEqual(evidence_kind('DYNAMIC_XHR_INTERCEPT'), 'runtime')
        self.assertEqual(evidence_kind('RUNTIME_FETCH'), 'runtime')
        self.assertEqual(evidence_kind('OPENAPI_SPEC'), 'spec')
        self.assertEqual(evidence_kind('NEXTJS_API_PROBE'), 'probe')
        self.assertEqual(evidence_kind('INDEXEDDB_CACHED_URL'), 'storage')
        # names containing DYNAMIC are not runtime evidence
        for t in ('WEBSOCKET_DYNAMIC_CONCAT', 'WEBSOCKET_DYNAMIC_VAR', 'RPC_CALL_DYNAMIC'):
            self.assertEqual(evidence_kind(t), 'static', t)


class Scoring(unittest.TestCase):
    def test_static_never_verified(self):
        for t, u in [('WEBSOCKET_DYNAMIC_CONCAT', 'ws://h/ws/x'), ('WEBSOCKET_STATIC_LITERAL', 'ws://h/ws/x'),
                     ('RPC_CALL_DYNAMIC', 'http://h/api/x'), ('NEXTJS_API_ROUTE', 'http://h/api/x'),
                     ('SW_WEB_WORKER', 'http://h/api/x'), ('STATIC_CODE', 'ws://h/socket')]:
            score, cat, _ = B.score(u, t, False)
            self.assertNotEqual(cat, 'VERIFIED_API', t)
            self.assertLess(score, 100, t)

    def test_runtime_is_verified(self):
        self.assertEqual(B.score('http://h/api/x', 'DYNAMIC_XHR_INTERCEPT', False)[:2], (100, 'VERIFIED_API'))


class Store(unittest.TestCase):
    def test_one_record_per_url_and_all_evidence_kept(self):
        an = store()
        an.add_endpoint(TARGET + '/api/orders', 'GET', [], 'FETCH_API', 'main.js', 'BACKEND_API', 85)
        an.add_endpoint(TARGET + '/api/orders/', 'GET', [], 'STATIC_CODE', 'main.js', 'BACKEND_API', 50)
        self.assertEqual(len(an.endpoints), 1)
        self.assertEqual(len(an.endpoints[0]['evidence']), 2)

    def test_explicit_methods_are_separate_entries(self):
        an = store()
        an.add_endpoint(TARGET + '/api/users', 'GET', [], 'HTTP_THIS', 'a.ts', 'BACKEND_API', 95)
        an.add_endpoint(TARGET + '/api/users', 'POST', [], 'HTTP_THIS', 'a.ts', 'BACKEND_API', 95)
        self.assertEqual(sorted(e['method'] for e in entries(an, TARGET + '/api/users')), ['GET', 'POST'])

    def test_guessed_get_does_not_add_a_method(self):
        an = store()
        an.add_endpoint(TARGET + '/api/items', 'GET', [], 'STATIC_CODE', 'main.js', 'BACKEND_API', 50)
        an.add_endpoint(TARGET + '/api/items', 'DELETE', [], 'HTTP_THIS', 'main.js', 'BACKEND_API', 95)
        self.assertEqual([e['method'] for e in entries(an, TARGET + '/api/items')], ['DELETE'])

    def test_request_is_not_an_http_method(self):
        an = store()
        an.add_endpoint(TARGET + '/api/query', 'REQUEST', [], 'NAMED_AXIOS_INSTANCE', 'main.js', 'BACKEND_API', 85)
        (e,) = entries(an, TARGET + '/api/query')
        self.assertEqual(e['method'], 'GET')
        self.assertTrue(e['method_inferred'])

    def test_spec_is_not_verified(self):
        an = store()
        an.add_endpoint(TARGET + '/api/spec-only', 'GET', [], 'OPENAPI_SPEC', 'openapi.json', 'VERIFIED_API', 100)
        (e,) = entries(an, TARGET + '/api/spec-only')
        self.assertNotEqual(e['classification'], 'VERIFIED_API')
        self.assertEqual(e['origin']['evidence_kinds'], ['spec'])

    def test_runtime_evidence_verifies_a_static_finding(self):
        an = store()
        an.add_endpoint(TARGET + '/api/cart', 'GET', [], 'FETCH_API', 'main.js', 'BACKEND_API', 85)
        an.add_endpoint(TARGET + '/api/cart', 'GET', [], 'DYNAMIC_XHR_INTERCEPT', 'Browser', 'VERIFIED_API', 100)
        (e,) = entries(an, TARGET + '/api/cart')
        self.assertEqual((e['confidence_score'], e['classification']), (100, 'VERIFIED_API'))

    def test_multi_source_needs_two_categories(self):
        an = store()
        an.add_endpoint(TARGET + '/api/accounts', 'GET', [], 'FETCH_API', 'main.js', 'BACKEND_API', 85)
        an.add_endpoint(TARGET + '/api/accounts', 'GET', [], 'STATIC_CODE', 'main.js', 'BACKEND_API', 50)
        one_cat = entries(an, TARGET + '/api/accounts')[0]['confidence_score']
        an.add_endpoint(TARGET + '/api/accounts', 'GET', [], 'FETCH_API', 'output/x/sourcemaps/extracted/src/api.ts',
                        'BACKEND_API', 85)
        (e,) = entries(an, TARGET + '/api/accounts')
        self.assertEqual(e['origin']['provenance'], ['SOURCEMAP', 'STATIC'])
        self.assertGreater(e['confidence_score'], one_cat)

    def test_runtime_not_dropped_by_client_code_filters(self):
        an = store()
        an.add_endpoint(TARGET + '/login', 'POST', [], 'DYNAMIC_XHR_INTERCEPT', 'Browser', 'VERIFIED_API', 100)
        an.add_endpoint(TARGET + '/dashboard', 'GET', [], 'STATIC_CODE', 'main.js', 'BACKEND_API', 50)
        urls = {e['endpoint'] for e in an.materialize()}
        self.assertIn(TARGET + '/login', urls)
        self.assertNotIn(TARGET + '/dashboard', urls)


class DetectMethod(unittest.TestCase):
    def test_local_only(self):
        an = store()
        self.assertEqual(an.detect_method('fetch("/api/x",{method:"POST"})', 0), 'POST')
        self.assertEqual(an.detect_method('x="/api/z";y=fetch(q,{method:"PUT"})', 2), 'GET')
        self.assertEqual(an.detect_method('this.http.delete("/api/y")', 17), 'DELETE')


class Domains(unittest.TestCase):
    def test_exact_host_matching(self):
        self.assertFalse(config.is_ignored_url('https://firestore.googleapis.com/v1/x'))
        self.assertFalse(config.is_ignored_url('https://myapi.azurewebsites.net/api/x'))
        self.assertFalse(config.is_ignored_url('https://d1.cloudfront.net/main.js'))
        self.assertTrue(config.is_ignored_url('https://www.google-analytics.com/collect'))
        self.assertTrue(config.is_ignored_url('https://o1.ingest.sentry.io/api/1/'))

    def test_first_party(self):
        self.assertTrue(config.is_first_party('https://api.example.com/x', 'https://app.example.com'))
        self.assertTrue(config.is_first_party('http://localhost:4001/x', 'http://localhost:3001'))
        self.assertFalse(config.is_first_party('https://auth.other.com/x', 'https://app.example.com'))


class Normalizer(unittest.TestCase):
    def test_relative_against_document_base(self):
        n = URLNormalizer('https://x.com/app')
        self.assertEqual(n.normalize('api/users'), 'https://x.com/app/api/users')
        n.set_base_href('/portal/')
        self.assertEqual(n.normalize('api/users'), 'https://x.com/portal/api/users')
        self.assertEqual(n.normalize('/api/users'), 'https://x.com/api/users')


class ClickDenylist(unittest.TestCase):
    def test_denylist(self):
        from shadow_scanner.dynamic.interceptor import DynamicInterceptor as D
        for t in ('Logout', 'Sign out', 'Delete user', 'Pay now', 'Remove', 'Confirm order', 'Checkout'):
            self.assertTrue(D.CLICK_DENYLIST.search(t), t)
        for t in ('Save', 'Settings', 'Open menu', 'View reports'):
            self.assertFalse(D.CLICK_DENYLIST.search(t), t)


if __name__ == '__main__':
    unittest.main()
