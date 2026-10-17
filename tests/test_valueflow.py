"""The value-flow bridge: corpus -> Node sidecar -> evidence in the endpoint store.

Skipped when Node or the Babel packages are not installed (run `npm ci` in analysis/).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shadow_scanner import config  # noqa: E402
from shadow_scanner.static import valueflow  # noqa: E402
from shadow_scanner.static.analyzer import EnhancedStaticAnalyzer  # noqa: E402

TARGET = 'http://app.example.com'
OK, WHY = valueflow.sidecar_available()


def analyzer(files):
    an = EnhancedStaticAnalyzer(None, TARGET)
    an.code_corpus.update(files)
    return an


def entries(an):
    return {(e['method'], e['endpoint'].replace(TARGET, '')): e for e in an.materialize()}


@unittest.skipUnless(OK, f'value-flow sidecar unavailable: {WHY}')
class ValueFlowBridge(unittest.TestCase):
    def setUp(self):
        self._cache = os.environ.get('SHADOW_VF_CACHE')
        self._tmp = tempfile.TemporaryDirectory()
        os.environ['SHADOW_VF_CACHE'] = self._tmp.name

    def tearDown(self):
        if self._cache is None:
            os.environ.pop('SHADOW_VF_CACHE', None)
        else:
            os.environ['SHADOW_VF_CACHE'] = self._cache
        config.INCLUDE_INFERRED = False
        self._tmp.cleanup()

    def test_findings_become_value_flow_evidence_with_method_params_and_auth(self):
        an = analyzer({'src/orders.ts': """
            export class S { constructor(private http: HttpClient) {}
              create(t: string) { return this.http.post('/api/orders', { productId: 1, qty: 2 },
                                                        { headers: { Authorization: 'Bearer ' + t } }); } }"""})
        an.run_extractor('value_flow', an.run_value_flow)
        e = entries(an)[('POST', '/api/orders')]
        self.assertEqual(e['parameters'], ['productId', 'qty'])
        self.assertTrue(e['auth_required'])
        ev = [x for x in e['evidence'] if x['extractor'] == 'value_flow'][0]
        self.assertEqual(ev['type'], 'VALUEFLOW_SINK')
        self.assertEqual(ev['detail']['kind'], 'http')

    def test_guessed_get_never_hides_the_sink_method(self):
        an = analyzer({'a.js': 'fetch("/api/items", {method: "DELETE"});'})
        an.add_endpoint(TARGET + '/api/items', 'GET', [], 'STATIC_CODE', 'a.js', 'BACKEND_API', 50)
        an.run_extractor('value_flow', an.run_value_flow)
        self.assertEqual({m for m, _ in entries(an)}, {'DELETE'})

    def test_graphql_operations_use_the_graphql_endpoint(self):
        an = analyzer({'r.ts': 'export const resolvers = { Query: { getUser: () => null }, Mutation: { createUser: () => null } };'})
        an.run_extractor('value_flow', an.run_value_flow)
        e = entries(an)
        self.assertIn(('GRAPHQL', '/graphql#getUser'), e)
        self.assertEqual(e[('GRAPHQL', '/graphql#createUser')]['classification'], 'GRAPHQL_API')

    def test_inferred_next_routes_are_left_out_unless_requested(self):
        files = {'src/app/api/users/[id]/route.ts': 'export async function GET() {}'}
        an = analyzer(files)
        an.run_extractor('value_flow', an.run_value_flow)
        self.assertNotIn(('GET', '/api/users/{id}'), entries(an))
        config.INCLUDE_INFERRED = True
        self.assertIn(('GET', '/api/users/{id}'), entries(an))

    def test_second_run_does_not_duplicate_and_uses_the_cache(self):
        an = analyzer({'a.js': 'fetch("/api/one");'})
        an.run_extractor('value_flow', an.run_value_flow)
        n = len(an.materialize()[0]['evidence'])
        an.code_corpus['b.js'] = 'fetch("/api/two");'
        an.run_extractor('value_flow', an.run_value_flow)
        e = entries(an)
        self.assertEqual(len(e[('GET', '/api/one')]['evidence']), n)       # not re-recorded
        self.assertIn(('GET', '/api/two'), e)
        res = valueflow.analyze_corpus([{'id': 'a.js', 'code': 'fetch("/api/one");'}])
        self.assertTrue(valueflow.analyze_corpus([{'id': 'a.js', 'code': 'fetch("/api/one");'}])['stats'].get('cached'))
        self.assertEqual(res['findings'][0]['url'], '/api/one')

    def test_analyze_code_collects_the_corpus_but_not_module_slices(self):
        an = EnhancedStaticAnalyzer(None, TARGET)
        an.analyze_code('fetch("/api/a");', TARGET + '/main.js')
        an.analyze_code('fetch("/api/a");', TARGET + '/main.js::module_3')
        self.assertEqual(list(an.code_corpus), [TARGET + '/main.js'])

    def test_prefix_artifacts_of_regex_extractors_are_dropped(self):
        an = EnhancedStaticAnalyzer(None, TARGET)
        an.add_endpoint(TARGET + '/api/admin/', 'GET', [], 'STATIC_CODE', 'x.js', 'BACKEND_API', 50)
        an.add_endpoint(TARGET + '/api/admin/users/{id}', 'DELETE', [], 'HTTP_THIS', 'x.js', 'BACKEND_API', 95)
        urls = {e['endpoint'] for e in an.materialize()}
        self.assertIn(TARGET + '/api/admin/users/{id}', urls)
        self.assertNotIn(TARGET + '/api/admin/', urls)


class SidecarMissing(unittest.TestCase):
    def test_missing_sidecar_is_a_warning_not_a_failure(self):
        saved = valueflow.ANALYSIS_DIR
        with tempfile.TemporaryDirectory() as empty:
            valueflow.ANALYSIS_DIR = empty
            try:
                an = analyzer({'a.js': 'fetch("/api/x");'})
                self.assertEqual(an.run_value_flow(), 0)
                self.assertIn('skipped', an.value_flow_stats)
            finally:
                valueflow.ANALYSIS_DIR = saved


if __name__ == '__main__':
    unittest.main()
