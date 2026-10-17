"""OpenAPI / Postman export."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shadow_scanner.reporting.exporters import to_openapi, to_postman  # noqa: E402

REPORT = {'scan_metadata': {'target': 'http://app.test', 'timestamp': 't'}, 'endpoints': [
    {'endpoint': 'http://app.test/api/users/{param}/orders/{param}', 'method': 'GET', 'confidence_score': 90,
     'auth_required': True, 'auth_method': 'authorization_header', 'parameters': ['limit'],
     'origin': {'evidence_kinds': ['static']}},
    {'endpoint': 'http://app.test/api/users/{param}/orders/{param}', 'method': 'DELETE', 'confidence_score': 70},
    {'endpoint': 'http://api.test/graphql', 'method': 'GRAPHQL', 'confidence_score': 80},
    {'endpoint': 'ws://app.test/socket', 'method': 'WS', 'confidence_score': 60},
    {'endpoint': 'http://app.test/low', 'method': 'GET', 'confidence_score': 10},
]}


class Export(unittest.TestCase):
    def test_openapi_paths_and_unique_holes(self):
        doc = to_openapi(REPORT)
        p = doc['paths']['/api/users/{param}/orders/{param2}']
        self.assertEqual(set(p), {'get', 'delete'})
        self.assertEqual([x['name'] for x in p['get']['parameters']], ['param', 'param2'])
        self.assertEqual(p['get']['security'], [{'bearerAuth': []}])
        self.assertEqual(p['get']['x-observed-parameters'], ['limit'])
        self.assertIn('post', doc['paths']['/graphql'])
        self.assertEqual(len(doc['x-websockets']), 1)
        self.assertIn('bearerAuth', doc['components']['securitySchemes'])

    def test_min_score(self):
        self.assertNotIn('/low', to_openapi(REPORT, 50)['paths'])
        self.assertIn('/low', to_openapi(REPORT, 0)['paths'])

    def test_postman(self):
        col = to_postman(REPORT, 50)
        names = [i['name'] for f in col['item'] for i in f['item']]
        self.assertIn('GET /api/users/{param}/orders/{param}', names)
        self.assertNotIn('GET /low', names)
        self.assertEqual({f['name'] for f in col['item']}, {'http://app.test', 'http://api.test'})


if __name__ == '__main__':
    unittest.main()
