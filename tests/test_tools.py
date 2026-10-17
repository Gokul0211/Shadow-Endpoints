"""tools/attribution.py and tools/diff_reports.py."""
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import attribution  # noqa: E402
import diff_reports  # noqa: E402


def ep(url, method='GET', score=80, auth=None, kinds=('static',), extractors=('a',), phase='2'):
    return {'endpoint': url, 'method': method, 'confidence_score': score, 'auth_required': auth,
            'origin': {'evidence_kinds': list(kinds)},
            'evidence': [{'extractor': x, 'phase': phase} for x in extractors]}


class Attribution(unittest.TestCase):
    def test_unique_and_overlap(self):
        rep = {'endpoints': [ep('http://h/x', extractors=('a', 'b')), ep('http://h/y', extractors=('a',)),
                             ep('http://h/z/{p}', extractors=('b',)), ep('http://h/noise', extractors=('b',))]}
        t = attribution.table(attribution.sightings([rep]))
        rows = {r['extractor']: r for r in t['by_extractor']}
        self.assertEqual((rows['a']['found'], rows['a']['unique']), (2, 1))
        self.assertEqual((rows['b']['found'], rows['b']['unique']), (3, 2))
        self.assertEqual(t['overlap'], {'a & b': 1})
        tp = attribution.table(attribution.sightings([rep]), {'/x', '/y', '/z/{}'})
        self.assertEqual({r['extractor']: r['unique'] for r in tp['by_extractor']}, {'a': 1, 'b': 1})


class Diff(unittest.TestCase):
    def test_added_removed_changed(self):
        old = {'endpoints': [ep('http://stg/api/a'), ep('http://stg/api/b'), ep('http://stg/api/c', score=40)]}
        new = {'endpoints': [ep('http://prod/api/a'), ep('http://prod/api/c', score=90, auth=True),
                             ep('http://prod/api/d')]}
        d = diff_reports.diff(old, new)
        self.assertEqual(d['added'], ['GET /api/d'])
        self.assertEqual(d['removed'], ['GET /api/b'])
        self.assertEqual(len(d['changed']), 1)
        self.assertIn('score 40 -> 90', d['changed'][0]['changes'][0])


if __name__ == '__main__':
    unittest.main()
