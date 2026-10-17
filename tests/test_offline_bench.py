"""Regression tests on SPABench v3, offline (no Docker, no network, no browser).

Skipped when the benchmark checkout is not next to this repository
(set SPABENCH_DIR to point at it).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
sys.path.insert(0, ROOT)

import offline_bench  # noqa: E402

BENCH = offline_bench.bench_dir()


@unittest.skipUnless(BENCH, 'SPABench not found (set SPABENCH_DIR)')
class OfflineBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, 'golden_offline.json'), encoding='utf-8') as f:
            cls.golden = {k: v for k, v in json.load(f).items() if not k.startswith('_')}

    def test_no_static_finding_is_runtime_verified(self):
        for app in offline_bench.APPS:
            rows, _ = offline_bench.run_static(app)
            self.assertTrue(rows, app)
            bad = [r['endpoint'] for r in rows if r['classification'] == 'VERIFIED_API']
            self.assertEqual(bad, [], app)

    def test_every_entry_has_evidence_and_an_extractor(self):
        rows, _ = offline_bench.run_static('react-ecommerce')
        for r in rows:
            self.assertTrue(r['evidence'], r['endpoint'])
            self.assertTrue(all(ev.get('extractor') for ev in r['evidence']), r['endpoint'])

    def _check_floors(self, setting, sourcemaps):
        for app, floor in self.golden[setting].items():
            rows, _ = offline_bench.run_static(app, sourcemaps=sourcemaps)
            got = offline_bench.evaluate(app, rows)
            for key, minimum in floor.items():
                self.assertGreaterEqual(got[key], minimum, f'{setting} {app} {key}: {got[key]} < {minimum}')

    def test_results_do_not_fall_below_golden_floors(self):
        self._check_floors('no_maps', False)

    def test_results_with_source_maps_do_not_fall_below_golden_floors(self):
        self._check_floors('maps', True)

    def test_disabling_an_extractor_changes_the_result(self):
        base, _ = offline_bench.run_static('react-ecommerce')
        ablated, _ = offline_bench.run_static('react-ecommerce', disabled=['rpc_patterns'])
        self.assertLess(len(ablated), len(base))

    def test_output_is_identical_for_different_hash_seeds(self):
        tool = os.path.join(ROOT, 'tools', 'offline_bench.py')
        outputs = []
        with tempfile.TemporaryDirectory() as tmp:
            for seed in ('1', '5'):
                out = os.path.join(tmp, f'rows_{seed}.json')
                subprocess.run([sys.executable, tool, '--app', 'angular-erp', '--dump-rows', out],
                               env={**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONIOENCODING': 'utf-8'},
                               check=True, capture_output=True, cwd=ROOT)
                with open(out, 'rb') as f:
                    outputs.append(f.read())
        self.assertEqual(outputs[0], outputs[1])


if __name__ == '__main__':
    unittest.main()
