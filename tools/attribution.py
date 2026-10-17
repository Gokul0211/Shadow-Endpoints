#!/usr/bin/env python3
"""
Per-extractor / per-phase attribution table from scanner reports.

For each report the evidence items of every endpoint (one entry per URL; methods are merged) say which
extractor and phase saw it. The table lists, per extractor: how many endpoints it saw, how many ONLY it saw
(unique), and the pairwise overlap. With --truth FILE (a JSON list of ground-truth paths, or a SPABench
manifest) the same counts are given for true positives only, so "unique" means "found by nothing else and
correct".

    python tools/attribution.py REPORT.json [REPORT2.json ...] [--truth manifest.json --app NAME] [--json OUT]
"""
import argparse
import itertools
import json
import re
import sys
import urllib.parse
from collections import defaultdict

_HOLE = re.compile(r'\{[^{}/]*\}')


def norm(url):
    p = urllib.parse.urlsplit(url)
    return _HOLE.sub('{}', p.path or '/')


def load_truth(path, app):
    data = json.load(open(path, encoding='utf-8'))
    if isinstance(data, list):
        return {norm(x) if '://' in x else _HOLE.sub('{}', x) for x in data}
    paths = set()
    for a in data.get('apps', []):
        if app and app not in (a.get('id'), a.get('name')):
            continue
        for e in a.get('endpoints', []):
            paths.add(norm(e.get('url') or e.get('path') or ''))
    return paths


def sightings(reports):
    """{path: {'extractors': set, 'phases': set}} merged over the reports' endpoints."""
    out = defaultdict(lambda: {'extractors': set(), 'phases': set()})
    for rep in reports:
        for e in rep.get('endpoints', []):
            slot = out[norm(e.get('endpoint', ''))]
            for ev in e.get('evidence', []) or []:
                if ev.get('extractor'):
                    slot['extractors'].add(ev['extractor'])
                if ev.get('phase') is not None:
                    slot['phases'].add(str(ev['phase']))
    return out


def table(seen, keep=None):
    paths = {p: v for p, v in seen.items() if keep is None or p in keep}
    ext = sorted({x for v in paths.values() for x in v['extractors']})
    rows = []
    for x in ext:
        mine = {p for p, v in paths.items() if x in v['extractors']}
        only = {p for p in mine if paths[p]['extractors'] == {x}}
        rows.append({'extractor': x, 'found': len(mine), 'unique': len(only)})
    overlap = {}
    for a, b in itertools.combinations(ext, 2):
        n = sum(1 for v in paths.values() if a in v['extractors'] and b in v['extractors'])
        if n:
            overlap[f'{a} & {b}'] = n
    phases = defaultdict(int)
    for v in paths.values():
        for ph in v['phases']:
            phases[ph] += 1
    return {'endpoints': len(paths), 'by_extractor': rows, 'overlap': overlap, 'by_phase': dict(sorted(phases.items()))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('reports', nargs='+')
    ap.add_argument('--truth')
    ap.add_argument('--app')
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    reports = [json.load(open(p, encoding='utf-8')) for p in args.reports]
    seen = sightings(reports)
    res = {'all': table(seen)}
    if args.truth:
        res['true_positives'] = table(seen, load_truth(args.truth, args.app))
    for name, t in res.items():
        print(f'\n[{name}] {t["endpoints"]} endpoint paths')
        print(f'  {"extractor":<28}{"found":>7}{"unique":>8}')
        for r in sorted(t['by_extractor'], key=lambda r: -r['found']):
            print(f'  {r["extractor"]:<28}{r["found"]:>7}{r["unique"]:>8}')
        print('  by phase:', t['by_phase'])
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
