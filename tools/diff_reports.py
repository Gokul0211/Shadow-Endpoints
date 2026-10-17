#!/usr/bin/env python3
"""
Compare two scanner reports of the same target (API-surface drift between builds or releases).

Endpoints are keyed by (METHOD, path-template); host is ignored so staging and production can be compared.
Reported: added, removed, and changed (score moved by >= --min-delta, auth requirement changed, new
evidence kind). Exit status is 1 when anything was added or removed - usable as a CI gate.

    python tools/diff_reports.py OLD.json NEW.json [--min-delta 15] [--json OUT] [--min-score 0]
"""
import argparse
import json
import re
import sys
import urllib.parse

_HOLE = re.compile(r'\{[^{}/]*\}')


def key(e):
    path = urllib.parse.urlsplit(e.get('endpoint', '')).path or '/'
    return (e.get('method') or 'GET').upper(), _HOLE.sub('{}', path)


def index(report, min_score):
    best = {}
    for e in report.get('endpoints', []):
        if (e.get('confidence_score') or 0) < min_score:
            continue
        k = key(e)
        if k not in best or (e.get('confidence_score') or 0) > (best[k].get('confidence_score') or 0):
            best[k] = e
    return best


def diff(old, new, min_delta=15, min_score=0):
    a, b = index(old, min_score), index(new, min_score)
    added = sorted(k for k in b if k not in a)
    removed = sorted(k for k in a if k not in b)
    changed = []
    for k in sorted(set(a) & set(b)):
        x, y = a[k], b[k]
        notes = []
        d = (y.get('confidence_score') or 0) - (x.get('confidence_score') or 0)
        if abs(d) >= min_delta:
            notes.append(f'score {x.get("confidence_score")} -> {y.get("confidence_score")}')
        if x.get('auth_required') != y.get('auth_required'):
            notes.append(f'auth_required {x.get("auth_required")} -> {y.get("auth_required")}')
        kinds = set((y.get('origin') or {}).get('evidence_kinds', [])) - set((x.get('origin') or {}).get('evidence_kinds', []))
        if kinds:
            notes.append('new evidence kind: ' + ', '.join(sorted(kinds)))
        if notes:
            changed.append({'endpoint': f'{k[0]} {k[1]}', 'changes': notes})
    return {'old_total': len(a), 'new_total': len(b),
            'added': [f'{m} {p}' for m, p in added], 'removed': [f'{m} {p}' for m, p in removed], 'changed': changed}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('old')
    ap.add_argument('new')
    ap.add_argument('--min-delta', type=int, default=15)
    ap.add_argument('--min-score', type=int, default=0)
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    res = diff(json.load(open(args.old, encoding='utf-8')), json.load(open(args.new, encoding='utf-8')),
               args.min_delta, args.min_score)
    print(f'{res["old_total"]} -> {res["new_total"]} endpoints; +{len(res["added"])} -{len(res["removed"])} ~{len(res["changed"])}')
    for label, sign in (('added', '+'), ('removed', '-')):
        for e in res[label]:
            print(f'  {sign} {e}')
    for c in res['changed']:
        print(f'  ~ {c["endpoint"]}: ' + '; '.join(c['changes']))
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=2)
    return 1 if res['added'] or res['removed'] else 0


if __name__ == '__main__':
    sys.exit(main())
