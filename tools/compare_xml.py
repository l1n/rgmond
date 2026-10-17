#!/usr/bin/env python3
"""Compare one host's metrics in two gmond XML dumps (C gmond vs rgmond).
usage: compare_xml.py C.xml OURS.xml HOSTNAME [--json]
Prints metadata mismatches (must be none) and value differences by size."""
import json, re, sys

def load(path, host):
    x = open(path, encoding='latin-1').read()
    blocks = re.findall(r'(<HOST [^>]*>)(.*?)</HOST>', x, re.S)
    out = {}
    for head, body in blocks:
        if f'NAME="{host}"' not in head or 'GMOND_STARTED="0"' in head:
            continue
        for m in re.finditer(r'<METRIC ([^>]*)>(.*?)</METRIC>', body, re.S):
            a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            a['EXTRA'] = re.findall(r'<EXTRA_ELEMENT NAME="([^"]*)" VAL="([^"]*)"', m.group(2))
            out[a['NAME']] = a
    return out

def num(v):
    try: return float(v)
    except ValueError: return None

c, r = load(sys.argv[1], sys.argv[2] if False else sys.argv[3]), None
c = load(sys.argv[1], sys.argv[3]); r = load(sys.argv[2], sys.argv[3])
meta_bad, val = [], []
for n in sorted(set(c) | set(r)):
    if n not in r: meta_bad.append(f'{n}: missing in rgmond'); continue
    if n not in c: meta_bad.append(f'{n}: only in rgmond'); continue
    for k in ('TYPE', 'UNITS', 'TMAX', 'DMAX', 'SLOPE', 'EXTRA'):
        if c[n][k] != r[n][k]:
            meta_bad.append(f'{n}: {k} C={c[n][k]!r} rgmond={r[n][k]!r}')
    a, b = num(c[n]['VAL']), num(r[n]['VAL'])
    if a is None or b is None:
        if c[n]['VAL'] != r[n]['VAL']: val.append((float('inf'), n, c[n]['VAL'], r[n]['VAL']))
    else:
        rel = abs(a - b) / max(abs(a), abs(b), 1e-9) if a != b else 0.0
        val.append((rel, n, c[n]['VAL'], r[n]['VAL']))
res = {'metrics_c': len(c), 'metrics_rgmond': len(r), 'metadata_mismatches': meta_bad,
       'exact': sum(1 for v in val if v[0] == 0), 'within_5pct': sum(1 for v in val if 0 < v[0] <= 0.05),
       'beyond_5pct': [(n, a, b, round(rel, 4)) for rel, n, a, b in sorted(val, reverse=True) if rel > 0.05]}
if '--json' in sys.argv:
    print(json.dumps(res))
else:
    for k, v in res.items():
        if isinstance(v, list):
            print(f'{k}: {len(v)}'); [print('   ', x) for x in v[:25]]
        else:
            print(f'{k}: {v}')
