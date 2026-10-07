#!/usr/bin/env python3
"""V4 pass 6: structure candidates from repeated [param + offset] accesses, merged across call edges
(param_k passed unchanged as argument j). Neutral names STRUCT_NNN. Writes analysis/v4/structures.txt and structures.csv."""
import re, os, sys, collections, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import ROOT, V4
txt = open(os.path.join(ROOT, 'eshop_decompile_v4.txt')).read()
funcs = txt.split('// ==== Function @ ')[1:]
ACC = re.compile(r'\*\((uint|byte|char|ushort|short|float|double|int) \*\)\((param_(\d+)|[a-z]Var\d+) \+ (0x[0-9a-f]+|\d+)\)')
ACC0 = re.compile(r'\*\((uint|byte|char|ushort|short|float|double|int) \*\)(param_(\d+))\b(?! \+)')
CALL = re.compile(r'(FUN_[0-9a-f]{8})\(([^;]*)\);')
SZ = {'uint': 4, 'int': 4, 'float': 4, 'byte': 1, 'char': 1, 'ushort': 2, 'short': 2, 'double': 8}
par = {}
def find(x):
    par.setdefault(x, x)
    while par[x] != x: par[x] = par[par[x]]; x = par[x]
    return x
def union(a, b): par[find(a)] = find(b)
fields = collections.defaultdict(lambda: collections.defaultdict(set))   # node -> off -> {types}
nuse = collections.Counter()
for f in funcs:
    m = re.match(r'([0-9a-f]{8})', f)
    a = m.group(1)
    body = f
    for t, v, pn, off in ACC.findall(body):
        if pn:
            n = (a, int(pn)); o = int(off, 0); fields[n][o].add(t); nuse[n] += 1
    for t, v, pn in ACC0.findall(body):
        n = (a, int(pn)); fields[n][0].add(t); nuse[n] += 1
    for callee, args in CALL.findall(body):
        for j, arg in enumerate([x.strip() for x in args.split(',')]):
            mm = re.fullmatch(r'param_(\d+)', arg)
            if mm and (a, int(mm.group(1))) in fields:
                union((a, int(mm.group(1))), (callee[4:], j + 1))
# merge
classes = collections.defaultdict(lambda: {'nodes': set(), 'fields': collections.defaultdict(set)})
for n in list(fields):
    r = find(n); c = classes[r]; c['nodes'].add(n)
    for o, ts in fields[n].items(): c['fields'][o] |= ts
for n in list(par):
    r = find(n)
    if r in classes: classes[r]['nodes'].add(n)
ranked = sorted(classes.values(), key=lambda c: (-len(c['fields']), -len(c['nodes'])))
rows = []; L = ['# Structure candidates (neutral names; derived from [param+offset] accesses merged along call edges)', '',
 'Offsets/types are *observed accesses only*. Size is a lower bound (max observed end). Nothing here is a claim about the original C++ class.', '']
k = 0
for c in ranked:
    if len(c['fields']) < 3 and len(c['nodes']) < 3: continue
    k += 1
    name = 'STRUCT_%03d' % k
    sz = max(o + max(SZ[t] for t in ts) for o, ts in c['fields'].items())
    fl = sorted(c['fields'].items())
    L.append('## %s  (>= %#x bytes, %d observed fields, %d function-parameter nodes)' % (name, sz, len(fl), len(c['nodes'])))
    L.append('users: ' + ', '.join('FUN_%s.param_%d' % n for n in sorted(c['nodes'])[:8]) + (' ...' if len(c['nodes']) > 8 else ''))
    for o, ts in fl[:60]: L.append('  +%#05x  %s' % (o, '/'.join(sorted(ts))))
    if len(fl) > 60: L.append('  ... %d more' % (len(fl) - 60))
    L.append('')
    for o, ts in fl: rows.append([name, '%#x' % o, '/'.join(sorted(ts)), len(c['nodes'])])
    if k >= 400: break
open(os.path.join(V4, 'structures.txt'), 'w').write('\n'.join(L) + '\n')
with open(os.path.join(V4, 'structures.csv'), 'w', newline='') as fh:
    w = csv.writer(fh); w.writerow(['struct', 'offset', 'types', 'n_param_nodes']); w.writerows(rows)
print('struct candidates', k, 'fields', len(rows))
