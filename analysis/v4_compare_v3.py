#!/usr/bin/env python3
"""Compare V4 against V3 (V3 treated only as a prior, never as truth). Writes analysis/v4/v3_comparison.md"""
import csv, os, sys, hashlib, collections, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import ROOT, V4
rows = list(csv.DictReader(open(os.path.join(ROOT, 'analysis', 'eshop_function_index.tsv')), delimiter='\t'))
v3 = {int(r['address'], 16) for r in rows}
v3anch = sum(1 for r in rows if r['string_anchors'])
v4 = {int(r['address'], 16): r for r in csv.DictReader(open(os.path.join(V4, 'functions.csv')))}
starts = sorted(v4); 
def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    if i < 0: return None
    e = starts[i]; return e if a < e + int(v4[e]['size']) else None
only3 = sorted(v3 - set(v4)); only4 = sorted(set(v4) - v3)
inside = [a for a in only3 if owner(a) is not None]
names = list(csv.DictReader(open(os.path.join(V4, 'function_names.csv'))))
v3names = sum(1 for r in rows if r['name'] != r['original'])
sx = list(csv.DictReader(open(os.path.join(V4, 'string_xrefs.csv'))))
h = hashlib.sha256(open(os.path.join(ROOT, 'eshop_decompile_v3.txt'), 'rb').read()).hexdigest()
disc = collections.Counter(r['discovery'] for r in v4.values())
L = ['# V4 vs V3', '', 'V3 (Ghidra output, sha256 `%s`) is unchanged and was not used as input to V4.' % h, '',
 '| metric | V3 | V4 |', '|---|---|---|',
 '| functions | %d | %d |' % (len(v3), len(v4)),
 '| function entries in common | %d | %d |' % (len(v3 & set(v4)), len(v3 & set(v4))),
 '| entries only in this version | %d | %d |' % (len(only3), len(only4)),
 '| functions with a string anchor / literal-string xref functions | %d | %d |' % (v3anch, len({r['from_func'] for r in sx if r['from_func']})),
 '| renamed functions (V3: all confidence levels; V4: HIGH+MEDIUM, evidence per row) | %d | %d |' % (v3names, len(names)),
 '| string cross-references | n/a | %d (incl. pc-relative `add` references that literal-pool scans miss) |' % len(sx), '',
 'V3-only entries: %d, of which %d fall inside a V4 function body (V3 split what V4 keeps as one function or vice versa); the rest lie in regions V4 classifies as data/strings/unresolved.' % (len(only3), len(inside)), '',
 'V4-only entries: %d (discovery reasons across all V4 functions: %s).' % (len(only4), dict(disc)), '',
 'Concrete improvements: independent verified mapping and BLZ check; Thumb functions decoded (V3 treated most of TEXT as ARM); jump tables with word entries resolved; ARM->Thumb veneers resolved; TEXT-resident URL strings resolved (all `%s/ninja/ws/...` formats); every instruction cross-checked against objdump; per-function evidence for each name.',
 'Known V4 regressions/gaps relative to V3: V3 carries decompiler-typed signatures and locals from Ghidra; V4 has no type recovery (everything `uint`), and V4 names far fewer functions on purpose.']
open(os.path.join(V4, 'v3_comparison.md'), 'w').write('\n'.join(L) + '\n')
print('\n'.join(L))
