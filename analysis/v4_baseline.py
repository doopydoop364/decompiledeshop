#!/usr/bin/env python3
"""Freeze structural baseline: writes analysis/v4/baseline.json and analysis/v4/unresolved.md"""
import sys, os, json, csv, struct, hashlib, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_disasm import *
m, d, funcs, entries = load_db()
cov = build_cov(d, funcs)
gaps = gaps_of_cov(d, cov)
def classify(a, n):
    b = m.read(a, n)
    if not any(b): return 'zero_padding'
    w = [struct.unpack_from('<I', b, k)[0] for k in range(0, n - 3, 4)]
    nz = [x for x in w if x]
    ptr = sum(1 for x in nz if 0x100000 <= x < 0x500000)
    if nz and ptr * 2 >= len(nz): return 'pointer/literal table'
    if a % 4 == 0 and n % 4 == 0 and sum(1 for k in range(0, n - 3, 4) if next(cs.disasm(b[k:k+4], a + k, 1), None)) < len(w) * 0.9: return 'data (non-code words)'
    asc = sum(1 for x in b if 32 <= x < 127 or x == 0)
    if asc > 0.9 * n: return 'string/ascii data'
    return 'unclassified (possible unreferenced code/data)'
cls = collections.Counter(); clsb = collections.Counter(); unc = []
for a, n in gaps:
    c = classify(a, n); cls[c] += 1; clsb[c] += n
    if c.startswith('unclassified') and n >= 16: unc.append((a, n))
strs = list(csv.DictReader(open(os.path.join(V4, 'strings.csv'))))
sx = list(csv.DictReader(open(os.path.join(V4, 'string_xrefs.csv'))))
ndirect = nind = 0; ntail = 0
for f in funcs.values():
    for s, t in f.calls.items():
        if t is None: nind += 1
        else: ndirect += 1
    ntail += len(f.tail)
unres_sw = sum(1 for f in funcs.values() for t in f.switches.values() if t is None)
h = lambda p: hashlib.sha256(open(os.path.join(os.path.dirname(V4), '..', p), 'rb').read()).hexdigest()
B = {
 'binary_sha256': {p: h(p) for p in ('code.bin', 'code_decompressed.bin', 'extheader.bin')},
 'functions': len(funcs), 'thumb_functions': sum(1 for f in funcs.values() if f.thumb),
 'discovery_reasons': dict(collections.Counter(pickle.load(open(os.path.join(V4, 'why.pkl'), 'rb')).values())),
 'text_bytes': m.text[1], 'text_bytes_covered_by_code_or_pools': int(sum(cov)),
 'gap_regions': len(gaps), 'gap_bytes': sum(n for a, n in gaps), 'gap_classes_count': dict(cls), 'gap_classes_bytes': dict(clsb),
 'strings': len(strs), 'string_xrefs': len(sx), 'direct_calls': ndirect, 'unresolved_indirect_calls_blx_reg': nind, 'tail_branches_to_other_functions': ntail,
 'unresolved_indirect_jumps(bx/ldr pc/mov pc)': unres_sw,
 'known_structures': 0,
}
json.dump(B, open(os.path.join(V4, 'baseline.json'), 'w'), indent=1)
L = ['# Unresolved items (structural baseline)', '', 'Machine-derived; see baseline.json.', '', '## Uncovered TEXT regions', '']
for k, v in cls.items(): L.append('- %s: %d regions, %d bytes' % (k, v, clsb[k]))
L += ['', '## Largest unclassified gaps (candidate unreferenced code/data; not decompiled)', '']
for a, n in sorted(unc, key=lambda x: -x[1])[:60]: L.append('- %08x +%#x' % (a, n))
L += ['', '## Known weaknesses', '',
 '- Function entries found only by data pointers / prologue scans / gap starts (discovery column in functions.csv) are lower confidence than call-reached ones.',
 '- %d indirect calls through registers (blx rN) and %d indirect jumps (bx rN, ldr pc, mov pc, add pc with non-table form) are left as indirect.' % (nind, unres_sw),
 '- Thumb: only Thumb-1 + BL/BLX pairs are decoded; Thumb function starts that begin with non-push instructions may be missed or begin late.',
 '- Signature inference is heuristic (liveness of r0-r3 and r0/r1 consumers); stack arguments are only counted, not bound at call sites.',
 '- Flag-dependent conditions use a static last-flag-setter descriptor; overflow (V) conditions are approximated.',
 '- No type recovery: all values are `uint`/`float`/`double`; no structures are declared yet.']
open(os.path.join(V4, 'unresolved.md'), 'w').write('\n'.join(L) + '\n')
print(json.dumps(B, indent=1))
