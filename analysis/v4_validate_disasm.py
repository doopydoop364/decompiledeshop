#!/usr/bin/env python3
"""Cross-check Capstone decoding of every discovered instruction against GNU objdump (arm-none-eabi-objdump).
Compares instruction mnemonic family and (for branches) targets.  Writes analysis/v4/disasm_crosscheck.txt"""
import sys, os, subprocess, re, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_disasm import *
m, d, funcs, entries = load_db()
text = m.code[:m.text[1]]
open('/tmp/v4_text.bin', 'wb').write(text)
def objdump(thumb):
    cmd = ['arm-none-eabi-objdump', '-D', '-b', 'binary', '-marm', '--adjust-vma=0x100000', '-M', 'force-thumb' if thumb else 'no-force-thumb', '/tmp/v4_text.bin']
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    r = {}
    for l in out.splitlines():
        mt = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s{2,}(\S+)\s*(.*)', l)
        if mt: r[int(mt.group(1), 16)] = (mt.group(3), mt.group(4))
    return r
od = {False: objdump(False), True: objdump(True)}
norm = lambda s: re.sub(r'[^a-z0-9]', '', s.lower().split('.')[0])
tot = ok = 0; bad = collections.Counter(); ex = {}
bt = bb = 0
for e, f in funcs.items():
    for a, i in f.insns.items():
        o = od[i.thumb].get(a)
        tot += 1
        if o is None: bad['missing'] += 1; continue
        c = norm(i.mn); g = norm(o[0])
        if c == g or c.startswith(g) or g.startswith(c): ok += 1
        else:
            k = (i.mn.split('.')[0], o[0].split('.')[0]); bad[k] += 1; ex.setdefault(k, (a, i.mn, i.ops, o))
        if i.kind in ('b', 'bcond') or (i.kind == 'call' and i.call):
            bt += 1
            mt = re.search(r'(?:0x)?([0-9a-f]+)\s*(?:<|$)', o[1]) if o else None
            tgt = i.targets[0] if i.targets else (i.call & ~1 if i.call else None)
            if mt and int(mt.group(1), 16) == tgt: bb += 1
L = ['instructions checked: %d  mnemonic-compatible: %d (%.3f%%)' % (tot, ok, 100.0 * ok / tot), 'branch/call targets checked: %d matching: %d' % (bt, bb), '', 'top mismatches (capstone, objdump) count example:']
for k, c in bad.most_common(40): L.append('%s %d %s' % (k, c, ex.get(k)))
open(os.path.join(V4, 'disasm_crosscheck.txt'), 'w').write('\n'.join(L) + '\n')
print('\n'.join(L[:30]))
