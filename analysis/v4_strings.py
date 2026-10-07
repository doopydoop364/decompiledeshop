#!/usr/bin/env python3
"""V4 pass 4/5: strings, literal-pool resolution and cross references.
Outputs analysis/v4/strings.csv, string_xrefs.csv, data_xrefs.csv and refs.pkl."""
import sys, os, re, csv, pickle, struct, bisect, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import *
from v4_disasm import load_db

PR = set(range(0x20, 0x7f)) | {9, 10, 13}

def find_strings(m):
    out = []
    for n, a, s, o in m.segs():
        buf = m.code[o:o + s]
        # ASCII
        minlen = 6 if n == 'TEXT' else 4
        for mt in re.finditer(rb'[\x20-\x7e\t\n\r]{%d,}' % minlen, buf):
            st, en = mt.start(), mt.end()
            term = buf[en:en + 1] == b'\0' if en < len(buf) else True
            if not term: continue
            out.append((a + st, n, 'ascii', en - st, mt.group().decode('ascii')))
        # UTF-16LE
        for mt in re.finditer(rb'(?:[\x20-\x7e\t\n\r]\x00){%d,}' % minlen, buf):
            st, en = mt.start(), mt.end()
            if buf[en:en + 2] != b'\0\0' and en + 2 <= len(buf): continue
            out.append((a + st, n, 'utf16', (en - st) // 2, mt.group().decode('utf-16le')))
    out.sort()
    return out

def main():
    m, d, funcs, entries = load_db()
    strs = find_strings(m)
    starts = [s[0] for s in strs]
    def lookup(v):
        i = bisect.bisect_right(starts, v) - 1
        if i < 0: return None
        a, seg, enc, ln, txt = strs[i]
        span = ln * (2 if enc == 'utf16' else 1) + (2 if enc == 'utf16' else 1)
        return (strs[i], v - a) if v < a + span else None
    refs = []                              # (kind, from_func, site, pool_addr, value)
    for e, f in funcs.items():
        for a, i in f.insns.items():
            if i.pool is not None and not i.thumb or (i.pool is not None and i.thumb):
                v = m.u32(i.pool)
                if v is not None: refs.append(('lit', e, a, i.pool, v))
    # data pointers in RODATA/DATA
    for n, a, s, o in m.segs()[1:]:
        for k in range(0, s - 3, 4):
            v = struct.unpack_from('<I', m.code, o + k)[0]
            if m.seg_of(v & ~1) in ('RODATA', 'DATA', 'BSS', 'TEXT') and v >= 0x100000:
                refs.append(('ptr', None, a + k, a + k, v))
    # also pools that weren't reached by ldr (adr-style) are ignored; recorded in unresolved.md
    # string xrefs
    sx = []
    for kind, fe, site, pool, v in refs:
        r = lookup(v)
        if r:
            (a, seg, enc, ln, txt), off = r
            sx.append((a, off, kind, fe, site, pool))
    # data xrefs (non-string)
    dx = collections.defaultdict(lambda: [0, set(), collections.Counter()])
    for kind, fe, site, pool, v in refs:
        sg = m.seg_of(v)
        if sg in ('DATA', 'BSS', 'RODATA') and not lookup(v):
            x = dx[v]; x[0] += 1; x[2][kind] += 1
            if fe is not None: x[1].add(fe)
    with open(os.path.join(V4, 'strings.csv'), 'w', newline='') as fh:
        w = csv.writer(fh); w.writerow(['addr', 'segment', 'file_offset', 'encoding', 'length', 'text'])
        for a, seg, enc, ln, txt in strs:
            w.writerow(['%08x' % a, seg, '%x' % m.va2off(a), enc, ln, txt.encode('unicode_escape').decode('ascii')])
    with open(os.path.join(V4, 'string_xrefs.csv'), 'w', newline='') as fh:
        w = csv.writer(fh); w.writerow(['string_addr', 'offset_in_string', 'kind', 'from_func', 'site', 'slot_addr'])
        for a, off, kind, fe, site, pool in sorted(sx):
            w.writerow(['%08x' % a, off, 'literal_pool' if kind == 'lit' else 'data_pointer', '' if fe is None else '%08x' % fe, '%08x' % site, '%08x' % pool])
    with open(os.path.join(V4, 'data_xrefs.csv'), 'w', newline='') as fh:
        w = csv.writer(fh); w.writerow(['addr', 'segment', 'refs', 'literal_refs', 'pointer_refs', 'n_funcs', 'funcs(first5)'])
        for v in sorted(dx):
            c, fs, kc = dx[v]
            w.writerow(['%08x' % v, m.seg_of(v), c, kc['lit'], kc['ptr'], len(fs), ' '.join('%08x' % x for x in sorted(fs)[:5])])
    pickle.dump({'strings': strs, 'refs': refs}, open(os.path.join(V4, 'refs.pkl'), 'wb'))
    nlit = sum(1 for r in sx if r[2] == 'lit')
    print('strings', len(strs), 'ascii', sum(1 for s in strs if s[2] == 'ascii'), 'utf16', sum(1 for s in strs if s[2] == 'utf16'))
    print('refs', len(refs), 'string xrefs', len(sx), 'via literal pool', nlit, 'via data pointer', len(sx) - nlit)
    print('strings with >=1 xref', len({r[0] for r in sx}))
main()
