#!/usr/bin/env python3
"""V4 pass 1/2: independent ARM disassembly + function discovery + CFG.
Recursive descent over code_decompressed.bin using Capstone, seeded by the
entry point, BL/BLX targets, prologues and code pointers found in RODATA/DATA.
Writes analysis/v4/db.pkl (consumed by later passes)."""
import sys, os, struct, pickle, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import *
import capstone
from capstone import arm_const as A

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cs.detail = True
cs_t = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
cs_t.detail = True

def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v

class Insn:
    __slots__ = ('addr','word','kind','targets','fall','pool','call','mn','ops','cond','size','thumb')
    # kind: 'seq','b','bcond','call','ret','bx','switch','undef','pc_write','svc'

class Disasm:
    def __init__(self, m):
        self.m = m
        self.tstart, self.tsize = m.text
        self.tend = self.tstart + self.tsize
        self.cache = {}

    def in_text(self, a):
        return self.tstart <= a < self.tend

    def decode(self, a, thumb=False):
        k = (a, thumb)
        if k in self.cache: return self.cache[k]
        r = self._decode_thumb(a) if thumb else self._decode(a)
        self.cache[k] = r
        return r

    def _decode_thumb(self, a):
        m = self.m
        o = a - self.tstart
        if o < 0 or o + 2 > self.tsize or a & 1: return None
        h = struct.unpack_from('<H', m.code, o)[0]
        i = Insn(); i.addr = a; i.targets = []; i.fall = True; i.pool = None; i.call = None
        i.cond = 0xE; i.kind = 'seq'; i.size = 2; i.thumb = True
        if (h & 0xF800) in (0xF000, 0xF800) and (h & 0xF800) == 0xF000 or (h & 0xF800) == 0xF000:
            if o + 4 > self.tsize: return None
            h2 = struct.unpack_from('<H', m.code, o + 2)[0]
            i.size = 4; i.word = (h << 16) | h2
            if (h2 & 0xD000) == 0xD000 or (h2 & 0xF800) in (0xF800, 0xE800):
                off = sext(((h & 0x7FF) << 12) | ((h2 & 0x7FF) << 1), 23)
                t = a + 4 + off
                if (h2 & 0xF800) == 0xE800:          # BLX imm -> ARM
                    i.call = (t & ~3) & 0xFFFFFFFF; i.mn = 'blx'
                else:
                    i.call = (t & 0xFFFFFFFF) | 1; i.mn = 'bl'
                i.kind = 'call'; i.ops = '%#x' % (i.call & ~1)
                return i
            i.kind = 'undef'; i.fall = False; i.mn = '.hword'; i.ops = '%#x' % h
            return i
        i.word = h
        ins = next(cs_t.disasm(m.code[o:o+2], a, 1), None)
        if ins is None or h == 0:
            i.kind = 'undef'; i.fall = False; i.mn = '.hword'; i.ops = '%#x' % h; return i
        i.mn = ins.mnemonic; i.ops = ins.op_str
        if (h & 0xF800) == 0xE000:
            i.kind = 'b'; i.fall = False; i.targets = [(a + 4 + (sext(h & 0x7FF, 11) << 1)) & 0xFFFFFFFF]
        elif (h & 0xF000) == 0xD000 and (h & 0x0F00) < 0x0E00:
            i.kind = 'bcond'; i.cond = (h >> 8) & 0xF; i.targets = [(a + 4 + (sext(h & 0xFF, 8) << 1)) & 0xFFFFFFFF]
        elif (h & 0xFF00) == 0xDF00:
            pass
        elif (h & 0xFF00) == 0xDE00:
            i.kind = 'undef'; i.fall = False
        elif (h & 0xFF87) == 0x4700:
            rm = (h >> 3) & 0xF
            i.kind = 'ret' if rm == 14 else 'bx'; i.fall = False
        elif (h & 0xFF87) == 0x4780:
            i.kind = 'call'; i.call = None
        elif (h & 0xFF00) == 0xBD00:
            i.kind = 'ret'; i.fall = False
        elif (h & 0xFF87) in (0x4687, 0x4487):
            i.kind = 'switch'; i.fall = False
        elif (h & 0xF800) == 0x4800:
            i.pool = ((a + 4) & ~3) + ((h & 0xFF) << 2)
        return i

    def _decode(self, a):
        m = self.m
        o = a - self.tstart
        if o < 0 or o + 4 > self.tsize or a & 3:
            return None
        raw = m.code[o:o+4]
        w = struct.unpack('<I', raw)[0]
        ins = next(cs.disasm(raw, a, 1), None)
        i = Insn()
        i.addr = a; i.word = w; i.targets = []; i.fall = True; i.pool = None; i.call = None
        i.size = 4; i.thumb = False
        i.cond = w >> 28
        if ins is None or w == 0:
            i.kind = 'undef'; i.fall = False; i.mn = '.word'; i.ops = '%#x' % w
            return i
        i.mn = ins.mnemonic; i.ops = ins.op_str
        i.kind = 'seq'
        alw = (i.cond == 0xE)
        top = (w >> 25) & 7
        if i.cond == 0xF:
            if (w & 0xFE000000) == 0xFA000000:       # BLX imm -> Thumb target
                tgt = a + 8 + (sext(w & 0xFFFFFF, 24) << 2) + (((w >> 24) & 1) << 1)
                i.kind = 'call'; i.call = tgt | 1
                return i
            return i
        if top == 5:                                    # B / BL
            tgt = (a + 8 + (sext(w & 0xFFFFFF, 24) << 2)) & 0xFFFFFFFF
            if w & (1 << 24):
                i.kind = 'call'; i.call = tgt
            else:
                i.targets = [tgt]
                if alw: i.kind = 'b'; i.fall = False
                else: i.kind = 'bcond'
            return i
        if (w & 0x0FFFFFF0) == 0x012FFF10:             # BX Rm
            rm = w & 0xF
            i.kind = 'ret' if rm == 14 else 'bx'
            i.fall = not alw
            return i
        if (w & 0x0FFFFFF0) == 0x012FFF30:             # BLX Rm
            i.kind = 'call'; i.call = None
            return i
        # PC writers
        try:
            _, wr = ins.regs_access()
        except Exception:
            wr = []
        if A.ARM_REG_PC in wr and ins.id not in (A.ARM_INS_BL, A.ARM_INS_BLX):
            if ins.id in (A.ARM_INS_POP, A.ARM_INS_LDM, A.ARM_INS_LDMDA, A.ARM_INS_LDMDB, A.ARM_INS_LDMIB):
                i.kind = 'ret'
            elif ins.id == A.ARM_INS_LDR and ins.operands and ins.operands[1].mem.base == A.ARM_REG_SP:
                i.kind = 'ret'
            elif ins.id == A.ARM_INS_MOV and ins.operands[1].type == A.ARM_OP_REG and ins.operands[1].reg == A.ARM_REG_LR:
                i.kind = 'ret'
            elif ins.id in (A.ARM_INS_ADD, A.ARM_INS_LDR, A.ARM_INS_MOV):
                i.kind = 'switch'                       # add pc / ldr pc,[pc,..] / ldr pc,[rX] / mov pc,rX
            else:
                i.kind = 'undef'; i.fall = False; return i   # data decoded as a PC write
            i.fall = not alw
            return i
        if i.mn.startswith('ldr') and ' pc,' in (' ' + i.ops) and False:
            pass
        # PC-relative literal load
        if ins.id in (A.ARM_INS_LDR,) and len(ins.operands) == 2 and ins.operands[1].type == A.ARM_OP_MEM:
            mem = ins.operands[1].mem
            if mem.base == A.ARM_REG_PC and mem.index == 0:
                i.pool = (a + 8 + mem.disp) & 0xFFFFFFFF
        elif ins.id in (A.ARM_INS_ADR,):
            pass
        return i

def ro_code_pointers(m, d):
    """Words in RODATA/DATA that look like pointers into TEXT."""
    out = {}
    for n, a, s, o in m.segs()[1:]:
        for k in range(0, s - 3, 4):
            v = struct.unpack_from('<I', m.code, o + k)[0]
            if d.in_text(v & ~1) and not (v & 2):
                out[a + k] = v
    return out

def looks_like_entry(d, t, thumb):
    o = t - d.tstart
    if o < 0 or o + 4 > d.tsize: return False
    if thumb:
        return (struct.unpack_from('<H', d.m.code, o)[0] & 0xFF00) == 0xB500
    w = struct.unpack_from('<I', d.m.code, o)[0]
    return (w & 0xFFFF4000) == 0xE92D4000 or w == 0xE52DE004

class Func:
    def __init__(self, entry, thumb=False):
        self.entry = entry; self.thumb = thumb; self.insns = {}; self.pools = set(); self.calls = {}   # call site -> target (|1 = thumb; None = indirect)
        self.tail = {}; self.tailthumb = set(); self.switches = {}; self.bad = []; self.rets = []; self.edges = {}
        self.xfall = []
    @property
    def end(self):
        e = self.entry + 2
        if self.insns: e = max(e, max(a + i.size for a, i in self.insns.items()))
        if self.pools: e = max(e, max(self.pools) + 4)
        return e
    def covered(self):
        out = []
        for a, i in self.insns.items(): out.append((a, i.size))
        for a in self.pools: out.append((a, 4))
        return out

def trace(d, entry, stops, thumb=False, roots=()):
    f = Func(entry, thumb)
    work = [(entry, thumb)] + [(r, thumb) for r in roots]
    while work:
        a, th = work.pop()
        while True:
            if a in f.insns or a in f.pools: break
            if a != entry and a in stops:
                f.xfall.append(a); break
            i = d.decode(a, th)
            if i is None or i.kind == 'undef':
                f.bad.append(a); break
            if i.pool is not None and d.in_text(i.pool):
                f.pools.add(i.pool)
                if i.pool in f.insns: f.bad.append(i.pool)
            f.insns[a] = i
            if i.kind == 'call':
                f.calls[a] = i.call
            elif i.kind in ('b', 'bcond'):
                t = i.targets[0]
                if (t in stops and t != entry) or (t not in f.insns and t != entry and looks_like_entry(d, t, th)):
                    f.tail[a] = t
                elif d.in_text(t):
                    f.edges.setdefault(a, []).append(t); work.append((t, th))
                else:
                    f.bad.append(a)
            elif i.kind == 'ret':
                f.rets.append(a)
            elif i.kind == 'bx':
                pj = d.decode(a - 4, th) if not th else None
                rm = i.ops.strip()
                if pj is not None and pj.mn == 'add' and pj.ops.replace(' ', '') == '%s,pc,#1' % rm:
                    f.tail[a] = a + 4; f.tailthumb.add(a)       # ARM->Thumb veneer: jumps to the Thumb code that follows
                else:
                    f.switches[a] = None
            elif i.kind == 'switch' and not th:
                tg = []
                is_ldr = i.mn.startswith('ldr')
                if is_ldr and not i.ops.replace(' ', '').startswith('pc,[pc,'):
                    f.switches[a] = None                 # ldr pc,[rX,..]: indirect jump through memory
                elif not is_ldr and not i.ops.replace(' ', '').startswith('pc,pc,'):
                    f.switches[a] = None                 # mov pc,rX / add pc,rX,..
                elif is_ldr:                             # word table at a+8, default `b` at a+4
                    n = None
                    pj = d.decode(a - 4)
                    if pj is not None and pj.mn == 'cmp' and '#' in pj.ops:
                        try: n = int(pj.ops.split('#')[-1], 0) + 1
                        except ValueError: n = None
                    dj = d.decode(a + 4)
                    if dj is not None and dj.kind == 'b':
                        f.insns[a + 4] = dj; tg.append(dj.targets[0])
                    b = a + 8
                    while n is None or len(tg) - 1 < n:
                        v = d.m.u32(b) if d.in_text(b) else None
                        if v is not None and d.in_text(v) and not v & 3 and len(tg) < 1025 and (n is not None or abs(v - a) < 0x4000):
                            tg.append(v); f.pools.add(b); b += 4
                        else: break
                    f.switches[a] = tg
                    for t in tg:
                        if t in stops: f.tail[a] = t
                        else: work.append((t, False))
                else:                                    # branch table (add pc,pc,rX,lsl #2): entry0 = default
                    b = a + 4
                    while True:
                        j = d.decode(b)
                        if j is not None and j.kind == 'b' and j.cond == 0xE: tg.append(j.targets[0]); b += 4
                        else: break
                        if len(tg) > 1024: break
                    for k in range(a + 4, b, 4): f.insns[k] = d.decode(k)
                    for t in tg:
                        if t in stops: f.tail[a] = t
                        elif d.in_text(t): work.append((t, False))
                    f.switches[a] = tg
                break
            elif i.kind == 'switch':
                f.switches[a] = None
            if not i.fall: break
            a += i.size
    return f

def build_cov(d, funcs):
    cov = bytearray(d.tsize)
    for f in funcs.values():
        for a, sz in f.covered(): cov[a - d.tstart:a - d.tstart + sz] = b'\1' * sz
    return cov

def gaps_of_cov(d, cov):
    out = []; i = 0
    n = len(cov)
    while i < n:
        if cov[i] == 0:
            j = i
            while j < n and cov[j] == 0: j += 1
            out.append((i + d.tstart, j - i)); i = j
        else: i += 1
    return out

class Discovery:
    """Incremental function discovery.
    Phase 1: strong closure (entry + BL/BLX targets + tail-call targets).
    Phase 2: gap candidates (code pointers from RODATA/DATA, prologues, gap starts) accepted only if the trace
             decodes cleanly, terminates, and does not overlap existing coverage."""
    def __init__(self, m, verbose=True):
        self.m = m; self.d = Disasm(m); self.verbose = verbose
        self.entries = {self.d.tstart: False}; self.why = {self.d.tstart: 'entry'}
        self.funcs = {}; self.rejected = {}; self.roots = {}
        self.ptrs = ro_code_pointers(m, self.d)

    def log(self, *a):
        if self.verbose: print(*a, file=sys.stderr, flush=True)

    def closure(self):
        d = self.d
        while True:
            new = False
            for e in sorted(self.entries):
                if e not in self.funcs: self.funcs[e] = trace(d, e, self.entries, self.entries[e], self.roots.get(e, ())); new = True
            for f in list(self.funcs.values()):
                for site, t in f.calls.items():
                    if t is None: continue
                    ta = t & ~1
                    if d.in_text(ta) and ta not in self.entries and ta not in self.rejected:
                        self.entries[ta] = bool(t & 1); self.why[ta] = 'call'; new = True
            for f in list(self.funcs.values()):
                for site, t in f.tail.items():
                    if d.in_text(t) and t not in self.entries and t not in self.rejected:
                        self.entries[t] = f.thumb or site in f.tailthumb; self.why[t] = 'tail'; new = True
            if new: continue
            changed = False
            for e in sorted(self.entries):
                nf = trace(d, e, self.entries, self.entries[e], self.roots.get(e, ()))
                if set(nf.insns) != set(self.funcs[e].insns) or nf.pools != self.funcs[e].pools: changed = True
                self.funcs[e] = nf
            if not changed: break

    def accept_ok(self, f, cov, th):
        if not f.insns or f.bad: return False
        if not (f.rets or f.tail or f.switches or any(i.kind == 'b' for i in f.insns.values())): return False
        if len(f.insns) < (3 if th else 2): return False
        for x in f.insns:
            if cov[x - self.d.tstart]: return False
        return True                      # overlap on literal-pool words only is allowed (pools are shared)

    WEAK = ('ptr', 'gapstart', 'prologue')
    def supersede(self, f, cov, owner):
        """A candidate overlapping weakly-discovered functions (entries that are labels inside it, or that mostly lie
        inside it) absorbs them: their entries become extra roots of the candidate."""
        d = self.d
        if not f.insns or f.bad: return None
        if not (f.rets or f.tail or f.switches or any(i.kind == 'b' for i in f.insns.values())): return None
        counts = {}
        for x in f.insns:
            if cov[x - d.tstart]:
                o = owner.get(x)
                if o is None: return None
                counts[o] = counts.get(o, 0) + 1
        for o, n in counts.items():
            g = self.funcs.get(o)
            if g is None or self.why.get(o) not in self.WEAK: return None
            if not (o in f.insns or n >= 0.5 * max(1, len(g.insns))): return None
        roots = [o for o in counts if o not in f.insns]
        saved = {o: (self.funcs.pop(o), self.entries.pop(o), self.why.pop(o)) for o in counts}
        stops = set(self.entries)
        f2 = trace(d, f.entry, stops, f.thumb, roots)
        ok = not f2.bad
        if ok:
            for x in f2.insns:
                if cov[x - d.tstart] and owner.get(x) not in counts: ok = False; break
        if not ok:
            for o, (g, th, w) in saved.items(): self.funcs[o] = g; self.entries[o] = th; self.why[o] = w
            return None
        for o in counts:
            self.rejected[o] = 'superseded'
            for x, sz in saved[o][0].covered(): cov[x - d.tstart:x - d.tstart + sz] = bytes(sz); owner.pop(x, None)
        self.roots[f.entry] = roots
        return f2

    def gap_round(self):
        d = self.d
        self.rejected = {k: v for k, v in self.rejected.items() if v == 'superseded'}
        cov = build_cov(d, self.funcs)
        cands = []                                           # (addr, thumb, why)
        for pa, v in self.ptrs.items():
            cands.append((v & ~1, bool(v & 1), 'ptr'))
        gaps = gaps_of_cov(d, cov)
        for ga, gs in gaps:
            if gs < 4: continue
            s0 = (ga + 3) & ~3
            cands.append((s0, False, 'gapstart'))
            for a in range(s0, ga + gs - 3, 4):
                w = struct.unpack_from('<I', d.m.code, a - d.tstart)[0]
                if (w & 0xFFFF4000) == 0xE92D4000: cands.append((a, False, 'prologue'))
            for a in range(ga + (ga & 1), ga + gs - 1, 2):
                h = struct.unpack_from('<H', d.m.code, a - d.tstart)[0]
                if (h & 0xFF00) == 0xB500:
                    st = a
                    for _ in range(3):
                        pi = d.decode(st - 2, True)
                        if st - 2 >= d.tstart and not cov[st - 2 - d.tstart] and pi is not None and pi.kind == 'seq' and pi.mn.split('.')[0] in ('push', 'mov', 'movs', 'sub', 'add') and pi.word != 0: st -= 2
                        else: break
                    cands.append((st, True, 'prologue'))
        added = 0
        seen = set()
        owner = {}
        for e, g in self.funcs.items():
            for x, sz in g.covered(): owner[x] = e
        for a, th, why in cands:
            if a in seen or a in self.entries or a in self.rejected: continue
            seen.add(a)
            if not d.in_text(a) or cov[a - d.tstart]: continue
            f = trace(d, a, self.entries, th)
            f2 = None
            if not self.accept_ok(f, cov, th) and why in ('prologue', 'gapstart'): f2 = self.supersede(f, cov, owner)
            if f2 is not None: f = f2
            if f2 is not None or self.accept_ok(f, cov, th):
                self.entries[a] = th; self.why[a] = why; self.funcs[a] = f; added += 1
                for x, sz in f.covered(): cov[x - d.tstart:x - d.tstart + sz] = b'\1' * sz; owner[x] = a
            else:
                self.rejected[a] = why
        return added

    def run(self):
        self.closure(); self.log('strong closure', len(self.funcs))
        for r in range(25):
            n = self.gap_round(); self.log('gap round', r, 'added', n)
            if not n: break
            self.closure(); self.log('closure', len(self.funcs))
        return self

def discover(m, verbose=True):
    r = Discovery(m, verbose).run()
    return r.d, r.funcs, r.entries, r.ptrs

def save_db(m, d, funcs, entries, path):
    db = {'entries': entries, 'funcs': {}}
    for e, f in funcs.items():
        db['funcs'][e] = {'thumb': f.thumb, 'end': f.end, 'insns': sorted((a, i.size) for a, i in f.insns.items()), 'pools': sorted(f.pools),
                          'calls': f.calls, 'tail': f.tail, 'tailthumb': sorted(f.tailthumb), 'switches': f.switches, 'bad': f.bad, 'rets': f.rets, 'xfall': f.xfall}
    pickle.dump(db, open(path, 'wb'))

if __name__ == '__main__':
    m = Map()
    _r = Discovery(m, False).run(); d, funcs, entries, ptrs = _r.d, _r.funcs, _r.entries, _r.ptrs; r_why = _r.why
    cov = sum(sz for f in funcs.values() for _, sz in f.covered())
    print('funcs', len(funcs), 'thumb', sum(1 for f in funcs.values() if f.thumb), 'covered bytes', cov, 'of', m.text[1])
    print('funcs with bad', sum(1 for f in funcs.values() if f.bad))
    save_db(m, d, funcs, entries, os.path.join(V4, 'db.pkl'))
    import pickle as _p; _p.dump(r_why, open(os.path.join(V4, 'why.pkl'), 'wb'))

def load_db(m=None):
    """Rebuild Func objects from analysis/v4/db.pkl (written by this module's main)."""
    m = m or Map(); d = Disasm(m)
    db = pickle.load(open(os.path.join(V4, 'db.pkl'), 'rb'))
    funcs = {}
    for e, r in db['funcs'].items():
        f = Func(e, r['thumb'])
        for a, sz in r['insns']: f.insns[a] = d.decode(a, r['thumb'])
        f.pools = set(r['pools']); f.calls = r['calls']; f.tail = r['tail']; f.tailthumb = set(r.get('tailthumb', [])); f.switches = r['switches']
        f.bad = r['bad']; f.rets = r['rets']; f.xfall = r['xfall']
        funcs[e] = f
    return m, d, funcs, db['entries']
