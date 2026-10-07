#!/usr/bin/env python3
"""V4 pass 2/3/7: per-function CFG construction on lifted IR, liveness/signature inference,
web (live-range) renaming and expression propagation."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collections import defaultdict
from v4_ir import *

ARGREGS = ['r0', 'r1', 'r2', 'r3']
CLOBBER = ['r0', 'r1', 'r2', 'r3', 'r12', 'lr']
FREGS = ['s%d' % i for i in range(32)] + ['d%d' % i for i in range(16)]
# d-regs alias s-regs: treat a write to dN as clobbering s(2N),s(2N+1) and vice versa for liveness bookkeeping
ALIAS = {}
for _n in range(16):
    ALIAS['d%d' % _n] = ['s%d' % (2 * _n), 's%d' % (2 * _n + 1)]
    ALIAS['s%d' % (2 * _n)] = ['d%d' % _n]
    ALIAS['s%d' % (2 * _n + 1)] = ['d%d' % _n]

class Sig:
    __slots__ = ('nparams', 'ret', 'ret2', 'noret', 'stack_args', 'ret_defined', 'callers_used_r0', 'callers_used_r1', 'fp_args', 'fp_ret')
    def __init__(self):
        self.nparams = 0; self.ret = False; self.ret2 = False; self.noret = False; self.stack_args = 0
        self.ret_defined = False; self.callers_used_r0 = False; self.callers_used_r1 = False; self.fp_args = 0; self.fp_ret = False

def expr_vars(e, out):
    t = e[0]
    if t == 'v': out.append(e[1])
    elif t == 'bin': expr_vars(e[2], out); expr_vars(e[3], out)
    elif t == 'un': expr_vars(e[2], out)
    elif t == 'ld': expr_vars(e[3], out)
    elif t == 'cmp': expr_vars(e[2], out); expr_vars(e[3], out)
    elif t == 'tern': expr_vars(e[1], out); expr_vars(e[2], out); expr_vars(e[3], out)
    elif t == 'flag': expr_vars(e[3], out); expr_vars(e[4], out)
    return out

def expr_has_ld(e):
    t = e[0]
    if t == 'ld': return True
    if t == 'bin': return expr_has_ld(e[2]) or expr_has_ld(e[3])
    if t == 'un': return expr_has_ld(e[2])
    if t in ('cmp',): return expr_has_ld(e[2]) or expr_has_ld(e[3])
    if t == 'tern': return expr_has_ld(e[1]) or expr_has_ld(e[2]) or expr_has_ld(e[3])
    return False

def expr_subst(e, name, rep):
    t = e[0]
    if t == 'v': return rep if e[1] == name else e
    if t == 'bin': return B(e[1], expr_subst(e[2], name, rep), expr_subst(e[3], name, rep)) if e[1] in ('+', '-', '&', '|', '^', '<<', '>>', 'sar', '*') else ('bin', e[1], expr_subst(e[2], name, rep), expr_subst(e[3], name, rep))
    if t == 'un': return U(e[1], expr_subst(e[2], name, rep)) if e[1] in ('~', 'neg') else ('un', e[1], expr_subst(e[2], name, rep))
    if t == 'ld': return ('ld', e[1], e[2], expr_subst(e[3], name, rep))
    if t == 'cmp': return ('cmp', e[1], expr_subst(e[2], name, rep), expr_subst(e[3], name, rep))
    if t == 'tern': return ('tern', expr_subst(e[1], name, rep), expr_subst(e[2], name, rep), expr_subst(e[3], name, rep))
    if t == 'flag': return ('flag', e[1], e[2], expr_subst(e[3], name, rep), expr_subst(e[4], name, rep))
    return e

class Block:
    __slots__ = ('id', 'addrs', 'stmts', 'term', 'succs', 'preds', 'entry_spd', 'entry_fl', 'out_fl', 'out_spd')
    def __init__(self, bid):
        self.id = bid; self.addrs = []; self.stmts = []; self.term = None; self.succs = []; self.preds = []
        self.entry_spd = None; self.entry_fl = None; self.out_fl = None; self.out_spd = None

class FuncIR:
    def __init__(self, f, lifter):
        self.f = f; self.entry = f.entry; self.blocks = {}; self.order = []; self.lifter = lifter
        self.stack_arg_max = -1
        self.build()

    # ---------- CFG ----------
    def build(self):
        f = self.f; ins = f.insns
        leaders = {f.entry}
        for a, i in ins.items():
            if i.kind in ('b', 'bcond'):
                for t in i.targets:
                    if t in ins: leaders.add(t)
                nxt = a + i.size
                if nxt in ins: leaders.add(nxt)
            elif i.kind in ('ret', 'bx', 'switch') or (i.kind == 'call' and False):
                nxt = a + i.size
                if nxt in ins: leaders.add(nxt)
            if a in f.switches and f.switches[a]:
                for t in f.switches[a]:
                    if t in ins: leaders.add(t)
        for a, tg in f.switches.items():
            pass
        # a block also starts after a predicated return/ tail
        sorted_addrs = sorted(ins)
        blocks = {}
        cur = None
        for a in sorted_addrs:
            i = ins[a]
            if a in leaders or cur is None or (cur.addrs and cur.addrs[-1] + ins[cur.addrs[-1]].size != a):
                cur = Block(a); blocks[a] = cur
            cur.addrs.append(a)
            if i.kind in ('b', 'bcond', 'ret', 'bx', 'switch') :
                cur = None
        self.blocks = blocks
        # lift in BFS order carrying sp-depth and flags
        lifter = self.lifter
        entry_state = {f.entry: (0, None)}
        work = [f.entry]; seen = set()
        while work:
            bid = work.pop(0)
            if bid in seen or bid not in blocks: continue
            seen.add(bid)
            b = blocks[bid]
            spd, fl = entry_state.get(bid, (None, None))
            b.entry_spd, b.entry_fl = spd, fl
            for a in b.addrs:
                i = ins[a]
                st, spd, fl = lifter.lift(i, spd, fl)
                b.stmts.extend((s, a) for s in st)
            b.out_fl, b.out_spd = fl, spd
            self.make_term(b)
            for s in b.succs:
                if s in blocks and s not in entry_state:
                    entry_state[s] = (b.out_spd, b.out_fl)
                if s in blocks and s not in seen: work.append(s)
                elif s in blocks and entry_state[s][1] != b.out_fl and False: pass
        # unreachable (by BFS) blocks: lift with unknown state
        for bid, b in blocks.items():
            if bid in seen: continue
            spd, fl = None, None
            for a in b.addrs:
                st, spd, fl = lifter.lift(ins[a], spd, fl)
                b.stmts.extend((s, a) for s in st)
            b.out_fl, b.out_spd = fl, spd
            self.make_term(b)
        # synthetic blocks for conditional returns / tails
        for b in list(self.blocks.values()):
            for s in b.succs:
                if s < 0 and s not in self.blocks:
                    nb = Block(s); nb.term = self._synth[s]; self.blocks[s] = nb
        for b in self.blocks.values():
            for s in b.succs:
                if s in self.blocks: self.blocks[s].preds.append(b.id)
        # reachable order (RPO)
        order = []; vis = set()
        def dfs(x):
            stack = [(x, iter(self.blocks[x].succs))]
            vis.add(x)
            while stack:
                n, it = stack[-1]
                for s in it:
                    if s in self.blocks and s not in vis:
                        vis.add(s); stack.append((s, iter(self.blocks[s].succs))); break
                else:
                    order.append(n); stack.pop()
        dfs(f.entry)
        self.order = order[::-1]
        for bid in list(self.blocks):
            if bid not in vis and bid >= 0: pass          # unreachable blocks stay in self.blocks, not in order

    _synth = {}
    def make_term(self, b):
        f = self.f; ins = f.insns; lifter = self.lifter
        last = ins[b.addrs[-1]]; a = last.addr
        ls = lifter
        nxt = a + last.size
        fl = b.out_fl
        synth = self._synth
        # flags just before the last instruction are needed for the condition: recompute by cond built from state before it
        fl_before = self._flags_before(b)
        def cond_for(ins_):
            cs_i = ls.cs_insn(ins_)
            cc = CC.get(cs_i.cc, 'al') if cs_i else 'al'
            if cc == 'al': return None
            c = ls.cond(cc, fl_before)
            return c if c is not None else ('cc', cc)
        k = last.kind
        if k == 'b':
            t = last.targets[0]
            if a in f.tail or t not in ins: b.term = ('tail', C(t), a); b.succs = []
            else: b.term = ('jmp', t); b.succs = [t]
        elif k == 'bcond':
            t = last.targets[0]; c = cond_for(last)
            if c is None: c = ('cc', 'al')
            if a in f.tail or t not in ins:
                sid = -(a | 1)
                synth[sid] = ('tail', C(t), a)
                b.term = ('br', c, sid, nxt); b.succs = [sid, nxt]
            else:
                b.term = ('br', c, t, nxt); b.succs = [t, nxt]
        elif k == 'ret':
            c = cond_for(last)
            if c is None: b.term = ('ret',); b.succs = []
            else:
                sid = -(a | 1); synth[sid] = ('ret',)
                b.term = ('br', c, sid, nxt); b.succs = [sid, nxt]
        elif k == 'bx':
            cs_i = ls.cs_insn(last)
            reg = ls.regexpr(cs_i, cs_i.operands[0].reg, last, b.out_spd) if cs_i and cs_i.operands else V('?')
            if a in f.tail: b.term = ('tail', C(f.tail[a]), a); b.succs = []
            else:
                c = cond_for(last)
                if c is None: b.term = ('itail', reg, a); b.succs = []
                else:
                    sid = -(a | 1); synth[sid] = ('itail', reg, a)
                    b.term = ('br', c, sid, nxt); b.succs = [sid, nxt]
        elif k == 'switch':
            tg = f.switches.get(a)
            cs_i = ls.cs_insn(last)
            if tg:
                idx = V('?')
                if cs_i:
                    for o in cs_i.operands:
                        if o.type == A.ARM_OP_MEM and o.mem.index: idx = ls.regexpr(cs_i, o.mem.index, last, b.out_spd)
                        elif o.type == A.ARM_OP_REG and o.reg not in (A.ARM_REG_PC,) and cs_i.mnemonic.startswith('add'): idx = ls.regexpr(cs_i, o.reg, last, b.out_spd)
                tg = [t for t in tg]
                targets = [t for t in tg]
                b.term = ('switch', idx, targets[0], targets[1:], a)
                b.succs = list(dict.fromkeys(t for t in targets if t in ins))
            else:
                b.term = ('ibr', '%s %s' % (cs_i.mnemonic, cs_i.op_str) if cs_i else '?', a); b.succs = []
        else:
            if nxt in ins and last.fall:
                b.term = ('jmp', nxt); b.succs = [nxt]
            elif last.fall:
                b.term = ('ibr', 'fall-through out of function at %#x' % nxt, a); b.succs = []
            else:
                b.term = ('ibr', 'terminator', a); b.succs = []

    def _flags_before(self, b):
        """flags state before the last instruction of block b"""
        spd, fl = b.entry_spd, b.entry_fl
        for a in b.addrs[:-1]:
            _, spd, fl = self.lifter.lift(self.f.insns[a], spd, fl)
        return fl

# ---------- statement def/use ----------
def stmt_uses(s, sigs, ctx=None):
    t = s[0]
    if t == 'set': return expr_vars(s[2], [])
    if t == 'st': return expr_vars(s[2], expr_vars(s[3], []))
    if t == 'call':
        u = expr_vars(s[1], []) if s[1][0] != 'c' else []
        n = call_nparams(s, sigs, ctx)
        return u + ARGREGS[:n]
    if t == 'svc': return ARGREGS[:4]
    if t == 'asm': return list(s[3])
    if t == 'pred':
        u = expr_vars(s[1], []) + stmt_uses(s[2], sigs, ctx)
        for d in stmt_defs(s[2], sigs, ctx): u.append(d)           # conditional def keeps old value
        return u
    return []

def stmt_defs(s, sigs, ctx=None):
    t = s[0]
    if t == 'set': return [s[1]]
    if t == 'call':
        return list(CLOBBER) + ['s%d' % i for i in range(16)] + ['d%d' % i for i in range(8)]
    if t == 'svc': return ['r0', 'r1', 'r2', 'r3']
    if t == 'asm': return list(s[2])
    if t == 'pred': return stmt_defs(s[2], sigs, ctx)
    return []

def call_nparams(s, sigs, ctx):
    tgt = s[1]
    if tgt[0] == 'c':
        sg = sigs.get(tgt[1])
        return sg.nparams if sg else 4
    return (ctx or {}).get(s[2], 1)

def term_uses(t, sigs, ctx, sig):
    k = t[0]
    if k == 'br': return expr_vars(t[1], [])
    if k == 'switch': return expr_vars(t[1], [])
    if k == 'ret':
        u = []
        if sig and sig.ret: u.append('r0')
        if sig and sig.ret2: u.append('r1')
        return u
    if k == 'tail':
        sg = sigs.get(t[1][1]) if t[1][0] == 'c' else None
        return ARGREGS[:(sg.nparams if sg else 4)]
    if k == 'itail': return expr_vars(t[1], []) + ARGREGS[:1]
    return []
