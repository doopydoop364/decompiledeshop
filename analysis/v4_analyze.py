#!/usr/bin/env python3
"""V4 pass 3/7/8 analysis: interprocedural signature inference (args/return), web renaming, propagation."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_func import *

ARGSET = {'r0': 1, 'r1': 2, 'r2': 4, 'r3': 8}
ALL4 = 15

def stmt_events(fi, sigs):
    """Per block event list relevant to r0-r3 tracking (rebuilt once; call args resolved lazily)."""
    ev = {}
    for bid, b in fi.blocks.items():
        L = []
        defined_since_call = 0
        for s, a in b.stmts:
            ss = s[2] if s[0] == 'pred' else s
            cond = s[0] == 'pred'
            t = ss[0]
            if t == 'call':
                if ss[1][0] == 'c':
                    L.append(('call', ss[1][1], a, None))
                else:
                    m = defined_since_call
                    if not m & 1 and not defined_since_call: m |= 1
                    # contiguous from r0
                    n = max([i + 1 for i in range(4) if m >> i & 1] or [1])
                    uses = 0
                    for u in expr_vars(ss[1], []):
                        if u in ARGSET: uses |= ARGSET[u]
                    L.append(('icall', None, a, (1 << n) - 1, uses))
                defined_since_call = 0
                continue
            if t == 'svc':
                L.append(('svc',)); defined_since_call = 0; continue
            us = [u for u in stmt_uses(ss, {}) if u in ARGSET] if t != 'call' else []
            if cond:
                for u in expr_vars(s[1], []):
                    if u in ARGSET and u not in us: us.append(u)
            # stmt_uses without sigs is fine for non-call stmts
            if t != 'call':
                um = 0
                for u in us: um |= ARGSET[u]
                dm = 0
                for d in stmt_defs(s if not cond else s, {}):
                    if d in ARGSET: dm |= ARGSET[d]
                if t == 'set' or t == 'asm' or t == 'st' or t == 'pred':
                    if um: L.append(('use', um))
                    if dm:
                        L.append(('def', dm, dm))     # predicated defs also kill: optimistic for param inference
                        defined_since_call |= dm
        ev[bid] = L
    return ev

class SigEngine:
    def __init__(self, firs):
        self.firs = firs                 # addr -> FuncIR
        self.sigs = {a: Sig() for a in firs}
        self.events = {a: stmt_events(fi, None) for a, fi in firs.items()}
        self.term_info = {}
        self.callers = defaultdict(set)
        for a, fi in firs.items():
            for b in fi.blocks.values():
                for s, site in b.stmts:
                    ss = s[2] if s[0] == 'pred' else s
                    if ss[0] == 'call' and ss[1][0] == 'c': self.callers[ss[1][1]].add(a)
                if b.term[0] == 'tail' and b.term[1][0] == 'c': self.callers[b.term[1][1]].add(a)
        # stack-arg count
        for a, fi in firs.items():
            mx = -1
            for b in fi.blocks.values():
                for s, site in b.stmts:
                    ss = s[2] if s[0] == 'pred' else s
                    for e in ([ss[2]] if ss[0] == 'set' else []):
                        mx = max(mx, self._stk(e))
                    if ss[0] == 'st': mx = max(mx, self._stk(ss[3]), self._stk(ss[2]))
                    if ss[0] == 'call': pass
            self.sigs[a].stack_args = mx + 1 if mx >= 0 else 0

    def _stk(self, e):
        t = e[0]
        if t == 'ld':
            ad = e[3]
            if ad[0] == 'sp' and ad[1] >= 0: return ad[1] // 4
            return self._stk(ad)
        if t == 'bin': return max(self._stk(e[2]), self._stk(e[3]))
        if t == 'un': return self._stk(e[2])
        if t == 'cmp': return max(self._stk(e[2]), self._stk(e[3]))
        return -1

    def call_args_mask(self, callee):
        sg = self.sigs.get(callee)
        n = sg.nparams if sg else 4
        return (1 << n) - 1

    def solve_func(self, a, record=True):
        """backward liveness on 4 arg regs.  returns (nparams, {call_site: (r0_live_after, r1_live_after)}, ret_defined, r1_defined)."""
        fi = self.firs[a]; ev = self.events[a]; sig = self.sigs[a]
        blocks = fi.blocks
        retmask = (1 if sig.ret else 0) | (2 if sig.ret2 else 0)
        live_in = {b: 0 for b in blocks}
        order = [b for b in fi.order][::-1]
        def term_use(t):
            k = t[0]
            if k == 'ret': return retmask
            if k == 'tail':
                return self.call_args_mask(t[1][1]) if t[1][0] == 'c' else 1
            if k == 'itail': return 1
            m = 0
            if k in ('br', 'switch'):
                for u in expr_vars(t[1], []):
                    if u in ARGSET: m |= ARGSET[u]
            return m
        changed = True
        while changed:
            changed = False
            for bid in order:
                b = blocks[bid]
                out = 0
                for s in b.succs:
                    out |= live_in.get(s, 0)
                lv = out | term_use(b.term)
                for e in reversed(ev[bid]):
                    k = e[0]
                    if k == 'use': lv |= e[1]
                    elif k == 'def': lv &= ~e[1]
                    elif k == 'call': lv = (lv & ~ALL4) | self.call_args_mask(e[1])
                    elif k == 'icall': lv = (lv & ~ALL4) | e[3] | e[4]
                    elif k == 'svc': lv = (lv & ~ALL4) | ALL4
                if lv != live_in[bid]:
                    live_in[bid] = lv; changed = True
        entry_live = live_in.get(a, 0)
        npar = max([i + 1 for i in range(4) if entry_live >> i & 1] or [0])
        after = {}
        for bid in order:
            b = blocks[bid]
            out = 0
            for s in b.succs: out |= live_in.get(s, 0)
            lv = out | term_use(b.term)
            for e in reversed(ev[bid]):
                k = e[0]
                if k == 'use': lv |= e[1]
                elif k == 'def': lv &= ~e[1]
                elif k in ('call', 'icall'):
                    after[e[2]] = (bool(lv & 1), bool(lv & 2))
                    lv = (lv & ~ALL4) | (self.call_args_mask(e[1]) if k == 'call' else (e[3] | e[4]))
                elif k == 'svc': lv = (lv & ~ALL4) | ALL4
        # forward may-defined r0/r1 at ret
        dfin = {b: 0 for b in blocks}
        rd0 = rd1 = False
        for _ in range(6):
            ch = False
            for bid in fi.order:
                b = blocks[bid]
                d = dfin[bid]
                for e in ev[bid]:
                    k = e[0]
                    if k == 'def': d |= e[2] & 3
                    elif k == 'call':
                        sg = self.sigs.get(e[1]); 
                        d &= ~3
                        if sg is None or sg.ret: d |= 1
                        if sg is None or sg.ret2: d |= 2
                    elif k == 'icall': d = (d & ~3) | 1
                    elif k == 'svc': d |= 3
                if b.term[0] == 'ret': 
                    rd0 |= bool(d & 1); rd1 |= bool(d & 2)
                if b.term[0] in ('tail', 'itail'):
                    pass
                for s in b.succs:
                    if s in dfin and (dfin[s] | d) != dfin[s]: dfin[s] |= d; ch = True
            if not ch: break
        return npar, after, rd0, rd1

    def run(self, maxit=12):
        firs = self.firs
        for it in range(maxit):
            changed = 0
            used0 = defaultdict(bool); used1 = defaultdict(bool); tailret = {}
            results = {}
            for a, fi in firs.items():
                npar, after, rd0, rd1 = self.solve_func(a)
                results[a] = (npar, rd0, rd1)
                for bid, b in fi.blocks.items():
                    for s, site in b.stmts:
                        ss = s[2] if s[0] == 'pred' else s
                        if ss[0] == 'call' and ss[1][0] == 'c' and site in after:
                            u0, u1 = after[site]
                            used0[ss[1][1]] |= u0; used1[ss[1][1]] |= u1
                    if b.term[0] == 'tail' and b.term[1][0] == 'c':
                        tailret.setdefault(a, []).append(b.term[1][1])
            for a, (npar, rd0, rd1) in results.items():
                sg = self.sigs[a]
                if npar > sg.nparams: sg.nparams = npar; changed += 1
                has_callers = bool(self.callers.get(a))
                if used0[a]: sg.callers_used_r0 = True
                if used1[a]: sg.callers_used_r1 = True
                sg.ret_defined = rd0
            # returns
            for a, sg in self.sigs.items():
                rd0 = results[a][1]; rd1 = results[a][2]
                ret = False
                has_callers = bool(self.callers.get(a))
                ret = sg.callers_used_r0 if has_callers else rd0
                for g in tailret.get(a, []):
                    gs = self.sigs.get(g)
                    if gs and gs.ret: ret = ret or rd0 or True
                if ret and not sg.ret: sg.ret = True; changed += 1
                r2 = sg.callers_used_r1 and has_callers
                if r2 and not sg.ret2: sg.ret2 = True; changed += 1
            # propagate "callers use r0" through tail calls
            for a, gl in tailret.items():
                for g in gl:
                    if self.sigs[a].callers_used_r0 and g in self.sigs and not self.sigs[g].callers_used_r0:
                        self.sigs[g].callers_used_r0 = True; changed += 1
            print('sig iter', it, 'changes', changed, file=sys.stderr, flush=True)
            if not changed: break
        for sg in self.sigs.values():
            if sg.ret2: sg.ret = True
        # noreturn
        for a, fi in firs.items():
            has_ret = any(b.term[0] in ('ret', 'itail', 'ibr', 'switch') for b in fi.blocks.values())
            self.sigs[a].noret = not has_ret and not any(b.term[0] == 'tail' for b in fi.blocks.values())


# ======================================================================================
# web renaming + propagation
# ======================================================================================
def is_pure(e):
    return True      # expressions are side-effect free (calls are statements)

def rewrite_expr(e, ren):
    """rename variables in expression using ren(var)->name"""
    t = e[0]
    if t == 'v': return ('v', ren(e[1]))
    if t == 'bin': return ('bin', e[1], rewrite_expr(e[2], ren), rewrite_expr(e[3], ren))
    if t == 'un': return ('un', e[1], rewrite_expr(e[2], ren))
    if t == 'ld': return ('ld', e[1], e[2], rewrite_expr(e[3], ren))
    if t == 'cmp': return ('cmp', e[1], rewrite_expr(e[2], ren), rewrite_expr(e[3], ren))
    if t == 'tern': return ('tern', rewrite_expr(e[1], ren), rewrite_expr(e[2], ren), rewrite_expr(e[3], ren))
    if t == 'flag': return ('flag', e[1], e[2], rewrite_expr(e[3], ren), rewrite_expr(e[4], ren))
    return e

class UF:
    def __init__(self): self.p = {}
    def find(self, x):
        p = self.p
        p.setdefault(x, x)
        while p[x] != x:
            p[x] = p[p[x]]; x = p[x]
        return x
    def union(self, a, b):
        a = self.find(a); b = self.find(b)
        if a != b: self.p[b] = a

def renamed_function(fi, sg_map):
    """Return dict(blocks=..., order=..., params=n, locals=[names]) with webs renamed and propagated."""
    blocks = fi.blocks; order = fi.order
    sig = sg_map[fi.entry]
    VAL_DEF_CALL = lambda callee: sg_map.get(callee)
    # ---- step 0: expand statements into def/use records --------------------------------
    recs = {}          # bid -> list of dict(stmt, uses[var], defs[var], cond(bool))
    for bid in order:
        b = blocks[bid]; L = []
        for s, a in b.stmts:
            ss = s[2] if s[0] == 'pred' else s
            cond = s[0] == 'pred'
            t = ss[0]
            uses = []; defs = []
            if t == 'set': uses = expr_vars(ss[2], []); defs = [ss[1]]
            elif t == 'st': uses = expr_vars(ss[2], expr_vars(ss[3], []))
            elif t == 'call':
                tg = ss[1]
                if tg[0] == 'c':
                    sg = sg_map.get(tg[1]); n = sg.nparams if sg else 4
                    rv = [x for x, flag in (('r0', sg.ret if sg else True), ('r1', sg.ret2 if sg else False)) if flag]
                else:
                    n = 1
                    # indirect: args = regs defined since previous call within block (approx via events)
                    rv = ['r0']
                    # use the same heuristic as the signature engine
                    n = max(1, ss_ind_args(b, s, a))
                    uses = expr_vars(tg, [])
                uses = uses + ARGREGS[:n]
                defs = list(rv)
                ss = ('call', tg, ss[2], n, rv, ss[3] if len(ss) > 3 else False)
            elif t == 'svc':
                uses = ARGREGS[:4]; defs = ['r0', 'r1', 'r2', 'r3']
            elif t == 'asm': uses = list(ss[3]); defs = list(ss[2])
            if cond:
                uses = expr_vars(s[1], []) + uses + defs      # conditional def reads old value
            L.append({'s': ss, 'cond': s[1] if cond else None, 'uses': uses, 'defs': defs, 'a': a})
        recs[bid] = L
    # kills from calls: clobber registers (value unknown afterwards)
    def clobbers(r):
        t = r['s'][0]
        if t == 'call': return [x for x in CLOBBER if x not in r['defs']]
        return []
    # ---- step 1: reaching definitions --------------------------------------------------
    defid = {}          # (bid, idx, var) -> id ; entry defs (None, None, var)
    nid = 0
    entry_defs = {}
    gen_last = {}
    block_gen = {}
    for bid in order:
        g = {}
        for idx, r in enumerate(recs[bid]):
            for v in r['defs']:
                nid += 1; defid[(bid, idx, v)] = nid
                if r['cond'] is not None:
                    g.setdefault(v, set()).add(nid)
                else:
                    g[v] = {nid}
            for v in clobbers(r):
                nid += 1; defid[(bid, idx, v)] = nid; g[v] = {nid}
        block_gen[bid] = g
    # entry-def ids allocated lazily per var
    def entry_def(v):
        if v not in entry_defs:
            nonlocal_nid[0] += 1; entry_defs[v] = nonlocal_nid[0]
        return entry_defs[v]
    nonlocal_nid = [nid]
    allvars = set()
    for bid in order:
        for r in recs[bid]:
            allvars.update(r['uses']); allvars.update(r['defs']); allvars.update(clobbers(r))
    for bid in order:
        allvars.update(term_uses_list0(blocks[bid].term, sig, sg_map))
    entry_in = {v: {entry_def(v)} for v in allvars}
    IN = {bid: {} for bid in order}
    OUT = {bid: {} for bid in order}
    # kill info: block kills var v fully if it has an unconditional def
    block_kill = {}
    for bid in order:
        k = set()
        for r in recs[bid]:
            if r['cond'] is None:
                k.update(r['defs']); k.update(clobbers(r))
        block_kill[bid] = k
    changed = True; it = 0
    while changed and it < 30:
        changed = False; it += 1
        for bid in order:
            b = blocks[bid]
            new_in = {v: set(x) for v, x in entry_in.items()} if bid == fi.entry else {}
            for p in b.preds:
                if p not in OUT: continue
                for v, s in OUT[p].items():
                    new_in.setdefault(v, set()).update(s)
            IN[bid] = new_in
            out = {}
            kill = block_kill[bid]; g = block_gen[bid]
            for v, s in new_in.items():
                if v not in kill: out[v] = s
            for v, s in g.items():
                if v in out: out[v] = out[v] | s
                else: out[v] = s
            if out != OUT[bid]:
                OUT[bid] = out; changed = True
    # ---- step 2: unify webs --------------------------------------------------------------
    uf = UF()
    def reaching(cur_in, v):
        s = cur_in.get(v)
        if s is None: return {entry_def(v)}
        return s
    bid_is_entry = [False]
    vartype = {}
    web_vars = {}
    def_var = {}
    for (bid, idx, v), d in defid.items(): def_var[d] = v
    for bid in order:
        cur = {v: set(s) for v, s in IN[bid].items()}
        bid_is_entry[0] = (bid == fi.entry)
        for idx, r in enumerate(recs[bid]):
            for v in r['uses']:
                rs = reaching(cur, v)
                rs = list(rs)
                for x in rs[1:]: uf.union(rs[0], x)
                uf.find(rs[0])
            if r['cond'] is None:
                for v in r['defs']: cur[v] = {defid[(bid, idx, v)]}
                for v in clobbers(r): cur[v] = {defid[(bid, idx, v)]}
            else:
                for v in r['defs']:
                    d = defid[(bid, idx, v)]
                    rs = reaching(cur, v); rs = list(rs)
                    for x in rs: uf.union(d, x)
                    cur[v] = {d}
        # terminator uses
    # terminators
    def term_uses_list(bid):
        t = blocks[bid].term; k = t[0]
        u = []
        if k == 'br': u = expr_vars(t[1], [])
        elif k == 'switch': u = expr_vars(t[1], [])
        elif k == 'ret':
            if sig.ret: u.append('r0')
            if sig.ret2: u.append('r1')
        elif k == 'tail':
            sg = sg_map.get(t[1][1]) if t[1][0] == 'c' else None
            u = ARGREGS[:(sg.nparams if sg else 4)]
        elif k == 'itail': u = expr_vars(t[1], []) + ['r0']
        return u
    term_use = {}
    for bid in order:
        bid_is_entry[0] = (bid == fi.entry)
        cur = {v: set(s) for v, s in IN[bid].items()}
        for idx, r in enumerate(recs[bid]):
            if r['cond'] is None:
                for v in r['defs']: cur[v] = {defid[(bid, idx, v)]}
                for v in clobbers(r): cur[v] = {defid[(bid, idx, v)]}
            else:
                for v in r['defs']: cur[v] = {defid[(bid, idx, v)]}
        for v in term_uses_list(bid):
            rs = list(reaching(cur, v))
            for x in rs[1:]: uf.union(rs[0], x)
            uf.find(rs[0])
    # ---- step 3: names ---------------------------------------------------------------------
    names = {}
    counters = defaultdict(int)
    entry_web = {}
    for v, d in entry_defs.items(): entry_web[uf.find(d)] = v
    def web_name(d):
        root = uf.find(d)
        n = names.get(root)
        if n: return n
        ev = entry_web.get(root)
        v = def_var.get(d) or ev
        if ev is not None:
            if ev in ARGSET and ARGREGS.index(ev) < sig.nparams: n = 'param_%d' % (ARGREGS.index(ev) + 1)
            else: n = 'in_%s' % ev
            if n in names.values(): n = n + '_%d' % (counters['dup'] + 1); counters['dup'] += 1
        else:
            base = def_var.get(d)
            if base is None: base = def_var.get(root, 'r')
            if base.startswith('cc') or base == 'cp': pre = 'cc'
            elif base.startswith('s'): pre = 'fVar'
            elif base.startswith('d'): pre = 'dVar'
            elif base.startswith('tmp'): pre = 'lVar'
            else: pre = 'uVar'
            counters[pre] += 1; n = '%s%d' % (pre, counters[pre])
        names[root] = n
        return n
    # ---- step 4: rewrite -------------------------------------------------------------------
    out_blocks = {}
    clobber_ids = {d for (bid_, idx_, v_), d in defid.items() if recs[bid_][idx_]['s'][0] == 'call' and v_ not in recs[bid_][idx_]['defs']}
    def undef_reg(cur_, v):
        rs = reaching(cur_, v)
        for d_ in rs:
            if d_ in clobber_ids: continue
            ev_ = None
            for vv, dd in entry_defs.items():
                if dd == d_: ev_ = vv
            if ev_ is not None and (ev_ not in ARGSET or ARGREGS.index(ev_) >= sig.nparams): continue
            return False
        return True
    for bid in order:
        b = blocks[bid]
        bid_is_entry[0] = (bid == fi.entry)
        cur = {v: set(s) for v, s in IN[bid].items()}
        newst = []
        def ren(v, _cur=None):
            rs = reaching(cur, v)
            return web_name(next(iter(rs)))
        for idx, r in enumerate(recs[bid]):
            s = r['s']; t = s[0]; cond = r['cond']
            cexpr = rewrite_expr(cond, ren) if cond is not None else None
            if t == 'set':
                e = rewrite_expr(s[2], ren)
                d = defid[(bid, idx, s[1])]
                ns = ('set', web_name(d), e)
            elif t == 'st':
                ns = ('st', s[1], rewrite_expr(s[2], ren), rewrite_expr(s[3], ren))
            elif t == 'call':
                tg = s[1]
                tgn = tg if tg[0] == 'c' else rewrite_expr(tg, ren)
                args = trim_args([('v', ren(x)) for x in ARGREGS[:s[3]]], [undef_reg(cur, x) for x in ARGREGS[:s[3]]])
                outs = [web_name(defid[(bid, idx, x)]) for x in s[4]]
                ns = ('call', tgn, args, outs, s[2], s[5])
            elif t == 'svc':
                outs = [web_name(defid[(bid, idx, x)]) for x in ('r0', 'r1', 'r2', 'r3')]
                args = [('v', ren(x)) for x in ARGREGS[:4]]
                ns = ('svcall', s[1], args, outs, s[2])
            elif t == 'asm':
                ns = ('asm', s[1], [web_name(defid[(bid, idx, x)]) for x in s[2]], [ren(x) for x in s[3]])
            else: ns = s
            newst.append((ns, cexpr, r['a']))
            if cond is None:
                for v in r['defs']: cur[v] = {defid[(bid, idx, v)]}
                for v in clobbers(r): cur[v] = {defid[(bid, idx, v)]}
            else:
                for v in r['defs']: cur[v] = {defid[(bid, idx, v)]}
        t = b.term; k = t[0]
        if k == 'br': nt = ('br', rewrite_expr(t[1], ren), t[2], t[3])
        elif k == 'switch': nt = ('switch', rewrite_expr(t[1], ren), t[2], t[3], t[4])
        elif k == 'ret':
            vals = []
            if sig.ret: vals.append(('v', ren('r0')))
            if sig.ret2: vals.append(('v', ren('r1')))
            nt = ('ret', vals)
        elif k == 'tail':
            sg = sg_map.get(t[1][1]) if t[1][0] == 'c' else None
            _n = (sg.nparams if sg else 4)
            nt = ('tail', t[1], trim_args([('v', ren(x)) for x in ARGREGS[:_n]], [undef_reg(cur, x) for x in ARGREGS[:_n]]), t[2])
        elif k == 'itail': nt = ('itail', rewrite_expr(t[1], ren), [('v', ren('r0'))], t[2])
        else: nt = t
        out_blocks[bid] = {'stmts': newst, 'term': nt, 'succs': b.succs, 'preds': b.preds}
    params = sorted({int(n.split('_')[1]) for n in names.values() if n.startswith('param_')})
    return {'blocks': out_blocks, 'order': order, 'names': names, 'entry': fi.entry, 'params': params}

def trim_args(args, undef):
    n = len(args)
    while n > 1 and undef[n - 1]: n -= 1
    return args[:n]

def term_uses_list0(t, sig, sg_map):
    k = t[0]; u = []
    if k in ('br', 'switch'): u = expr_vars(t[1], [])
    elif k == 'ret':
        if sig.ret: u.append('r0')
        if sig.ret2: u.append('r1')
    elif k == 'tail':
        sg = sg_map.get(t[1][1]) if t[1][0] == 'c' else None
        u = ARGREGS[:(sg.nparams if sg else 4)]
    elif k == 'itail': u = expr_vars(t[1], []) + ['r0']
    return u

def ss_ind_args(b, s, a):
    """number of arg regs for an indirect call: contiguous regs defined since previous call in the block (min 1)"""
    m = 0
    for st, aa in b.stmts:
        if aa == a and st is s: break
        ss = st[2] if st[0] == 'pred' else st
        if ss[0] == 'call': m = 0; continue
        if ss[0] == 'set' and ss[1] in ARGSET: m |= ARGSET[ss[1]]
    n = max([i + 1 for i in range(4) if m >> i & 1] or [1])
    return n


# ======================================================================================
# propagation / dead-code elimination on renamed IR
# ======================================================================================
def stmt_used_names(ns, c):
    t = ns[0]; u = []
    if c is not None: expr_vars(c, u)
    if t == 'set': expr_vars(ns[2], u)
    elif t == 'st': expr_vars(ns[2], u); expr_vars(ns[3], u)
    elif t == 'call':
        if ns[1][0] != 'c': expr_vars(ns[1], u)
        for a in ns[2]: expr_vars(a, u)
    elif t == 'svcall':
        for a in ns[2]: expr_vars(a, u)
    elif t == 'asm': u.extend(ns[3])
    return u

def stmt_def_names(ns):
    t = ns[0]
    if t == 'set': return [ns[1]]
    if t in ('call', 'svcall'): return list(ns[3])
    if t == 'asm': return list(ns[2])
    return []

def subst_stmt(ns, c, name, rep):
    if c is not None: c = expr_subst(c, name, rep)
    t = ns[0]
    if t == 'set': ns = ('set', ns[1], expr_subst(ns[2], name, rep))
    elif t == 'st': ns = ('st', ns[1], expr_subst(ns[2], name, rep), expr_subst(ns[3], name, rep))
    elif t == 'call':
        tg = ns[1] if ns[1][0] == 'c' else expr_subst(ns[1], name, rep)
        ns = ('call', tg, [expr_subst(a, name, rep) for a in ns[2]], ns[3], ns[4], ns[5])
    elif t == 'svcall': ns = ('svcall', ns[1], [expr_subst(a, name, rep) for a in ns[2]], ns[3], ns[4])
    elif t == 'asm': ns = ('asm', ns[1], ns[2], [rep[1] if (u == name and rep[0] == 'v') else u for u in ns[3]])
    return ns, c

def term_used_names(t):
    k = t[0]; u = []
    if k in ('br', 'switch'): expr_vars(t[1], u)
    elif k == 'ret':
        for a in t[1]: expr_vars(a, u)
    elif k in ('tail',):
        for a in t[2]: expr_vars(a, u)
    elif k == 'itail':
        expr_vars(t[1], u)
        for a in t[2]: expr_vars(a, u)
    return u

def subst_term(t, name, rep):
    k = t[0]
    if k == 'br': return ('br', expr_subst(t[1], name, rep), t[2], t[3])
    if k == 'switch': return ('switch', expr_subst(t[1], name, rep), t[2], t[3], t[4])
    if k == 'ret': return ('ret', [expr_subst(a, name, rep) for a in t[1]])
    if k == 'tail': return ('tail', t[1], [expr_subst(a, name, rep) for a in t[2]], t[3])
    if k == 'itail': return ('itail', expr_subst(t[1], name, rep), [expr_subst(a, name, rep) for a in t[2]], t[3])
    return t

def has_effect(ns):
    return ns[0] in ('st', 'call', 'svcall', 'asm')

def simplify(rf):
    blocks = rf['blocks']; order = rf['order']
    dse_stack(rf)
    for rnd in range(6):
        changed = False
        uses = defaultdict(int); defs = defaultdict(int); defsite = {}
        for bid in order:
            b = blocks[bid]
            for idx, (ns, c, a) in enumerate(b['stmts']):
                for u in stmt_used_names(ns, c): uses[u] += 1
                for dn in stmt_def_names(ns):
                    defs[dn] += 1
                    defsite[dn] = (bid, idx)
                if c is not None:
                    for dn in stmt_def_names(ns): defs[dn] += 1     # conditional def counts twice => multi-def
            for u in term_used_names(b['term']): uses[u] += 1
        # --- global constant / copy propagation of single-def webs
        gsub = {}
        for dn, (bid, idx) in defsite.items():
            if defs[dn] != 1: continue
            ns, c, a = blocks[bid]['stmts'][idx]
            if ns[0] != 'set' or c is not None: continue
            e = ns[2]
            if e[0] in ('c', 'sp', 'fc') or (e[0] == 'v' and defs.get(e[1], 0) == 0):
                gsub[dn] = e
        if gsub:
            # resolve chains
            def res(e, depth=0):
                while e[0] == 'v' and e[1] in gsub and depth < 20: e = gsub[e[1]]; depth += 1
                return e
            for bid in order:
                b = blocks[bid]
                new = []
                for ns, c, a in b['stmts']:
                    if ns[0] == 'set' and ns[1] in gsub and c is None:
                        changed = True; continue
                    for n_ in set(stmt_used_names(ns, c)):
                        if n_ in gsub: ns, c = subst_stmt(ns, c, n_, res(('v', n_)))
                    new.append((ns, c, a))
                b['stmts'] = new
                t = b['term']
                for n_ in set(term_used_names(t)):
                    if n_ in gsub: t = subst_term(t, n_, res(('v', n_)))
                b['term'] = t
            continue
        # --- dead code
        for bid in order:
            b = blocks[bid]
            new = []
            for ns, c, a in b['stmts']:
                if ns[0] == 'set' and uses.get(ns[1], 0) == 0:
                    changed = True; continue
                if ns[0] in ('call', 'svcall'):
                    outs = ns[3]
                    if any(uses.get(o, 0) == 0 for o in outs):
                        # keep positions: replace unused outs by None only at tail
                        keep = list(outs)
                        while keep and uses.get(keep[-1], 0) == 0: keep.pop()
                        if len(keep) != len(outs):
                            ns = ns[:3] + (keep,) + ns[4:]; changed = True
                        if ns[0] == 'call' and len(keep) == 0 and len(outs) == 0: pass
                if ns[0] == 'asm' and ns[2] and all(uses.get(o, 0) == 0 for o in ns[2]) and False: pass
                new.append((ns, c, a))
            b['stmts'] = new
        # --- block-local single-use forwarding
        for bid in order:
            b = blocks[bid]
            st = b['stmts']; pending = {}; dead = set(); multi = {}; multi_e = {}      # multi: name -> [didx, substituted_count]
            for idx in range(len(st)):
                ns, c, a = st[idx]
                # substitute pending exprs into this stmt
                for n_ in list(dict.fromkeys(stmt_used_names(ns, c))):
                    if n_ in pending:
                        e, didx = pending.pop(n_)
                        ns, c = subst_stmt(ns, c, n_, e); dead.add(didx); changed = True
                    elif n_ in multi:
                        e, didx = multi_e[n_]
                        cnt = (stmt_used_names(ns, c)).count(n_)
                        ns, c = subst_stmt(ns, c, n_, e); multi[n_][1] += cnt; changed = True
                        if multi[n_][1] >= uses.get(n_, 0): dead.add(didx); multi.pop(n_)
                st[idx] = (ns, c, a)
                # invalidate
                dnames = stmt_def_names(ns)
                for dn in dnames:
                    for k in [k for k, (e, _) in pending.items() if dn in expr_vars(e, [])]: pending.pop(k)
                    for k in [k for k in multi if dn in expr_vars(multi_e[k][0], [])]: multi.pop(k)
                if has_effect(ns):
                    for k in [k for k, (e, _) in pending.items() if expr_has_ld(e)]: pending.pop(k)
                if ns[0] == 'set' and c is None and defs.get(ns[1], 0) == 1 and ns[1] not in expr_vars(ns[2], []):
                    if uses.get(ns[1], 0) == 1:
                        pending[ns[1]] = (ns[2], idx)
                    elif ns[2][0] in ('v',):
                        multi[ns[1]] = [idx, 0]; multi_e[ns[1]] = (ns[2], idx)
            t = b['term']
            for n_ in list(dict.fromkeys(term_used_names(t))):
                if n_ in pending:
                    e, didx = pending.pop(n_)
                    t = subst_term(t, n_, e); dead.add(didx); changed = True
                elif n_ in multi:
                    e, didx = multi_e[n_]
                    cnt = term_used_names(t).count(n_)
                    t = subst_term(t, n_, e); multi[n_][1] += cnt; changed = True
                    if multi[n_][1] >= uses.get(n_, 0): dead.add(didx); multi.pop(n_)
            b['term'] = t
            if dead: b['stmts'] = [x for i, x in enumerate(st) if i not in dead]
        if not changed: break
    dse_stack(rf)
    return rf

def _sp_escape(e, inld=False):
    """returns (set of slots loaded, escaped?) for an expression"""
    t = e[0]
    if t == 'sp': return set(), True
    if t == 'ld':
        ad = e[3]
        if ad[0] == 'sp': return {ad[1]}, False
        return _sp_escape(ad)
    if t in ('bin', 'cmp'):
        a = _sp_escape(e[2]); b = _sp_escape(e[3]); return a[0] | b[0], a[1] or b[1]
    if t in ('un',): return _sp_escape(e[2])
    if t == 'tern':
        r = [_sp_escape(x) for x in e[1:4]]; return set().union(*[x[0] for x in r]), any(x[1] for x in r)
    if t == 'flag':
        a = _sp_escape(e[3]); b = _sp_escape(e[4]); return a[0] | b[0], a[1] or b[1]
    return set(), False

def dse_stack(rf):
    """remove stores to stack slots that are never read and whose address never escapes (register spills)"""
    loaded = set(); esc = False
    blocks = rf['blocks']
    def scan(e):
        nonlocal esc
        l, x = _sp_escape(e); loaded.update(l); esc = esc or x
    for bid in rf['order']:
        b = blocks[bid]
        for ns, c, a in b['stmts']:
            if c is not None: scan(c)
            t = ns[0]
            if t == 'set': scan(ns[2])
            elif t == 'st':
                if ns[2][0] != 'sp': scan(ns[2])
                scan(ns[3])
            elif t in ('call', 'svcall'):
                for a_ in ns[2]: scan(a_)
                if t == 'call' and ns[1][0] != 'c': scan(ns[1])
            elif t == 'asm': esc = True if any(u.startswith('sp') for u in ns[3]) else esc
        t = b['term']
        if t[0] in ('br', 'switch'): scan(t[1])
        elif t[0] == 'ret':
            for a_ in t[1]: scan(a_)
        elif t[0] in ('tail', 'itail'):
            for a_ in t[2]: scan(a_)
    for bid in rf['order']:
        b = blocks[bid]
        b['stmts'] = [(ns, c, a) for ns, c, a in b['stmts'] if not (ns[0] == 'st' and ns[2][0] == 'sp' and ns[2][1] < 0 and ns[1] == 4 and ns[3][0] == 'v' and (ns[3][1].startswith('in_') ) and c is None)]
    if esc: return
    for bid in rf['order']:
        b = blocks[bid]
        new = []
        for ns, c, a in b['stmts']:
            if ns[0] == 'st' and ns[2][0] == 'sp' and ns[2][1] < 0 and ns[2][1] not in loaded and ns[1] == 4:
                continue
            new.append((ns, c, a))
        b['stmts'] = new
