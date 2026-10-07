#!/usr/bin/env python3
"""V4 pass 8: control-flow structuring (if/else, loops, switch, goto fallback) and pseudo-C formatting."""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collections import defaultdict
from v4_ir import *

NEG = {'==': '!=', '!=': '==', 'u<': 'u>=', 'u>=': 'u<', 'u>': 'u<=', 'u<=': 'u>', 's<': 's>=', 's>=': 's<', 's>': 's<=', 's<=': 's>'}

def negate(c):
    if c[0] == 'or': return ('and', negate(c[1]), negate(c[2]))
    if c[0] == 'and': return ('or', negate(c[1]), negate(c[2]))
    if c[0] == 'cmp' and c[1] in NEG: return ('cmp', NEG[c[1]], c[2], c[3])
    if c[0] == 'not': return c[1]
    if c[0] == 'c': return ('c', 0 if c[1] else 1)
    return ('not', c)

# ---------------------------------------------------------------------------------------------
# dominators
# ---------------------------------------------------------------------------------------------
def compute_idom(nodes, preds, entry):
    """Cooper-Harvey-Kennedy on given RPO list."""
    idx = {n: i for i, n in enumerate(nodes)}
    idom = {entry: entry}
    changed = True
    def inter(a, b):
        while a != b:
            while idx[a] > idx[b]: a = idom[a]
            while idx[b] > idx[a]: b = idom[b]
        return a
    while changed:
        changed = False
        for n in nodes:
            if n == entry: continue
            ps = [p for p in preds.get(n, []) if p in idom]
            if not ps: continue
            new = ps[0]
            for p in ps[1:]: new = inter(p, new)
            if idom.get(n) != new: idom[n] = new; changed = True
    return idom

def merge_conditions(rf):
    """Fold short-circuit chains of empty conditional blocks into && / || conditions."""
    blocks = rf['blocks']
    changed = True
    while changed:
        changed = False
        for a in list(rf['order']):
            if a not in blocks: continue
            A = blocks[a]; t = A['term']
            if t[0] != 'br': continue
            c1, T, F = t[1], t[2], t[3]
            for side in (0, 1):
                X = F if side == 0 else T          # candidate intermediate block
                if X not in blocks or X == a: continue
                B_ = blocks[X]
                if B_['stmts'] or B_['term'][0] != 'br' or len(set(B_['preds'])) != 1 or B_['preds'][0] != a: continue
                if T == F: continue
                c2, T2, F2 = B_['term'][1], B_['term'][2], B_['term'][3]
                new = None
                if side == 0:           # c1 false -> X
                    if T2 == T: new = ('or', c1, c2), T, F2
                    elif F2 == T: new = ('or', c1, negate(c2)), T, T2
                else:                   # c1 true -> X
                    if F2 == F: new = ('and', c1, c2), T2, F
                    elif T2 == F: new = ('and', c1, negate(c2)), F2, F
                if new:
                    cond, nT, nF = new
                    A['term'] = ('br', cond, nT, nF)
                    A['succs'] = [nT, nF]
                    for y in B_['succs']:
                        if y in blocks:
                            blocks[y]['preds'] = [p for p in blocks[y]['preds'] if p != X]
                    for y in (nT, nF):
                        if y in blocks and a not in blocks[y]['preds']: blocks[y]['preds'].append(a)
                    del blocks[X]
                    rf['order'] = [x for x in rf['order'] if x != X]
                    changed = True
                    break
    return rf

class Structurer:
    def __init__(self, rf):
        self.rf = rf; self.blocks = rf['blocks']; self.order = rf['order']; self.entry = rf['entry']
        self.succs = {b: [s for s in self.blocks[b]['succs'] if s in self.blocks] for b in self.order}
        self.preds = defaultdict(list)
        for b in self.order:
            for s in self.succs[b]: self.preds[s].append(b)
        self.rpo = {b: i for i, b in enumerate(self.order)}
        self.idom = compute_idom(self.order, self.preds, self.entry)
        # post-dominators with virtual exit
        EXIT = 'EXIT'
        rsucc = defaultdict(list)           # reverse graph: edges reversed
        for b in self.order:
            ss = self.succs[b]
            if not ss: rsucc[EXIT].append(b)
            for s in ss: rsucc[s].append(b)
        # nodes in infinite loops don't reach EXIT: connect their loop heads later (they get no ipdom)
        rorder = []; seen = {EXIT}
        stack = [(EXIT, iter(rsucc[EXIT]))]
        while stack:
            n, it = stack[-1]
            for s in it:
                if s not in seen: seen.add(s); stack.append((s, iter(rsucc[s]))); break
            else: rorder.append(n); stack.pop()
        rorder.reverse()
        rpreds = defaultdict(list)           # preds in reverse graph = succs in forward graph
        for b in self.order:
            for s in self.succs[b]: rpreds[b].append(s)
            if not self.succs[b]: rpreds[b].append(EXIT)
        self.ipdom = compute_idom(rorder, rpreds, EXIT)
        self.EXIT = EXIT
        # loops
        self.loops = {}                      # header -> set(body)
        for b in self.order:
            for s in self.succs[b]:
                if self.dominates(s, b):
                    body = self.loops.setdefault(s, {s})
                    stack = [b]
                    while stack:
                        x = stack.pop()
                        if x in body: continue
                        body.add(x)
                        stack.extend(self.preds[x])
        self.emitted = set(); self.labels_needed = set(); self.frames = []
        self.second = False
        self.goto_targets = set()
        self.sw_depth = 0

    def dominates(self, a, b):
        while True:
            if a == b: return True
            nb = self.idom.get(b)
            if nb is None or nb == b: return False
            b = nb

    def is_terminal(self, bid):
        b = self.blocks[bid]
        return b['term'][0] in ('ret', 'tail', 'itail') and len(b['stmts']) <= 2 and bid < 0

    # ---- emission ----
    def run(self):
        self.goto_targets = set()
        self.second = False
        self.emitted = set(); self.frames = []
        out = []
        self.emit_seq(self.entry, None, out)
        # handle blocks not reached structurally (shouldn't normally happen)
        for b in self.order:
            if b not in self.emitted and b >= 0:
                out.append(('label', b)); self.goto_targets.add(b)
                self.emit_seq(b, None, out)
        need = set(self.goto_targets)
        # second pass with labels
        self.emitted = set(); self.frames = []; self.second = True; self.need = need
        out = []
        self.emit_seq(self.entry, None, out)
        for b in self.order:
            if b not in self.emitted and b >= 0:
                self.emit_seq(b, None, out)
        return out

    def label_if_needed(self, b, out):
        if self.second and b in self.need and b >= 0: out.append(('label', b))

    def goto(self, t, out):
        self.goto_targets.add(t)
        out.append(('goto', t))

    def jump_to(self, t, stop, out):
        """control transfers to t. returns True if emission should continue inline at t."""
        if t == stop: return False
        if self.frames:
            hdr, follow, body = self.frames[-1]
            if t == hdr: out.append(('continue',)); return False
            if follow is not None and t == follow and t != stop:
                if self.sw_depth: self.goto(t, out)
                else: out.append(('break',))
                return False
            for fr in self.frames[:-1]:
                if t == fr[0] or (fr[1] is not None and t == fr[1]):
                    self.goto(t, out); return False
        if t in self.emitted:
            if self.is_terminal(t):
                self.emit_block_body(t, out, dup=True); return False
            self.goto(t, out); return False
        return True

    def emit_seq(self, node, stop, out):
        while node is not None and node != stop:
            if node in self.emitted:
                if self.is_terminal(node): self.emit_block_body(node, out, dup=True)
                else: self.goto(node, out)
                return
            if node in self.loops and not any(f[0] == node for f in self.frames):
                node = self.emit_loop(node, stop, out)
                continue
            node = self.emit_block(node, stop, out)

    def emit_loop(self, h, stop, out):
        body = self.loops[h]
        # loop exits
        exits = []
        for n in body:
            for s in self.succs[n]:
                if s not in body and s not in exits: exits.append(s)
        follow = None
        ip = self.ipdom.get(h)
        cands = [e for e in exits if not self.is_terminal(e)]
        if ip is not None and ip != self.EXIT and ip not in body: follow = ip
        elif cands:
            follow = min(cands, key=lambda e: self.rpo.get(e, 1 << 30))
        frame = (h, follow, body)
        self.frames.append(frame)
        inner = []
        self.emitted_loop_hdr = h
        nxt = self.emit_block(h, None, inner, is_loop_header=True)
        self.emit_seq(nxt, None, inner)
        self.frames.pop()
        out.append(('loop', inner))
        if follow is not None:
            if follow in self.emitted and not self.is_terminal(follow):
                self.goto(follow, out); return None
            return follow
        return None

    def emit_block(self, node, stop, out, is_loop_header=False):
        self.emitted.add(node)
        if self.second and node in self.need and node >= 0 and not is_loop_header: out.append(('label', node))
        elif self.second and node in self.need and node >= 0 and is_loop_header: out.append(('label', node))
        self.emit_block_body(node, out)
        b = self.blocks[node]; t = b['term']; k = t[0]
        if k == 'jmp':
            tgt = t[1]
            if tgt not in self.blocks: return None
            if self.jump_to(tgt, stop, out): return tgt
            return None
        if k == 'br':
            c, T, F = t[1], t[2], t[3]
            join = self.ipdom.get(node)
            if join == self.EXIT or join is None or (self.frames and join not in self.frames[-1][2] and self.frames[-1][1] != join and False): join = None
            # inside a loop: a join outside the loop is the loop exit -> handled by break
            if self.frames:
                hdr, follow, body = self.frames[-1]
                if join is not None and join not in body: join = None
            return self.emit_if(node, c, T, F, join, stop, out)
        if k == 'switch':
            return self.emit_switch(node, t, stop, out)
        # ret / tail / itail / ibr handled in body
        return None

    def emit_if(self, node, c, T, F, join, stop, out):
        if join is None:
            # no join: emit smaller/terminal arm inside the if, continue with the other inline
            tt = self.is_terminal(T) or (T in self.emitted); ft = self.is_terminal(F) or (F in self.emitted)
            def size(x): return sum(1 for n in self.order if self.dominates(x, n)) if x in self.blocks else 0
            if ft and not tt: c, T, F = negate(c), F, T
            elif not tt and not ft:
                ts, fs = size(T), size(F)
                # prefer the arm that is a break/continue/return target in the if
                if fs < ts: c, T, F = negate(c), F, T
            then = []
            cont = self.jump_to(T, stop, then)
            if cont: self.emit_seq(T, stop, then)
            if not then: then = [('s', ';')]
            out.append(('if', c, then, []))
            if self.jump_to(F, stop, out): return F
            return None
        then = []; els = []
        cont = self.jump_to(T, join, then)
        if cont: self.emit_seq(T, join, then)
        cont = self.jump_to(F, join, els)
        if cont: self.emit_seq(F, join, els)
        if not then and els: c, then, els = negate(c), els, then
        if not then: then = [('s', ';')]
        out.append(('if', c, then, els))
        if join == stop or join is None: return None
        if join in self.emitted and not self.is_terminal(join):
            self.goto(join, out); return None
        return join

    def emit_switch(self, node, t, stop, out):
        _, e, default, cases, site = t
        join = self.ipdom.get(node)
        if join == self.EXIT: join = None
        if self.frames and join is not None and join not in self.frames[-1][2]: join = None
        groups = []                              # (labels, target)
        tmap = {}
        for i, tg in enumerate(cases):
            if tg == default and False: continue
            if tg in tmap: groups[tmap[tg]][0].append(i)
            else: tmap[tg] = len(groups); groups.append(([i], tg))
        body = []
        saved_frames = self.frames
        self.sw_depth += 1
        for labels, tg in groups:
            arm = []
            if tg == join or tg == stop: pass
            elif tg in self.emitted:
                self.goto(tg, arm) if not self.is_terminal(tg) else self.emit_block_body(tg, arm, dup=True)
            else:
                self.frames = saved_frames + [('SW', join, set(self.order))] if False else saved_frames
                self.emit_seq(tg, join, arm)
            body.append((labels, arm))
        darm = []
        if default == join or default == stop: pass
        elif default in self.emitted:
            self.goto(default, darm) if not self.is_terminal(default) else self.emit_block_body(default, darm, dup=True)
        else:
            self.emit_seq(default, join, darm)
        self.sw_depth -= 1
        out.append(('switch', e, body, darm))
        if join is None or join == stop: return None
        if join in self.emitted: self.goto(join, out); return None
        return join

    def emit_block_body(self, node, out, dup=False):
        b = self.blocks[node]
        out.append(('block', node, b['stmts'], b['term'], dup))
