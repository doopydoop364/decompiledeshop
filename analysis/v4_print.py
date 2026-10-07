#!/usr/bin/env python3
"""V4: pseudo-C formatter for structured AST."""
import sys, os, struct, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_ir import *
from v4_struct import negate, Structurer, merge_conditions

PREC = {'*': 10, '/': 10, '+': 9, '-': 9, '<<': 8, '>>': 8, '<': 7, '>': 7, '<=': 7, '>=': 7, '==': 6, '!=': 6, '&': 5, '^': 4, '|': 3, '&&': 2, '||': 1}
CMPOP = {'==': '==', '!=': '!=', 'u<': '<', 'u>=': '>=', 'u>': '>', 'u<=': '<=', 's<': '<', 's>=': '>=', 's>': '>', 's<=': '<=', 'f<': '<', 'f>=': '>=', 'f>': '>', 'f<=': '<='}
CTYPE = {(1, False): 'byte', (1, True): 'char', (2, False): 'ushort', (2, True): 'short', (4, False): 'uint', (4, True): 'int', (8, False): 'double', (8, True): 'double'}

class Ctx:
    """Naming context: function names, strings, data classification."""
    def __init__(self, m, entries, strings, func_names=None, data_names=None):
        self.m = m; self.entries = entries
        self.strs = {a: (enc, txt) for a, seg, enc, ln, txt in strings}
        self.str_starts = sorted(self.strs)
        self.func_names = func_names or {}
        self.data_names = data_names or {}
        self.str_cache = {}

    def func_name(self, a):
        return self.func_names.get(a) or 'FUN_%08x' % a

    def const(self, n, hint=None):
        m = self.m
        seg = m.seg_of(n) if n >= 0x100000 else None
        if seg == 'TEXT':
            if n in self.entries or (n & ~1) in self.entries: return self.func_name(n & ~1)
            return 'LAB_%08x' % n
        if seg in ('RODATA', 'DATA', 'BSS'):
            s = self.strs.get(n)
            if s is not None:
                enc, txt = s
                esc = txt.encode('unicode_escape').decode('ascii').replace('"', '\\"')
                if len(esc) > 70: esc = esc[:67] + '...'
                return ('L"%s"' if enc == 'utf16' else '"%s"') % esc
            nm = self.data_names.get(n)
            return nm if nm else '&DAT_%08x' % n if seg != 'RODATA' else '&DAT_%08x' % n
        if n < 10: return str(n)
        if n >= 0xFFFF0000: return '-0x%x' % (0x100000000 - n)
        return '0x%x' % n

class Fmt:
    def __init__(self, ctx, sigs=None, svc_names=None):
        self.ctx = ctx; self.sigs = sigs or {}

    def slot(self, slot):
        return 'local_%x' % -slot if slot < 0 else 'stack_arg_%x' % slot

    def ex(self, e, p=0):
        t = e[0]
        if t == 'c': return self.ctx.const(e[1])
        if t == 'v': return e[1]
        if t == 'sp': return '&' + self.slot(e[1])
        if t == 'fc':
            v = e[1]
            return ('%r' % v) + ('f' if len(e) < 3 or True else '')
        if t == 'cf': return 'CARRY'
        if t == 'cc': return 'COND_%s' % e[1]
        if t == 'bin':
            op, a, b = e[1], e[2], e[3]
            if op in PREC:
                pr = PREC[op]
                s = '%s %s %s' % (self.ex(a, pr), op, self.ex(b, pr + 1))
                return '(%s)' % s if pr < p else s
            if op == 'sar':
                s = '(int)%s >> %s' % (self.ex(a, 11), self.ex(b, 9))
                return '(%s)' % s if 8 < p else s
            if op == 'ror': return 'ROR32(%s, %s)' % (self.ex(a), self.ex(b))
            if op in ('f+', 'f-', 'f*', 'f/'):
                o = op[1]; pr = PREC[o]
                s = '%s %s %s' % (self.ex(a, pr), o, self.ex(b, pr + 1))
                return '(%s)' % s if pr < p else s
            if op == 'umul64': return '(ulonglong)%s * %s' % (self.ex(a, 11), self.ex(b, 11))
            if op == 'smul64': return '(longlong)(int)%s * (int)%s' % (self.ex(a, 11), self.ex(b, 11))
            if op == 'cat64': return 'CONCAT44(%s, %s)' % (self.ex(a), self.ex(b))
            return '%s(%s, %s)' % (op, self.ex(a), self.ex(b))
        if t == 'un':
            op, a = e[1], e[2]
            if op == '~': return '~%s' % self.ex(a, 11)
            if op == 'neg': return '-%s' % self.ex(a, 11)
            if op == 'fneg': return '-%s' % self.ex(a, 11)
            if op == 'lo32': return '(uint)%s' % self.ex(a, 11)
            if op == 'hi32': return '(uint)(%s >> 0x20)' % self.ex(a, 11)
            if op in ('sx8', 'sx16'): return '(int)(%s)%s' % ('char' if op == 'sx8' else 'short', self.ex(a, 11))
            return '%s(%s)' % (op.upper() if op in ('clz',) else op, self.ex(a))
        if t == 'ld':
            size, sg, ad = e[1], e[2], e[3]
            if ad[0] == 'sp' and size == 4 and ad[1] % 4 == 0: return self.slot(ad[1])
            ty = CTYPE.get((size, sg), 'uint')
            if size == 8 and False: ty = 'ulonglong'
            if ad[0] == 'sp': return '*(%s *)&%s' % (ty, self.slot(ad[1]))
            return '*(%s *)%s' % (ty, self.ex(ad, 11))
        if t == 'cmp':
            op, a, b = e[1], e[2], e[3]
            sa, sb = self.ex(a, 7), self.ex(b, 7)
            if op[0] == 's' and op not in ('==',):
                if a[0] != 'c': sa = '(int)%s' % self.ex(a, 11)
                if b[0] != 'c': sb = '(int)%s' % self.ex(b, 11)
                elif a[0] != 'c': pass
                if a[0] == 'c' and b[0] != 'c': sa = '(int)%s' % self.ex(a, 11)
            s = '%s %s %s' % (sa, CMPOP[op], sb)
            return '(%s)' % s if 7 < p else s
        if t in ('and', 'or'):
            pr = 2 if t == 'and' else 1
            sx = '%s %s %s' % (self.ex(e[1], pr), '&&' if t == 'and' else '||', self.ex(e[2], pr + 1))
            return '(%s)' % sx if pr < p else sx
        if t == 'not': return '!(%s)' % self.ex(e[1])
        if t == 'tern':
            a_, b_ = self.ex(e[2], p), self.ex(e[3], p)
            if a_ == b_: return a_
            return '(%s ? %s : %s)' % (self.ex(e[1]), a_, b_)
        if t == 'flag': return 'FLAG_%s(%s, %s)' % (e[1], self.ex(e[3]), self.ex(e[4]))
        return '?%r' % (e,)

    def callee(self, tg):
        if tg[0] == 'c': return self.ctx.func_name(tg[1] & ~1)
        return '(*(code *)%s)' % self.ex(tg, 11)

    def stmt(self, ns, c):
        t = ns[0]
        if t == 'set':
            e = ns[2]
            if e[0] == 'ld' and ns[1].startswith(('fVar', 'dVar')) and not (e[3][0] == 'sp' and e[1] == 4):
                ad = e[3]
                s = '%s = *(%s *)%s;' % (ns[1], 'float' if ns[1][0] == 'f' else 'double', self.ex(ad, 11) if ad[0] != 'sp' else '&' + self.slot(ad[1]))
            else: s = '%s = %s;' % (ns[1], self.ex(e))
        elif t == 'st':
            size, ad, v = ns[1], ns[2], ns[3]
            ty = CTYPE.get((size, False), 'uint')
            if v[0] == 'v' and v[1].startswith('fVar') and size == 4: ty = 'float'
            if v[0] == 'v' and v[1].startswith('dVar') and size == 8: ty = 'double'
            if ad[0] == 'sp' and size == 4 and ad[1] % 4 == 0 and ty == 'uint': s = '%s = %s;' % (self.slot(ad[1]), self.ex(v))
            elif ad[0] == 'sp': s = '*(%s *)&%s = %s;' % (ty, self.slot(ad[1]), self.ex(v))
            else: s = '*(%s *)%s = %s;' % (ty, self.ex(ad, 11), self.ex(v))
        elif t == 'call':
            args = ', '.join(self.ex(a) for a in ns[2])
            call = '%s(%s)' % (self.callee(ns[1]), args)
            outs = ns[3]
            if len(outs) == 1: s = '%s = %s;' % (outs[0], call)
            elif len(outs) == 2: s = '{%s, %s} = %s;' % (outs[0], outs[1], call)
            else: s = call + ';'
        elif t == 'svcall':
            nm = SVC_NAMES.get(ns[1], '0x%x' % ns[1])
            call = 'svc_%s(%s)' % (nm, ', '.join(self.ex(a) for a in ns[2][:SVC_NARGS.get(ns[1], 4)]))
            outs = ns[3]
            if outs: s = '%s = %s;' % ('{%s}' % ', '.join(outs) if len(outs) > 1 else outs[0], call)
            else: s = call + ';'
        elif t == 'asm':
            d = ', '.join(ns[2])
            s = '%s__asm("%s");%s' % ((d + ' = ') if len(ns[2]) == 1 else '', ns[1], ('  /* defs: %s */' % d) if len(ns[2]) > 1 else '')
        else: s = '/* %r */' % (ns,)
        return s

    def term_stmts(self, t):
        k = t[0]
        if k == 'ret':
            if not t[1]: return ['return;']
            if len(t[1]) == 1: return ['return %s;' % self.ex(t[1][0])]
            return ['return CONCAT44(%s, %s);' % (self.ex(t[1][1]), self.ex(t[1][0]))]
        if k == 'tail':
            tg = t[1]; sg = self.sigs.get(tg[1] & ~1) if tg[0] == 'c' else None
            call = '%s(%s)' % (self.callee(tg), ', '.join(self.ex(a) for a in t[2]))
            if sg is not None and not sg.ret: return [call + ';  /* tail call */', 'return;']
            return ['return %s;  /* tail call */' % call]
        if k == 'itail':
            return ['return (*(code *)%s)(%s);  /* indirect tail call */' % (self.ex(t[1], 11), self.ex(t[2][0]) if t[2] else '')]
        if k == 'ibr': return ['/* unresolved indirect jump: %s */' % t[1]]
        return []

SVC_NARGS = {0x01: 5, 0x02: 3, 0x03: 0, 0x08: 4, 0x09: 0, 0x0A: 2, 0x0B: 1, 0x0C: 2, 0x13: 1, 0x14: 1, 0x15: 2, 0x16: 2, 0x17: 1, 0x18: 1, 0x19: 1,
             0x1A: 1, 0x1B: 3, 0x1C: 1, 0x1D: 1, 0x1E: 4, 0x1F: 4, 0x20: 2, 0x21: 0, 0x22: 4, 0x23: 1, 0x24: 3, 0x25: 4, 0x28: 0, 0x32: 1, 0x3C: 1, 0x3D: 2}

def render(fm, ast, ind=1, lines=None):
    """AST -> list of text lines"""
    if lines is None: lines = []
    pad = '  ' * ind
    for n in ast:
        k = n[0]
        if k == 'label': lines.append('%sLAB_%08x:' % ('  ' * (ind - 1) if ind > 0 else '', abs(n[1])))
        elif k == 'goto': lines.append('%sgoto LAB_%08x;' % (pad, abs(n[1])))
        elif k == 'break': lines.append(pad + 'break;')
        elif k == 'continue': lines.append(pad + 'continue;')
        elif k == 's': lines.append(pad + n[1])
        elif k == 'block':
            _, bid, stmts, term, dup = n
            render_stmts(fm, stmts, lines, pad)
            for l in fm.term_stmts(term): lines.append(pad + l)
        elif k == 'if':
            _, c, th, el = n
            lines.append('%sif (%s) {' % (pad, fm.ex(c)))
            render(fm, th, ind + 1, lines)
            if el:
                lines.append(pad + '}')
                # else-if chain
                if len(el) == 1 and el[0][0] == 'if' :
                    sub = []
                    render(fm, el, ind, sub)
                    sub[0] = pad + 'else ' + sub[0].lstrip()
                    lines.extend(sub); continue
                lines.append(pad + 'else {')
                render(fm, el, ind + 1, lines)
            lines.append(pad + '}')
        elif k == 'loop':
            body = list(n[1])
            if len(body) >= 2 and body[-1] == ('break',) and body[-2][0] == 'if' and body[-2][2] == [('continue',)] and not body[-2][3]:
                lines.append(pad + 'do {')
                render(fm, body[:-2], ind + 1, lines)
                lines.append('%s} while (%s);' % (pad, fm.ex(body[-2][1])))
            elif len(body) >= 2 and body[0][0] == 'block' and not body[0][2] and body[0][3][0] in ('jmp', 'br') and body[1][0] == 'if' and body[1][2] == [('break',)] and not body[1][3]:
                lines.append('%swhile (%s) {' % (pad, fm.ex(negate(body[1][1]))))
                render(fm, body[2:], ind + 1, lines)
                lines.append(pad + '}')
            else:
                lines.append(pad + 'while (true) {')
                render(fm, body, ind + 1, lines)
                lines.append(pad + '}')
        elif k == 'switch':
            _, e, cases, darm = n
            lines.append('%sswitch (%s) {' % (pad, fm.ex(e)))
            for labels, arm in cases:
                for lb in labels: lines.append('%scase %d:' % (pad, lb))
                render(fm, arm, ind + 1, lines)
                if not (arm and arm[-1][0] in ('goto', 'continue', 'break')) and not ends_with_return(arm): lines.append(pad + '  break;')
            lines.append(pad + 'default:')
            render(fm, darm, ind + 1, lines)
            if not (darm and darm[-1][0] in ('goto', 'continue', 'break')) and not ends_with_return(darm): lines.append(pad + '  break;')
            lines.append(pad + '}')
    return lines

def ends_with_return(arm):
    if not arm: return False
    n = arm[-1]
    if n[0] == 'block': return n[3][0] in ('ret', 'tail', 'itail')
    return False

def render_stmts(fm, stmts, lines, pad):
    i = 0
    n = len(stmts)
    while i < n:
        ns, c, a = stmts[i]
        if c is None:
            lines.append(pad + fm.stmt(ns, None)); i += 1; continue
        # group consecutive statements with identical predicate
        j = i
        grp = []
        while j < n and stmts[j][1] == c:
            grp.append(stmts[j][0]); j += 1
        if len(grp) == 1:
            lines.append('%sif (%s) %s' % (pad, fm.ex(c), fm.stmt(grp[0], c)))
        else:
            lines.append('%sif (%s) {' % (pad, fm.ex(c)))
            for g in grp: lines.append('%s  %s' % (pad, fm.stmt(g, c)))
            lines.append(pad + '}')
        i = j

def collect_vars(rf):
    seen = {}
    def walk(e):
        if e is None: return
        t = e[0]
        if t == 'v': seen.setdefault(e[1], 1)
        elif t == 'bin': walk(e[2]); walk(e[3])
        elif t in ('un', 'not'): walk(e[2] if t == 'un' else e[1])
        elif t == 'ld': walk(e[3])
        elif t == 'cmp': walk(e[2]); walk(e[3])
        elif t == 'tern': walk(e[1]); walk(e[2]); walk(e[3])
        elif t in ('and', 'or'): walk(e[1]); walk(e[2])
        elif t == 'flag': walk(e[3]); walk(e[4])
    for bid in rf['order']:
        b = rf['blocks'][bid]
        for ns, c, a in b['stmts']:
            walk(c)
            t = ns[0]
            if t == 'set': seen.setdefault(ns[1], 1); walk(ns[2])
            elif t == 'st': walk(ns[2]); walk(ns[3])
            elif t in ('call', 'svcall'):
                for o in ns[3]: seen.setdefault(o, 1)
                for a_ in ns[2]: walk(a_)
                if t == 'call' and ns[1][0] != 'c': walk(ns[1])
            elif t == 'asm':
                for o in ns[2]: seen.setdefault(o, 1)
        t = b['term']
        if t[0] in ('br', 'switch'): walk(t[1])
        elif t[0] == 'ret':
            for a_ in t[1]: walk(a_)
        elif t[0] in ('tail', 'itail'):
            for a_ in t[2]: walk(a_)
            if t[0] == 'itail': walk(t[1])
    return list(seen)

def func_text(fm, rf, sig, fname, thumb, header_comments):
    merge_conditions(rf)
    st = Structurer(rf)
    ast = st.run()
    nparams = max(sig.nparams, max(rf['params'] or [0]))
    ret = 'void'
    if sig.ret2: ret = 'ulonglong'
    elif sig.ret: ret = 'uint'
    plist = ', '.join('uint param_%d' % (i + 1) for i in range(nparams)) or 'void'
    if sig.stack_args: plist += ', ...' if plist != 'void' else ''
    L = list(header_comments)
    L.append('%s %s(%s)' % (ret, fname, plist))
    L.append('{')
    vs = [v for v in collect_vars(rf) if not v.startswith('param_')]
    groups = {}
    for v in vs:
        ty = 'float' if v.startswith('fVar') else 'double' if v.startswith('dVar') else 'ulonglong' if v.startswith('lVar') else 'uint'
        groups.setdefault(ty, []).append(v)
    for ty, names in groups.items():
        for i in range(0, len(names), 8): L.append('  %s %s;' % (ty, ', '.join(names[i:i + 8])))
    if vs: L.append('')
    render(fm, ast, 1, L)
    L.append('}')
    return L
