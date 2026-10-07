#!/usr/bin/env python3
"""V4 pass 3: instruction lifting.  ARM/Thumb (Capstone operand model) -> small expression/statement IR.

Expressions (tuples):  ('c',n) ('v',name) ('bin',op,a,b) ('un',op,a) ('ld',size,signed,addr) ('sp',slot)
Statements (tuples):   ('set',var,expr) ('st',size,addr,val) ('call',target,site) ('svc',n,site)
                       ('asm',text,defs,uses) ('pred',cond,stmt)
Anything the lifter does not model precisely becomes an 'asm' statement carrying Capstone's register
read/write sets, so dataflow stays conservative instead of silently wrong."""
import struct
from capstone import arm_const as A

M32 = 0xFFFFFFFF
CC = {1: 'eq', 2: 'ne', 3: 'hs', 4: 'lo', 5: 'mi', 6: 'pl', 7: 'vs', 8: 'vc', 9: 'hi', 10: 'ls', 11: 'ge', 12: 'lt', 13: 'gt', 14: 'le', 15: 'al'}
CC_NEG = {'eq': 'ne', 'ne': 'eq', 'hs': 'lo', 'lo': 'hs', 'mi': 'pl', 'pl': 'mi', 'vs': 'vc', 'vc': 'vs', 'hi': 'ls', 'ls': 'hi', 'ge': 'lt', 'lt': 'ge', 'gt': 'le', 'le': 'gt'}

def C(n): return ('c', n & M32)
def V(n): return ('v', n)

def sx32(n):
    n &= M32
    return n - (1 << 32) if n & 0x80000000 else n

def B(op, a, b):
    """binary expression with light constant folding"""
    if a[0] == 'c' and b[0] == 'c':
        x, y = a[1], b[1]
        r = {'+': lambda: x + y, '-': lambda: x - y, '*': lambda: x * y, '&': lambda: x & y, '|': lambda: x | y, '^': lambda: x ^ y,
             '<<': lambda: x << (y & 255) if y < 32 else 0, '>>': lambda: x >> y if y < 32 else 0,
             'sar': lambda: (sx32(x) >> min(y, 31))}.get(op)
        if r: return C(r())
    if a[0] == 'sp' and b[0] == 'c' and op in ('+', '-'):
        return ('sp', a[1] + (sx32(b[1]) if op == '+' else -sx32(b[1])))
    if op in ('+', '-') and b[0] == 'c' and b[1] == 0: return a
    if op == '+' and a[0] == 'c' and a[1] == 0: return b
    if op == '+' and b[0] == 'c' and sx32(b[1]) < 0 and b[1] != 0x80000000:
        return ('bin', '-', a, C(-sx32(b[1])))
    if op == '+' and a[0] == 'c' and b[0] != 'c': return ('bin', '+', b, a)
    if op in ('|', '^') and b[0] == 'c' and b[1] == 0: return a
    if op == '&' and b[0] == 'c' and b[1] == M32: return a
    if op in ('<<', '>>', 'sar') and b[0] == 'c' and b[1] == 0: return a
    if op == '+' and a[0] == 'bin' and a[1] in ('+', '-') and a[3][0] == 'c' and b[0] == 'c':
        d = a[3][1] if a[1] == '+' else -a[3][1]
        return B('+', a[2], C(d + b[1]))
    if op == '-' and a[0] == 'bin' and a[1] in ('+', '-') and a[3][0] == 'c' and b[0] == 'c':
        d = a[3][1] if a[1] == '+' else -a[3][1]
        return B('+', a[2], C(d - b[1]))
    return ('bin', op, a, b)

def U(op, a):
    if a[0] == 'c':
        if op == '~': return C(~a[1])
        if op == 'neg': return C(-a[1])
    return ('un', op, a)

REGNAME = {A.ARM_REG_SP: 'sp', A.ARM_REG_LR: 'lr', A.ARM_REG_PC: 'pc', A.ARM_REG_IP: 'r12', A.ARM_REG_FP: 'r11', A.ARM_REG_SB: 'r9', A.ARM_REG_SL: 'r10'}
for i in range(13):
    REGNAME[getattr(A, 'ARM_REG_R%d' % i)] = 'r%d' % i
for i in range(32):
    REGNAME[getattr(A, 'ARM_REG_S%d' % i)] = 's%d' % i
for i in range(16):
    REGNAME[getattr(A, 'ARM_REG_D%d' % i)] = 'd%d' % i

ASM_OPAQUE_MEM = {A.ARM_INS_STM, A.ARM_INS_STMDA, A.ARM_INS_STMDB, A.ARM_INS_STMIB}

SVC_NAMES = {0x01: 'ControlMemory', 0x02: 'QueryMemory', 0x03: 'ExitProcess', 0x08: 'CreateThread', 0x09: 'ExitThread', 0x0A: 'SleepThread',
             0x0B: 'GetThreadPriority', 0x0C: 'SetThreadPriority', 0x13: 'CreateMutex', 0x14: 'ReleaseMutex', 0x15: 'CreateSemaphore',
             0x16: 'ReleaseSemaphore', 0x17: 'CreateEvent', 0x18: 'SignalEvent', 0x19: 'ClearEvent', 0x1A: 'CreateTimer', 0x1B: 'SetTimer',
             0x1C: 'CancelTimer', 0x1D: 'ClearTimer', 0x1E: 'CreateMemoryBlock', 0x1F: 'MapMemoryBlock', 0x20: 'UnmapMemoryBlock',
             0x21: 'CreateAddressArbiter', 0x22: 'ArbitrateAddress', 0x23: 'CloseHandle', 0x24: 'WaitSynchronization1', 0x25: 'WaitSynchronizationN',
             0x27: 'DuplicateHandle', 0x28: 'GetSystemTick', 0x29: 'GetHandleInfo', 0x2A: 'GetSystemInfo', 0x2B: 'GetProcessInfo',
             0x2C: 'GetThreadInfo', 0x2D: 'ConnectToPort', 0x32: 'SendSyncRequest', 0x35: 'GetProcessId', 0x37: 'GetThreadId',
             0x38: 'GetResourceLimit', 0x3C: 'Break', 0x3D: 'OutputDebugString'}

def norm_id(ins):
    """Capstone gives some Thumb flag-setting forms their own ids (MOVS, ADDS...). Map back to the base op."""
    mn = ins.mnemonic.split('.')[0]
    cc = ins.cc
    if cc not in (0, A.ARM_CC_AL):
        n = CC.get(cc, '')
        if mn.endswith(n): mn = mn[:-len(n)]
    if ins.update_flags and mn.endswith('s') and len(mn) > 2:
        i = getattr(A, 'ARM_INS_' + mn[:-1].upper(), None)
        if i is not None: return i
    return ins.id

class Lifter:
    """Lifts the instructions of one function into per-instruction statement lists."""
    def __init__(self, m, d):
        self.m = m; self.d = d
        self._cs = {}

    def cs_insn(self, i):
        k = (i.addr, i.thumb)
        r = self._cs.get(k)
        if r is None:
            from v4_disasm import cs, cs_t
            raw = self.m.code[i.addr - self.m.text[0]: i.addr - self.m.text[0] + i.size]
            r = next((cs_t if i.thumb else cs).disasm(raw, i.addr, 1), None)
            self._cs[k] = r
        return r

    # ---- operand helpers -------------------------------------------------
    def pcval(self, i):
        return (i.addr + 4) & ~3 if i.thumb else i.addr + 8

    def regexpr(self, ins, reg, i, spd):
        n = REGNAME.get(reg)
        if n is None: return ('v', ins.reg_name(reg))
        if n == 'pc': return C(i.addr + 4 if i.thumb else i.addr + 8)
        if n == 'sp': return ('sp', spd) if spd is not None else V('sp')
        return V(n)

    def shifted(self, ins, op, i, spd):
        e = self.regexpr(ins, op.reg, i, spd)
        t, v = op.shift.type, op.shift.value
        if t == 0: return e
        if t == A.ARM_SFT_LSL: return B('<<', e, C(v))
        if t == A.ARM_SFT_LSR: return B('>>', e, C(v if v else 32))
        if t == A.ARM_SFT_ASR: return B('sar', e, C(v if v else 32))
        if t == A.ARM_SFT_ROR: return ('bin', 'ror', e, C(v))
        if t == A.ARM_SFT_RRX: return ('un', 'rrx', e)
        rs = V(REGNAME.get(v, 'r%d' % v)) if v in REGNAME else ('v', ins.reg_name(v))
        op_ = {A.ARM_SFT_LSL_REG: '<<', A.ARM_SFT_LSR_REG: '>>', A.ARM_SFT_ASR_REG: 'sar', A.ARM_SFT_ROR_REG: 'ror'}[t]
        return ('bin', op_, e, ('bin', '&', rs, C(255)))

    def op2(self, ins, op, i, spd):
        if op.type == A.ARM_OP_IMM: return C(op.imm)
        if op.type == A.ARM_OP_REG: return self.shifted(ins, op, i, spd)
        return ('v', '?')

    def memaddr(self, ins, mem, i, spd, subtracted=False):
        base = self.regexpr(ins, mem.base, i, spd) if mem.base else C(0)
        if mem.index:
            idx = self.regexpr(ins, mem.index, i, spd)
            if mem.lshift: idx = B('<<', idx, C(mem.lshift))
            return B('-' if mem.scale < 0 else '+', base, idx)
        d = mem.disp
        return B('+', base, C(d))

    # ---- main entry ------------------------------------------------------
    def lift(self, i, spd, flags):
        """returns (stmts, new_spd, new_flags).  spd = sp offset from function-entry sp (None if unknown)."""
        ins = self.cs_insn(i)
        if ins is None: return [('asm', '.word %#x' % i.word, [], [])], spd, flags
        if i.kind in ('b', 'bcond', 'bx', 'switch'): return [], spd, flags
        if i.kind == 'ret' and ins.id not in (A.ARM_INS_POP, A.ARM_INS_LDM, A.ARM_INS_LDMDA, A.ARM_INS_LDMDB, A.ARM_INS_LDMIB):
            return [], spd, flags
        stmts, spd2, flags2 = self._lift(ins, i, spd, flags)
        cc = CC.get(ins.cc, 'al')
        if cc != 'al' and stmts:
            cond = self.cond(cc, flags)
            if cond is None: cond = ('cc', cc)
            pre = []
            if flags2 is not flags and flags2 is not None:        # predicated flag setter: remember predicate, select at use
                pre = [('set', 'cp', cond)]
                cond = V('cp')
                flags2 = ('sel', V('cp'), flags2, flags)
            stmts = pre + [('pred', cond, s) if s[0] != 'pred' else s for s in stmts]
        return stmts, spd2, flags2

    def cond(self, cc, fl):
        """Build a comparison expression from the flag descriptor.  fl = (kind, a, b) with a,b expressions."""
        if cc == 'al': return ('c', 1)
        if fl is None: return None
        if fl[0] == 'sel':
            n = self.cond(cc, fl[2]); o = self.cond(cc, fl[3])
            if n is None or o is None: return None
            return ('tern', fl[1], n, o)
        k, a, b = fl
        if k == 'cmp':
            m = {'eq': '==', 'ne': '!=', 'hs': 'u>=', 'lo': 'u<', 'hi': 'u>', 'ls': 'u<=', 'ge': 's>=', 'lt': 's<', 'gt': 's>', 'le': 's<='}
            if cc in m: return ('cmp', m[cc], a, b)
            if cc == 'mi': return ('cmp', 's<', ('bin', '-', a, b), C(0))
            if cc == 'pl': return ('cmp', 's>=', ('bin', '-', a, b), C(0))
            return ('flag', cc, k, a, b)
        if k == 'cmn':
            s = ('bin', '+', a, b)
            m = {'eq': ('==', s, C(0)), 'ne': ('!=', s, C(0)), 'mi': ('s<', s, C(0)), 'pl': ('s>=', s, C(0)), 'lt': ('s<', s, C(0)), 'ge': ('s>=', s, C(0)),
                 'gt': ('s>', s, C(0)), 'le': ('s<=', s, C(0)), 'hs': ('u<', s, a), 'lo': ('u>=', s, a)}
            if cc in m:
                o, x, y = m[cc]
                if cc in ('hs', 'lo'): o = {'hs': 'u<', 'lo': 'u>='}[cc]
                return ('cmp', o, x, y)
            return ('flag', cc, k, a, b)
        if k == 'res':                      # logical result / movs: N,Z valid, C from shifter (unknown)
            m = {'eq': '==', 'ne': '!=', 'mi': 's<', 'pl': 's>=', 'lt': 's<', 'ge': 's>=', 'gt': 's>', 'le': 's<='}
            if cc in m: return ('cmp', m[cc], a, C(0))
            return ('flag', cc, k, a, b)
        if k == 'fcmp':
            m = {'eq': '==', 'ne': '!=', 'mi': 'f<', 'lo': 'f<', 'pl': 'f>=', 'hs': 'f>=', 'gt': 'f>', 'hi': 'f>', 'ge': 'f>=', 'le': 'f<=', 'ls': 'f<=', 'lt': 'f<'}
            if cc in m: return ('cmp', m[cc], a, b)
            if cc in ('vs', 'vc'): return ('flag', cc, k, a, b)
        return ('flag', cc, k, a, b)

    def _lift(self, ins, i, spd, flags):
        I = norm_id(ins)
        ops = ins.operands
        mn = ins.mnemonic
        S = []
        R = lambda op: self.regexpr(ins, op.reg, i, spd)
        dst = lambda op: REGNAME.get(op.reg) or ins.reg_name(op.reg)
        sets_flags = ins.update_flags
        newfl = flags

        def setflags(kind, a, b=None):
            S.append(('set', 'cc_a', a))
            if b is not None: S.append(('set', 'cc_b', b))
            return (kind, V('cc_a'), V('cc_b') if b is not None else C(0))

        def finish(): return S, spd, newfl

        if I == A.ARM_INS_NOP or mn.startswith(('nop', 'dmb', 'dsb', 'isb', 'pld', 'pli', 'yield', 'wfe', 'sev', 'cpsi', 'clrex')) or I == A.ARM_INS_PLD or I == A.ARM_INS_PLDW:
            return S, spd, flags
        # ---- data processing ----
        dp = {A.ARM_INS_AND: '&', A.ARM_INS_EOR: '^', A.ARM_INS_ORR: '|', A.ARM_INS_ADD: '+', A.ARM_INS_SUB: '-', A.ARM_INS_RSB: 'rsb',
              A.ARM_INS_BIC: 'bic', A.ARM_INS_ADC: 'adc', A.ARM_INS_SBC: 'sbc', A.ARM_INS_RSC: 'rsc'}
        if I in dp and len(ops) >= 2 and ops[0].type == A.ARM_OP_REG:
            rd = ops[0]
            if len(ops) == 2: a_e = R(rd) if rd.reg != A.ARM_REG_PC else C(0); b_e = self.op2(ins, ops[1], i, spd)
            else: a_e = R(ops[1]); b_e = self.op2(ins, ops[2], i, spd)
            o = dp[I]
            if o == 'rsb': e = B('-', b_e, a_e)
            elif o == 'bic': e = B('&', a_e, U('~', b_e))
            elif o in ('adc', 'sbc', 'rsc'):
                carry = ('cf',)
                e = {'adc': ('bin', '+', B('+', a_e, b_e), carry), 'sbc': ('bin', '-', B('-', a_e, b_e), ('bin', '-', C(1), carry)),
                     'rsc': ('bin', '-', B('-', b_e, a_e), ('bin', '-', C(1), carry))}[o]
            else: e = B(o, a_e, b_e)
            n = dst(rd)
            if sets_flags and rd.reg != A.ARM_REG_PC:
                if o in ('-',): newfl = setflags('cmp', a_e, b_e)
                elif o == '+': newfl = setflags('cmn', a_e, b_e)
                elif o == 'rsb': newfl = setflags('cmp', b_e, a_e)
                else:
                    S.append(('set', n, e)); newfl = setflags('res', V(n)); return S, spd, newfl
            if n == 'sp':
                if a_e[0] == 'sp' and b_e[0] == 'c' and spd is not None and o in ('+', '-'):
                    spd = spd + (b_e[1] if o == '+' else -b_e[1]); S2 = []
                    return S2, sx32(spd), newfl
                return S, None, newfl
            if n == 'pc': return [('asm', '%s %s' % (mn, ins.op_str), ['pc'], [])], spd, newfl
            S.append(('set', n, e)); return S, spd, newfl
        if I in (A.ARM_INS_MOV, A.ARM_INS_MVN, A.ARM_INS_MOVW, A.ARM_INS_MOVT) and len(ops) == 2 and ops[0].type == A.ARM_OP_REG:
            rd = ops[0]; n = dst(rd)
            if n == 'pc':
                return [('asm', '%s %s' % (mn, ins.op_str), ['pc'], [])], spd, newfl
            src = self.op2(ins, ops[1], i, spd)
            if I == A.ARM_INS_MVN: src = U('~', src)
            if I == A.ARM_INS_MOVT: src = ('bin', '|', B('&', V(n), C(0xFFFF)), C((ops[1].imm & 0xFFFF) << 16))
            if n == 'sp': return S, (spd if src[0] != 'sp' else src[1]), newfl
            S.append(('set', n, src))
            if sets_flags: newfl = setflags('res', V(n))
            return S, spd, newfl
        # shift pseudo-instructions: lsl rd, rm, rs/#imm
        sh = {A.ARM_INS_LSL: '<<', A.ARM_INS_LSR: '>>', A.ARM_INS_ASR: 'sar', A.ARM_INS_ROR: 'ror'}
        if I in sh and len(ops) == 2 and ops[1].type == A.ARM_OP_REG and ops[1].shift.type != 0:
            n = dst(ops[0]); S.append(('set', n, self.shifted(ins, ops[1], i, spd)))
            if sets_flags: newfl = setflags('res', V(n))
            return S, spd, newfl
        if I in sh and len(ops) >= 2:
            rd = ops[0]; a_e = R(ops[1]) if len(ops) == 3 else R(rd)
            amt = ops[-1]
            amt_e = C(amt.imm) if amt.type == A.ARM_OP_IMM else ('bin', '&', R(amt), C(255))
            if amt.type == A.ARM_OP_IMM and amt.imm == 0 and I != A.ARM_INS_LSL: amt_e = C(32)
            n = dst(rd); e = B(sh[I], a_e, amt_e)
            S.append(('set', n, e))
            if sets_flags: newfl = setflags('res', V(n))
            return S, spd, newfl
        if I == A.ARM_INS_RRX:
            S.append(('set', dst(ops[0]), ('un', 'rrx', R(ops[1])))); return S, spd, newfl
        if I in (A.ARM_INS_CMP, A.ARM_INS_CMN, A.ARM_INS_TST, A.ARM_INS_TEQ) and len(ops) >= 2:
            a_e = R(ops[0]); b_e = self.op2(ins, ops[1], i, spd)
            if I == A.ARM_INS_CMP: newfl = setflags('cmp', a_e, b_e)
            elif I == A.ARM_INS_CMN: newfl = setflags('cmn', a_e, b_e)
            elif I == A.ARM_INS_TST: S.append(('set', 'cc_a', B('&', a_e, b_e))); newfl = ('res', V('cc_a'), C(0))
            else: S.append(('set', 'cc_a', B('^', a_e, b_e))); newfl = ('res', V('cc_a'), C(0))
            return S, spd, newfl
        # ---- multiply ----
        if I == A.ARM_INS_MUL and len(ops) == 3:
            S.append(('set', dst(ops[0]), ('bin', '*', R(ops[1]), R(ops[2]))))
            if sets_flags: newfl = setflags('res', V(dst(ops[0])))
            return S, spd, newfl
        if I == A.ARM_INS_MLA and len(ops) == 4:
            S.append(('set', dst(ops[0]), ('bin', '+', ('bin', '*', R(ops[1]), R(ops[2])), R(ops[3])))); return S, spd, newfl
        if I == A.ARM_INS_MLS and len(ops) == 4:
            S.append(('set', dst(ops[0]), ('bin', '-', R(ops[3]), ('bin', '*', R(ops[1]), R(ops[2]))))); return S, spd, newfl
        if I in (A.ARM_INS_UMULL, A.ARM_INS_SMULL) and len(ops) == 4:
            f = 'umul64' if I == A.ARM_INS_UMULL else 'smul64'
            lo, hi = dst(ops[0]), dst(ops[1])
            S.append(('set', 'tmp64', ('bin', f, R(ops[2]), R(ops[3]))))
            S.append(('set', lo, ('un', 'lo32', V('tmp64')))); S.append(('set', hi, ('un', 'hi32', V('tmp64')))); return S, spd, newfl
        if I in (A.ARM_INS_UMLAL, A.ARM_INS_SMLAL) and len(ops) == 4:
            f = 'umul64' if I == A.ARM_INS_UMLAL else 'smul64'
            lo, hi = dst(ops[0]), dst(ops[1])
            S.append(('set', 'tmp64', ('bin', '+', ('bin', f, R(ops[2]), R(ops[3])), ('bin', 'cat64', V(hi), V(lo)))))
            S.append(('set', lo, ('un', 'lo32', V('tmp64')))); S.append(('set', hi, ('un', 'hi32', V('tmp64')))); return S, spd, newfl
        # ---- misc ALU ----
        if I == A.ARM_INS_ADR and len(ops) == 2 and ops[1].type == A.ARM_OP_IMM:
            S.append(('set', dst(ops[0]), C(ops[1].imm))); return S, spd, newfl
        if I == A.ARM_INS_CLZ: S.append(('set', dst(ops[0]), ('un', 'clz', R(ops[1])))); return S, spd, newfl
        if I == A.ARM_INS_REV: S.append(('set', dst(ops[0]), ('un', 'bswap32', R(ops[1])))); return S, spd, newfl
        if I == A.ARM_INS_REV16: S.append(('set', dst(ops[0]), ('un', 'bswap16x2', R(ops[1])))); return S, spd, newfl
        ext = {A.ARM_INS_UXTB: ('&', 0xFF), A.ARM_INS_UXTH: ('&', 0xFFFF), A.ARM_INS_SXTB: ('sx', 8), A.ARM_INS_SXTH: ('sx', 16)}
        if I in ext and len(ops) >= 2:
            k, v = ext[I]; src = self.op2(ins, ops[1], i, spd)
            if len(ops) >= 3 and ops[-1].type == A.ARM_OP_IMM and ops[-1].imm: src = ('bin', 'ror', src, C(ops[-1].imm))
            S.append(('set', dst(ops[0]), B('&', src, C(v)) if k == '&' else ('un', 'sx%d' % v, src))); return S, spd, newfl
        if I in (A.ARM_INS_UBFX, A.ARM_INS_SBFX) and len(ops) == 4:
            lsb, w = ops[2].imm, ops[3].imm
            e = B('>>', R(ops[1]), C(lsb)) if I == A.ARM_INS_UBFX else B('sar', B('<<', R(ops[1]), C(32 - lsb - w)), C(32 - w))
            if I == A.ARM_INS_UBFX: e = B('&', e, C((1 << w) - 1))
            S.append(('set', dst(ops[0]), e)); return S, spd, newfl
        if I == A.ARM_INS_BFC and len(ops) == 3:
            lsb, w = ops[1].imm, ops[2].imm
            S.append(('set', dst(ops[0]), B('&', R(ops[0]), C(~(((1 << w) - 1) << lsb))))); return S, spd, newfl
        if I == A.ARM_INS_BFI and len(ops) == 4:
            lsb, w = ops[2].imm, ops[3].imm; mask = ((1 << w) - 1) << lsb
            S.append(('set', dst(ops[0]), B('|', B('&', R(ops[0]), C(~mask)), B('&', B('<<', R(ops[1]), C(lsb)), C(mask))))); return S, spd, newfl
        # ---- loads / stores ----
        ldst = {A.ARM_INS_LDR: (4, False), A.ARM_INS_LDRB: (1, False), A.ARM_INS_LDRH: (2, False), A.ARM_INS_LDRSB: (1, True), A.ARM_INS_LDRSH: (2, True),
                A.ARM_INS_STR: (4, False), A.ARM_INS_STRB: (1, False), A.ARM_INS_STRH: (2, False),
                A.ARM_INS_LDRT: (4, False), A.ARM_INS_LDRBT: (1, False), A.ARM_INS_STRT: (4, False), A.ARM_INS_STRBT: (1, False)}
        if I in ldst and len(ops) >= 2 and ops[1].type == A.ARM_OP_MEM:
            size, sg = ldst[I]; is_ld = I in (A.ARM_INS_LDR, A.ARM_INS_LDRB, A.ARM_INS_LDRH, A.ARM_INS_LDRSB, A.ARM_INS_LDRSH, A.ARM_INS_LDRT, A.ARM_INS_LDRBT)
            mem = ops[1].mem; rt = ops[0]
            base_is_pc = mem.base == A.ARM_REG_PC
            if base_is_pc and not mem.index:
                addr = (self.pcval(i) + mem.disp) & M32
            else:
                addr = self.memaddr(ins, mem, i, spd)
            post = ins.post_index and len(ops) >= 3
            if post:
                off = ops[2]
                offe = self.op2(ins, off, i, spd)
                if off.type == A.ARM_OP_REG and off.subtracted: offe = U('neg', offe)
                if off.type == A.ARM_OP_IMM: offe = C(off.imm)
                addr = self.regexpr(ins, mem.base, i, spd)
            addr_e = C(addr) if isinstance(addr, int) else addr
            if mem.base == A.ARM_REG_PC and not mem.index and is_ld and size == 4:
                v = self.m.u32(addr)
                if v is not None:
                    n = dst(rt)
                    if n == 'pc': return [('asm', '%s %s' % (mn, ins.op_str), ['pc'], [])], spd, newfl
                    S.append(('set', n, ('c', v, 'pool', addr))); return S, spd, newfl
            if is_ld:
                n = dst(rt)
                if n == 'pc':
                    return [('asm', '%s %s' % (mn, ins.op_str), ['pc'], self.uses_of(ins))], spd, newfl
                if n == 'sp': return [('asm', '%s %s' % (mn, ins.op_str), ['sp'], self.uses_of(ins))], None, newfl
                S.append(('set', n, ('ld', size, sg, addr_e)))
            else:
                S.append(('st', size, addr_e, R(rt)))
            # writeback
            if ins.writeback and mem.base != A.ARM_REG_PC:
                bn = REGNAME.get(mem.base)
                if post: newb = B('-' if (ops[2].type == A.ARM_OP_REG and ops[2].subtracted) else '+', V(bn) if bn != 'sp' else ('sp', spd), self.op2(ins, ops[2], i, spd)) if ops[2].type == A.ARM_OP_REG else B('+', V(bn) if bn != 'sp' else ('sp', spd), C(ops[2].imm))
                else: newb = addr_e
                if bn == 'sp':
                    if newb[0] == 'sp': spd = newb[1]
                    else: spd = None
                else:
                    # base update must follow the access; the access above already used the old base
                    S.append(('set', bn, newb))
            return S, spd, newfl
        if I in (A.ARM_INS_LDRD, A.ARM_INS_STRD) and len(ops) >= 3 and ops[2].type == A.ARM_OP_MEM:
            addr_e = self.memaddr(ins, ops[2].mem, i, spd)
            for k in range(2):
                a2 = B('+', addr_e, C(4 * k))
                if I == A.ARM_INS_LDRD: S.append(('set', dst(ops[k]), ('ld', 4, False, a2)))
                else: S.append(('st', 4, a2, R(ops[k])))
            return S, spd, newfl
        # ---- push / pop / ldm / stm ----
        if I in (A.ARM_INS_PUSH, A.ARM_INS_POP) or I in (A.ARM_INS_LDM, A.ARM_INS_STM, A.ARM_INS_STMDB, A.ARM_INS_LDMDB, A.ARM_INS_LDMDA, A.ARM_INS_STMDA, A.ARM_INS_LDMIB, A.ARM_INS_STMIB):
            return self.lift_multi(ins, i, spd, newfl)
        # ---- atomics / system ----
        if I == A.ARM_INS_LDREX: S.append(('set', dst(ops[0]), ('ld', 4, False, self.memaddr(ins, ops[1].mem, i, spd)))); return S, spd, newfl
        if I == A.ARM_INS_STREX:
            S.append(('st', 4, self.memaddr(ins, ops[2].mem, i, spd), R(ops[1]))); S.append(('set', dst(ops[0]), C(0))); return S, spd, newfl
        if I == A.ARM_INS_LDREXB: S.append(('set', dst(ops[0]), ('ld', 1, False, self.memaddr(ins, ops[1].mem, i, spd)))); return S, spd, newfl
        if I == A.ARM_INS_STREXB:
            S.append(('st', 1, self.memaddr(ins, ops[2].mem, i, spd), R(ops[1]))); S.append(('set', dst(ops[0]), C(0))); return S, spd, newfl
        if I == A.ARM_INS_SWP or I == A.ARM_INS_SWPB:
            sz = 1 if I == A.ARM_INS_SWPB else 4
            a_e = self.memaddr(ins, ops[2].mem, i, spd)
            S.append(('set', 'tmp', ('ld', sz, False, a_e))); S.append(('st', sz, a_e, R(ops[1]))); S.append(('set', dst(ops[0]), V('tmp'))); return S, spd, newfl
        if I == A.ARM_INS_SVC:
            return [('svc', ops[0].imm if ops else 0, i.addr)], spd, newfl
        if I == A.ARM_INS_MRC and ins.op_str.startswith('p15, #0, ') and 'c13, c0, #3' in ins.op_str:
            S.append(('set', dst(ops[2]), V('tls'))); return S, spd, newfl
        if I == A.ARM_INS_BL or I == A.ARM_INS_BLX:
            return self.lift_call(ins, i, spd, newfl)
        return self.lift_vfp(ins, i, spd, newfl)

    def uses_of(self, ins):
        try: rd, wr = ins.regs_access()
        except Exception: return []
        return [REGNAME.get(r) or ins.reg_name(r) for r in rd]

    def lift_call(self, ins, i, spd, newfl):
        if i.kind == 'call':
            if i.call is not None: return [('call', C(i.call & ~1), i.addr, bool(i.call & 1))], spd, newfl
            ops = ins.operands
            tgt = self.regexpr(ins, ops[0].reg, i, spd) if ops and ops[0].type == A.ARM_OP_REG else V('?')
            return [('call', tgt, i.addr, False)], spd, newfl
        return [('asm', '%s %s' % (ins.mnemonic, ins.op_str), [], [])], spd, newfl

    def lift_multi(self, ins, i, spd, newfl):
        I = ins.id; ops = ins.operands; S = []
        regs = [o for o in ops if o.type == A.ARM_OP_REG]
        if I in (A.ARM_INS_PUSH, A.ARM_INS_POP):
            base_sp = True; pre = I == A.ARM_INS_PUSH; inc = I == A.ARM_INS_POP
        else:
            br = regs[0]; regs = regs[1:]
            base_sp = br.reg == A.ARM_REG_SP
            inc = I in (A.ARM_INS_LDM, A.ARM_INS_STM, A.ARM_INS_LDMIB, A.ARM_INS_STMIB)
            pre = I in (A.ARM_INS_LDMIB, A.ARM_INS_STMIB, A.ARM_INS_LDMDB, A.ARM_INS_STMDB)
        isld = I in (A.ARM_INS_POP, A.ARM_INS_LDM, A.ARM_INS_LDMDB, A.ARM_INS_LDMDA, A.ARM_INS_LDMIB)
        names = [REGNAME.get(o.reg) or ins.reg_name(o.reg) for o in regs]
        n = len(regs)
        saved = all(x in ('r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'lr', 'pc') for x in names)
        if base_sp and spd is not None:
            if I == A.ARM_INS_PUSH or (not inc and pre):  # full descending push
                start = spd - 4 * n
                if not saved:
                    for k, o in enumerate(regs): S.append(('st', 4, ('sp', start + 4 * k), self.regexpr(ins, o.reg, i, spd)))
                return S, sx32(start), newfl
            if I == A.ARM_INS_POP or (inc and not pre):
                if not saved:
                    for k, o in enumerate(regs):
                        S.append(('set', names[k], ('ld', 4, False, ('sp', spd + 4 * k))))
                return S, sx32(spd + 4 * n), newfl
        # generic ldm/stm through a general base register
        mem_base = self.regexpr(ins, ops[0].reg, i, spd) if not base_sp and I not in (A.ARM_INS_PUSH, A.ARM_INS_POP) else V('sp')
        off0 = (4 if pre else 0) if inc else (-4 * n if pre else -4 * n + 4)
        for k, o in enumerate(regs):
            a_e = B('+', mem_base, C(off0 + 4 * k))
            if isld: S.append(('set', names[k], ('ld', 4, False, a_e)))
            else: S.append(('st', 4, a_e, self.regexpr(ins, o.reg, i, spd)))
        if ins.writeback and not base_sp:
            bn = REGNAME.get(ops[0].reg)
            S.append(('set', bn, B('+', V(bn), C(4 * n if inc else -4 * n))))
        return S, (None if base_sp else spd), newfl

    def lift_vfp(self, ins, i, spd, newfl):
        I = ins.id; ops = ins.operands; mn = ins.mnemonic; S = []
        R = lambda op: self.regexpr(ins, op.reg, i, spd)
        dst = lambda op: REGNAME.get(op.reg) or ins.reg_name(op.reg)
        base = mn.split('.')[0]
        if ins.cc not in (0, A.ARM_CC_AL) and base[-2:] in CC.values(): base = base[:-2]
        if ins.cc not in (0, A.ARM_CC_AL) and base[-2:] in CC.values(): base = base[:-2]
        isf64 = '.f64' in mn
        bin_ops = {'vadd': '+', 'vsub': '-', 'vmul': '*', 'vdiv': '/'}
        if base in bin_ops and len(ops) == 3:
            S.append(('set', dst(ops[0]), ('bin', 'f' + bin_ops[base], R(ops[1]), R(ops[2])))); return S, spd, newfl
        if base == 'vnmul' and len(ops) == 3:
            S.append(('set', dst(ops[0]), ('un', 'fneg', ('bin', 'f*', R(ops[1]), R(ops[2]))))); return S, spd, newfl
        if base in ('vmla', 'vmls', 'vnmla', 'vnmls') and len(ops) == 3:
            prod = ('bin', 'f*', R(ops[1]), R(ops[2]))
            acc = R(ops[0])
            e = {'vmla': ('bin', 'f+', acc, prod), 'vmls': ('bin', 'f-', acc, prod), 'vnmla': ('un', 'fneg', ('bin', 'f+', acc, prod)),
                 'vnmls': ('bin', 'f-', prod, acc)}[base]
            S.append(('set', dst(ops[0]), e)); return S, spd, newfl
        un_ops = {'vneg': 'fneg', 'vabs': 'fabs', 'vsqrt': 'fsqrt'}
        if base in un_ops and len(ops) == 2:
            S.append(('set', dst(ops[0]), ('un', un_ops[base], R(ops[1])))); return S, spd, newfl
        if base == 'vmov' and len(ops) == 2:
            if ops[1].type == A.ARM_OP_FP: S.append(('set', dst(ops[0]), ('fc', ops[1].fp))); return S, spd, newfl
            if ops[1].type == A.ARM_OP_IMM: S.append(('set', dst(ops[0]), ('fc', float(ops[1].imm)))); return S, spd, newfl
            if ops[0].type == A.ARM_OP_REG and ops[1].type == A.ARM_OP_REG:
                a, b = dst(ops[0]), R(ops[1])
                ra = a[0] if a else ''
                if ra in 'sd' and not isinstance(b, int) and b[0] == 'v' and b[1].startswith('r'):
                    S.append(('set', a, ('un', 'bits2f', b))); return S, spd, newfl
                if a.startswith('r') and b[0] == 'v' and b[1][0] in 'sd':
                    S.append(('set', a, ('un', 'f2bits', b))); return S, spd, newfl
                S.append(('set', a, b)); return S, spd, newfl
        if base == 'vmov' and len(ops) == 3 and ops[0].type == A.ARM_OP_REG:
            # vmov rLo, rHi, dN  or vmov dN, rLo, rHi
            a0 = dst(ops[0])
            if a0.startswith('d'):
                S.append(('set', a0, ('bin', 'cat64', R(ops[2]), R(ops[1])))); return S, spd, newfl
            if a0.startswith('r'):
                S.append(('set', a0, ('un', 'lo32', R(ops[2])))); S.append(('set', dst(ops[1]), ('un', 'hi32', R(ops[2])))); return S, spd, newfl
        if base == 'vcvt' or base == 'vcvtr' or base == 'vcvtb' or base == 'vcvtt':
            if len(ops) >= 2 and ops[0].type == A.ARM_OP_REG and ops[1].type == A.ARM_OP_REG:
                t = mn.split('.')[1:]
                S.append(('set', dst(ops[0]), ('un', 'cvt_' + '_'.join(t), R(ops[1])))); return S, spd, newfl
        if base in ('vcmp', 'vcmpe') and len(ops) == 2:
            b = R(ops[1]) if ops[1].type == A.ARM_OP_REG else ('fc', 0.0)
            S.append(('set', 'cc_a', R(ops[0]))); S.append(('set', 'cc_b', b))
            return S, spd, ('fcmp', V('cc_a'), V('cc_b'))
        if base == 'vmrs' and ins.op_str.lower().startswith('apsr_nzcv'): return S, spd, newfl      # flags already in fcmp descriptor
        if base in ('vldr', 'vstr') and len(ops) == 2 and ops[1].type == A.ARM_OP_MEM:
            mem = ops[1].mem
            if mem.base == A.ARM_REG_PC: addr = C((self.pcval(i) + mem.disp) & M32)
            else: addr = self.memaddr(ins, mem, i, spd)
            sz = 8 if dst(ops[0]).startswith('d') else 4
            if base == 'vldr':
                if mem.base == A.ARM_REG_PC:
                    raw = self.m.read(addr[1], sz)
                    if raw is not None and len(raw) == sz:
                        fv = struct.unpack('<d' if sz == 8 else '<f', raw)[0]
                        S.append(('set', dst(ops[0]), ('fc', fv, addr[1]))); return S, spd, newfl
                S.append(('set', dst(ops[0]), ('ld', sz, False, addr)))
            else: S.append(('st', sz, addr, R(ops[0])))
            return S, spd, newfl
        if base in ('vpush', 'vpop'):
            regs = [o for o in ops if o.type == A.ARM_OP_REG]
            w = 8 if dst(regs[0]).startswith('d') else 4
            n = len(regs) * w
            if spd is None: return S, None, newfl
            if base == 'vpush': return S, sx32(spd - n), newfl
            return S, sx32(spd + n), newfl
        if base in ('vldmia', 'vldm', 'vstmia', 'vstm', 'vldmdb', 'vstmdb', 'vldr', 'vstr') and ops and ops[0].type == A.ARM_OP_REG:
            regs = [o for o in ops[1:] if o.type == A.ARM_OP_REG]
            w = 8 if regs and dst(regs[0]).startswith('d') else 4
            a_e = self.regexpr(ins, ops[0].reg, i, spd)
            isld = base.startswith('vld')
            for k, o in enumerate(regs):
                a2 = B('+', a_e, C(w * k))
                if isld: S.append(('set', dst(o), ('ld', w, False, a2)))
                else: S.append(('st', w, a2, R(o)))
            if ins.writeback:
                bn = REGNAME.get(ops[0].reg)
                if bn and bn != 'sp': S.append(('set', bn, B('+' if 'db' not in base else '-', V(bn), C(w * len(regs)))))
            return S, spd, newfl
        # ---- generic fallback: keep Capstone's read/write sets ----
        try: rd, wr = ins.regs_access()
        except Exception: rd, wr = [], []
        nm = lambda r: REGNAME.get(r) or ins.reg_name(r)
        defs = [nm(r) for r in wr if nm(r) not in ('pc', 'apsr', 'cpsr', 'fpscr', 'sp', 'spsr') and not nm(r).startswith('apsr')]
        uses = [nm(r) for r in rd if nm(r) not in ('pc', 'apsr', 'cpsr', 'fpscr', 'sp', 'spsr') and not nm(r).startswith('apsr')]
        if A.ARM_REG_SP in list(rd) + list(wr): pass
        return [('asm', '%s %s' % (mn, ins.op_str), defs, uses)], spd, newfl
