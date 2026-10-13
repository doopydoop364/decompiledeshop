#!/usr/bin/env python3
"""Differential-test vector generator (development tool only; not part of the app).

Runs selected *leaf* functions of the ORIGINAL ARM executable (code_decompressed.bin,
supplied by the repo owner, mapped flat at 0x100000) inside the Unicorn CPU core and
records inputs/outputs. The C++ reconstructions in src/original/ are then checked
against these recorded results. The vectors contain only synthetic input data and
observed return/memory values -- no Nintendo code or assets.

Usage: oracle_vectors.py <code_decompressed.bin> <out_dir>
"""
import os, random, sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_PROT_ALL
from unicorn.arm_const import *

BASE = 0x100000
A_BASE, B_BASE, STACK = 0x10000000, 0x20000000, 0x30000000
BUF = 0x2000
WIN = 384   # only this prefix of each buffer is non-zero / recorded
MASK = 0xFFFFFFFF

class Oracle:
    def __init__(self, path):
        self.code = open(path, 'rb').read()
    def call(self, addr, args, a, b):
        """addr: function address; bit0 set => Thumb. Returns (r0, r1, a', b')."""
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB if addr & 1 else UC_MODE_ARM)
        uc.mem_map(BASE, (len(self.code) + 0xFFF) & ~0xFFF, UC_PROT_ALL)
        uc.mem_write(BASE, self.code)
        for base in (A_BASE, B_BASE, STACK):
            uc.mem_map(base, BUF, UC_PROT_ALL)
        uc.mem_write(A_BASE, a); uc.mem_write(B_BASE, b)
        uc.mem_map(0x40000000, 0x1000, UC_PROT_ALL)
        for i, v in enumerate(args):
            uc.reg_write(UC_ARM_REG_R0 + i, v & MASK)
        uc.reg_write(UC_ARM_REG_SP, STACK + BUF - 0x100)
        uc.reg_write(UC_ARM_REG_LR, 0x40000000)  # return trap (ARM, even)
        # return address 0x40000000 has no code: stop when PC reaches it
        uc.emu_start(addr, 0x40000000, count=2_000_000)
        return (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                bytes(uc.mem_read(A_BASE, BUF)), bytes(uc.mem_read(B_BASE, BUF)))

def rbytes(r, n, zero_free=False):
    return bytes(r.randrange(1, 256) if zero_free else r.randrange(256) for _ in range(n))

def main():
    code, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    o = Oracle(code); r = random.Random(0x3D5)
    # name -> (addr, kind). Cases file: one case per line, whitespace separated:
    #   oa ob n  A_hex B_hex  ret  A_after_hex B_after_hex
    # oa/ob are byte offsets of the pointer arguments inside buffers A/B.
    specs = {
        'cstring_length_002a8f8c':   0x2a8f8c,
        'string16_length_002a0964':  0x2a0964 | 1,
        'compare_bytes_0029e4f0':    0x29e4f0 | 1,
        'cstring_copy_002a8f1c':     0x2a8f1c,
        'cstring_append_00100186':   0x100186 | 1,
        'copy_bytes_forward_0029b7a0': 0x29b7a0,
        'copy_bytes_forward_002a81f0': 0x2a81f0,
    }
    for name, addr in specs.items():
        lines = []
        for _ in range(200):
            oa, ob = r.randrange(0, 8), r.randrange(0, 8)
            n = r.choice([0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 100, 200])
            a = bytearray(rbytes(r, WIN)) + bytearray(BUF - WIN); b = bytearray(rbytes(r, WIN)) + bytearray(BUF - WIN)
            if name.startswith('cstring_length'):
                s = rbytes(r, r.choice([0, 1, 2, 3, 4, 5, 8, 31, 130]), True)
                a[oa:oa+len(s)+1] = s + b'\0'
                args = [A_BASE + oa]
            elif name.startswith('string16_length'):
                oa &= ~1
                k = r.choice([0, 1, 2, 5, 33])
                a[oa:oa+2*k+2] = b''.join((r.randrange(1, 65536)).to_bytes(2, 'little') for _ in range(k)) + b'\0\0'
                args = [A_BASE + oa]
            elif name.startswith('compare_bytes'):
                if r.random() < 0.6:
                    b[ob:ob+n] = a[oa:oa+n]
                    if n and r.random() < 0.7:
                        j = r.randrange(n); b[ob+j] = (b[ob+j] + r.randrange(1, 256)) & 255
                if r.random() < 0.3: ob = oa  # aligned fast path
                args = [A_BASE + oa, B_BASE + ob, n]
            elif name.startswith('cstring_copy'):
                s = rbytes(r, r.choice([0, 1, 2, 3, 4, 5, 8, 31, 130]), True)
                a[oa:oa+len(s)+1] = s + b'\0'
                if r.random() < 0.3: ob = oa
                args = [B_BASE + ob, A_BASE + oa]
            elif name.startswith('cstring_append'):
                s = rbytes(r, r.choice([0, 1, 4, 31]), True); t = rbytes(r, r.choice([0, 1, 4, 31]), True)
                b[ob:ob+len(s)+1] = s + b'\0'; a[oa:oa+len(t)+1] = t + b'\0'
                args = [B_BASE + ob, A_BASE + oa]
            else:  # copy_bytes_forward: dst=B, src=A, byte_count
                args = [B_BASE + ob, A_BASE + oa, n]
            r0, r1, a2, b2 = o.call(addr, args, bytes(a), bytes(b))
            assert a2[WIN:] == bytes(BUF - WIN) and b2[WIN:] == bytes(BUF - WIN), 'write outside window'
            lines.append(f"{oa} {ob} {n} {bytes(a[:WIN]).hex()} {bytes(b[:WIN]).hex()} {r0:08x} {a2[:WIN].hex()} {b2[:WIN].hex()}")
        with open(os.path.join(out, name + '.vec'), 'w') as f:
            f.write('\n'.join(lines) + '\n')
        print(name, len(lines), 'cases')

if __name__ == '__main__':
    main()
