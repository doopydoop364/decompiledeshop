#!/usr/bin/env python3
"""Quick disassembly helper: v4_dis.py <hexva> <hexlen> [t]   (t = Thumb)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_disasm import *
m = Map()
a = int(sys.argv[1], 16); n = int(sys.argv[2], 16); th = len(sys.argv) > 3 and sys.argv[3] == 't'
for x in (cs_t if th else cs).disasm(m.read(a, n), a):
    print('%08x  %-8s %s %s' % (x.address, x.bytes.hex(), x.mnemonic, x.op_str))
