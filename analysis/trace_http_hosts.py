#!/usr/bin/env python3
import struct

BIN="code_decompressed.bin"
OUT="analysis/http_host_trace.txt"
data=open(BIN,"rb").read()

TEXT_VA=0x00100000
RO_FILE=0x002B3000
RO_VA=0x003B3000
DATA_FILE=0x002DA000
DATA_VA=0x003DA000

def u32(off): return struct.unpack_from("<I",data,off)[0]
def va(off): return TEXT_VA+off
def off_for_va(v):
    if TEXT_VA <= v < TEXT_VA+0x2B2638: return v-TEXT_VA
    if RO_VA <= v < DATA_VA: return RO_FILE+(v-RO_VA)
    if DATA_VA <= v < DATA_VA+0x15D68: return DATA_FILE+(v-DATA_VA)
    return None
def s_at(off):
    if off is None or off<0 or off>=len(data): return None
    b=data[off:off+512]; z=b.find(b"\\0")
    if z<0: z=min(len(b),200)
    try:
        s=b[:z].decode("ascii")
        return s if s.isprintable() else None
    except: return None

targets={
 "ninja_base":0x002D1500,
 "samurai_base":0x002D1504,
 "ccif_base":0x002D14F4,
 "service_hosts_fmt":0x002D15D8,
 "online_prices_fmt":0x002D1570,
 "directories_fmt":0x002D1784,
 "recommend_fmt":0x002D1514,
}
with open(OUT,"w") as f:
    f.write("HTTP HOST / REQUEST ARGUMENT TRACE\\n")
    f.write("page-aligned mapping: TEXT file=0x0 VA=0x100000; RODATA file=0x2B3000 VA=0x3B3000; DATA file=0x2DA000 VA=0x3DA000\\n\\n")
    for name,so in targets.items():
        f.write(f"{name}: file=0x{so:08X} VA=0x{va(so):08X} string={s_at(so)!r}\\n")
        refs=[]
        needle=struct.pack("<I",va(so))
        start=0
        while True:
            p=data.find(needle,start)
            if p<0: break
            refs.append(p); start=p+1
        f.write(f"  exact pointer refs: {len(refs)}\\n")
        for p in refs[:20]:
            f.write(f"    ref file=0x{p:08X} VA=0x{va(p):08X}\\n")
    f.write("\\n=== WRAPPER WINDOWS AROUND SHARED HTTP CALLS ===\\n")
    call_sites=[0x21EE90,0x21EF30,0x21EFC0,0x21FF48,0x21FFF8,0x2202B0,0x220334,0x220398,0x2207BC,0x220870,0x21FB3C,0x21FBD4,0x21FC4C,0x221D40,0x221DA4,0x2204C8,0x2205B0]
    for c in call_sites:
        f.write(f"\\nCALL file=0x{c:08X} VA=0x{va(c):08X} -> shared VA=0x002A7B94\\n")
        for p in range(max(0,c-0x30),c+4,4):
            w=u32(p)
            # ARM literal LDR: 0xE59Fxxxx / 0xE51Fxxxx
            lit=None
            if (w & 0x0F7F0000)==0x051F0000:
                imm=w&0xFFF; up=bool(w&0x00800000)
                pc=va(p)+8; litva=pc+imm if up else pc-imm
                lit=off_for_va(litva)
            f.write(f"  0x{va(p):08X}: {w:08X}")
            if lit is not None:
                f.write(f"  literal VA=0x{litva:08X} file=0x{lit:08X} val=0x{u32(lit):08X} str={s_at(lit)!r}")
            f.write("\\n")
    f.write("\\n=== DATA VALUES AROUND BASE-URL STRUCTURE ===\\n")
    for base in [0x002E1D80,0x002E1D90,0x002E1DA0,0x002E1DB0,0x002E1DC0,0x002E1DD0]:
        f.write(f"\\nfile 0x{base:08X}:\\n")
        for p in range(base,base+0x30,4):
            w=u32(p)
            mapped=off_for_va(w)
            extra=f" -> file 0x{mapped:08X} str={s_at(mapped)!r}" if mapped is not None else ""
            f.write(f"  +0x{p-base:02X} 0x{w:08X}{extra}\\n")
