from pathlib import Path
import struct

d=Path("code_decompressed.bin").read_bytes()
TEXT_VA=0x100000
TEXT_SIZE=0x2B2638
RO_VA=0x3B3000
RO_START=(TEXT_SIZE+0xFFF)&~0xFFF

def u32(o): return struct.unpack_from("<I",d,o)[0]
def va2f(va):
    if TEXT_VA <= va < TEXT_VA+TEXT_SIZE: return va-TEXT_VA
    if RO_VA <= va < 0x3DA000: return RO_START+(va-RO_VA)
    return None
def s(off):
    if off is None or off>=len(d): return ""
    e=off
    while e<len(d) and 32<=d[e]<=126: e+=1
    return d[off:e].decode("ascii","replace") if e-off>=4 else ""

targets=[0x1A7DE8,0x1A7DEC,0x1A7DF0,0x1A7DF4,0x1A7DF8,0x1A7DFC,0x1A7E00,
         0x1A7E04,0x1A7E0C,0x1A7EEC,0x1A7EF8,0x1A7EFC,0x1A7F00,0x1A7F04,
         0x1A7F08,0x1A7F0C,0x1A7F10]

out=["Shared HTTP literal-pool / pointer-chain trace",""]
for off in targets:
    w=u32(off)
    out.append(f"FILE 0x{off:08X} VA 0x{TEXT_VA+off:08X}: {w:08X}")
    if TEXT_VA <= w < 0x500000:
        fo=va2f(w)
        out.append(f"  word-as-VA -> file 0x{fo:08X}" if fo is not None else "  word-as-VA -> unmapped")
        if fo is not None:
            out.append(f"  pointee dword: 0x{u32(fo):08X}")
            ps=va2f(u32(fo))
            if ps is not None: out.append(f"  pointee-of-pointee file: 0x{ps:08X}")
            st=s(fo)
            if st: out.append(f"  ASCII: {st}")
    out.append("")

# Dump all printable strings near every resolved pointer target.
out.append("Pointer targets near the shared routine:")
seen=set()
for off in range(0x1A7B94,0x1A7DE8,4):
    w=u32(off)
    if 0x003B3000 <= w < 0x003DA000:
        fo=va2f(w)
        if fo is not None and fo not in seen:
            seen.add(fo)
            out.append(f"0x{TEXT_VA+off:08X} -> VA 0x{w:08X} file 0x{fo:08X} ASCII={s(fo)!r}")
Path("analysis/shared_http_pointer_chain.txt").write_text("\n".join(out),encoding="utf-8")
