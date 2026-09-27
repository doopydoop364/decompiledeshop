from pathlib import Path
import struct

data = Path("code_decompressed.bin").read_bytes()
TEXT_VA = 0x00100000
SHARED = 0x001A7B94

def u32(o):
    return struct.unpack_from("<I", data, o)[0]

def file_from_va(va):
    if TEXT_VA <= va < TEXT_VA + 0x2B2638:
        return va - TEXT_VA
    return None

def arm_branch_target(file_off, word):
    if ((word >> 25) & 0x7) != 0b101:
        return None
    imm = word & 0x00ffffff
    if imm & 0x00800000:
        imm -= 0x01000000
    pc = TEXT_VA + file_off + 8
    return (pc + (imm << 2)) & 0xffffffff

# Endpoint wrapper starts observed immediately after their string-pointer tables.
wrappers = {
    "service_hosts": 0x0021EE60,
    "online_prices": 0x0021FF28,
    "recommend_title": 0x00220298,
    "directories": 0x0022078C,
    "prepurchase_info": 0x0021FADC + 4,
    "coupon_titles": 0x00221D14,
    "transactions": 0x00220474,
}

out = []
out.append("Shared HTTP routine trace")
out.append(f"Expected shared target VA: 0x{SHARED:08X}")
out.append(f"Expected shared target file offset: 0x{file_from_va(SHARED):08X}")
out.append("")

# Scan all ARM BL instructions in each wrapper and print their exact targets.
for name, start in wrappers.items():
    off = start
    end = min(len(data), start + 0x180)
    out.append(f"=== {name} @ file 0x{start:08X}, VA 0x{TEXT_VA+start:08X} ===")
    for p in range(off, end - 3, 4):
        w = u32(p)
        target = arm_branch_target(p, w)
        if target is not None and (w & (1 << 24)):
            tf = file_from_va(target)
            if tf is None:
                out.append(f"BL file=0x{p:08X} -> VA=0x{target:08X} (outside text)")
            else:
                out.append(f"BL file=0x{p:08X} -> VA=0x{target:08X} file=0x{tf:08X}")
    out.append("")

# Dump a larger raw instruction window around the shared routine.
shared_off = file_from_va(SHARED)
if shared_off is not None:
    out.append("=== SHARED ROUTINE ===")
    lo = max(0, shared_off - 0x100)
    hi = min(len(data), shared_off + 0x500)
    for p in range(lo & ~3, hi - 3, 4):
        w = u32(p)
        target = arm_branch_target(p, w)
        if target is not None:
            out.append(f"0x{p:08X} VA=0x{TEXT_VA+p:08X} {w:08X} BRANCH -> VA 0x{target:08X}")
        else:
            out.append(f"0x{p:08X} VA=0x{TEXT_VA+p:08X} {w:08X}")

Path("analysis/shared_http_trace.txt").write_text("\n".join(out), encoding="utf-8")
