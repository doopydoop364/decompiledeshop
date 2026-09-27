from pathlib import Path
import struct

data = Path("code_decompressed.bin").read_bytes()
TEXT_VA = 0x00100000
TEXT_SIZE = 0x2B2638
RO_VA = 0x003B3000
RO_SIZE = 0x24000  # only used as a sanity bound; actual file offsets are resolved below

# Page-aligned layout used by the earlier address trace.
RO_FILE = (TEXT_SIZE + 0xFFF) & ~0xFFF
DATA_VA = 0x003DA000

def u32(o):
    return struct.unpack_from("<I", data, o)[0]

def va_to_file(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SIZE:
        return va - TEXT_VA
    if RO_VA <= va < DATA_VA:
        return RO_FILE + (va - RO_VA)
    return None

def printable_at(off):
    if off is None or not (0 <= off < len(data)):
        return None
    end = off
    while end < len(data) and 32 <= data[end] <= 126:
        end += 1
    if end - off >= 4:
        return data[off:end].decode("ascii", "replace")
    return None

def decode_ldr_literal(off, word):
    # ARM LDR/STR immediate, literal form: cond 01 I=0 P=1 W=0 L=1 Rn=PC.
    if ((word >> 26) & 0x3) != 0b01:
        return None
    if ((word >> 25) & 1) != 0:  # register-offset form
        return None
    if ((word >> 24) & 1) != 1:  # P
        return None
    if ((word >> 21) & 1) != 0:  # W
        return None
    if ((word >> 20) & 1) != 1:  # L
        return None
    rn = (word >> 16) & 0xF
    if rn != 15:
        return None
    rd = (word >> 12) & 0xF
    imm = word & 0xFFF
    pc = TEXT_VA + off + 8
    target = pc + imm if ((word >> 23) & 1) else pc - imm
    return rd, target

def decode_arm_branch(off, word):
    if ((word >> 25) & 0x7) != 0b101:
        return None
    imm = word & 0x00FFFFFF
    if imm & 0x00800000:
        imm -= 0x01000000
    return (TEXT_VA + off + 8 + (imm << 2)) & 0xFFFFFFFF

start = 0x001A7B94
end = start + 0x500

out = [
    "Shared HTTP routine literal/reference trace",
    f"Routine file offset: 0x{start:08X}",
    f"Routine VA:          0x{TEXT_VA + start:08X}",
    "",
    "LDR literal references in the routine:",
]

for p in range(start, min(end, len(data) - 3), 4):
    w = u32(p)
    dec = decode_ldr_literal(p, w)
    if dec:
        rd, target = dec
        fo = va_to_file(target)
        value = u32(fo) if fo is not None and fo + 4 <= len(data) else None
        s = printable_at(value if value is not None else None)
        out.append(
            f"0x{p:08X} VA=0x{TEXT_VA+p:08X} {w:08X} "
            f"LDR r{rd}, [pc] -> VA 0x{target:08X}"
        )
        if fo is None:
            out.append("  target file offset: UNMAPPED")
        else:
            out.append(f"  target file offset: 0x{fo:08X}")
            out.append(f"  32-bit value: 0x{value:08X}")
            if s:
                out.append(f"  ASCII: {s}")

out += ["", "Branches/calls from the routine:"]
for p in range(start, min(end, len(data) - 3), 4):
    w = u32(p)
    target = decode_arm_branch(p, w)
    if target is not None:
        link = bool(w & (1 << 24))
        out.append(
            f"0x{p:08X} VA=0x{TEXT_VA+p:08X} {w:08X} "
            f"{'BL' if link else 'B'} -> VA 0x{target:08X}"
        )

Path("analysis/shared_http_literals.txt").write_text("\n".join(out), encoding="utf-8")
