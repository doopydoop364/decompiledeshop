from pathlib import Path
import struct

data = Path("code_decompressed.bin").read_bytes()

# Known reference locations from network_address_refs.txt.
targets = [
    0x0021EE5C,
    0x0021FF24,
    0x00220294,
    0x00220788,
    0x0021FAD8,
    0x00221D10,
    0x00220470,
]

def u16(o):
    return struct.unpack_from("<H", data, o)[0]

def u32(o):
    return struct.unpack_from("<I", data, o)[0]

def arm_movw_movt(addr, word):
    # ARM MOVW/MOVT immediate decoder, useful for detecting address construction.
    if ((word >> 25) & 0x7f) != 0x30:
        return None
    op = (word >> 20) & 0x1f
    if op not in (0x10, 0x14):
        return None
    rd = (word >> 12) & 0xf
    imm16 = ((word >> 16) & 0xf) | ((word >> 4) & 0xf000)
    kind = "MOVT" if op == 0x14 else "MOVW"
    return f"{kind} r{rd}, #0x{imm16:04X}"

def decode_arm(word):
    # Small decoder for common instructions useful around literal/address refs.
    cond = (word >> 28) & 0xf
    if ((word >> 25) & 0x7) == 0b101:
        off = word & 0x00ffffff
        if off & 0x00800000:
            off -= 0x01000000
        target = (off << 2)
        link = bool(word & (1 << 24))
        return f"{'BL' if link else 'B'} {target:+#x} (PC-relative)"
    if (word & 0x0C000000) == 0x04000000:
        l = bool(word & (1 << 20))
        rn = (word >> 16) & 0xf
        rd = (word >> 12) & 0xf
        imm = word & 0xfff
        sign = "-" if not (word & (1 << 23)) else "+"
        return f"{'LDR' if l else 'STR'} r{rd}, [r{rn}, {sign}0x{imm:X}]"
    if (word & 0x0C000000) == 0x00000000:
        rd = (word >> 12) & 0xf
        rn = (word >> 16) & 0xf
        rm = word & 0xf
        return f"data-processing r{rd}, r{rn}, r{rm}"
    mt = arm_movw_movt(0, word)
    return mt

out = []
out.append("Focused ARM/Thumb context around network reference sites")
out.append("")

for target in targets:
    out.append(f"=== TARGET file offset 0x{target:08X} ===")
    # Show a generous window; this is still small enough to inspect manually.
    lo = max(0, target - 0x80)
    hi = min(len(data), target + 0x100)

    # ARM interpretation, 4-byte aligned.
    out.append("-- ARM 32-bit words --")
    start = lo & ~3
    for p in range(start, hi - 3, 4):
        w = u32(p)
        text = decode_arm(w)
        mark = " <TARGET>" if p == target else ""
        if text:
            out.append(f"0x{p:08X}: {w:08X}  {text}{mark}")
        else:
            out.append(f"0x{p:08X}: {w:08X}{mark}")

    # Thumb-2 interpretation, 2-byte aligned, showing raw halfwords.
    out.append("-- Thumb halfwords --")
    start = lo & ~1
    for p in range(start, hi - 1, 2):
        h = u16(p)
        mark = " <TARGET>" if p == target else ""
        out.append(f"0x{p:08X}: {h:04X}{mark}")

    out.append("")

Path("analysis/network_instruction_context.txt").write_text("\n".join(out), encoding="utf-8")
