from pathlib import Path
import struct, re

code = Path("code_decompressed.bin").read_bytes()
exh = Path("extheader.bin").read_bytes()

def u32(off):
    return struct.unpack_from("<I", exh, off)[0]

# ExHeader SCI Code Set Info:
# 0x10 text: address, pages, size
# 0x20 rodata: address, pages, size
# 0x30 data: address, pages, size
text_addr, text_pages, text_size = u32(0x10), u32(0x14), u32(0x18)
ro_addr, ro_pages, ro_size = u32(0x20), u32(0x24), u32(0x28)
data_addr, data_pages, data_size = u32(0x30), u32(0x34), u32(0x38)

lines = []
lines.append("3DS code address / network reference analysis")
lines.append("")
lines.append(f"Binary size: 0x{len(code):X} ({len(code):,})")
lines.append(f"TEXT: addr=0x{text_addr:08X} pages=0x{text_pages:X} size=0x{text_size:X} ({text_size:,})")
lines.append(f"RODATA: addr=0x{ro_addr:08X} pages=0x{ro_pages:X} size=0x{ro_size:X} ({ro_size:,})")
lines.append(f"DATA: addr=0x{data_addr:08X} pages=0x{data_pages:X} size=0x{data_size:X} ({data_size:,})")
lines.append("")

# The decompressed .code is normally laid out as text, rodata, data,
# with page alignment between regions. Try both exact-size and page-aligned
# starts because dumps can differ in how they preserve padding.
PAGE = 0x1000
layouts = []
for align_ro in (False, True):
    ro_start = text_size if not align_ro else (text_size + PAGE - 1) & ~(PAGE - 1)
    data_start = ro_start + ro_size if not align_ro else (ro_start + ro_size + PAGE - 1) & ~(PAGE - 1)
    if data_start <= len(code):
        layouts.append((f"exact" if not align_ro else "page-aligned", ro_start, data_start))

# Find all endpoint strings in the binary.
rx = re.compile(rb'(?:https?://|%s/(?:ninja|samurai)/ws/|(?:ninja|samurai)\\.ctr\\.shop\\.nintendo\\.net|'
                 rb'X-Nintendo-ServiceToken|service_hosts|tagaya.*versionlist)', re.I)

strings = []
for m in re.finditer(rb'[ -~]{8,}', code):
    if rx.search(m.group()):
        strings.append((m.start(), m.group().decode("ascii", "replace")))

lines.append(f"Network strings found: {len(strings)}")
lines.append("")

for layout_name, ro_start, data_start in layouts:
    lines.append(f"=== Layout candidate: {layout_name} ===")
    lines.append(f"rodata file start=0x{ro_start:X}, data file start=0x{data_start:X}")

    hits = 0
    for off, s in strings:
        if ro_start <= off < ro_start + ro_size:
            va = ro_addr + (off - ro_start)
        elif data_start <= off < data_start + data_size:
            va = data_addr + (off - data_start)
        elif off < text_size:
            va = text_addr + off
        else:
            continue

        refs = []
        for needle in (struct.pack("<I", va), struct.pack("<I", va & 0xFFFFFFFF)):
            pos = 0
            while True:
                p = code.find(needle, pos)
                if p < 0:
                    break
                if p != off:
                    refs.append(p)
                pos = p + 1

        # Also search the address with the low Thumb bit set.
        thumb = va | 1
        needle = struct.pack("<I", thumb)
        pos = 0
        while True:
            p = code.find(needle, pos)
            if p < 0:
                break
            if p != off:
                refs.append(p)
            pos = p + 1

        if refs:
            hits += 1
            uniq = sorted(set(refs))
            lines.append(f"STRING file=0x{off:08X} VA=0x{va:08X}")
            lines.append(f"  {s}")
            for p in uniq[:16]:
                lo, hi = max(0,p-24), min(len(code),p+28)
                lines.append(f"  REF file=0x{p:08X} bytes={code[lo:hi].hex()}")
            if len(uniq) > 16:
                lines.append(f"  ... {len(uniq)-16} more")
    lines.append(f"Referenced network strings in this layout: {hits}")
    lines.append("")

Path("analysis/network_address_refs.txt").write_text("\n".join(lines), encoding="utf-8")
