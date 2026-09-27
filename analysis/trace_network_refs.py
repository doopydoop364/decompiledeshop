from pathlib import Path
import re, struct

data = Path("code_decompressed.bin").read_bytes()

patterns = re.compile(
    rb'(https?://|ninja\\.ctr|samurai\\.ctr|ccif\\.ctr|'
    rb'ninja/ws/|samurai/ws/|service_hosts|X-Nintendo-ServiceToken|'
    rb'tagaya.*versionlist)',
    re.I
)

strings = []
for m in re.finditer(rb'[ -~]{8,}', data):
    raw = m.group()
    if patterns.search(raw):
        strings.append((m.start(), raw.decode("ascii", "replace")))

out = []
out.append("Focused references to network endpoint strings")
out.append(f"Binary size: {len(data):,} bytes")
out.append(f"Candidate endpoint strings: {len(strings)}")
out.append("")

for off, s in strings:
    out.append(f"STRING 0x{off:08X} ({off})")
    out.append(f"  {s}")

    needles = {
        f"file_offset_le": struct.pack("<I", off),
        f"file_offset_be": struct.pack(">I", off),
    }

    refs = []
    for kind, needle in needles.items():
        pos = 0
        while True:
            p = data.find(needle, pos)
            if p < 0:
                break
            refs.append((p, kind))
            pos = p + 1

    # Also inspect words near each reference as a compact code/data clue.
    if refs:
        for p, kind in refs[:32]:
            lo = max(0, p - 16)
            hi = min(len(data), p + 20)
            chunk = data[lo:hi]
            out.append(f"  REF 0x{p:08X} {kind} bytes={chunk.hex()}")
        if len(refs) > 32:
            out.append(f"  ... {len(refs)-32} more references omitted")
    else:
        out.append("  REF none (direct file-offset pointer not found)")

    out.append("")

Path("analysis/network_refs.txt").write_text("\n".join(out), encoding="utf-8")
