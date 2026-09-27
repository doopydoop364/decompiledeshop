from pathlib import Path

src = Path("eshop_decompile_v3.txt").read_text(errors="replace")
terms = [
    "ninja/ws/",
    "samurai/ws/",
    "service_hosts",
    "X-Nintendo-ServiceToken",
    "ninja.ctr.shop.nintendo.net",
    "samurai.ctr.shop.nintendo.net",
    "ccif.ctr.shop.nintendo.net",
    "tagaya-ctr.cdn.nintendo.net",
]

lines = src.splitlines()
out = []

for i, line in enumerate(lines):
    if any(t in line for t in terms):
        start = max(0, i - 12)
        end = min(len(lines), i + 13)
        out.append(f"=== lines {start + 1}-{end} ===")
        out.extend(f"{n + 1}: {lines[n]}" for n in range(start, end))
        out.append("")

Path("analysis/network_code_context.txt").write_text(
    "\n".join(out), encoding="utf-8"
)
