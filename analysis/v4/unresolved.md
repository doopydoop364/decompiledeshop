# Unresolved items (structural baseline)

Machine-derived; see baseline.json.

## Uncovered TEXT regions

- unclassified (possible unreferenced code/data): 1179 regions, 45250 bytes
- zero_padding: 484 regions, 1918 bytes
- string/ascii data: 1397 regions, 52090 bytes
- data (non-code words): 524 regions, 17912 bytes
- pointer/literal table: 107 regions, 1384 bytes

## Largest unclassified gaps (candidate unreferenced code/data; not decompiled)

- 0027f730 +0x8d0
- 0027f01c +0x710
- 00135408 +0x6a8
- 0013ba08 +0x6a8
- 0024f9dc +0x644
- 00142008 +0x5b8
- 00272794 +0x51c
- 00208518 +0x2cc
- 0012fca8 +0x28c
- 001362a8 +0x28c
- 0013c8a8 +0x28c
- 002a863c +0x26c
- 001c85c8 +0x218
- 0034fde8 +0x218
- 00101184 +0x214
- 003500e4 +0x204
- 00291b30 +0x200
- 00138610 +0x1d4
- 00136718 +0x190
- 0013cd18 +0x190
- 0013047c +0x180
- 00136a7c +0x180
- 0013d07c +0x180
- 0012f838 +0x174
- 00135e38 +0x174
- 0013c438 +0x174
- 002c866c +0x174
- 00248680 +0x164
- 0027c62c +0x164
- 001307e0 +0x158
- 00136de0 +0x158
- 0013d3e0 +0x158
- 0012fa80 +0x154
- 00136080 +0x154
- 0013c680 +0x154
- 0012f584 +0x14c
- 00130d54 +0x14c
- 00130f90 +0x14c
- 00135b84 +0x14c
- 00137354 +0x14c
- 00137590 +0x14c
- 0013c184 +0x14c
- 0013d954 +0x14c
- 0013db90 +0x14c
- 0029bd48 +0x134
- 00130118 +0x10c
- 0029bb28 +0x10c
- 002a7218 +0x106
- 002286ec +0xf8
- 0021ff10 +0xf0
- 002786f8 +0xec
- 00132dec +0xd4
- 001393ec +0xd4
- 0013f9ec +0xd4
- 0020ff44 +0xc0
- 00172f40 +0xb8
- 0023d2f0 +0xa0
- 002a0164 +0x94
- 0029ca80 +0x90
- 0033b4e8 +0x8c

## Known weaknesses

- Function entries found only by data pointers / prologue scans / gap starts (discovery column in functions.csv) are lower confidence than call-reached ones.
- 7709 indirect calls through registers (blx rN) and 1062 indirect jumps (bx rN, ldr pc, mov pc, add pc with non-table form) are left as indirect.
- Thumb: only Thumb-1 + BL/BLX pairs are decoded; Thumb function starts that begin with non-push instructions may be missed or begin late.
- Signature inference is heuristic (liveness of r0-r3 and r0/r1 consumers); stack arguments are only counted, not bound at call sites.
- Flag-dependent conditions use a static last-flag-setter descriptor; overflow (V) conditions are approximated.
- No type recovery: all values are `uint`/`float`/`double`; no structures are declared yet.
