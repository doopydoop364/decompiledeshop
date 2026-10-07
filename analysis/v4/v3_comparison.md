# V4 vs V3

V3 (Ghidra output, sha256 `e03157a20d9b66d2d7eb45afaa905b472e99b00e90c431f1207784e62563fb44`) is unchanged and was not used as input to V4.

| metric | V3 | V4 |
|---|---|---|
| functions | 9903 | 12719 |
| function entries in common | 9745 | 9745 |
| entries only in this version | 158 | 2974 |
| functions with a string anchor / literal-string xref functions | 715 | 920 |
| renamed functions (V3: all confidence levels; V4: HIGH+MEDIUM, evidence per row) | 115 | 658 |
| string cross-references | n/a | 5611 (incl. pc-relative `add` references that literal-pool scans miss) |

V3-only entries: 158, of which 57 fall inside a V4 function body (V3 split what V4 keeps as one function or vice versa); the rest lie in regions V4 classifies as data/strings/unresolved.

V4-only entries: 2974 (discovery reasons across all V4 functions: {'entry': 1, 'call': 2587, 'tail': 180, 'prologue': 4745, 'gapstart': 1895, 'ptr': 3311}).

Concrete improvements: independent verified mapping and BLZ check; Thumb functions decoded (V3 treated most of TEXT as ARM); jump tables with word entries resolved; ARM->Thumb veneers resolved; TEXT-resident URL strings resolved (all `%s/ninja/ws/...` formats); every instruction cross-checked against objdump; per-function evidence for each name.
Known V4 regressions/gaps relative to V3: V3 carries decompiler-typed signatures and locals from Ghidra; V4 has no type recovery (everything `uint`), and V4 names far fewer functions on purpose.
