# analysis/v4 — outputs of the V4 pipeline

Reproduce everything with `sh analysis/v4_run_all.sh` (≈15 min, 4 cores; needs `capstone` and, for the cross-check, `binutils-arm-none-eabi`).

| file | content |
|---|---|
| `binary_map.txt/json` | verified hashes, BLZ relationship, TEXT/RODATA/DATA/BSS map |
| `functions.csv` | every function: VA, file offset, ARM/Thumb, size, discovery reason, inferred signature, caller/callee counts |
| `function_names.csv` | semantic names (HIGH/MEDIUM only) with evidence and pass; everything else keeps its `FUN_xxxxxxxx` id |
| `call_graph.csv` | direct call and tail-call edges |
| `strings.csv`, `string_xrefs.csv`, `data_xrefs.csv`/`globals.csv`, `globals_named.csv` | strings, cross references (literal pool, `add rX,pc,#imm`, data pointer), data objects, named globals |
| `structures.txt/csv` | neutral STRUCT_NNN field-access candidates |
| `network_map.md`, `subsystems.md` | network and subsystem maps |
| `baseline.json`, `unresolved.md` | frozen structural baseline and unresolved regions |
| `disasm_crosscheck.txt` | Capstone vs GNU objdump comparison |
| `audit_last.json`, `v3_comparison.md`, `pass_log.md` | audit counters, V3 comparison, full pass log |

`db.pkl`, `refs.pkl`, `why.pkl`, `fails.pkl` are intermediate (db.pkl is git-ignored and regenerated).
