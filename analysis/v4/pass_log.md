# V4 pass log

Binary of record: `code_decompressed.bin` sha256 `34a50e03…c58d7` (verified to equal an independent BLZ decompression of `code.bin`, sha256 `41b510d6…19d5a`, using `ExHeader` `tiger`). V3 was used only for comparison, never as input to V4.

Tooling: Ghidra could not be obtained (network policy limits GitHub to this repo; no mirror on PyPI/conda/Maven). Pipeline is Python + Capstone 5.0.7; cross-validated against GNU `arm-none-eabi-objdump` 2.42.

## PHASE A — structural

### Pass 0 — binary map (`v4_pass0_map.py`, `binary_map.txt/json`)
- ExHeader SCI: TEXT va 0x100000 size 0x2b2638, RODATA va 0x3b3000 size 0x26370, DATA va 0x3da000 size 0x15d68, BSS 0x61e30 (va 0x3f0000), stack 0x4000. File offsets 0 / 0x2b3000 / 0x2da000 (page-contiguous). All re-derived, not taken from earlier notes.
- BLZ footer: enc_len 0x1a14ce, hdr_len 11, inc_len 0x14ea20 → 3080192 bytes; independent decompress == `code_decompressed.bin`.
- Strings inside TEXT (inline, in function literal pools) are real and numerous (all `%s/ninja/ws/...` format strings live in TEXT, not RODATA).

### Pass 1 — disassembly / function discovery (`v4_disasm.py`)
Iterations and what each fixed (counts are functions):
1. Recursive descent from entry + BL/BLX targets, ARM only: 9106, 82 % of TEXT covered. Gap analysis showed Thumb code and unreferenced ARM.
2. Added Thumb-1 decoder (BL/BLX pairs, push/pop, literal loads). Data code-pointers with bit0 set produced many false Thumb seeds → added "weak seed" ban when the trace hits undecodable bytes.
3. Weak seeds (RODATA/DATA pointers) were cutting real functions at labels inside them (e.g. 0x100004 inside the entry routine). Restructured into: strong closure first, then gap candidates (pointers, prologues, gap starts) accepted only if the trace is clean, terminates and does not overlap instructions of existing functions.
4. Zero words are padding, never code. Unconditional/conditional `b` to a push-lr prologue is a tail call, not an in-function edge (fixed a 440 KB bogus function).
5. Jump tables: `ldr<cc> pc,[pc,rX,lsl #2]` word tables (count from the preceding `cmp rX,#N`) were previously truncated to one entry; `add pc,pc,rX,lsl #2` branch tables kept. PC writes by non-switch instructions are treated as data. ARM→Thumb veneers (`add ip,pc,#1; bx ip`) resolved as Thumb tail targets.
6. Overlap resolution: a clean candidate absorbing weakly-discovered functions whose entries are labels inside it (their entries become extra roots) — fixed 14 KB functions split by jump-table pointers.
7. Stale rejections retried each gap round.
Result: 12881 functions (217 Thumb), see `baseline.json`.
Cross-check (`v4_validate_disasm.py` → `disasm_crosscheck.txt`): 626 836 decoded instructions compared with GNU objdump; all mismatches are alias spellings (hs/cs, lo/cc, `mov r0,r0`/nop, push/str lr); 104 354 of 104 355 branch/call targets agree.

### Pass 2 — CFG (`v4_func.py`)
Blocks from leaders; conditional/predicated returns and tail calls become synthetic blocks; switch terminators; fall-through into non-code recorded as an unresolved terminator. 87 functions initially failed structuring because of such fall-throughs → fixed (0 failures).

### Pass 3 — lifting and signatures (`v4_ir.py`, `v4_analyze.py`)
Capstone operand model → IR (ARM, Thumb, VFP, ldrex/strex, mrc TLS, svc). Unknowns (SIMD media ops etc.) stay as `__asm` with Capstone read/write sets. Interprocedural fixpoint over r0–r3 liveness (params) and consumers of r0/r1 after calls (returns). Corrections made during passes: predicated defs no longer count as parameter uses (strlen was 3-param); pass-through returns (strcpy returning dest) counted by caller use; ret2 implies ret; trailing undefined args trimmed at call sites.

### Pass 4/5 — literal pools, strings, xrefs (`v4_strings.py`)
4 577 strings (ASCII+UTF-16LE, TEXT strings need ≥6 chars), 2 023 xrefs (376 via literal pools, rest via data pointers). Almost every RODATA string ≥8 chars has an xref (26 do not), so low literal-xref count is real, not a scanner miss.

### Pass 6 — structures (`v4_structs.py`, `structures.txt/csv`)
Neutral `STRUCT_NNN` candidates from `[param+offset]` accesses merged along call edges (param_k passed as argument j). Top 400 candidates, ~6 k observed fields. Over-merging is possible (a base-class pointer passed through generic helpers merges unrelated classes), so these are *access sets*, not class definitions; no pseudocode type was changed.

### Pass 7/8 — structuring and printing (`v4_struct.py`, `v4_print.py`)
Dominator/post-dominator structuring (if/else, loops → while/do-while, switch, goto fallback), short-circuit merging into `&&`/`||`, web (live-range) renaming, single-use forwarding, global constant propagation, dead-code removal, stack-spill DSE. Quality artefacts found and fixed: `asr rd,rm,#imm` two-operand form misread as register shift; sp-relative address folding; float loads typed as uint; degenerate ternaries; duplicate-value arguments.

### Later structural passes (after the first candidate file)
8. **String xrefs were badly under-counted** (2 023): literal-pool scans miss `add rX, pc, #imm` address generation. Adding it raised xrefs to 5 611 and strings with ≥1 xref to 4 304 of 4 577. This also exposed that every `%s/ninja/ws/...` URL lives in TEXT (function-adjacent), which the printer now renders as literals.
9. **Loop emission bug**: the code following a loop header block inside the loop body was dropped to an "unreached" tail. Fixed; gotos 15 k → 11.9 k and loops such as strstr are now correct.
10. Far unconditional branches (>16 KB) and branches to push-lr prologues are tail calls (largest bogus function 1.8 MB → 20 KB).
11. Shrink-wrapped prologues (early conditional return followed by a mid-function `push`) were split into two functions; weak entries reached only by fall-through are merged (−493 functions). Thumb prologue candidates also try the instruction(s) before the push.
12. `ret2` (r1 as second return value) inference fed back on over-estimated parameter counts and made hundreds of functions return `CONCAT44`; disabled. Known gap: genuine 64-bit returns (e.g. `__aeabi_idivmod`) therefore show r1 as an unconsumed value.
13. Call arguments that are undefined at the call site (trailing registers) are trimmed.

### Structural audits and convergence
`v4_audit.py` (read of never-assigned variables, unreachable statements, entry-register reads, goto-heavy functions, inline asm) plus manual comparison of simple/switch/float/network functions against the disassembly (strstr, strlen, TitleInfo text switch, a float/object-init routine, NPNS/shop flows). Defects found and fixed in rounds 8–13 above. Final three consecutive full regenerations (`.scratch` runs 1–3): 12 719 functions, 0 decompilation failures, identical function set, identical naming output (657 names) — i.e. no further structural change from the tooling; **this indicates convergence of this toolchain, not correctness**. Remaining audit counts are in `audit_last.json` (405 functions read a variable assigned only on an unmodelled path, 1 240 read entry registers, 85 have >20 gotos, 313 contain an unresolved indirect jump).

Known remaining artefacts: ~15 k `goto` (mostly large parsers/printf-style functions and shared tails), predicated sequences leave `ccN` snapshots when the flag operand is modified under the predicate, no type recovery.

## PHASE B — semantic (`v4_semantic.py`; output `function_names.csv`, `globals_named.csv`, `network_map.md`, `subsystems.md`)
Names are never taken from V3. Rules re-read the structural pseudocode (previous names are mapped back to `FUN_` ids first so passes are idempotent). Confidence is per row with an evidence string; LOW/UNKNOWN functions keep `FUN_` ids and are not written.

- **S1 library/utility**: `svc_*` wrappers (single svc, number→name from 3dbrew SVC table), exact accessors/predicates/setters, exact trivial bodies (`nop_return`, `returns_const_N`, `get_addr_of_<global>`, vtable-pointer constructors = MEDIUM), curated runtime routines each guarded by a pseudocode validator (strlen, strcpy, strcat, strlen16, memcmp, strstr, snprintf, once-guard, heap alloc/free wrappers, crt entry, `app_main`).
- **S2 strings**: URL builders (`build_url_<service>_<path>`, 74+ MEDIUM: exactly one service format string + snprintf call), URL-path classifiers (`url_find_path_*`: strstr on the request URL, only reachable via pointer tables), log-string anchors for the NIM shop layer / NPNS / fs service (unique-match rule; ambiguous anchors are recorded LOW and not published), nlib EXI translation units via their own `__FILE__` assertion paths.
- **S3 networking / S4 eShop functionality**: `network_map.md` (hosts, headers, endpoint table by category, shared layers, not-established list).
- **S5 UI**: strings/layout names catalogued in `subsystems.md`; deliberately no UI function names (pane-name strings are shared by hundreds of screens).
- **S6 globals**: `g_heap_allocator`, `g_fs_user_session`, `g_shop_base_url` (MEDIUM, evidence in file); printed in pseudocode.
- **S7 naming** is the sum of the above; **S8 cross-check**: re-derives accessor/builder preconditions and downgrades failures; manual challenge found one over-specific name (`shop_download_dtl` → `shop_register_npns_and_download_dtl`, because its first action is `npns_register_device`) and one scope error (`open_fs_user_session` belongs to the callee, not `FUN_00103b48`, which is `app_main`).
- **S9 convergence**: naming output identical across three consecutive complete passes (657 names; no new HIGH findings), plus thunk propagation (1 added, then 0).

Remaining uncertainties: ~95 % of functions are unnamed by design; `url_find_path_*` role is inferred; "shop_*" names rest on trace-log strings that can describe the function or its immediate caller; STRUCT_* merging; HTTP verb per endpoint and JSON field parsers not traced; indirect calls (7.7 k `blx rN`) are not resolved to vtable targets.
