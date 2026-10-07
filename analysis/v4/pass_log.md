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

### Pass 6 — structures: NOT yet done (see later section).

### Pass 7/8 — structuring and printing (`v4_struct.py`, `v4_print.py`)
Dominator/post-dominator structuring (if/else, loops → while/do-while, switch, goto fallback), short-circuit merging into `&&`/`||`, web (live-range) renaming, single-use forwarding, global constant propagation, dead-code removal, stack-spill DSE. Quality artefacts found and fixed: `asr rd,rm,#imm` two-operand form misread as register shift; sp-relative address folding; float loads typed as uint; degenerate ternaries; duplicate-value arguments.

Known remaining artefacts: ~15 k `goto` (mostly large parsers/printf-style functions and shared tails), predicated sequences leave `ccN` snapshots when the flag operand is modified under the predicate, no type recovery.
