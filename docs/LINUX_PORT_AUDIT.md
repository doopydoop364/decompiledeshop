# Linux port – repository audit

Scope: what exists in `doopydoop364/decompiledeshop` (the checkout of the reverse-engineering project) and what it
realistically allows. Facts below were measured from the repository contents; anything inferred is marked *(inferred)*.

## 1. Artifacts present

| Artifact | Notes |
|---|---|
| `code.bin`, `.code` | Identical (verified with `cmp`), 1,709,536 bytes: the **BLZ-compressed** ExeFS `.code`. |
| `code_decompressed.bin` | 3,080,192 bytes (0x2F0000). Output of `blz_decompress.py`. |
| `extheader.bin` | 2 KiB ExHeader. Title name `tiger`. |
| `eshop_decompile_v3.txt` | 15 MB Ghidra pseudocode, **9,903 functions**, with an identifier-only rename pass (`analysis/eshop_names.json`, only ~100 symbols renamed; the rest are `FUN_xxxxxxxx`). Not compilable as-is. |
| `analysis/` | Function index (9,903 rows), network trace scripts/reports, rename tooling, `NETWORK.md`. |
| `.github/workflows/` | CI jobs that produced the network reports. |
| **Not present** | RomFS, ExeFS icon/banner, Ghidra project, symbols from the original build, any ARM disassembly listing (the workflows print instruction context only for network references). |

Git history (20+ commits) is entirely network-tracing work (`analysis/NETWORK.md` and friends). No earlier port attempt exists.

## 2. Executable structure (from `extheader.bin`, verified against the file size)

| Segment | Address | Size | Notes |
|---|---|---|---|
| .text | 0x00100000 | 0x2B2638 (691 pages) | ARM + Thumb mixed code |
| .rodata | 0x003B3000 | 0x26370 (39 pages) | strings, tables |
| .data | 0x003DA000 | 0x15D68 (22 pages) | + .bss 0x61E30 |
| Stack | – | 0x4000 | |

The decompressed file is exactly text+rodata+data page-padded, so it can be mapped flat at 0x00100000 (the oracle tool does this).
Both ARM and Thumb are used; the decompile does not tell you which mode a function uses – it must be determined by disassembly.

## 3. Entry point and startup

`runtime_entry_00100000` zeroes BSS (`zero_startup_memory_00100024`), then calls in order
`FUN_00103e1c, FUN_002a6ca4, FUN_00104db0, FUN_00102520, FUN_00103de8, FUN_00103e70, FUN_00103b48`, then `svc 3` (ExitProcess).
That is the CRT-style startup; `main`‑level application code is reached through those calls. **The application main loop has not been
identified yet** (not claimed).

## 4. Platform dependencies observed

* **SVCs** used in the decompile: 0x13, 0x14, 0x17–0x25, 0x28, 0x2B, 0x2D, 0x32, 0x35, 0x38, 0x3A, 0x3C (mutex/event/semaphore/thread/timer/memory family), plus `svc 1,2,3,8,9,10`.
* **Services** (string literals in .rodata): `fs:USER`, `fs:LDR`, `hid:USER` (+`hid:NFC/QTM/SPVR`), `srv:`, `APT:U/S/A`, `cfg:u/s/i`, `http:C`, `ac:u`, `act:u`, `am:sys`, `nim:s`, `boss:U/P/M`, `frd:u`, `cam:u`, `y2r:u`, `ptm:*`, `ndm:u`, `err:f`.
* **Networking**: large HTTP client over `http:C` with `/ninja_ws/…`, `/samurai_ws/…`, `/CCIF/services/…` request builders (see `analysis/NETWORK.md`).
* **UI**: format strings reference NintendoWare CTR layout files (`.bclyt` layouts, `.bclan` animations, `.bclim` images, `.bcfnt` fonts) and decompile functions for pane lookup (`layout_find_pane_handle`, `layout_find_typed_pane_handle`), message catalogs (`message_file_create`, `section_find_fourcc`). So the interface is data driven: **the UI layer cannot be reproduced without the RomFS layout assets**, which are not in the repository and which this project must not download.
* **Runtime**: Nintendo's CRT/allocator (`heap_allocate_*`), Rogue Wave-style C++ strings (copy-on-write `std::string`, `RWSTDERR` string present).
* **Graphics**: the GPU is driven by PICA200 command lists; no OpenGL-style API is visible. A port needs an interpreter/translator for GPU command buffers *(inferred – not yet investigated)*.

## 5. What can realistically be reused

| Class | Examples | Feasibility |
|---|---|---|
| Pure leaf utilities | strlen/strcpy/strcat/memcmp/memcpy variants, UTF‑16 length | **Done** (7 functions, differential-tested) |
| Data-structure walkers | `section_find_fourcc`, message-catalog lookup, layout pane lookup, field accessors | Feasible once structure layouts are recovered; need care (decompiler dropped arguments, e.g. `message_lookup_text_0021b50c` calls `FUN_0021b56c` with a string argument the pseudocode omits) |
| Allocator / C++ string | `heap_*`, COW string | Feasible but tied to 32‑bit pointer layouts (see §6) |
| Request builders | `/ninja_ws/…` functions | Feasible: mostly formatting; need HTTP-object layouts |
| Application / UI logic | state machines, layout animation | Blocked on layout assets and a **32-bit object model** (§6) |
| GPU/rendering | | Blocked: needs PICA200 command interpretation |

## 6. The central technical blocker: 32‑bit ARM object layouts on x86‑64

Original structures embed 4-byte pointers and fixed field offsets (e.g. `*(int *)(request + 0x30)`). Mechanically converting decompiler output to
x86‑64 C++ breaks every such struct. Two viable strategies:

1. Compile recovered code as **32-bit** (`-m32`) so layouts hold – works on x86‑64 Linux with multilib, but not on ARM64 (no 32-bit ARM at runtime on many CPUs) and complicates SDL linking.
2. Re-derive each struct with explicit `uint32_t` offsets / handle indirection (a "guest pointer" abstraction) and keep the code 64-bit clean.

The work so far is deliberately layout-independent (leaf functions on byte buffers). Choosing between (1) and (2) is the key design decision before porting object-based code; see `docs/ROADMAP.md`.

## 7. Method used so far (evidence)

`linux-port/tools/oracle_vectors.py` runs the *original machine code* of leaf functions inside the Unicorn CPU core (development tool only – the shipping program never executes ARM code) and records results for synthetic inputs. The C++ reconstructions are verified against these recordings in `ctest`. This gives behavioural evidence per function rather than relying on decompiler readability (which was misleading in places: the strlen routine appears as saturating-subtract soup; copy routines are `undefined8` returns of `dst+n, src+n`).

## 8. Honest summary

* Real original-derived logic running in the Linux app today: 7 string/memory leaf routines (used by the bring-up screen).
* Everything visible on screen is substitute UI.
* The original eShop UI is **not** running and cannot be until the layout/RomFS assets are supplied by the owner (from their own console dump) and the object-model decision in §6 is made.
