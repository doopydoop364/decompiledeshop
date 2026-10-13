# Function port status

Classes: Unexamined · Decompiled · Analyzed · Reconstructed · Compiles · Tested · Integrated · Blocked.
"Tested" here = differential test against the original ARM machine code run in Unicorn (`ctest -R original_vs_arm_oracle`, 200 random cases each,
including all alignment combinations; mutation-checked that the test fails on a deliberate bug). "Integrated" = called by the Linux app.
Provenance for all entries: **faithful source reconstruction** (behaviour verified; code is newly written C++, not Nintendo source).

| Address | Original symbol | Reconstructed as | Mode | Status | Notes |
|---|---|---|---|---|---|
| 0x002A8F8C | `cstring_length_002a8f8c` | `eshop_orig::cstring_length` | ARM | Integrated | strlen; original is word-at-a-time (UQSUB8). Used to centre text. |
| 0x002A0964 | `string16_length_002a0964` | `string16_length` | Thumb | Integrated | UTF-16 unit count. |
| 0x002A8F1C | `cstring_copy_002a8f1c` | `cstring_copy` | ARM | Integrated | strcpy. |
| 0x00100186 | `cstring_append_00100186` | `cstring_append` | Thumb | Integrated | strcat. |
| 0x0029E4F0 | `compare_bytes_0029e4f0` | `compare_bytes` | Thumb | Tested | Result magnitude follows word-prefix differences; matched exactly. Not yet called by the app. |
| 0x0029B7A0 | `copy_bytes_forward_0029b7a0` | `copy_bytes_forward` | ARM | Tested | Returns (dst+n, src+n) in r0:r1. Non-overlapping only. |
| 0x002A81F0 | `copy_bytes_forward_002a81f0` | `copy_bytes_forward` | ARM | Tested | Same behaviour as above. |
| 0x0029B318 | `section_find_fourcc_0029b318` | – | – | Analyzed | Needs `FUN_0029b380` (a 4-byte equality helper, ARM; semantics partially read from disassembly) and the file-reader struct (count u16 @+0xA, table ptr @+0xC, 16-byte entries, tag @+4). Next candidate. |
| 0x0021B50C | `message_lookup_text_0021b50c` | – | – | Blocked | Decompiler dropped the string argument passed to `FUN_0021b56c`; signature must be re-derived from disassembly first. |
| 0x00380364 | `http_extract_set_cookie_00380364` | – | – | Analyzed | Depends on `FUN_0031cc5c` (header lookup) and COW string assign; needs HTTP object layout (32-bit pointers, §6 of audit). |
| 0x00100000 | `runtime_entry_00100000` | – | – | Decompiled | CRT startup; replaced by native `main` (not reconstructed). |
| 0x00100024 | `zero_startup_memory_00100024` | – | – | Decompiled | BSS zeroing; unnecessary on Linux. |
| 0x002A7030 etc. | `heap_*` | – | – | Decompiled | Allocator; replacement planned via compat layer, not reconstruction. |
| all others | (≈9,890 functions) | – | – | Unexamined / Decompiled | See `analysis/eshop_function_index.tsv`. |

Newly written (non-original) code: everything under `src/compatibility`, `src/graphics`, `src/input`, `src/application`, `src/main.cpp`.
