# eShop decompilation naming notes

`../eshop_decompile_v3.txt` is the renamed dump. Changes are identifiers only: recovered types, signatures, control flow, constants, labels, strings, and existing warnings are preserved. This is decompiler pseudocode, not a buildable C project.

Names describe observed behavior rather than claiming to recover original source symbols. Every renamed function retains its hexadecimal address. High confidence means the operation is directly apparent; medium confidence means its purpose is inferred from implementation plus callers. Unknown field meanings remain explicit offsets (`get_field_...`, `set_field_...`, `field_..._is_nonzero`). Field offsets belong to the particular object's layout, not one shared structure.

The pass covers runtime initialization, common heap/string/copy routines, callback management, pane lookup, message-file sections, cookie extraction, and exact single-operation accessors. Most application functions still need deeper analysis. String anchors in the index make it easier to find purchase, search, title-information, and other UI paths without assigning speculative names.

- `eshop_names.json`: old/new symbol names, addresses, confidence, evidence, function-scoped parameter/local renames, and original/renamed SHA-256 hashes. `DAT_` names can identify literal-pool pointer slots; they do not necessarily identify the pointed-to global storage itself.
- `eshop_function_index.tsv`: every function entry, address, original/current name, textual reference count (including header and definition), and existing `s_...` string anchors. Repeated original names are retained as separate address rows.
- `rename_dump.py`: validates the exact rename round trip, restores a separate original dump, or reapplies the recorded names. It refuses mismatched input hashes and refuses to overwrite an output file.

Run from the workspace root:

```sh
python3 analysis/rename_dump.py
python3 analysis/rename_dump.py --reverse --output /tmp/eshop_original_restored.txt
python3 analysis/rename_dump.py --input /tmp/eshop_original_restored.txt --output /tmp/eshop_renamed_again.txt
```

Validation checks that reversing every rename reproduces the original SHA-256 and that applying the names again reproduces the renamed dump exactly. No binary execution or functional equivalence testing is claimed. The verifier checks the recorded snapshot; after further manual edits, its hash check intentionally fails until the manifest is updated against a preserved original.

Decompiler limitations matter when reading these names: some calls pass more arguments than the recovered callee signature, some return values are missing or packed into `CONCAT44`, and indirect calls can omit apparent arguments. In particular, byte-copy helpers retain their recovered register-pair return convention rather than being rewritten as standard `memcpy`. Copy-on-write string names are inferred from the storage header and reference-count operations. Cookie extraction preserves the observed return polarity: true when header lookup returns zero.
