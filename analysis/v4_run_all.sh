#!/bin/sh
# Reproduce the whole V4 pipeline from the checked-in binaries (about 6-8 minutes on 4 cores).
set -e
cd "$(dirname "$0")/.."
python3 analysis/v4_pass0_map.py > /dev/null
python3 analysis/v4_disasm.py            # function discovery -> analysis/v4/db.pkl
python3 analysis/v4_strings.py           # strings + xrefs
python3 analysis/v4_decompile.py         # structural eshop_decompile_v4.txt (+functions.csv, call_graph.csv)
for i in 1 2 3; do python3 analysis/v4_semantic.py; python3 analysis/v4_decompile.py; done   # names -> regenerate -> re-derive until stable
python3 analysis/v4_structs.py           # structures.txt
python3 analysis/v4_baseline.py > /dev/null
python3 analysis/v4_audit.py; python3 analysis/v4_compare_v3.py > /dev/null
python3 analysis/v4_validate_disasm.py > /dev/null
