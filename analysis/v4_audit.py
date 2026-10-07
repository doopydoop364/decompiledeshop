#!/usr/bin/env python3
"""Structural audit detectors over eshop_decompile_v4.txt. Prints counts and writes analysis/v4/audit_last.json."""
import re, os, sys, json, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import ROOT, V4
t = open(os.path.join(ROOT, 'eshop_decompile_v4.txt')).read()
fs = t.split('// ==== Function @ ')[1:]
C = collections.Counter(); ex = collections.defaultdict(list)
for f in fs:
    a = f[:8]
    body = f[f.find('{\n'):] if '{\n' in f else ''
    assigned = set(re.findall(r'\b([ufdlc]Var\d+|cc\d+)\b\s*=(?!=)', body)) | set(re.findall(r'\{([^}]*)\} =', body))
    for grp in re.findall(r'\{([^}]*)\} =', body): assigned |= set(x.strip() for x in grp.split(','))
    used = set(re.findall(r'\b([ufdl]Var\d+|cc\d+)\b', body))
    undef = used - assigned
    if undef: C['functions_with_read_of_never_assigned_var'] += 1; ex['undef'].append(a)
    if re.search(r'\bin_r\d+|\bin_lr|\bin_[sd]\d+', body): C['functions_reading_entry_registers(in_*)'] += 1
    if 'FAILED' in f.split('\n', 3)[1] or 'DECOMPILATION FAILED' in f: C['failed'] += 1
    lines = body.splitlines()
    for i in range(len(lines) - 1):
        l = lines[i].strip(); n = lines[i + 1].strip()
        if (l.startswith('return ') or l == 'return;' or l.startswith('goto ') or l == 'break;' or l == 'continue;') and n and not n.startswith(('}', 'LAB_', 'case ', 'default:', 'else', '//')) and not re.match(r'^\w+:$', n):
            C['unreachable_statement_after_jump'] += 1; ex['unreach'].append(a); break
    if len(re.findall(r'goto ', body)) > 20: C['functions_with_gt20_gotos'] += 1
    if 'unresolved indirect jump' in body: C['unresolved_indirect_jump'] += 1
    if '__asm(' in body: C['functions_with_inline_asm'] += 1
C['functions'] = len(fs)
for k, v in C.items(): print(k, v)
json.dump({'counts': C, 'examples': {k: v[:10] for k, v in ex.items()}}, open(os.path.join(V4, 'audit_last.json'), 'w'), indent=1)
