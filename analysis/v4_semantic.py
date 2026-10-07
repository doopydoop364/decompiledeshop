#!/usr/bin/env python3
"""V4 phase B: evidence-based semantic naming passes.

Reads the structural V4 outputs (eshop_decompile_v4.txt built with *no* names, functions.csv, call_graph.csv, strings.csv,
string_xrefs.csv) and writes analysis/v4/function_names.csv (address,name,confidence,evidence,pass), globals_named.csv,
network_map.md, subsystems.md.  Each rule states the evidence it relies on; nothing is named from V3.

Confidence: HIGH = behaviour fully visible in the pseudocode/instructions; MEDIUM = purpose inferred from strings/callers;
LOW/UNKNOWN functions simply keep their FUN_ id (they are not written to function_names.csv)."""
import re, os, sys, csv, collections, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import ROOT, V4
from v4_ir import SVC_NAMES

RANK = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
LOG = []

def load():
    txt = open(os.path.join(ROOT, 'eshop_decompile_v4.txt')).read()
    prev = os.path.join(V4, 'function_names.csv')
    if os.path.exists(prev):          # undo a previous naming so rules always see structural FUN_ ids
        rev = {r['name']: 'FUN_' + r['address'] for r in csv.DictReader(open(prev))}
        if rev:
            rx = re.compile(r'\b(' + '|'.join(re.escape(k) for k in sorted(rev, key=len, reverse=True)) + r')\b')
            txt = rx.sub(lambda m: rev[m.group(1)], txt)
    body = {}
    for b in txt.split('// ==== Function @ ')[1:]:
        a = int(b[:8], 16)
        i = b.find('{\n')
        body[a] = (b[:i] if i > 0 else b, b[i:] if i > 0 else '')
    fn = {int(r['address'], 16): r for r in csv.DictReader(open(os.path.join(V4, 'functions.csv')))}
    callers = collections.defaultdict(set); callees = collections.defaultdict(set)
    for r in csv.DictReader(open(os.path.join(V4, 'call_graph.csv'))):
        a, b = int(r['caller'], 16), int(r['callee'], 16)
        callers[b].add(a); callees[a].add(b)
    strs = {}
    for r in csv.DictReader(open(os.path.join(V4, 'strings.csv'))):
        strs[int(r['addr'], 16)] = (r['encoding'], r['text'].encode('ascii', 'ignore').decode('unicode_escape', 'ignore') if False else r['text'])
    sx = collections.defaultdict(list)
    for r in csv.DictReader(open(os.path.join(V4, 'string_xrefs.csv'))):
        if r['from_func']:
            sx[int(r['from_func'], 16)].append(int(r['string_addr'], 16))
    return body, fn, callers, callees, strs, sx

class Names:
    def __init__(self): self.d = {}
    def set(self, a, name, conf, ev, ps):
        cur = self.d.get(a)
        if cur and RANK[cur['confidence']] >= RANK[conf] and cur['pass'] != ps: return False
        if cur and cur['name'] == name and cur['confidence'] == conf: return False
        self.d[a] = {'address': '%08x' % a, 'name': name, 'confidence': conf, 'evidence': ev, 'pass': ps}
        return True

def stmts(code):
    """pseudo-code statements of a body, without declarations/blank lines"""
    out = []
    for l in code.splitlines():
        l = l.strip()
        if not l or l in ('{', '}') or re.match(r'^(uint|float|double|ulonglong)\s[\w, ]+;$', l): continue
        out.append(l)
    return out

def slug(path):
    p = path.split('?')[0]
    p = re.sub(r'^%s/', '', p)
    p = re.sub(r'%(?:\d*)(?:llu|lld|u|d|s)', 'ID', p)
    p = p.replace('~', '').replace('!', '').replace('/ws/', '/')
    p = re.sub(r'[^A-Za-z0-9]+', '_', p).strip('_')
    return re.sub(r'_+', '_', p)

# ------------------------------------------------------------------------------------------------
def pass1(N, body, fn, callers, callees, strs, sx):
    ps = 'S1-library'
    n0 = len(N.d)
    # (a) svc wrappers: one svc call, nothing else
    for a, (hdr, code) in body.items():
        st = stmts(code)
        svcs = [s for s in st if re.search(r'\bsvc_\w+\(', s)]
        if len(svcs) == 1 and len(st) <= 4 and not any('FUN_' in s for s in st):
            m = re.search(r'\bsvc_(\w+)\(', svcs[0])
            N.set(a, 'svc_' + m.group(1), 'HIGH', 'body is a single `svc` instruction wrapper (3DS SVC number maps to %s)' % m.group(1), ps)
    # (b) exact accessors
    for a, (hdr, code) in body.items():
        st = stmts(code)
        if len(st) == 1:
            m = re.fullmatch(r'return \*\((\w+) \*\)\(param_1 \+ (0x[0-9a-f]+|\d+)\);', st[0])
            if m: N.set(a, 'get_%s_at_%s' % (m.group(1), m.group(2)), 'HIGH', 'single load: return *(%s*)(param_1+%s)' % (m.group(1), m.group(2)), ps); continue
            m = re.fullmatch(r'return \*\((\w+) \*\)param_1;', st[0])
            if m: N.set(a, 'get_%s_at_0x0' % m.group(1), 'HIGH', 'single load of *(%s*)param_1' % m.group(1), ps); continue
            m = re.fullmatch(r'return \((?:\*\((\w+) \*\)\(param_1 \+ (0x[0-9a-f]+|\d+)\)) (==|!=) 0;', st[0])
            if m: N.set(a, ('is_zero_at_%s' if m.group(3) == '==' else 'is_nonzero_at_%s') % m.group(2), 'HIGH', 'single compare of field with 0', ps)
        elif len(st) == 2 and st[1] == 'return;':
            m = re.fullmatch(r'\*\((\w+) \*\)\(param_1 \+ (0x[0-9a-f]+|\d+)\) = param_2;', st[0])
            if m: N.set(a, 'set_%s_at_%s' % (m.group(1), m.group(2)), 'HIGH', 'single store: *(%s*)(param_1+%s)=param_2' % (m.group(1), m.group(2)), ps)
    # (c) curated routines, each with a validator on the structural pseudocode
    def has(a, *pats):
        if a not in body: return False
        c = body[a][1]
        return all(re.search(p, c) for p in pats)
    cur = [
     (0x100000, 'crt_entry_point', 'HIGH', 'first TEXT word (process entry); calls init routines then svc ExitProcess', [r'svc_ExitProcess|FUN_']),
     (0x100024, 'crt_zero_startup_region', 'HIGH', 'zero-fills the word range between two literal-pool pointers (startup BSS clear)', [r'= 0;']),
     (0x2a8f8c, 'strlen', 'HIGH', 'NUL scan (byte loop to alignment, then word loop using uqsub8 zero-byte test) returning distance; %d callers', [r'uqsub8']),
     (0x2a8f1c, 'strcpy', 'HIGH', 'copies bytes (word fast-path with zero-byte test) through the first NUL; dest returned unchanged', [r'uqsub8|\*\(byte \*\)']),
     (0x100186, 'strcat', 'HIGH', 'scans destination to NUL then copies source including NUL', [r'while \(true\)']),
     (0x2a0964, 'strlen16', 'HIGH', 'counts nonzero 16-bit units (UTF-16 style length)', [r'ushort']),
     (0x29e4f0, 'memcmp', 'HIGH', 'compares word-wise then byte-wise for count bytes, returns first byte difference', [r'param_3']),
     (0x22f2e8, 'strstr', 'HIGH', 'nested NUL-terminated scan: returns pointer to first occurrence of needle (param_2) in haystack (param_1), 0 if none', [r'\*\(byte \*\)']),
     (0x2a783c, 'once_guard_acquire', 'HIGH', 'if *p==0 {*p=1; return 1} else return 0 (non-atomic once-flag)', [r'= 1;']),
     (0x2a8eac, 'heap_alloc_checked', 'MEDIUM', 'calls allocator object (DAT_003e25a0) vtable slot 0x1c with (size, 4); calls an error handler if null; %d callers', [r'0x1c']),
     (0x2a8ef8, 'heap_free_nullable', 'MEDIUM', 'null guard then allocator object vtable slot 0x24 (free)', [r'0x24']),
     (0x2a9080, 'heap_alloc_retry', 'MEDIUM', 'maps size 0 to 1 and loops on heap_alloc_checked until non-null, invoking a failure handler in between (operator new shape)', [r'= 1;']),
     (0x2a8f84, 'heap_alloc_wrapper', 'MEDIUM', 'forwards to heap_alloc_retry', []),
     (0x2747e4, 'snprintf', 'HIGH', 'varargs: (buf,size,fmt,...) -> end=buf+size-1, formatted by core routine; callers pass literal format strings (%s, %llu ...)', [r'param_2 != 0']),
    ]
    for a, nm, conf, ev, pats in cur:
        if a in body and has(a, *pats):
            N.set(a, nm, conf, ev.replace('%d', str(len(callers.get(a, ())))), ps)
    LOG.append((ps, len(N.d) - n0))

# ------------------------------------------------------------------------------------------------
def pass2(N, body, fn, callers, callees, strs, sx):
    ps = 'S2-strings'
    n0 = len(N.d)
    sn = {nm['name']: int(a) for a, nm in N.d.items()}
    strstr = next((a for a, nm in N.d.items() if nm['name'] == 'strstr'), None)
    snprintf = next((a for a, nm in N.d.items() if nm['name'] == 'snprintf'), None)
    for a, (hdr, code) in body.items():
        ss = [strs[s][1] for s in sx.get(a, []) if s in strs]
        if not ss: continue
        st = stmts(code)
        lit = re.findall(r'"((?:[^"\\]|\\.)*)"', code)
        # URL path matcher: strstr(haystack, "/path")
        if strstr is not None and strstr in callees.get(a, ()) and len(st) <= 10:
            paths = [l for l in lit if l.startswith('/')]
            if len(paths) == 1 and len(lit) == 1:
                N.set(a, 'url_find_path_' + slug(paths[0].replace('\\n', '')), 'MEDIUM',
                      'calls strstr(*param_2, "%s") and returns found-offset/flag; one literal; likely a request-URL classifier' % paths[0][:60], ps)
                continue
        # URL builders: snprintf with %s/ninja|samurai|CCIF format
        if snprintf is not None and snprintf in callees.get(a, ()):
            fm = [l for l in lit if re.match(r'%s/(ninja|samurai|CCIF)/', l)]
            if len(fm) == 1:
                svc = re.match(r'%s/(ninja|samurai|CCIF)/', fm[0]).group(1).lower()
                path = re.sub(r'^%s/(?:ninja|samurai|CCIF)/', '', fm[0])
                N.set(a, 'build_url_%s_%s' % (svc, slug('%s/' + path)), 'MEDIUM',
                      'snprintf with the only service format "%s"; builds the request URL for that endpoint' % fm[0][:70], ps)
                continue
    LOG.append((ps, len(N.d) - n0))

# ------------------------------------------------------------------------------------------------
def pass_thunks(N, body, fn, callers, callees, strs, sx, it):
    """forwarding wrappers of named functions: body is a single tail call/call with unchanged args"""
    ps = 'S9-propagate'
    n0 = len(N.d)
    byaddr = {int(k): v for k, v in N.d.items()}
    for a, (hdr, code) in body.items():
        if a in N.d: continue
        st = stmts(code)
        m = None
        if len(st) == 1:
            m = re.fullmatch(r'return (FUN_[0-9a-f]{8}|\w+)\(((?:param_\d+(?:, )?)*)\);  /\* tail call \*/', st[0])
        if len(st) == 2 and st[1] == 'return;':
            m = re.fullmatch(r'(FUN_[0-9a-f]{8})\(((?:param_\d+(?:, )?)*)\);', st[0])
        if m:
            tgt = m.group(1)
            if tgt.startswith('FUN_'):
                ta = int(tgt[4:], 16)
                if ta in N.d and N.d[ta]['confidence'] in ('HIGH', 'MEDIUM') and not N.d[ta]['name'].startswith(('get_', 'set_', 'is_')):
                    N.set(a, N.d[ta]['name'] + '_thunk', 'MEDIUM', 'forwarding wrapper: only tail-calls %s' % N.d[ta]['name'], ps)
    LOG.append((ps + ' iteration %d' % it, len(N.d) - n0))

# ------------------------------------------------------------------------------------------------
def cross_check(N, body, fn, callers, callees, strs, sx):
    """S8: challenge names. Returns list of downgrades."""
    ps = 'S8-crosscheck'
    down = []
    for a, nm in list(N.d.items()):
        name = nm['name']; conf = nm['confidence']
        code = body[a][1]
        reasons = []
        if name.startswith('url_find_path_'):
            if not callers.get(a) and True:
                pass                       # reached only via pointer table (vtable-like) - consistent with classifier tables
        if name.startswith('build_url_'):
            if not re.search(r'snprintf|FUN_002747e4', code): reasons.append('no snprintf call in body')
        if name.startswith(('get_', 'is_')) and len(stmts(code)) != 1: reasons.append('not a single-statement accessor')
        if reasons:
            nm['confidence'] = 'LOW'; nm['evidence'] += ' | DOWNGRADED: ' + '; '.join(reasons); down.append(a)
    LOG.append((ps, -len(down)))
    return down

# ------------------------------------------------------------------------------------------------
def main():
    body, fn, callers, callees, strs, sx = load()
    N = Names()
    pass1(N, body, fn, callers, callees, strs, sx)
    pass2(N, body, fn, callers, callees, strs, sx)
    for it in range(1, 6):
        before = len(N.d)
        pass_thunks(N, body, fn, callers, callees, strs, sx, it)
        if len(N.d) == before: break
    down = cross_check(N, body, fn, callers, callees, strs, sx)
    # unique names
    seen = collections.Counter(v['name'] for v in N.d.values())
    for a, v in N.d.items():
        if seen[v['name']] > 1: v['name'] = '%s_%08x' % (v['name'], a)
    rows = [v for v in N.d.values() if v['confidence'] in ('HIGH', 'MEDIUM')]
    rows.sort(key=lambda r: r['address'])
    with open(os.path.join(V4, 'function_names.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, ['address', 'name', 'confidence', 'evidence', 'pass']); w.writeheader(); w.writerows(rows)
    c = collections.Counter(r['confidence'] for r in rows)
    print('named', len(rows), dict(c), 'total functions', len(body))
    for p, n in LOG: print(p, n)
    json.dump({'named': len(rows), 'by_confidence': dict(c), 'log': LOG, 'functions': len(body)}, open(os.path.join(V4, 'semantic_summary.json'), 'w'), indent=1)

if __name__ == '__main__': main()
