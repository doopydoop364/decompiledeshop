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
        svcs = [s for s in st if re.search(r'__svc_\w+\(', s)]
        if len(svcs) == 1 and len(st) <= 4 and not any('FUN_' in s for s in st):
            m = re.search(r'__svc_(\w+)\(', svcs[0])
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
    # (b2) exact trivial bodies
    for a, (hdr, code) in body.items():
        if a in N.d: continue
        st = stmts(code)
        if st == ['return;']: N.set(a, 'nop_return', 'HIGH', 'body is only `return;`', ps); continue
        if len(st) == 1:
            m = re.fullmatch(r'return (0|1|0x[0-9a-f]+|-0x[0-9a-f]+|\d+);', st[0])
            if m: N.set(a, 'returns_const_%s' % m.group(1).replace('-', 'neg'), 'HIGH', 'body is only `%s`' % st[0], ps); continue
            if st[0] == 'return param_1;': N.set(a, 'returns_param_1', 'HIGH', 'identity function', ps); continue
            m = re.fullmatch(r'return &(DAT_[0-9a-f]{8}|g_\w+);', st[0])
            if m: N.set(a, 'get_addr_of_%s' % m.group(1), 'HIGH', 'body returns the address of global %s' % m.group(1), ps); continue
        if len(st) == 2 and st[1] == 'return param_1;':
            m = re.fullmatch(r'\*\(uint \*\)param_1 = &(DAT_[0-9a-f]{8});', st[0])
            if m: N.set(a, 'store_ptr_%s_into_obj' % m.group(1), 'MEDIUM', 'stores the static address %s at offset 0 of param_1 and returns it (typical vtable-pointer constructor)' % m.group(1), ps)
    # (c) curated routines, each with a validator on the structural pseudocode
    def has(a, *pats):
        if a not in body: return False
        c = body[a][1]
        return all(re.search(p, c) for p in pats)
    cur = [
     (0x100000, 'crt_entry_point', 'HIGH', 'first TEXT word (process entry); calls init routines then svc ExitProcess', [r"svc_ExitProcess|FUN_"]),
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

ANCHORS = [  # (name, must-contain strings ('=' prefix = exact), must-not, evidence)
 ('npns_register_device', ['Register device to NPNS'], [], 'log text "Register device to NPNS..." plus nn::npns::RegisterDeviceRequest error strings in the same function'),
 ('npns_unregister_device', ['Unregister device from NPNS'], [], 'log text "Unregister device from NPNS..." plus UnregisterDeviceRequest error strings'),
 ('shop_download_dtl', ['DTL downloaded successfully'], [], 'logs "DTL downloaded successfully." / "DTL download failure"'),
 ('shop_log_failure_reason', ['Need System Update', 'Cannot Set IVS'], ['Title Already Downloaded'], 'maps NIM failure kinds to log text (Need System Update, Server is under Maintainance, Invalid Country...)'),
 ('shop_log_download_failure_reason', ['Need System Update', 'Title Already Downloaded'], [], 'same failure-text mapping plus download-specific cases (Title Already Downloaded, Task Already Exists)'),
 ('shop_list_titles', ['Shop::ListTitles'], [], 'trace log "Shop::ListTitles();"'),
 ('shop_initialize', ['InitializeForShop'], [], 'trace log InitializeForShop / Shop::SetApplicationId / SetTin / NeedsSystemUpdate'),
 ('shop_unregister', ['Shop::Unregister'], [], 'trace log "Shop::Unregister();"'),
 ('shop_start_download_content', ['Shop::StartDownload'], [], 'trace logs RegisterTask / StartDownload / Download Content -> Failure/Cancel/SD Error'),
 ('shop_download_tickets', ['nim::shop::DownloadTickets'], [], 'trace log "nim::shop::DownloadTickets()"'),
 ('shop_set_country', ['Shop::SetCountry'], [], 'trace log "Shop::SetCountry(%s);"'),
 ('shop_get_balance', ['Shop::GetBalance'], [], 'trace logs Shop::GetBalance / Shop::ListBalances'),
 ('shop_delete_saved_credit_card', ['DeleteSavedCreditCard'], [], 'trace log "Shop::DeleteSavedCreditCard();"'),
 ('shop_delete_credit_card_on_system_save_data', ['DeleteCreditCardOnSystemSaveData'], ['DeleteSavedCreditCard'], 'trace log "Shop::DeleteCreditCardOnSystemSaveData();"'),
 ('title_set_tag_and_external_seed', ['SetTitleTag', 'External Key Seed'], [], 'logs SetTitleTag() / SetExternalSeed() / ExternalSeed already exists'),
 ('title_check_locked', ['nn::fs::IsTitleLocked'], [], 'error log naming nn::fs::IsTitleLocked'),
 ('parse_playable_date', ['PARSE PLAYABLE DATE FAILED'], [], 'logs PARSE/GET PLAYABLE DATE FAILED'),
 ('open_fs_user_session', ['=fs:USER'], [], 'passes the service name "fs:USER" to the service-session open routine'),
 ('build_tagaya_versionlist_url', ['tagaya-ctr.cdn.nintendo.net'], [], 'selects between the production and dev tagaya version-list URLs'),
 ('build_npns_api_url', ['npns.app.nintendo.net/api/v1'], [], 'formats https://%c-npns.app.nintendo.net/api/v1/'),
 ('http_set_service_token_header', ['=X-Nintendo-ServiceToken'], [], 'adds the X-Nintendo-ServiceToken request header'),
 ('http_set_origin_header', ['=ninja.ctr.shop.nintendo.net'], [], 'passes "Origin" with the ninja shop host to the header-add call'),
 ('init_shop_service_host_urls', ['=https://ninja.ctr.shop.nintendo.net', '=https://samurai.ctr.shop.nintendo.net', '=https://ccif.ctr.shop.nintendo.net'], [], 'references the samurai/ninja/ccif/eou production host URL strings together (host table initialisation)'),
 ('molive_allocator_oom_handler', ['MoLive::Allocator: not enough memory'], [], 'prints "MoLive::Allocator: not enough memory to allocate %d bytes"'),
]

def pass2b(N, body, fn, callers, callees, strs, sx):
    ps = 'S2-anchors'; n0 = len(N.d)
    fstr = {a: [strs[s][1] for s in set(ss) if s in strs] for a, ss in sx.items()}
    for name, must, mustnot, ev in ANCHORS:
        def ok(lst, items):
            for it in items:
                if it.startswith('='):
                    if it[1:] not in lst: return False
                elif not any(it in x for x in lst): return False
            return True
        hits = [a for a, lst in fstr.items() if ok(lst, must) and not any(any(m in x for x in lst) for m in mustnot)]
        if len(hits) == 1: N.set(hits[0], name, 'MEDIUM', ev, ps)
        elif len(hits) > 1:
            for a in hits: N.set(a, '%s_%08x' % (name, a), 'LOW', 'ambiguous anchor (%d functions): ' % len(hits) + ev, ps)
    # nlib EXI translation units via assertion/source paths
    for a, lst in fstr.items():
        files = {re.sub(r'.*[\\/]', '', x) for x in lst if re.search(r'cibuild.*nlib.*exi', x)}
        if len(files) == 1:
            f = files.pop(); stem = re.sub(r'\W', '_', f)
            N.set(a, 'nlib_exi_%s_%08x' % (stem, a), 'MEDIUM', 'references its own source path d:\\cibuild\\nlib\\exi\\...\\%s (assert/log macro __FILE__)' % f, ps)
    LOG.append((ps, len(N.d) - n0))


CATS = [  # (category, regex over slug)
 ('Session / account', r'session|account|loyalty|migrate'),
 ('Wishlist', r'wishlist'),
 ('Balance / payment instruments', r'balance|credit_card|cc_|wallet|auto_billing|redeemable|replenish'),
 ('Coupons', r'coupon'),
 ('Purchase / transactions / receipts', r'purchase|transaction|receipt|redeem|prepurchase|ec_info'),
 ('Votes', r'vote'),
 ('Shared / recommended titles', r'shared|recommend|votable'),
 ('Catalog (titles, directories, rankings, search)', r'titles?_|_titles?|directory|directories|rankings?|genres|search|contents|publishers|languages|news|telops|aocs|movie|online_prices'),
 ('Shop configuration (country, tax, language, hosts)', r'country|tax|language|service_hosts'),
]

def category(slugname):
    for c, rx in CATS:
        if re.search(rx, slugname): return c
    return 'Other'

def gen_docs(N, body, fn, callers, callees, strs, sx):
    byname = {v['name']: (a, v) for a, v in N.d.items()}
    def nm(a): return N.d[a]['name'] if a in N.d and N.d[a]['confidence'] in ('HIGH', 'MEDIUM') else 'FUN_%08x' % a
    L = ['# Network subsystem map (V4)', '',
         'Every row cites its evidence; names are in `function_names.csv` with confidence. Confidence MEDIUM means purpose inferred from strings/callers, not proven.', '']
    # hosts and URLs
    L += ['## Hosts, base URLs and fixed URLs found as strings', '', '| string address | string | referencing functions |', '|---|---|---|']
    urls = [(a, t) for a, (e, t) in sorted(strs.items()) if re.search(r'https?://|\.nintendo\.(net|com)|nintendowifi', t)]
    fx = collections.defaultdict(list)
    for a, ss in sx.items():
        for sa in set(ss): fx[sa].append(a)
    for a, t in urls[:80]:
        fs = ', '.join(nm(f) for f in sorted(set(fx.get(a, [])))[:3]) or '(data table / no direct code xref)'
        L.append('| %08x | `%s` | %s |' % (a, t[:90].replace('|', '/'), fs))
    L += ['', '## HTTP header and cookie strings', '', '| string | referencing functions |', '|---|---|']
    for a, (e, t) in sorted(strs.items()):
        if t in ('Cookie', 'Set-Cookie', 'User-Agent', 'Content-Type', 'Content-Range', 'Accept', 'Referer', 'Origin', 'X-Nintendo-ServiceToken'):
            L.append('| `%s` @%08x | %s |' % (t, a, ', '.join(nm(f) for f in sorted(set(fx.get(a, [])))[:6])))
    # endpoint table
    rows = []
    for a, v in N.d.items():
        if v['name'].startswith('build_url_'):
            ev = re.search(r'"(%s/[^"]*)"', v['evidence'])
            fmt = ev.group(1) if ev else ''
            rows.append((category(v['name']), v['name'], a, fmt))
    L += ['', '## Endpoint request builders (MEDIUM: function formats exactly one service URL with snprintf)', '',
          'Method hints come from the path markers in the format string (`!put`, `!delete`, `!purchase` ...); the HTTP verb itself is chosen by the caller and was not traced.', '']
    for c in [c for c, _ in CATS] + ['Other']:
        rr = sorted(r for r in rows if r[0] == c)
        if not rr: continue
        L += ['### ' + c, '', '| function | address | callers | URL format |', '|---|---|---|---|']
        for _, n, a, f in rr:
            L.append('| `%s` | %08x | %d | `%s` |' % (n, a, len(callers.get(a, ())), f.replace('|', '/')))
        L.append('')
    pm = sorted((v['name'], a) for a, v in N.d.items() if v['name'].startswith('url_find_path_'))
    L += ['## URL-path classifiers (strstr on the request URL; reached through pointer tables, no direct callers)', '', 'count: %d' % len(pm), '']
    for n, a in pm[:100]: L.append('- `%s` @%08x' % (n, a))
    L += ['', '## Shared layers observed', '',
          '- `snprintf` @%08x: formats every URL (callers pass `%%s/ninja/ws/...`, `%%s/samurai/ws/...`, `%%s/CCIF/...`; first %%s argument is a base-host string held in a global at 0x003e1da8).' % byname.get('snprintf', (0,))[0],
          '- Builders end by constructing a string object from the C string (`FUN_002a8e48`-style copy-construct) into their first parameter: the URL is *returned by output parameter*, the request itself is issued elsewhere.',
          '- Service hosts: the production host URLs `https://samurai.ctr.shop.nintendo.net`, `https://ninja.ctr.shop.nintendo.net`, `https://ccif.ctr.shop.nintendo.net`, `https://eou.c.shop.nintendowifi.net` are all referenced by one function (`%s` @%s); the builders take the active base host from a global (0x003e1da8).' % (byname['init_shop_service_host_urls'][1]['name'] if 'init_shop_service_host_urls' in byname else 'FUN_0038ae7c', byname['init_shop_service_host_urls'][1]['address'] if 'init_shop_service_host_urls' in byname else '0038ae7c'),
          '- Tagaya: `https://tagaya-ctr.cdn.nintendo.net/tagaya/versionlist` (prod) / `tagaya-dev-ctr` (dev) chosen in one function; a second hard-coded `tagaya.wup.shop.nintendo.net/tagaya_ctr/dev/tiger/versionlist%d` form also exists. (analysis/NETWORK.md listed `tagaya.ctr.cdn...`; the binary string is `tagaya-ctr.cdn...`.)',
          '- NPNS: `https://%c-npns.app.nintendo.net/api/v1/` built by one function; register/unregister flows log through `nn::npns::*Request` messages and use `nn::act::AcquireIndependentServiceToken`.',
          '- Authentication: header `X-Nintendo-ServiceToken` is set from a token object; `Cookie`/`Set-Cookie` are copied through a header-lookup helper; `Origin: ninja.ctr.shop.nintendo.net` is set explicitly.',
          '- TLS: no certificate/verification strings were identified in this binary (the HTTPS stack is the system `httpc`/`ssl` services); this was not traced further.',
          '', '## Not established', '', '- The HTTP method used for each endpoint, the request object lifecycle and the JSON field parsers were not traced to named functions.']
    open(os.path.join(V4, 'network_map.md'), 'w').write('\n'.join(L) + '\n')
    # subsystems
    S = ['# Subsystems (V4)', '', 'Counts are from string anchors and the call graph; membership is evidence-based, not exhaustive.', '']
    exi = [(a, v) for a, v in N.d.items() if v['name'].startswith('nlib_exi_')]
    files = collections.Counter(re.sub(r'_[0-9a-f]{8}$', '', v['name'])[len('nlib_exi_'):] for a, v in exi)
    S += ['## nlib EXI/XML codec', '', '%d functions reference their own `d:\\cibuild\\nlib\\exi\\...` source path (assert strings). Source units seen:' % len(exi), '']
    for f, c in files.most_common(): S.append('- %s: %d functions' % (f, c))
    shop = sorted((a, v) for a, v in N.d.items() if v['name'].startswith(('shop_', 'npns_', 'title_', 'parse_playable', 'open_fs')))
    S += ['', '## NIM / shop control layer (log-string anchored, MEDIUM)', '']
    for a, v in shop: S.append('- `%s` @%08x - %s' % (v['name'], a, v['evidence']))
    ui = [t for a, (e, t) in strs.items() if re.match(r'^(N|P|T|L|A|B|S)_\w+_\d\d$', t)]
    S += ['', '## UI (layout panes)', '',
          '%d pane-name strings of the form `N_*_NN`/`P_*_NN`/`T_*_NN` (layout-pane lookups by name), e.g. N_root_00, N_nextPos_00, N_button_00, P_title_00, N_loadingIcon_00. Error UI uses `ErrorDialog_D_NN` and `error_txt01_NN` (%d strings). Layout archives such as `cad/TitleInfo.arc.lz`, `cad/Shelf.arc.lz` are referenced by name.' % (len(ui), sum(1 for a, (e, t) in strs.items() if t.startswith('error_txt'))),
          'No UI function is named in V4: pane-name strings are used by hundreds of screens and do not by themselves identify a function.',
          '', '## Graphics / media (strings only)', '',
          '- `dmp_TexEnv[n].*`, `dmp_*` uniform/shader names: PICA200 shader uniform names (GPU state setup).',
          '- `MoLive::*` strings: a movie/stream player library with its own allocator (error text "not enough memory", ReadEp stream messages).',
          '', '## Runtime / library', '',
          '- C runtime helpers named in S1 (strlen, strcpy, strcat, memcmp, strstr, snprintf, heap alloc/free wrappers, once guard) and `svc_*` wrappers for 3DS kernel calls.',
          '']
    open(os.path.join(V4, 'subsystems.md'), 'w').write('\n'.join(S) + '\n')

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
    pass2b(N, body, fn, callers, callees, strs, sx)
    for it in range(1, 6):
        before = len(N.d)
        pass_thunks(N, body, fn, callers, callees, strs, sx, it)
        if len(N.d) == before: break
    down = cross_check(N, body, fn, callers, callees, strs, sx)
    gen_docs(N, body, fn, callers, callees, strs, sx)
    # S6: named globals (only where a named function's behaviour fixes the object's role)
    G = []
    def have(n): return next((a for a, v in N.d.items() if v['name'] == n), None)
    if have('heap_alloc_checked') and have('heap_free_nullable'):
        G.append(('003e25a0', 'g_heap_allocator', 'MEDIUM', 'object whose vtable slots +0x1c (allocate size,align) and +0x24 (free) are invoked by heap_alloc_checked / heap_free_nullable'))
    if have('open_fs_user_session'):
        G.append(('003e2450', 'g_fs_user_session', 'MEDIUM', 'filled by open_fs_user_session (service name "fs:USER") and tested for non-zero before reuse'))
    if any(v['name'].startswith('build_url_') for v in N.d.values()):
        G.append(('003e1da8', 'g_shop_base_url', 'MEDIUM', 'first %s argument of every build_url_* snprintf (base host string for ninja/samurai/ccif paths)'))
    with open(os.path.join(V4, 'globals_named.csv'), 'w', newline='') as fh:
        w = csv.writer(fh); w.writerow(['address', 'name', 'confidence', 'evidence']); w.writerows(G)
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
