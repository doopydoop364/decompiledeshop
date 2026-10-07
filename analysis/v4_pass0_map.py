#!/usr/bin/env python3
"""V4 pass 0: verify inputs and write analysis/v4/binary_map.{txt,json}."""
import sys, os, json, hashlib, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v4_common import *
sha = lambda b: hashlib.sha256(b).hexdigest()
raw = open(os.path.join(ROOT, 'code.bin'), 'rb').read()
dec = blz_decompress(raw)
ref = open(os.path.join(ROOT, 'code_decompressed.bin'), 'rb').read()
ext = open(os.path.join(ROOT, 'extheader.bin'), 'rb').read()
m = Map(ext, ref)
enc_hdr, inc = struct.unpack('<II', raw[-8:])
info = {
 'files': {'code.bin': {'size': len(raw), 'sha256': sha(raw)}, 'code_decompressed.bin': {'size': len(ref), 'sha256': sha(ref)},
           'extheader.bin': {'size': len(ext), 'sha256': sha(ext)}},
 'blz': {'footer_enc_len': enc_hdr & 0xFFFFFF, 'footer_hdr_len': enc_hdr >> 24, 'inc_len': inc,
         'independent_decompress_matches_code_decompressed': dec == ref},
 'extheader': {'name': m.name, 'flag_byte_0xd': m.flags, 'code_compressed_flag': bool(m.flags & 1), 'stack_size': m.stack, 'bss_size': m.bss},
 'segments': [{'name': n, 'va': a, 'size': s, 'file_offset': o, 'end_va': a + s} for n, a, s, o in m.segs()],
 'bss': {'va': m.bss_addr, 'size': m.bss, 'note': 'BSS follows DATA pages (page-aligned); size from SCI offset 0x3C'},
 'arch': 'ARM11 (ARMv6K), ARM + Thumb-1 (BL/BLX pairs), VFPv2 float code present',
 'entry_va': 0x100000, 'entry_note': 'first TEXT word is the .code entry (3DS process start); TEXT page size 0x1000',
 'page_pages': {'text': m.t_pages, 'ro': m.r_pages, 'data': m.d_pages},
}
# sanity: file length == data end rounded to page
info['file_len_check'] = {'text_pages+ro_pages+data_pages_bytes': (m.t_pages + m.r_pages + m.d_pages) * 0x1000, 'decompressed_len': len(ref)}
# first-word / alignment checks
info['first_words'] = [hex(struct.unpack_from('<I', ref, i)[0]) for i in (0, 4, 8)]
json.dump(info, open(os.path.join(V4, 'binary_map.json'), 'w'), indent=1)
L = ['Nintendo 3DS eShop (ExHeader name "%s") - binary map (verified by analysis/v4_pass0_map.py)' % m.name, '']
for k, v in info['files'].items(): L.append('%-22s size=%-9d sha256=%s' % (k, v['size'], v['sha256']))
L += ['', 'code.bin is BLZ-compressed (ExHeader flag bit0 = %d); independent decompression %s code_decompressed.bin' % (m.flags & 1, 'MATCHES' if dec == ref else 'DOES NOT MATCH'),
      'BLZ footer: enc_len=%#x hdr_len=%d inc_len=%#x' % (enc_hdr & 0xFFFFFF, enc_hdr >> 24, inc), '',
      '%-7s %-10s %-10s %-10s %-10s' % ('seg', 'VA', 'size', 'end VA', 'file_off')]
for s in info['segments']: L.append('%-7s %08x   %08x   %08x   %08x' % (s['name'], s['va'], s['size'], s['end_va'], s['file_offset']))
L += ['BSS     %08x   %08x   (follows DATA pages; not present in file)' % (m.bss_addr, m.bss), 'stack size %#x' % m.stack, '',
      'Architecture: ' + info['arch'], 'Entry: 0x00100000', 'Alignment: segments page (0x1000) aligned, segment sizes not page multiples.']
open(os.path.join(V4, 'binary_map.txt'), 'w').write('\n'.join(L) + '\n')
print('\n'.join(L))
