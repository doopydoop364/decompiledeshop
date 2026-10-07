#!/usr/bin/env python3
"""Shared helpers for the V4 pipeline: binary mapping, VA<->offset, BLZ."""
import struct, os, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V4 = os.path.join(ROOT, 'analysis', 'v4')

def blz_decompress(data):
    """3DS backward-LZ (3dbrew BLZ). Footer = last 8 bytes: u32 (hdrlen<<24 | enc_len), u32 inc_len."""
    enc_hdr, inc = struct.unpack('<II', data[-8:])
    hdr_len = enc_hdr >> 24
    enc_len = enc_hdr & 0xFFFFFF
    total = len(data) + inc
    out = bytearray(data) + bytearray(inc)
    raw_len = len(data) - enc_len           # uncompressed prefix
    src = len(data) - hdr_len               # read pointer (exclusive), moves down
    dst = total
    stop = len(data) - enc_len
    while src > stop:
        src -= 1
        flags = out[src]
        for _ in range(8):
            if src <= stop: break
            if flags & 0x80:
                src -= 2
                pair = out[src] | (out[src+1] << 8)
                n = (pair >> 12) + 3
                disp = (pair & 0xFFF) + 3
                for _ in range(n):
                    dst -= 1
                    out[dst] = out[dst + disp]
            else:
                src -= 1; dst -= 1
                out[dst] = out[src]
            flags = (flags << 1) & 0xFF
    return bytes(out)

class Map:
    """Segments derived from extheader.bin (SCI) – verified in pass0."""
    def __init__(self, ext=None, code=None):
        ext = ext or open(os.path.join(ROOT,'extheader.bin'),'rb').read()
        self.name = ext[:8].rstrip(b'\0').decode()
        self.flags = ext[0xD]
        (t_addr,t_pages,t_size,stack,r_addr,r_pages,r_size,_,d_addr,d_pages,d_size,bss) = struct.unpack('<12I', ext[0x10:0x40])
        self.text=(t_addr,t_size); self.ro=(r_addr,r_size); self.data=(d_addr,d_size); self.bss=bss; self.stack=stack
        self.t_pages,self.r_pages,self.d_pages=t_pages,r_pages,d_pages
        # file layout: segments page-aligned & contiguous
        self.t_off=0; self.r_off=t_pages*0x1000; self.d_off=self.r_off+r_pages*0x1000
        self.bss_addr=d_addr+d_pages*0x1000  # approx: bss follows data pages
        self.code = code if code is not None else open(os.path.join(ROOT,'code_decompressed.bin'),'rb').read()
    def segs(self):
        return [('TEXT',self.text[0],self.text[1],self.t_off),('RODATA',self.ro[0],self.ro[1],self.r_off),('DATA',self.data[0],self.data[1],self.d_off)]
    def va2off(self, va):
        for n,a,s,o in self.segs():
            if a <= va < a + s: return o + va - a
        return None
    def seg_of(self, va):
        for n,a,s,o in self.segs():
            if a <= va < a + s: return n
        if self.data[0]<=va<self.data[0]+self.d_pages*0x1000+self.bss: return 'BSS'
        return None
    def read(self, va, n):
        o = self.va2off(va)
        return None if o is None else self.code[o:o+n]
    def u32(self, va):
        b = self.read(va,4)
        return None if b is None or len(b)<4 else struct.unpack('<I',b)[0]
