#!/usr/bin/env python3
"""
blz_decompress.py

Decompresses Nintendo 3DS "BLZ" (backward LZ77) compressed .code files.
This is the standard compression 3DS ExeFS .code sections use -- it's a
straightforward space-saving LZ77 variant (documented publicly on 3dbrew:
https://www.3dbrew.org/wiki/BLZ), not encryption or DRM. This script only
reverses that compression so the result can be properly disassembled.

USAGE:
    python3 blz_decompress.py <input.code> <output_decompressed.bin>

If the input isn't actually BLZ-compressed (footer doesn't parse
sensibly), the script will tell you rather than silently producing
garbage.
"""

import sys
import struct


def blz_decompress(data: bytes) -> bytes:
    if len(data) < 12:
        raise ValueError("File too small to contain a BLZ footer.")

    # Footer: last 12 bytes = [footer_size(1) + pad(3)] [compressed_size(4)] [additional_size(4)]
    # Actually the standard layout (from 3dbrew) is, reading the LAST 12 bytes:
    #   footer[0:4]  = additional_size (u32, LE)  -- extra space needed after decompression
    #   footer[4:8]  = compressed_size (u32, LE)  -- size of the compressed region (header+data)
    #   footer[8:12] = footer_size     (u32, LE)  -- but only the low byte is meaningful typically
    #
    # We parse defensively and validate against the file length.

    footer = data[-12:]
    additional_size, compressed_size, footer_and_pad = struct.unpack("<III", footer)
    footer_size = footer_and_pad & 0xFF

    if compressed_size > len(data):
        raise ValueError(
            "Parsed compressed_size (%d) exceeds file length (%d). "
            "This file may not be BLZ-compressed, or the footer format "
            "differs from what this script expects." % (compressed_size, len(data))
        )

    # The compressed region sits at the END of the file, of length compressed_size.
    start_of_compressed_region = len(data) - compressed_size
    raw = bytearray(data[:start_of_compressed_region])
    comp = data[start_of_compressed_region:]

    # Header inside the compressed region: last `footer_size` bytes of `comp`
    # contain [header_size(u8)] plus padding -- header sits just before the
    # 12-byte footer we already consumed. The compressed bytes to process
    # are comp[0 : len(comp) - footer_size - 12]... but many real-world
    # implementations simply treat everything except the trailing 12-byte
    # footer as the compressed stream, with header_size telling you how
    # many of the LAST bytes before the footer are themselves header
    # padding (not compressed data). We handle both conventions:

    body = comp[:-12] if len(comp) >= 12 else comp
    if footer_size > 0 and footer_size <= len(body):
        body = body[:-footer_size]

    out = bytearray()
    pos = len(body)

    # BLZ decompresses BACKWARD: start from the end of `body`, walk toward
    # the start, using flag bytes to decide literal-copy vs back-reference.
    buf = bytearray(body)

    while pos > 0:
        pos -= 1
        flags = buf[pos]
        for bit in range(8):
            if pos <= 0:
                break
            if flags & (0x80 >> bit):
                # Back-reference: 2 bytes, encode length+distance
                if pos < 2:
                    break
                pos -= 2
                pair = (buf[pos] << 8) | buf[pos + 1]
                length = (pair >> 12) + 3
                disp = (pair & 0xFFF) + 3
                for _ in range(length):
                    if len(out) < disp:
                        raise ValueError(
                            "Back-reference distance exceeds decompressed "
                            "output so far -- footer/header parsing is "
                            "likely misaligned for this file."
                        )
                    out.append(out[-disp])
            else:
                # Literal byte
                pos -= 1
                out.append(buf[pos])

    out.reverse()
    result = bytes(raw) + bytes(out)

    # Pad/extend with the additional_size the footer specified, if the
    # decompressed data doesn't already reach that length (BLZ sometimes
    # reserves extra zeroed space at the end for BSS-like regions).
    target_len = len(result) + additional_size - compressed_size
    if target_len > len(result):
        result += b"\x00" * (target_len - len(result))

    return result


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 blz_decompress.py <input.code> <output.bin>")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]

    with open(in_path, "rb") as f:
        data = f.read()

    try:
        decompressed = blz_decompress(data)
    except Exception as e:
        print("Decompression failed: %s" % e)
        print("This may mean the file isn't BLZ-compressed, or uses a")
        print("slightly different footer layout than expected.")
        sys.exit(1)

    with open(out_path, "wb") as f:
        f.write(decompressed)

    print("Decompressed %d bytes -> %d bytes" % (len(data), len(decompressed)))
    print("Written to: %s" % out_path)


if __name__ == "__main__":
    main()
