#!/usr/bin/env python3
"""Validate or reverse the documented identifier-only renames without a C parser."""
import argparse
import hashlib
import json
from pathlib import Path
import re

TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\b[A-Za-z_]\w*\b')


def substitute(text, mapping):
    return TOKEN.sub(lambda match: mapping.get(match[0], match[0]), text)


def transform(text, manifest, reverse=False):
    symbols = {row['original']: row['name'] for row in manifest['symbols']}
    if reverse:
        symbols = {value: key for key, value in symbols.items()}
    output = []
    for block in re.split(r'(?=// ==== Function:)', text):
        header = re.search(r'// ==== Function: (\w+) @ (\w+) ====', block)
        if header:
            local = manifest['locals'].get(header[2], {})
            if reverse:
                local = {value: key for key, value in local.items()}
            block = substitute(substitute(block, local), symbols)
            old = header[1]
            block = block.replace('// ==== Function: ' + old + ' @',
                                  '// ==== Function: ' + symbols.get(old, old) + ' @', 1)
        output.append(block)
    return ''.join(output)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=root / 'eshop_decompile_v3.txt')
    parser.add_argument('--reverse', action='store_true', help='Input is renamed dump (default check also assumes this).')
    parser.add_argument('--output', type=Path, help='Write transformed dump to a NEW file; without this, validate only.')
    args = parser.parse_args()
    manifest = json.loads((root / 'analysis/eshop_names.json').read_text())
    source = args.input.read_text()
    reverse = args.reverse or args.output is None
    before = 'renamed_sha256' if reverse else 'original_sha256'
    after = 'original_sha256' if reverse else 'renamed_sha256'
    if digest(source) != manifest[before]:
        raise SystemExit('Input hash mismatch; refusing to transform an edited or different dump.')
    result = transform(source, manifest, reverse)
    if digest(result) != manifest[after] or transform(result, manifest, not reverse) != source:
        raise SystemExit('Validation failed: transformation is not an exact reversible rename.')
    if args.output:
        with args.output.open('x') as output:
            output.write(result)
    print('Verified: exact original SHA-256 and byte-identical rename round trip.')


if __name__ == '__main__':
    main()
