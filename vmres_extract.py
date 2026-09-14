#!/usr/bin/env python3
"""vmres_extract.py — standalone VM string-table extractor for .NET Reactor
virtualized targets, reimplemented from Krypton.Core's ResourceParser layout
(header magic -> operand table -> string table (size-prefixed, Encoding.Unicode)
-> method count/sizes) with the encrypted-leb128 integer decoding.

This is the missing piece for the Tuts4You Reactor 7.3 target: Krypton's report
prints Ldstr operand INDICES (3, 4, 2002, ...) but never the string VALUES.
Slayer cannot touch them (method decrypter init fails on 7.x). This tool dumps
the whole VM string table in index order so indices in any devirtualization
report can be looked up directly.

Usage: python vmres_extract.py <resource.bin> [--utf8]
"""
import struct
import sys
from pathlib import Path


def read_encrypted_leb128(data, pos):
    """Port of Krypton ReadEncryptedLeb128: 6 payload bits + sign flag in bit 6,
    continuation in bit 7; negative values arrive as ~value."""
    num2 = data[pos]; pos += 1
    num = num2 & 63
    flag = (num2 & 64) != 0
    if num2 < 128:
        return (~num if flag else num), pos
    num3 = 0
    while True:
        num4 = data[pos]; pos += 1
        num |= (num4 & 127) << (7 * num3 + 6)
        if num4 < 128:
            break
        num3 += 1
    return (~num if flag else num), pos


def find_magic(data):
    """Reactor VM resource header magic, same probe Krypton profiles use."""
    for magic in (b'\x2e\x0e\xe7', b'\x56\xee\xba\xba', b'\x01\x00\x00\x00'):
        idx = data.find(magic)
        if idx >= 0:
            return idx, magic.hex()
    return 0, 'none(0)'


def parse(data):
    hdr, magic = find_magic(data)
    pos = hdr
    out = {'header_offset': hdr, 'magic': magic}
    # operandCount + operand pairs (index, value)
    n, pos = read_encrypted_leb128(data, pos)
    out['operand_count'] = n
    operands = {}
    for _ in range(max(0, min(n, 4096))):
        idx, pos = read_encrypted_leb128(data, pos)
        val, pos = read_encrypted_leb128(data, pos)
        operands[idx] = val
    out['operands'] = operands
    # string table: count, then per-string size + UTF-16LE bytes
    scount, pos = read_encrypted_leb128(data, pos)
    out['string_count'] = scount
    strings = []
    for i in range(max(0, min(scount, 0x4000))):
        size, pos = read_encrypted_leb128(data, pos)
        if size < 0 or pos + size > len(data):
            out['strings'] = strings
            out['truncated_at'] = i
            return out, pos
        strings.append(data[pos:pos + size].decode('utf-16-le', 'replace'))
        pos += size
    out['strings'] = strings
    # method count + sizes
    mcount, pos = read_encrypted_leb128(data, pos)
    sizes = []
    for _ in range(max(0, min(mcount, 0x8000))):
        s, pos = read_encrypted_leb128(data, pos)
        sizes.append(s)
    out['method_count'] = mcount
    out['method_sizes'] = sizes
    out['method_payload_offset'] = pos
    return out, pos


def main():
    path = Path(sys.argv[1])
    data = path.read_bytes()
    res, _ = parse(data)
    print(f"resource      : {path.name} ({len(data)} bytes)")
    print(f"header offset : {res['header_offset']} (magic {res['magic']})")
    print(f"operand count : {res.get('operand_count')}")
    print(f"string count  : {res.get('string_count')}")
    print(f"method count  : {res.get('method_count')}")
    print("--- STRING TABLE ---")
    for i, s in enumerate(res.get('strings', [])):
        print(f"[{i:5}] {s!r}")
    if 'truncated_at' in res:
        print(f"(truncated at index {res['truncated_at']} — size prefix exceeded data)")


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    main()
