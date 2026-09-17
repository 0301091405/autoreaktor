import struct

def corflags_detail(p):
    d = open(p, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    ddoff = opt + (96 if magic == 0x10b else 112)
    cdir_rva = struct.unpack_from('<I', d, ddoff + 14 * 8)[0]
    if not cdir_rva:
        return 'yonetilmeyen (no CLR)'
    # RVA->offset
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optSize = struct.unpack_from('<H', d, pe + 20)[0]
    secTab = pe + 24 + optSize
    off = 0
    for i in range(nsec):
        s = secTab + i * 40
        vaddr = struct.unpack_from('<I', d, s + 12)[0]
        vsize = struct.unpack_from('<I', d, s + 8)[0]
        raw = struct.unpack_from('<I', d, s + 20)[0]
        if vaddr <= cdir_rva < vaddr + vsize:
            off = cdir_rva - vaddr + raw
            break
    flags = struct.unpack_from('<I', d, off + 16)[0]
    bits = []
    if flags & 1: bits.append('ILOnly')
    if flags & 2: bits.append('Required32Bit')
    if flags & 4: bits.append('ILLibrary')
    if flags & 8: bits.append('StrongNameSigned')
    if flags & 0x10: bits.append('NativeEntryPoint')
    if flags & 0x20: bits.append('TrackDebugData')
    if flags & 0x10000: bits.append('32BitPreferred')
    return 'flags=0x%X %s' % (flags, ' '.join(bits))

for t in ['../multi-target/t1/sample.exe',
          '../multi-target/real-targets/c1/CrackBeePck.exe',
          '../multi-target/real-targets/c2/UnpackME.exe',
          '../multi-target/real-targets/t4y/NET Reactor Unpack Me.exe']:
    print(t.split('/')[-1], '->', corflags_detail(t))