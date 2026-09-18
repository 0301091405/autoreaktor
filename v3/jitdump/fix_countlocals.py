# vars=1 but Stloc_2, Ldloc_2, Stloc_3 exist — CountLocalsFromCil
# counts wrong. BUG: ldloc.0-3 short forms (0x06-0x09) are skipped
# with "i += 1; continue" but the INDEX is never recorded!
# Same for stloc.0-3 (0x0A-0x0D). maxIdx never exceeds 0
# -> returns 1 (min). FIX: record the index for short forms too.
# Also 0xFE 0x06 ldloc (long form) operand is 2 bytes:
# 0xFE 06 <u16 index> — i+=3 is correct. 0xFE 09 ldloca, 0xFE 0D
# stloc same. 0x0E ldloc.s / 0x0F ldloca.s / 0x13 stloc.s are 1-byte.
# Table: ldloc.0=0x06..ldloc.3=0x09 (idx=op-0x06),
#        stloc.0=0x0A..stloc.3=0x0D (idx=op-0x0A),
#        ldloc.s=0x0E, ldloca.s=0x0F, stloc.s=0x13 (1-byte idx).
print('CountLocalsFromCil short-form bug fix')