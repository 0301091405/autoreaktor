# vars=1 ama Stloc_2, Ldloc_2, Stloc_3 var — CountLocalsFromCil
# yanlis sayiyor. BUG: ldloc.0-3 kisa formlar (0x06-0x09) kodda
# "i += 1; continue" ile GECILIYOR ama index KAYDEDILMIYOR!
# Aynisi stloc.0-3 (0x0A-0x0D) icin. maxIdx asla 0'dan buyuk
# olmuyor -> return 1 (min). DUZELT: kisa formlarda index kaydet.
# Ayrica 0xFE 0x06 ldloc (uzun form) 2 bayt operand degil 2 byte:
# 0xFE 06 <u16 index> — i+=3 dogru. 0xFE 09 ldloca, 0xFE 0D
# stloc ayni. 0x0E ldloc.s / 0x0F ldloca.s / 0x13 stloc.s 1 bayt.
# Tablo: ldloc.0=0x06..ldloc.3=0x09 (idx=op-0x06),
#        stloc.0=0x0A..stloc.3=0x0D (idx=op-0x0A),
#        ldloc.s=0x0E, ldloca.s=0x0F, stloc.s=0x13 (1 bayt idx).
print('CountLocalsFromCil kisa-form bug fix')