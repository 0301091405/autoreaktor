# jitdump.log yok — DLL_PROCESS_DETACH'te flushLog cagriliyor ama
# taskkill /F ile oldurulunce detach atlanir (kaba kill = flush
# yok). g_lines kayboldu ama m_*.bin'ler her compileMethod'da
# ANINDA yaziliyor — asil kanit saglam. log'u bin'lerden yeniden
# uret (header'dan):
import struct, glob, os

DUMPS = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\jitdump'
bins = sorted(glob.glob(DUMPS + r'\m_*.bin'))
lines = []
tot = 0
for f in bins:
    d = open(f, 'rb').read()
    tok, il, mx, eh, op = struct.unpack_from('<5I', d, 0)
    tot += il
    lines.append(f'token=0x{tok:08X} il={il} maxStack={mx} eh={eh}')
print('govde:', len(bins), '| toplam IL:', tot)
lines.sort(key=lambda l: -int(l.split('il=')[1].split()[0]))
for b in lines[:8]:
    print('  ', b)