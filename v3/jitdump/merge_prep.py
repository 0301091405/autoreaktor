# Her iki launcher da x86. t1'de DLL yuklenmedi ama t4y'de
# yuklendi. Fark: t1'in NecroBit'i (6.x-7.0) APC injection'a karsi
# CreateProcess sonrasi kendi loader'ini calistiriyor olabilir.
# Ya da daha basit: t1 sample.exe ANYCPU-32BITPREF + 32BITREQ:
# 0x600 = 32BITREQUIRED. Hmm, aynisi dotqw'de de.
# Pratik teshis: t1 targetini launcher ILE DEGIL, python'un
# env'ine COMPlus degiskeni ile baslat? En saglam yol:
# .NET profiler env (COR_ENABLE_PROFILING + COR_PROFILER) ile
# DLL'i CLR yukler (standart, APC'ye gore cok daha guvenilir).
# Ama o yeni bir rota. ONCELIK: nbilmerge (write-back) — dump'i
# zaten 7.5.9.1'den 238 body aldik. Token esleme + dnlib geri
# yazim: nb2 filesi acilir (metadata gorunur), dump'taki IL
# pattern'leriyle eslenir. Once dump filelarindan biri ile
# nb2'deki methodlari karsilastir — IL hash eslemesi mumkun mu:
import struct, glob, os

DUMPS = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\jitdump'
bins = sorted(glob.glob(DUMPS + r'\m_*.bin'))
print('dump:', len(bins))
# ilk 3 bodynin IL'ini hex yaz — dnlib tarafinda esleme icin
for f in bins[:3]:
    d = open(f, 'rb').read()
    tok, il, mx, eh, op = struct.unpack_from('<5I', d, 0)
    body = d[20:20+min(il, 24)]
    print(os.path.basename(f), 'il=', il, 'maxStack=', mx, 'eh=', eh, 'IL[0:24]=', body.hex())