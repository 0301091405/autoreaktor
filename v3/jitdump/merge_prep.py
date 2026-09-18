# Her iki launcher da x86. t1'de DLL yuklenmedi ama t4y'de
# loaded. Difference: t1's NecroBit (6.x-7.0) against APC injection
# and may run its own loader after CreateProcess.
# Ya da daha basit: t1 sample.exe ANYCPU-32BITPREF + 32BITREQ:
# 0x600 = 32BITREQUIRED. Hmm, aynisi dotqw'de de.
# Practical diagnosis: start the t1 target WITHOUT the launcher,
# with a COMPlus variable in python's env? Most robust path:
# .NET profiler env (COR_ENABLE_PROFILING + COR_PROFILER) ile
# DLL'i CLR yukler (standart, APC'ye gore cok daha guvenilir).
# But that's a new route. PRIORITY: nbilmerge (write-back) — we
# already have 238 bodies from 7.5.9.1. Token matching + dnlib write-back
# yazim: nb2 filesi acilir (metadata gorunur), dump'taki IL
# matched by patterns. First, with one of the dump files
# nb2'deki methodlari karsilastir — IL hash eslemesi mumkun mu:
import struct, glob, os

DUMPS = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\jitdump'
bins = sorted(glob.glob(DUMPS + r'\m_*.bin'))
print('dump:', len(bins))
# hex-dump the IL of the first 3 bodies — for matching on the dnlib side
for f in bins[:3]:
    d = open(f, 'rb').read()
    tok, il, mx, eh, op = struct.unpack_from('<5I', d, 0)
    body = d[20:20+min(il, 24)]
    print(os.path.basename(f), 'il=', il, 'maxStack=', mx, 'eh=', eh, 'IL[0:24]=', body.hex())