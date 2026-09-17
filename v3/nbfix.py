"""nbfix.py — NecroBit 7.5 sahte-body fulliri (t1 proof araci).

KOK KANIT (olculmus):
  NecroBit 7.5 demo, ornekledigi methodlarin metadata bodysini nop/ret
  sahte bodyyle degistirir (SampleForm::.ctor = nop nop nop ret —
  C# derleyicisi asla boyle uretemez, base Form ctor eksik).
  Gercek body runtime'da native taraftan geliyor → original runir,
  dnlib with writeilan herhangi bir rebuild sahte bodylerle writeilir → AV.

COZUM (bu fwith):
  Sahte body (<=6 instr, hepsi nop/ret, base call none) tespit →
  dnlib with GERCEK bodyyi newden uret: base ctor call enjekte et.
  Bu target for ctor: call Form::.ctor; ret.

GENELLEME: sahte bodyleri kaynak-analizle onar. t7'de tek sahte: ctor.
"""
import subprocess
import sys

BASE = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3'
RT = BASE + r'\nagstrip\bin\Release\nagstrip.exe'  # simdilik sadece wrapper
IN = BASE + r'\multi-target\t7\sample.exe'
OUT = BASE + r'\multi-target\t7\sample-t1-fixed.exe'

# once tespit: hangi methodlar sahte?
r = subprocess.run([BASE + r'\mdread\bin\Release\mdread.exe', IN, '--il'],
                   capture_output=True, text=True)
print(r.stdout.split('\n')[0])
