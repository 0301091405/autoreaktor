"""nbfix.py — NecroBit 7.5 sahte-gövde tamiri (t1 kanıt aracı).

KÖK KANIT (ölçülmüş):
  NecroBit 7.5 demo, örneklediği metotların metadata gövdesini nop/ret
  sahte gövdeyle değiştirir (SampleForm::.ctor = nop nop nop ret —
  C# derleyicisi asla böyle üretemez, base Form ctor eksik).
  Gerçek gövde runtime'da native taraftan geliyor → orijinal çalışır,
  dnlib ile yazılan herhangi bir rebuild sahte gövdelerle yazılır → AV.

ÇÖZÜM (bu dosya):
  Sahte gövde (<=6 instr, hepsi nop/ret, base çağrısı yok) tespit →
  dnlib ile GERÇEK gövdeyi yeniden üret: base ctor çağrısı enjekte et.
  Bu hedef için ctor: call Form::.ctor; ret.

GENELLEME: sahte gövdeleri kaynak-analizle onar. t7'de tek sahte: ctor.
"""
import subprocess
import sys

BASE = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3'
RT = BASE + r'\nagstrip\bin\Release\nagstrip.exe'  # simdilik sadece wrapper
IN = BASE + r'\multi-target\t7\sample.exe'
OUT = BASE + r'\multi-target\t7\sample-t1-fixed.exe'

# once tespit: hangi metotlar sahte?
r = subprocess.run([BASE + r'\mdread\bin\Release\mdread.exe', IN, '--il'],
                   capture_output=True, text=True)
print(r.stdout.split('\n')[0])