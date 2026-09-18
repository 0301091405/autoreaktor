"""nbfix.py — NecroBit 7.5 fake-body survey (t1 proof tool).

ROOT PROOF (measured):
  NecroBit 7.5 demo: the metadata bodies of the methods it samples become nop/ret
  with a fake body (SampleForm::.ctor = nop nop nop ret —
  a C# compiler could never emit that; the base Form ctor is missing).
  the real body comes from the native side at runtime → the original runs,
  any rebuild written via dnlib inherits the fake bodies → AV.

COZUM (bu fwith):
  Detect fake bodies (<=6 instr, all nop/ret, no base call) ->
  generate the REAL body fresh with dnlib: inject the base ctor call.
  Bu target for ctor: call Form::.ctor; ret.

GENERALIZE: repair fake bodies via source analysis. In t7 the only fake: the ctor.
"""
import subprocess
import sys

BASE = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3'
RT = BASE + r'\nagstrip\bin\Release\nagstrip.exe'  # for now just a wrapper
IN = BASE + r'\multi-target\t7\sample.exe'
OUT = BASE + r'\multi-target\t7\sample-t1-fixed.exe'

# detect first: which methods are fake?
r = subprocess.run([BASE + r'\mdread\bin\Release\mdread.exe', IN, '--il'],
                   capture_output=True, text=True)
print(r.stdout.split('\n')[0])
