# "module MethodDef: 1853" + dump token 0x06000003 exists but
# byToken MISSES! Is RID 3 missing from the module? ridcheck.exe
# FOUND rid 3 ('?'). Difference: ridcheck scanned nb2; nbilmerge
# loads the ORIGINAL. In the original, rid 3 may be a different
# method OR rid 3 may not exist (obf type layout). Quick check:
# list rid ranges in the original + which of the dump's small
# tokens exist in the original:
code = r'''
using System;
using System.Collections.Generic;
using dnlib.DotNet;
class Q4 {
    static void Main(string[] a) {
        var m = ModuleDefMD.Load(a[0]);
        var toks = new HashSet<uint>();
        foreach (var t in m.GetTypes())
            foreach (var mm in t.Methods)
                toks.Add((uint)mm.MDToken.Raw);
        Console.WriteLine("modul token sayisi: " + toks.Count);
        foreach (var q in new uint[] { 0x06000001, 0x06000002, 0x06000003, 0x06000005, 0x06000006, 0x06000007, 0x06000009, 0x0600000A }) {
            Console.WriteLine("0x" + q.ToString("X8") + " modulde VAR MI: " + toks.Contains(q));
        }
        // rid 3 hangisi:
        foreach (var t in m.GetTypes())
            foreach (var mm in t.Methods)
                if ((uint)mm.MDToken.Raw == 0x06000003)
                    Console.WriteLine("rid3 = " + t.FullName + "::" + mm.Name + " HasBody=" + mm.HasBody);
    }
}'''
open(r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\jitdump\q4.cs', 'w').write(code)
import subprocess
JIT = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\jitdump'
subprocess.run([r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe', '/nologo',
                '/r:dnlib.dll', '/out:q4.exe', 'q4.cs'], cwd=JIT, capture_output=True)
r = subprocess.run([JIT + r'\q4.exe',
                    r"C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\NET Reactor Unpack Me.exe"],
                   capture_output=True, cwd=JIT)
print((r.stdout or b'').decode('mbcs', 'replace'))