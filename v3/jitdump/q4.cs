
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
}