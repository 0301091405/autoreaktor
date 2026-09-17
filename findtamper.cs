// findtamper.cs — "tampered" stringini iceren metotlari bulur
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class FindTamper {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.OpCode.Name != "ldstr") continue;
                    string s = i.Operand as string;
                    if (s != null && s.ToLower().Contains("tampered")) {
                        Console.WriteLine("TIP: " + t.FullName + " | METOT: " + m.Name + " | str: " + s);
                    }
                }
            }
        }
    }
}