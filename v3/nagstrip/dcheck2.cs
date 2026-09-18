// dcheck2.cs — specifically analyze the calls targeting AoIBWWl.
// Question: does the AoIBWWl type EXIST in metadata (does dnlib read it as a TypeDef),
// yoksa MemberRef'in DeclaringType'i nereye scope ediliyor?
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DCheck2 {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);

        // 1) is there a TypeDef in the module whose name contains AoIBWWl?
        foreach (var t in mod.GetTypes()) {
            if (t.Name.String.Contains("AoIBWWl") || t.FullName.Contains("AoIBWWl"))
                Console.WriteLine($"[typedef] {t.FullName} methods={t.Methods.Count}");
        }

        // 2) AoIBWWl'e giden TUM operand'larin cozunum statusunu yazdir
        int n = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    var op = i.Operand as IMethod;
                    if (op == null) continue;
                    if (!op.FullName.Contains("AoIBWWl")) continue;
                    var r = op.ResolveMethodDef();
                    string scope = null, da = null;
                    try { scope = op.DeclaringType?.Scope?.ToString(); } catch {}
                    try { da = op.DeclaringType?.DefinitionAssembly?.FullName; } catch {}
                    Console.WriteLine($"[aoib] {t.Name}::{m.Name} op={i.OpCode} " +
                        $"target={op.FullName} resolved={(r != null ? "DOLU:" + r.FullName : "NULL")} " +
                        $"scope={scope} da={da}");
                    n++;
                }
            }
        }
        Console.WriteLine($"toplam AoIBWWl operand: {n}");
    }
}