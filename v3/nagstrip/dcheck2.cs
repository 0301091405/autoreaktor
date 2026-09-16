// dcheck2.cs — AoIBWWl hedefli cagrilari OZEL analiz et.
// Soru: AoIBWWl tipi metadata'da VAR MI (dnlib TypeDef olarak okuyor mu),
// yoksa MemberRef'in DeclaringType'i nereye scope ediliyor?
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DCheck2 {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);

        // 1) modulde AoIBWWl adi gecen TypeDef var mi?
        foreach (var t in mod.GetTypes()) {
            if (t.Name.String.Contains("AoIBWWl") || t.FullName.Contains("AoIBWWl"))
                Console.WriteLine($"[typedef] {t.FullName} methods={t.Methods.Count}");
        }

        // 2) AoIBWWl'e giden TUM operand'larin cozunum durumunu yazdir
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