// dcheck.cs — debug dnlib's view of the AoIBWWl::* calls.
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DCheck {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        int n = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    var op = i.Operand as IMethod;
                    if (op == null) continue;
                    var r = op.ResolveMethodDef();
                    if (r != null) continue;
                    string da = null;
                    try { da = op.DeclaringType?.DefinitionAssembly?.FullName; } catch {}
                    if (n < 25)
                        Console.WriteLine($"[dead] {t.Name}::{m.Name} op={i.OpCode} " +
                            $"target={op.FullName} da={da} scope={op.DeclaringType?.Scope?.ToString()}");
                    n++;
                }
            }
        }
        Console.WriteLine($"toplam unresolvable: {n}");
    }
}