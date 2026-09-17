// nagstrip3.cs — v3: branch targetli call'lari da temizle.
// dnlib hatasi: kaldirilan call, bir branch'in targetiydi. Cozum: Instruction
// listesini yeniden kur ama targetleri once sabitle — dnlib de branch'lari da
// kaldirmak yerine call yerine `nop` yaz (stack etkisi 0, void call).
using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class NagStrip3 {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nagstrip3 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);

        var runtimeMethods = new HashSet<IMethod>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                bool isRuntime = false;
                if (m.HasBody) {
                    foreach (var i in m.Body.Instructions) {
                        if (i.OpCode == OpCodes.Ldstr &&
                            i.Operand is string s &&
                            s.Contains("unregistered version")) { isRuntime = true; break; }
                    }
                }
                if (m.Name.String.StartsWith("qp1d5IbOJ")) isRuntime = true;
                if (m.Name.String.StartsWith("OHl6UVo6W")) isRuntime = true;
                if (isRuntime) {
                    runtimeMethods.Add(m);
                    if (m.HasBody) {
                        m.Body.Instructions.Clear();
                        m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    }
                }
            }
        }
        Console.WriteLine($"runtime method: {runtimeMethods.Count}");

        // nop'la (kaldirma yok — branch targetleri bozulmaz)
        int nopped = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if ((i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt)
                        && i.Operand is IMethod im && runtimeMethods.Contains(im)) {
                        i.OpCode = OpCodes.Nop;
                        i.Operand = null;
                        nopped++;
                    }
                }
            }
        }
        Console.WriteLine($"call nop'landi: {nopped}");
        mod.Write(args[1]);
        Console.WriteLine($"[ok] -> {args[1]}");
        return 0;
    }
}
