// nagstrip4.cs — v4: branch targetlerini bozmayan nag-strip.
//
// Onceki iki denemenin ogrettigi:
//   v2 (call'i listeden cikar): branch targeti kirilir
//   v3 (call'i nop'la ama runtime method bodysini Clear() et): Clear()
//       branch targetlerini kiriyor — cunku KALDIRILAN instruction'lar
//       baska methodlarin branch targeti olarak recordli.
// Dogru yontem: runtime method bodysindeki HER instruction'i NOP yap,
// sonuncuyu ret yap (liste hep full — Instruction objeleri yerinde kalir,
// branch targeti referanslari gecerli).
using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class NagStrip4 {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nagstrip4 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);

        var runtimeMethods = new HashSet<IMethod>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                bool isRuntime = false;
                if (m.Name.String.StartsWith("qp1d5IbOJ")) isRuntime = true;
                if (m.Name.String.StartsWith("OHl6UVo6W")) isRuntime = true;
                if (m.HasBody) {
                    foreach (var i in m.Body.Instructions) {
                        if (i.OpCode == OpCodes.Ldstr &&
                            i.Operand is string s &&
                            s.Contains("unregistered version")) { isRuntime = true; break; }
                    }
                }
                if (isRuntime) runtimeMethods.Add(m);
            }
        }
        Console.WriteLine($"runtime method: {runtimeMethods.Count}");

        // body: her instruction -> nop, sonuncu -> ret (yerinde degisim)
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int k = 0; k < ins.Count; k++) {
                    var i = ins[k];
                    if (runtimeMethods.Contains(m)) {
                        i.OpCode = OpCodes.Nop;
                        i.Operand = null;
                        if (k == ins.Count - 1) i.OpCode = OpCodes.Ret;
                        continue;
                    }
                    // diger methodlardaki runtime-call'lari nop'la
                    if ((i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt)
                        && i.Operand is IMethod im && runtimeMethods.Contains(im)) {
                        i.OpCode = OpCodes.Nop;
                        i.Operand = null;
                    }
                }
            }
        }
        // obfuscate bodylerde max-stack yeniden hesabi patlar — koru
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.HasBody) m.Body.KeepOldMaxStack = true;
            }
        }
        mod.Write(args[1]);
        Console.WriteLine($"[ok] -> {args[1]}");
        return 0;
    }
}
