// nagstrip5.cs — v5 MINIMAL: just ret the nag-throw body.
// do NOT touch the Reactor runtime inits (qp1d5IbOJ, OHl6UVo6W).
// Finding chain: the original is alive; de4dot AVs; nop-everything AVs.
// Simdi minimal: nag metodu bodysi -> tek ret.
using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class NagStrip5 {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nagstrip5 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);

        int patched = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool hasNag = false;
                foreach (var i in m.Body.Instructions) {
                    if (i.OpCode == OpCodes.Ldstr &&
                        i.Operand is string s &&
                        s.Contains("unregistered version")) { hasNag = true; break; }
                }
                if (!hasNag) continue;
                // rebuild the body in place: all nops + final ret
                var ins = m.Body.Instructions;
                for (int k = 0; k < ins.Count; k++) {
                    ins[k].OpCode = OpCodes.Nop;
                    ins[k].Operand = null;
                }
                ins[ins.Count - 1].OpCode = OpCodes.Ret;
                patched++;
                Console.WriteLine($"[patch] {t.FullName}::{m.Name}");
            }
        }

        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.HasBody) m.Body.KeepOldMaxStack = true;

        mod.Write(args[1]);
        Console.WriteLine($"[ok] patched={patched} -> {args[1]}");
        return 0;
    }
}
