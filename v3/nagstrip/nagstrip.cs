// nagstrip.cs — t1 kanıtı: NecroBit-only 7.5 hedeften demo-nag'ı çıkar,
// runnable rebuild üret. Borç: "nbrebuild runnable kanıtı" 7.5 layout'unda.
//
// Bulgu (ölçülmüş): 7.5 demo NecroBit comp-mode gövdeleri metadata'da
// bırakıyor (dnlib 179/179 görüyor, 0 stub) → rebuild = dnlib ile
// <Module>::m8DF1397502BE3EE (nag throw) gövdesini ret ile değiştir.
using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NagStrip {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nagstrip <in> <out>"); return 1; }
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
                // nag metodu: throw yerine ret (stack-nötr: void metot)
                m.Body.Instructions.Clear();
                m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                patched++;
                Console.WriteLine($"[patch] {t.FullName}::{m.Name} -> ret");
            }
        }
        var opts = new ModuleWriterOptions(mod);
        mod.Write(args[1], opts);
        Console.WriteLine($"[ok] patched={patched} -> {args[1]}");
        return 0;
    }
}