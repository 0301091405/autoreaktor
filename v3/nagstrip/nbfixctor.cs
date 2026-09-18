// nbfixctor.cs — NecroBit 7.5 fake-ctor repair: inject the base call.
//
// Proof chain (t7):
//   1. original sample.exe CALISIR (GUI acilir)
//   2. dnlib roundtrip (no patching at all) -> NullReferenceException at
//      Control.set_Text: ctor base Form::.ctor cagirmiyor
//   3. in metadata SampleForm::.ctor = nop nop nop ret (impossible for a compiler
//      output) -> the NecroBit demo left a fake body
//   4. source code: should be a default ctor (with the base call)
// REPAIR: if the fake-body method is a .ctor: write call base::.ctor + ret.
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NbFixCtor {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nbfixctor <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);
        int fixedBodies = 0;

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                // fake body: <= 6 instr, no call/newobj at all, all nop/ret
                bool fake = ins.Count <= 6;
                bool anyCall = false;
                int nonNopRet = 0;
                foreach (var i in ins) {
                    if (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt ||
                        i.OpCode == OpCodes.Newobj) anyCall = true;
                    if (i.OpCode != OpCodes.Nop && i.OpCode != OpCodes.Ret) nonNopRet++;
                }
                if (nonNopRet > 0) fake = false;
                if (!fake || anyCall) continue;

                Console.WriteLine($"[cand] {t.FullName}::{m.Name} ins={ins.Count} ctor={m.IsConstructor} static={m.IsStatic}");
                if (m.IsConstructor && !m.IsStatic) {
                    // inject the base::.ctor call
                    var baseType = t.BaseType;
                    IMethod baseCtor = null;
                    if (baseType != null) {
                        var bt = baseType.ResolveTypeDef();
                        if (bt != null) {
                            foreach (var c in bt.Methods) {
                                if (c.IsConstructor && !c.IsStatic &&
                                    c.MethodSig.GetParamCount() == 0) {
                                    baseCtor = c; break;
                                }
                            }
                        }
                    }
                    if (baseCtor != null) {
                        // bodyyi yeniden kur: ldarg.0; call base::.ctor; ret
                        for (int k = 0; k < ins.Count; k++) {
                            ins[k].OpCode = OpCodes.Nop;
                            ins[k].Operand = null;
                        }
                        ins[0].OpCode = OpCodes.Ldarg_0;
                        ins[1].OpCode = OpCodes.Call;
                        ins[1].Operand = baseCtor;
                        ins[ins.Count - 1].OpCode = OpCodes.Ret;
                        fixedBodies++;
                        Console.WriteLine($"[fix] {t.FullName}::{m.Name} -> base ctor");
                    }
                }
            }
        }

        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.HasBody) m.Body.KeepOldMaxStack = true;

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        mod.Write(args[1], opts);
        Console.WriteLine($"[ok] fixed={fixedBodies} -> {args[1]}");
        return 0;
    }
}
