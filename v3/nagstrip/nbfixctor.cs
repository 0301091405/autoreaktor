// nbfixctor.cs — NecroBit 7.5 sahte-ctor tamiri: base çağrısı enjekte et.
//
// Kanıt zinciri (t7):
//   1. orijinal sample.exe ÇALIŞIR (GUI açılır)
//   2. dnlib roundtrip (hiç patch yok) -> NullReferenceException at
//      Control.set_Text: ctor base Form::.ctor çağırmıyor
//   3. metadata'da SampleForm::.ctor = nop nop nop ret (imkansız derleyici
//      çıktısı) -> NecroBit demo sahte gövde bırakmış
//   4. kaynak kod: default ctor olmalı (base çağrılı)
// TAMİR: sahte gövdeli metot .ctor ise: call base::.ctor + ret yaz.
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
                // sahte govde: <= 6 instr, hicbir call/newobj yok, hepsi nop/ret
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
                    // base::.ctor cagrisi enjekte et
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
                        // govdeyi yeniden kur: ldarg.0; call base::.ctor; ret
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