// nagstrip2.cs — t1 runnable proof v2.
//
// v1 finding: just ret-ing the nag-throw was not enough (0xC0000005).
// Kalan iki Reactor runtime call:
//   AoIBWWlDJbaf7LijnA.oMu6jVbdhHEH79DDhU::qp1d5IbOJ()  (anti-tamper check)
//   UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM::OHl6UVo6W() (which de4dot already
//   ret'ledigi ama <Module> cctor'dan calllan init)
// strategy: remove both method calls (call opcode) from the whole body
// AND ret the bodies of those methods. Strings are already resolved in de4dot
// decrypted (plain ldstr) — no decryptor needed on this target.
using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NagStrip2 {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nagstrip2 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);

        // 1) Reactor runtime methodlarini bul (bodysi olmayan 42 method icinden
        //    the called ones + the nag ones) — by name signature:
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
                // qp1d5IbOJ: her tipin cctor'unda calllan — string decryptor init
                // could exist. FIRST see who they are: collect the called methods
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

        // 2) remove all CALLs to these methods from every body
        int removed = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var keep = new List<Instruction>();
                foreach (var i in m.Body.Instructions) {
                    bool isCall = (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt)
                                  && i.Operand is IMethod im
                                  && runtimeMethods.Contains(im);
                    if (isCall) { removed++; continue; }
                    keep.Add(i);
                }
                m.Body.Instructions.Clear();
                foreach (var k in keep) m.Body.Instructions.Add(k);
            }
        }
        Console.WriteLine($"call kaldirildi: {removed}");

        // 3) orphaned calls in cctors — all already end with ret
        mod.Write(args[1]);
        Console.WriteLine($"[ok] -> {args[1]}");
        return 0;
    }
}
