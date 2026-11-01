// Passes/AntiDebugPass.cs — Neutralize anti-debugging checks in dnlib ModuleDef
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AutoReaktor.Passes {
    public static class AntiDebugPass {
        public static int Run(ModuleDef mod) {
            int removed = 0;
            foreach (var t in mod.GetTypes()) {
                foreach (var m in t.Methods) {
                    if (!m.HasBody) continue;
                    var instrs = m.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++) {
                        // Detect calls to Debugger.IsAttached or Environment.TickCount anti-debug patterns
                        var call = instrs[i];
                        if (call.OpCode == OpCodes.Call && call.Operand is IMethod meth) {
                            if (meth.DeclaringType.FullName == "System.Diagnostics.Debugger" && meth.Name == "get_IsAttached") {
                                // Replace call with 'ldc.i4.0' (false)
                                instrs[i].OpCode = OpCodes.Ldc_I4_0;
                                instrs[i].Operand = null;
                                removed++;
                            }
                        }
                    }
                }
            }
            Console.WriteLine("[pass] AntiDebugPass neutralized checks: " + removed);
            return removed;
        }
    }
}
