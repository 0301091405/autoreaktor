// Passes/ProxyCallPass.cs — Inline and resolve proxy method calls (proxy stubs)
using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AutoReaktor.Passes {
    public static class ProxyCallPass {
        public static int Run(ModuleDef mod) {
            int resolvedProxies = 0;
            var proxyMap = new Dictionary<MethodDef, IMethod>();

            // Phase 1: Identify proxy methods (methods that just load args and call another method then return)
            foreach (var t in mod.GetTypes()) {
                foreach (var m in t.Methods) {
                    if (!m.HasBody || m.IsConstructor || m.IsAbstract) continue;
                    var instrs = m.Body.Instructions;
                    
                    // Simple proxy pattern: [ldarg*,] call/callvirt targetMethod, ret
                    if (instrs.Count >= 2 && instrs[instrs.Count - 1].OpCode == OpCodes.Ret) {
                        var callInst = instrs[instrs.Count - 2];
                        if ((callInst.OpCode == OpCodes.Call || callInst.OpCode == OpCodes.Callvirt) && callInst.Operand is IMethod targetMeth) {
                            bool isProxy = true;
                            for (int i = 0; i < instrs.Count - 2; i++) {
                                var op = instrs[i].OpCode;
                                if (!op.Name.StartsWith("ldarg") && op != OpCodes.Nop) {
                                    isProxy = false;
                                    break;
                                }
                            }
                            if (isProxy && targetMeth != m) {
                                proxyMap[m] = targetMeth;
                                resolvedProxies++;
                            }
                        }
                    }
                }
            }

            // Phase 2: Redirect callers of proxy methods directly to the target method
            if (proxyMap.Count > 0) {
                foreach (var t in mod.GetTypes()) {
                    foreach (var m in t.Methods) {
                        if (!m.HasBody) continue;
                        var instrs = m.Body.Instructions;
                        for (int i = 0; i < instrs.Count; i++) {
                            var ins = instrs[i];
                            if ((ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Ldftn) && ins.Operand is MethodDef calledMethod) {
                                if (proxyMap.TryGetValue(calledMethod, out var realTarget)) {
                                    ins.Operand = realTarget;
                                }
                            }
                        }
                    }
                }
            }

            Console.WriteLine("[pass] ProxyCallPass resolved & redirected proxy stubs: " + resolvedProxies);
            return resolvedProxies;
        }
    }
}
