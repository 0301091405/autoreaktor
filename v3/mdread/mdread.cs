// mdread.cs — dnlib with MethodDef body okuyucu (ground truth).
// Amac: manually parser'im with dnlib'in okudugunu karsilastir — kim dogru?
// Kullanim: mdread.exe <assembly> [--il]
using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class MDRead {
    static int Main(string[] args) {
        if (args.Length < 1) { Console.WriteLine("mdread <asm>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);
        int withBody = 0, noBody = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.HasBody) { withBody++; }
                else noBody++;
            }
        }
        Console.WriteLine($"types={mod.Types.Count} methods withBody={withBody} noBody={noBody}");
        // NecroBit stub detection: is the body just ldsfld + callvirt/call Invoke?
        int stubs = 0, real = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var instrs = m.Body.Instructions;
                if (instrs.Count <= 6) {
                    bool ldsfldSeen = false, invokeSeen = false;
                    foreach (var i in instrs) {
                        if (i.OpCode.Code == Code.Ldsfld) ldsfldSeen = true;
                        if (i.ToString().Contains("Invoke")) invokeSeen = true;
                    }
                    if (ldsfldSeen && invokeSeen) { stubs++; continue; }
                }
                real++;
                if (real <= 8 && args.Length > 1 && args[1] == "--il") {
                    Console.WriteLine($"--- {t.Name}::{m.Name} ({instrs.Count} instr) ---");
                    foreach (var i in instrs)
                        Console.WriteLine($"  {i.OpCode} {i.Operand}");
                }
            }
        }
        Console.WriteLine($"NecroBit-stub={stubs} gercek-body={real}");
        return 0;
    }
}
