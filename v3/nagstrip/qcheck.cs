// qcheck.cs — tek methodun IL dump'u (packed vs rebuilt diff icin).
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class QCheck {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        string needle = args[1]; // method ad parcasi
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.FullName.Contains(needle)) continue;
                Console.WriteLine($"=== {m.FullName}");
                Console.WriteLine($"    RVA={m.RVA} maxstack={m.Body?.MaxStack} " +
                    $"locals={m.Body?.Variables.Count} instr={m.Body?.Instructions.Count}");
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                    Console.WriteLine($"  IL_{i.Offset:x4}: {i.OpCode} {FormatOp(i.Operand)}");
                if (m.Body.ExceptionHandlers.Count > 0) {
                    Console.WriteLine("  EH:");
                    foreach (var eh in m.Body.ExceptionHandlers)
                        Console.WriteLine($"    {eh.HandlerType} try={eh.TryStart?.Offset:x4}-{eh.TryEnd?.Offset:x4} " +
                            $"hand={eh.HandlerStart?.Offset:x4} catch={eh.CatchType}");
                }
            }
        }
    }
    static string FormatOp(object o) {
        if (o == null) return "";
        if (o is Instruction ins) return $"IL_{ins.Offset:x4}";
        return o.ToString().Replace("\r", "").Replace("\n", "");
    }
}