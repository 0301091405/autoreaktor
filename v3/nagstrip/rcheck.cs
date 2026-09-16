// rcheck.cs — null-operand'lı metotların RVA kontrolü.
// Hipotez: NecroBit 7.5 comp-mode bu metotların RVA'sını 0'lar,
// dnlib fake body üretir, 'call' operand null kalır.
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class RCheck {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand != null) continue;
                    var ot = i.OpCode.OperandType;
                    if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                        ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                        ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                        Console.WriteLine($"[null] {t.Name}::{m.Name} rva={m.RVA} " +
                            $"op={i.OpCode} off={i.Offset} instr={m.Body.Instructions.Count}");
                    }
                }
            }
        }
    }
}