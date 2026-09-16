// mdread2.cs — dump image içinden dnlib ile tam gövde okuma (nbimage route).
// Ayrıca: dump'tan kesilen image ile disk dosyasının method-body farkını çıkar.
// Kullanım: mdread2 <asm> [--dump <image.bin> --imgbase 0x...]
using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class MDRead2 {
    static void Walk(string path, string tag, ref int withBody, ref int total, ref int stubs) {
        var mod = ModuleDefMD.Load(path);
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                total++;
                if (!m.HasBody) continue;
                withBody++;
                var ins = m.Body.Instructions;
                if (ins.Count <= 6) {
                    bool lds = false, inv = false;
                    foreach (var i in ins) {
                        if (i.OpCode.Code == Code.Ldsfld) lds = true;
                        if (i.Operand != null && i.Operand.ToString().Contains("Invoke")) inv = true;
                    }
                    if (lds && inv) { stubs++; continue; }
                }
            }
        }
        Console.WriteLine($"{tag}: types={mod.Types.Count} methods={total} withBody={withBody} stubs={stubs}");
    }

    static int Main(string[] args) {
        int wb = 0, tt = 0, st = 0;
        Walk(args[0], "assembly", ref wb, ref tt, ref st);
        return 0;
    }
}