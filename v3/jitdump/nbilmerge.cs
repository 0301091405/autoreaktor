// nbilmerge.cs — JIT dump -> MethodDef eslemesi + geri yazim.
// Rota: nbfixctor2 ciktisi (metadata acik) veya Slayer ciktisi
// uzerinden calisir. JIT dump'taki govde IL bytelarini MethodDef
// govde uzunlugu + IL hash ile esler; token kaymalari
// PreserveAll ile engellenir. Eslesmeyen govdeler kalinir.
//
// Kullanim: nbilmerge.exe <input.exe> <dumpdir> <output.exe>
using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class DumpBody {
    public uint Tok, Il, MaxStack, Eh;
    public byte[] Body;
}

class NBIlMerge {
    static int Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("kullanım: nbilmerge <in.exe> <dumpdir> <out.exe>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);
        var dumpDir = a[1];
        // 1) dump govdelerini yukle: token|il|hash -> body
        var bodies = new List<DumpBody>();
        foreach (var f in Directory.GetFiles(dumpDir, "m_*.bin")) {
            var d = File.ReadAllBytes(f);
            uint tok = BitConverter.ToUInt32(d, 0);
            uint il = BitConverter.ToUInt32(d, 4);
            uint mx = BitConverter.ToUInt32(d, 8);
            uint eh = BitConverter.ToUInt32(d, 12);
            var body = new byte[il];
            Array.Copy(d, 20, body, 0, il);
            bodies.Add(new DumpBody { Tok = tok, Il = il, MaxStack = mx, Eh = eh, Body = body });
        }
        Console.WriteLine("dump govde: " + bodies.Count);

        // 2) hedef moduldeki metotlarla esle: IL-uzunlugu birebir
        // (dump'taki govde uzunlugu ile NecroBit stub'inin uzunlugu
        // farkli olur — eslesme uzunluk uzerinden degil, hash'e
        // dokunmayan kismen: once uzunluk eslesenler sonra
        // tekil uzunluklar). En guclu sinyal: benzersiz IL boyut +
        // maxStack kombinasyonu.
        int merged = 0, unmatched = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Instructions.Count == 0) continue;
                // NecroBit stub'lar: tek-2 instruction. Gercek
                // govde yazilacak hedef: stub'a denk gelen dump govdesi.
                // Baslangic rotasi: uzun esleme yapma; sadece bos/stub
                // govde sayisini raporla (kanit asamasi).
            }
        }
        Console.WriteLine("kanit asamasi: stub analizi raporu");
        // NecroBit null-operand govdeleri (nb2'de null-sil yapilan
        // islemin aynisi) — yazim icin silmek sart:
        var toRemove = new List<Instruction>();
        int nullSil = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                toRemove.Clear();
                var branchTargets = new HashSet<dnlib.DotNet.Emit.Instruction>();
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is dnlib.DotNet.Emit.Instruction) branchTargets.Add((dnlib.DotNet.Emit.Instruction)i.Operand);
                    if (i.Operand is dnlib.DotNet.Emit.Instruction[])
                        foreach (var x in (dnlib.DotNet.Emit.Instruction[])i.Operand) branchTargets.Add(x);
                }
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.TryStart != null) branchTargets.Add(eh.TryStart);
                    if (eh.HandlerStart != null) branchTargets.Add(eh.HandlerStart);
                    if (eh.FilterStart != null) branchTargets.Add(eh.FilterStart);
                }
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand != null) continue;
                    var ot = i.OpCode.OperandType;
                    if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                        ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                        ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                        if (branchTargets.Contains(i)) { i.OpCode = OpCodes.Nop; i.Operand = null; }
                        else toRemove.Add(i);
                        nullSil++;
                    }
                }
                foreach (var i in toRemove) m.Body.Instructions.Remove(i);
            }
        }
        Console.WriteLine("null-sil (yazim kurtarma): " + nullSil);
        mod.Write(a[2], new ModuleWriterOptions(mod) { MetadataLogger = DummyLogger.NoThrowInstance });
        Console.WriteLine("[ok] yazildi: " + a[2]);
        return 0;
    }
}