// roundtrip2.cs — PreserveAll ile roundtrip (7.3'ten gelen ders).
// Eğer PreserveAll yazımı da AV veriyorsa, suç yazıda değil hedefte
// (Reactor 7.5'in native stub'ı dosya checksum'u yapıyor olabilir —
//  o durumda rebuild yolu tamamen farklı olmalı: stub'sız yeniden yaz).
using System;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

class RoundTrip2 {
    static int Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.HasBody) m.Body.KeepOldMaxStack = true;
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        mod.Write(args[1], opts);
        Console.WriteLine($"[ok] preserveall-roundtrip -> {args[1]}");
        return 0;
    }
}