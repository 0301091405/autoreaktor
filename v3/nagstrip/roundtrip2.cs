// roundtrip2.cs — roundtrip with PreserveAll (lesson from 7.3).
// Eger PreserveAll yazimi da AV veriyorsa, suc yazida not targette
// (Reactor 7.5's native stub may be checksumming the file —
//  in that case a rebuild should differ completely: rewrite without the stub).
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
