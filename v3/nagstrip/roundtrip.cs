// roundtrip.cs — write-test: patch YOK, sadece Load + Write.
// AV roundtrip'ten geliyorsa suc nagstrip'te not, dnlib yaziminda.
using System;
using dnlib.DotNet;

class RoundTrip {
    static int Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.HasBody) m.Body.KeepOldMaxStack = true;
        mod.Write(args[1]);
        Console.WriteLine($"[ok] roundtrip -> {args[1]}");
        return 0;
    }
}
