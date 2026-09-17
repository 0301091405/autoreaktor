// findform.cs: locate the Form type + its ctor token in a packed module.
// The dumped form-init body references FieldDef tokens; the OWNING type of
// those fields is the form, and its .ctor is the write target for the dump.
// Usage: findform.exe <module> [fieldTokHex ...] -> prints owning type and ctor.
using System;
using System.Linq;
using dnlib.DotNet;

static class P {
    static int Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: findform.exe <module> <fieldTokHex>..."); return 1; }
        var mod = ModuleDefMD.Load(a[0]);
        for (int i = 1; i < a.Length; i++) {
            uint ft = Convert.ToUInt32(a[i], 16);
            foreach (var t in mod.GetTypes()) {
                foreach (var f in t.Fields) {
                    if (f.MDToken.Raw == ft) {
                        Console.WriteLine("field 0x{0:X8} -> type {1} (tok 0x{2:X8})", ft, t.FullName, t.MDToken.Raw);
                        foreach (var m in t.Methods)
                            Console.WriteLine("    method {0} tok=0x{1:X8} static={2} pars={3} body={4}",
                                m.Name, m.MDToken.Raw, m.IsStatic, m.Parameters.Count,
                                m.HasBody ? m.Body.Instructions.Count : 0);
                    }
                }
            }
        }
        return 0;
    }
}