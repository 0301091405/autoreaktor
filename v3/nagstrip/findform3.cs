// findform3.cs: dump EVERY method of the itlpu type tree (form + nested)
// with tokens, body sizes, and ldfld targets — identify the form ctor
// candidate whose stub body references the TextBox fields.
using System;
using System.Linq;
using dnlib.DotNet;

static class P3 {
    static int Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: findform3.exe <module> <typeNameSubstring>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);
        string sub = a[1];
        foreach (var t in mod.GetTypes()) {
            if (!t.FullName.Contains(sub)) continue;
            Console.WriteLine("TYPE {0} (tok 0x{1:X8}) methods={2} fields={3}",
                t.FullName, t.MDToken.Raw, t.Methods.Count, t.Fields.Count);
            foreach (var f in t.Fields)
                Console.WriteLine("  field {0} : {1} tok=0x{2:X8}", f.Name,
                    f.FieldType == null ? "?" : f.FieldType.FullName, f.MDToken.Raw);
            foreach (var m in t.Methods) {
                string refs = "";
                if (m.HasBody) {
                    var flds = m.Body.Instructions
                        .Where(i => i.Operand is FieldDef && i.OpCode.Name.StartsWith("ldfld"))
                        .Select(i => ((FieldDef)i.Operand).Name.String)
                        .Distinct().ToList();
                    refs = string.Join(",", flds);
                }
                Console.WriteLine("  method {0} tok=0x{1:X8} static={2} pars={3} body={4} ldfld=[{5}]",
                    m.Name, m.MDToken.Raw, m.IsStatic, m.Parameters.Count,
                    m.HasBody ? m.Body.Instructions.Count : 0, refs);
            }
        }
        return 0;
    }
}