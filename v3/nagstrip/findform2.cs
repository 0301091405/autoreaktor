// findform2.cs: scan every TypeDef for fields typed TextBox/Button/Form-ish
// and print candidate form types with their ctor tokens + current body state.
using System;
using System.Linq;
using dnlib.DotNet;

static class P2 {
    static int Main(string[] a) {
        if (a.Length < 1) { Console.WriteLine("usage: findform2.exe <module>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            var uiFields = t.Fields.Where(f => {
                var s = f.FieldType == null ? "" : f.FieldType.FullName;
                return s.Contains("TextBox") || s.Contains("Button") || s.Contains("Label");
            }).ToList();
            if (uiFields.Count == 0) continue;
            Console.WriteLine("TYPE {0} (tok 0x{1:X8}) ui-fields={2} total-fields={3}",
                t.FullName, t.MDToken.Raw, uiFields.Count, t.Fields.Count);
            foreach (var f in uiFields)
                Console.WriteLine("    field {0} : {1} tok=0x{2:X8}", f.Name, f.FieldType.FullName, f.MDToken.Raw);
            foreach (var m in t.Methods)
                Console.WriteLine("    method {0} tok=0x{1:X8} static={2} pars={3} body={4}",
                    m.Name, m.MDToken.Raw, m.IsStatic, m.Parameters.Count,
                    m.HasBody ? m.Body.Instructions.Count : 0);
        }
        return 0;
    }
}