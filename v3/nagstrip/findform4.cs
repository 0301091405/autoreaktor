// findform4.cs: dump methods of a type that reference UI memberrefs
// (TextBox ctor / Button ctor / Controls.Add) in their CURRENT bodies.
// Compiles under csc 5.0 (no pattern-matching 'is' expressions).
using System;
using System.Linq;
using dnlib.DotNet;

static class P4 {
    static int Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: findform4.exe <module> <typeNameSubstring>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);
        string sub = a[1];
        foreach (var t in mod.GetTypes()) {
            if (!t.FullName.Contains(sub)) continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool ui = false;
                foreach (var i in m.Body.Instructions) {
                    IMethod im = i.Operand as IMethod;
                    if (im == null) continue;
                    string dn = im.DeclaringType == null ? "" : im.DeclaringType.FullName;
                    if (dn.Contains("TextBox") || dn.Contains("Button") ||
                        (im.Name.String.StartsWith("add_") && dn.Contains("Control"))) { ui = true; break; }
                }
                if (!ui) continue;
                Console.WriteLine("CANDIDATE {0}::{1} tok=0x{2:X8} static={3} pars={4} body={5}",
                    t.Name, m.Name, m.MDToken.Raw, m.IsStatic, m.Parameters.Count,
                    m.Body.Instructions.Count);
                foreach (var i in m.Body.Instructions.Take(60)) {
                    string opnd = "";
                    IMethod im2 = i.Operand as IMethod;
                    IField fld = i.Operand as IField;
                    if (im2 != null) opnd = im2.DeclaringType + "::" + im2.Name;
                    else if (fld != null) opnd = fld.DeclaringType + "::" + fld.Name;
                    else if (i.Operand != null) opnd = i.Operand.ToString();
                    Console.WriteLine("    {0} {1}", i.OpCode.Name, opnd);
                }
            }
        }
        return 0;
    }
}