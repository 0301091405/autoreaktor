// pinv.cs — P/Invoke (ImplMap) tablosu + SuppressIldasm attribute taramasi.
using System;
using System.Linq;
using dnlib.DotNet;

class PInv {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        Console.WriteLine("--- P/Invoke metotlari ---");
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.ImplMap != null) {
                    Console.WriteLine($"{t.FullName}::{m.Name} -> {m.ImplMap.Module.Name}!{m.ImplMap.Name}");
                }
            }
        }
        Console.WriteLine("--- SuppressIldasm / Obfuscation attribute ---");
        foreach (var a in mod.Assembly.CustomAttributes) {
            Console.WriteLine($"asm-attr: {a.TypeFullName}");
        }
        foreach (var t in mod.GetTypes()) {
            foreach (var a in t.CustomAttributes) {
                var n = a.TypeFullName;
                if (n.Contains("Suppress") || n.Contains("ldasm") || n.Contains("Obfuscat"))
                    Console.WriteLine($"{t.FullName}: {n}");
            }
        }
        // Debugger ile ilgili her turlu string:
        Console.WriteLine("--- debugger string tarama ---");
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is string s && (s.ToLower().Contains("debug") || s.Contains("MDbg") || s.Contains("corflags"))) {
                        Console.WriteLine($"{t.FullName}::{m.Name}: \"{s.Substring(0, Math.Min(70, s.Length))}\"");
                    }
                }
            }
        }
    }
}