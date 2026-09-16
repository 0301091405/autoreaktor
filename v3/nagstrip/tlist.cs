// tlist.cs — modulun tum tiplerini + metot adlarini listele.
using System;
using System.Linq;
using dnlib.DotNet;

class TList {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        foreach (var t in mod.GetTypes()) {
            Console.WriteLine($"TYPE {t.FullName} (methods={t.Methods.Count})");
            foreach (var m in t.Methods)
                Console.WriteLine($"  {m.Name} | {m.MethodSig?.RetType} | body={(m.HasBody ? m.Body.Instructions.Count : -1)}");
        }
        // antidebug taramasi: tipik API adi/ipucu:
        Console.WriteLine("--- antidebug/antiildasm tarama ---");
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is IMethod im) {
                        var n = im.Name?.ToString() ?? "";
                        if (n.Contains("Debugger") || n.Contains("IsDebuggerPresent") ||
                            n.Contains("CheckRemoteDebugger") || n.Contains("OutputDebugString") ||
                            n.Contains("GetCurrentProcess") || n.Contains("anti") ||
                            n.Contains("Anti") || n.Contains("ManagedDebugger") ||
                            n.Contains("GetForegroundWindow") || n.Contains("IsWow64") ||
                            n.Contains("QueryInformation")) {
                            Console.WriteLine($"{t.FullName}::{m.Name} -> {n}");
                        }
                    }
                    if (i.Operand is string s) {
                        if (s.Contains("ildasm") || s.ToLower().Contains("debugger") || s.Contains("MDbg")) {
                            Console.WriteLine($"{t.FullName}::{m.Name} -> ldstr \"{s.Substring(0, Math.Min(60, s.Length))}\"");
                        }
                    }
                }
            }
        }
    }
}