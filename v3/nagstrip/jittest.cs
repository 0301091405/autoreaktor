// jittest.cs — qp1d5IbOJ'u tek basina JIT'le, hata detayini al.
using System;
using System.Reflection;
using System.Runtime.CompilerServices;

class JitTest {
    static void Main(string[] args) {
        string asmPath = args[0];
        try {
            Assembly asm = Assembly.LoadFrom(asmPath);
            Module mod = asm.GetModules()[0];
            foreach (Type t in asm.GetTypes()) {
                if (t.FullName == null || !t.FullName.Contains("AoIBWWl")) continue;
                MethodInfo mi = t.GetMethod("qp1d5IbOJ",
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                if (mi == null) continue;
                Console.WriteLine("metot bulundu: " + t.FullName + "::qp1d5IbOJ");
                try {
                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                    Console.WriteLine("JIT OK");
                } catch (Exception ex) {
                    Console.WriteLine("JIT HATA: " + ex.GetType().Name + ": " + ex.Message);
                    Exception e = ex;
                    while (e != null) {
                        Console.WriteLine("  tip: " + e.GetType().Name + ": " + e.Message);
                        string st = e.StackTrace;
                        if (st != null) {
                            string[] sl = st.Split(new char[] { '\r', '\n' },
                                System.StringSplitOptions.RemoveEmptyEntries);
                            foreach (string ln in sl)
                                if (ln.Contains("AoIBWWl") || ln.Contains("Module"))
                                    Console.WriteLine("    " + ln.Trim());
                        }
                        e = e.InnerException;
                    }
                }
                return;
            }
            Console.WriteLine("turlar listelenemedi");
        } catch (Exception ex) {
            Console.WriteLine("yukleme hatasi: " + ex.GetType().Name + ": " + ex.Message);
            if (ex.InnerException != null)
                Console.WriteLine("  ic: " + ex.InnerException.Message);
        }
    }
}