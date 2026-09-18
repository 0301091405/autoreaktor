using System;
using System.Reflection;
class ResTest2 {
    static void Main(string[] a) {
        Assembly asm = Assembly.LoadFrom(a[0]);
        foreach (Type t in asm.GetTypes()) {
            if (t.FullName == null || !t.FullName.Contains("oMu6jVbdhHEH79DDhU") || t.Name.Contains("/")) continue;
            Console.WriteLine("tip: " + t.FullName);
            try {
                FieldInfo f = t.GetField("liEFV4Ewy", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                if (f == null) { Console.WriteLine("liEFV4Ewy yok"); continue; }
                object v = f.GetValue(null);
                Console.WriteLine("liEFV4Ewy = " + (v == null ? "NULL" : v.ToString()));
            } catch (Exception ex) {
                Console.WriteLine("field error: " + ex.GetType().Name + ": " + ex.Message);
                if (ex.InnerException != null) Console.WriteLine("  ic: " + ex.InnerException.Message);
            }
            return;
        }
    }
}