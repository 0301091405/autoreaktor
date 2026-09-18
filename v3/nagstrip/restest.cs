using System;
using System.Reflection;
class ResTest {
    static void Main(string[] a) {
        Assembly asm = Assembly.LoadFrom(a[0]);
        foreach (string n in asm.GetManifestResourceNames())
            Console.WriteLine("res: " + n);
        try {
            var s = asm.GetManifestResourceStream("lIbmsk8bjV8OfC2Eei.hLMLXK0edH4c3LAnjX");
            Console.WriteLine("target res: " + (s == null ? "NULL" : s.Length + "B"));
        } catch (Exception ex) { Console.WriteLine("error: " + ex.Message); }
    }
}