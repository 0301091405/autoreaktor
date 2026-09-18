// refltest.cs — Reflection Compatibility Mode proof:
// load the rebuilt binary via reflection, list the types,
// check whether the entry call can be made in the current state.
using System;
using System.Reflection;

class ReflTest {
    static void Main(string[] args) {
        string f = args[0];
        try {
            var asm = Assembly.LoadFrom(f);
            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) {
                types = ex.Types;
                int nonNull = 0;
                foreach (var tt in types) if (tt != null) nonNull++;
                Console.WriteLine($"tip yukleme kismi: {nonNull}/{types.Length}");
            }
            int live = 0;
            foreach (var t in types) {
                if (t == null) continue;
                live++;
                if (t.FullName.Contains("RnpXMmauY4qryS2lPg") || t.FullName.Contains("Bei6dDVRWBIU1kkC4M"))
                    Console.WriteLine("form tipi yansimada gorunur: " + t.FullName);
            }
            Console.WriteLine($"GetTypes OK: {live} tip reflection-erisilebilir");
            var ep = asm.EntryPoint;
            Console.WriteLine("EntryPoint: " + (ep != null ? ep.ToString() : "YOK"));
            // reflection invoke TEST (opens GUI — we do not close it, proof only):
            if (ep != null && args.Length > 1 && args[1] == "invoke") {
                Console.WriteLine("invoke test (close after 2s)...");
                var t = new System.Threading.Thread(() => ep.Invoke(null, null));
                t.Start();
                System.Threading.Thread.Sleep(6000);
                Environment.Exit(0);
            }
        } catch (Exception ex) {
            Console.WriteLine("HATA: " + ex.GetType().Name + ": " + ex.Message);
        }
    }
}