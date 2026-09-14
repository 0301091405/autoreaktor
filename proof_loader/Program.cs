// Deep proof: invoke the slayed Main and see if it still runs + check its
// resolved string constant. Also dump the IL of Main to look for ldstr.
using System;
using System.IO;
using System.Linq;
using System.Reflection;

class ProofDeep
{
    static void Main(string[] args)
    {
        var path = args[0];
        var asm = Assembly.Load(File.ReadAllBytes(path));
        var t = asm.GetTypes().FirstOrDefault(x => x.GetMethod("Main", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic) != null);
        if (t == null) { Console.WriteLine("no Main found"); return; }
        var main = t.GetMethod("Main", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
        Console.WriteLine($"type: {t.FullName}, method: {main.Name}");

        // 1) dump IL opcodes with ldstr resolution
        var il = main.GetMethodBody()?.GetILAsByteArray();
        Console.WriteLine($"IL size: {il?.Length ?? -1}");
        // 2) actually RUN it — protected-with-decrypted-strings should print
        Console.WriteLine("--- invoking Main(null) ---");
        try
        {
            var o = main.Invoke(null, new object[] { new string[0] });
            Console.WriteLine($"exit: {o}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"invoke threw: {ex.InnerException?.GetType().Name ?? ex.GetType().Name}: {(ex.InnerException ?? ex).Message.Split('\n')[0]}");
        }
        Console.WriteLine("--- invoking Main(dump) ---");
        try
        {
            var o = main.Invoke(null, new object[] { new[] { "dump" } });
            Console.WriteLine($"exit: {o}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"invoke threw: {ex.InnerException?.GetType().Name ?? ex.GetType().Name}: {(ex.InnerException ?? ex).Message.Split('\n')[0]}");
        }
    }
}
