// forcedump — force-JIT every resolvable MethodDef inside the hooked process.
//
// The JIT dump route only captures bodies the target actually runs; a GUI
// that idles after startup leaves most methods undumped (jitdrive.py grew
// coverage by clicking every control). This companion closes the gap at the
// root: loaded INTO the hooked process, it walks every type and calls
// RuntimeHelpers.PrepareMethod on every method with a body — the runtime
// JIT-compiles each one, the compileMethod hook snapshots each body. One
// pass replaces the whole GUI-drive heuristic.
//
// Order matters and mirrors nbdump's proven sequence: module cctors run
// FIRST (anti-tamper init completes while nothing is suspect — PrepareMethod
// never executes code), then the per-method walk, then class constructors.
// Every step is individually faulted: a hostile cctor or a generic that
// refuses preparation must not stop the walk.
//
// Bitness and TFM must match the target (nbjitdump.py picks the build):
// x86 targets need the x86 binary, .NET Core targets the net8.0 one.
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

static class ForceDump
{
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("usage: forcedump <assembly>");
            return 1;
        }
        string path = Path.GetFullPath(args[0]);
        Console.WriteLine("[fd] target: " + path);

        Assembly asm;
        try
        {
            asm = Assembly.Load(File.ReadAllBytes(path));
        }
        catch (Exception e1)
        {
            // load-from-path so sibling dependencies resolve from the target dir
            try
            {
                asm = Assembly.LoadFrom(path);
                Console.WriteLine("[fd] bytes-load failed, path-load ok: " +
                                  (e1.InnerException ?? e1).Message);
            }
            catch (Exception e2)
            {
                Console.WriteLine("[fd] load failed: " +
                                  (e2.InnerException ?? e2).Message);
                return 2;
            }
        }
        Console.WriteLine("[fd] loaded: " + asm.FullName);

        Type[] types;
        try
        {
            types = asm.GetTypes();
        }
        catch (ReflectionTypeLoadException e)
        {
            types = e.Types;
            Console.WriteLine("[fd] partial type load: " + types.Length + " of " +
                              e.Types.Length + " (loader errors logged)");
            foreach (var le in e.LoaderExceptions)
                if (le != null) { Console.WriteLine("[fd]   loader: " + le.Message); break; }
        }
        Console.WriteLine("[fd] types: " + types.Length);

        // 1) module initializers first — NecroBit decrypters and anti-tamper
        //    init live here, and the walk below needs them initialized.
        foreach (Module mod in asm.GetModules())
        {
            try
            {
                RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle);
                Console.WriteLine("[fd] module cctor ok: " + mod.Name);
            }
            catch (Exception e)
            {
                Console.WriteLine("[fd] module cctor failed (continuing): " +
                                  (e.InnerException ?? e).Message);
            }
        }

        int prepared = 0, failed = 0, skipped = 0;
        foreach (Type t in types)
        {
            if (t == null) { skipped++; continue; }
            MethodInfo[] methods;
            try
            {
                methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                       BindingFlags.Instance | BindingFlags.Static |
                                       BindingFlags.DeclaredOnly);
            }
            catch
            {
                skipped++;
                continue;
            }
            foreach (MethodInfo m in methods)
            {
                try
                {
                    if (m.GetMethodBody() == null) { skipped++; continue; }   // abstract/extern/pinvoke
                    RuntimeHelpers.PrepareMethod(m.MethodHandle);
                    prepared++;
                }
                catch
                {
                    // open generics and runtime-refused bodies land here —
                    // counted, never fatal
                    failed++;
                }
            }
            // class constructors: RunClassConstructor JITs the cctor body too
            try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
            catch { }
        }

        Console.WriteLine("[fd] done: prepared=" + prepared +
                          " failed=" + failed + " skipped=" + skipped);
        return 0;
    }
}
