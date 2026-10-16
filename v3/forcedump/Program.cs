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
    static void Put(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)v;
        buf[off + 1] = (byte)(v >> 8);
        buf[off + 2] = (byte)(v >> 16);
        buf[off + 3] = (byte)(v >> 24);
    }

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

        int prepared = 0, failed = 0, skipped = 0, ehWritten = 0, dumped = 0;
        var manifest = new System.Collections.Generic.List<int[]>();
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
                byte[] ilBytes = null;
                MethodBody body0 = null;
                try
                {
                    var body = m.GetMethodBody();
                    if (body == null) { skipped++; continue; }   // abstract/extern/pinvoke
                    body0 = body;
                    ilBytes = body.GetILAsByteArray();
                    RuntimeHelpers.PrepareMethod(m.MethodHandle);
                    prepared++;
                    // Exception clauses ride along, read from the SAME decoded
                    // body the JIT just consumed (PrepareMethod cached it).
                    // Written in the hook's .eh format so nbilmerge attaches
                    // them without any extra wiring: [u32 count][count x
                    // 28B: flags, tryOff, tryLen, hOff, hLen, classTok,
                    // filterOff]. Managed option enums map 1:1 except Fault
                    // (4 managed -> 3 CORINFO).
                    ilBytes = body.GetILAsByteArray();
                    manifest.Add(new int[] { m.MetadataToken, ilBytes.Length });
                    // Dump the decoded body under its REAL MethodDef token —
                    // the JIT hook's x86 token reads can be unreliable on
                    // fresh MethodDescs, but this reflection view IS the
                    // decoded body (proven: ilSize multiset matches the hook
                    // dump on NecroBit 7.5.0.0). Same 20-byte header the
                    // hook writes, so nbilmerge consumes both unchanged.
                    string bdir = Environment.GetEnvironmentVariable("JITDUMP_DIR");
                    if (!string.IsNullOrEmpty(bdir) && ilBytes.Length > 0)
                    {
                        try
                        {
                            // 24-byte header, same layout as the hook: the
                            // sixth dword is the LocalVarSig token, which only
                            // the hook can see — never overwrite its dumps
                            string bpath = Path.Combine(bdir,
                                "m_" + m.MetadataToken.ToString("X8") + ".bin");
                            if (File.Exists(bpath)) { dumped++; }
                            else
                            {
                                var bout = new byte[24 + ilBytes.Length];
                                Put(bout, 0, (uint)m.MetadataToken);
                                Put(bout, 4, (uint)ilBytes.Length);
                                Put(bout, 8, (uint)body.MaxStackSize);
                                Put(bout, 12, (uint)body.ExceptionHandlingClauses.Count);
                                Put(bout, 16, 0);
                                Put(bout, 20, 0);
                                Array.Copy(ilBytes, 0, bout, 24, ilBytes.Length);
                                File.WriteAllBytes(bpath, bout);
                                dumped++;
                            }
                        }
                        catch { }
                    }
                    var clauses = body.ExceptionHandlingClauses;
                    if (clauses.Count > 0)
                    {
                        string dir = Environment.GetEnvironmentVariable("JITDUMP_DIR");
                        if (!string.IsNullOrEmpty(dir))
                        {
                            try
                            {
                                var buf = new byte[4 + clauses.Count * 28];
                                Put(buf, 0, (uint)clauses.Count);
                                for (int ci = 0; ci < clauses.Count; ci++)
                                {
                                    var c = clauses[ci];
                                    int o = 4 + ci * 28;
                                    uint flags =
                                        c.Flags == ExceptionHandlingClauseOptions.Finally ? 2u :
                                        c.Flags == ExceptionHandlingClauseOptions.Filter ? 1u :
                                        c.Flags == ExceptionHandlingClauseOptions.Fault ? 3u : 0u;
                                    Put(buf, o, flags);
                                    Put(buf, o + 4, (uint)c.TryOffset);
                                    Put(buf, o + 8, (uint)c.TryLength);
                                    Put(buf, o + 12, (uint)c.HandlerOffset);
                                    Put(buf, o + 16, (uint)c.HandlerLength);
                                    uint tok20 = 0;
                                    if (c.Flags == ExceptionHandlingClauseOptions.Filter)
                                        tok20 = (uint)c.FilterOffset;
                                    else if (c.Flags == ExceptionHandlingClauseOptions.Clause &&
                                             c.CatchType != null)
                                        tok20 = (uint)c.CatchType.MetadataToken;
                                    Put(buf, o + 20, tok20);
                                    Put(buf, o + 24, 0);
                                }
                                string ehPath = Path.Combine(dir,
                                    "m_" + m.MetadataToken.ToString("X8") + ".eh");
                                File.WriteAllBytes(ehPath, buf);
                                ehWritten++;
                                Console.WriteLine("[fd] eh: " + Path.GetFileName(ehPath) +
                                                  " clauses=" + clauses.Count);
                            }
                            catch (Exception we) { Console.WriteLine("[dbg] eh write failed: " + we.Message); }
                        }
                    }
                }
                catch
                {
                    // open generics and runtime-refused bodies land here —
                    // counted, never fatal
                    failed++;
                    // a body we ALREADY read still gets dumped: prepare
                    // failures (entry points on packed modules, exotic
                    // methods) must not lose recoverable bodies
                    if (ilBytes != null && ilBytes.Length > 0)
                    {
                        try
                        {
                            // EH clauses from the PRE-prepare body object: the
                            // decoded view exists even when PrepareMethod
                            // refused - without these, cflow'd bodies lose
                            // their try/finally tables (InvalidProgram)
                            string edir = Environment.GetEnvironmentVariable("JITDUMP_DIR");
                            var ecl = body0 == null ? null : body0.ExceptionHandlingClauses;
                            if (!string.IsNullOrEmpty(edir) && ecl != null && ecl.Count > 0)
                            {
                                var ebuf = new byte[4 + ecl.Count * 28];
                                Put(ebuf, 0, (uint)ecl.Count);
                                for (int ci = 0; ci < ecl.Count; ci++)
                                {
                                    var c = ecl[ci];
                                    int o = 4 + ci * 28;
                                    uint eflags =
                                        c.Flags == ExceptionHandlingClauseOptions.Finally ? 2u :
                                        c.Flags == ExceptionHandlingClauseOptions.Filter ? 1u :
                                        c.Flags == ExceptionHandlingClauseOptions.Fault ? 3u : 0u;
                                    Put(ebuf, o, eflags);
                                    Put(ebuf, o + 4, (uint)c.TryOffset);
                                    Put(ebuf, o + 8, (uint)c.TryLength);
                                    Put(ebuf, o + 12, (uint)c.HandlerOffset);
                                    Put(ebuf, o + 16, (uint)c.HandlerLength);
                                    uint etok = 0;
                                    if (c.Flags == ExceptionHandlingClauseOptions.Filter)
                                        etok = (uint)c.FilterOffset;
                                    else if (c.Flags == ExceptionHandlingClauseOptions.Clause && c.CatchType != null)
                                        etok = (uint)c.CatchType.MetadataToken;
                                    Put(ebuf, o + 20, etok);
                                    Put(ebuf, o + 24, 0);
                                }
                                string epath = Path.Combine(edir,
                                    "m_" + m.MetadataToken.ToString("X8") + ".eh");
                                if (!File.Exists(epath)) File.WriteAllBytes(epath, ebuf);
                            }
                            string bdir2 = Environment.GetEnvironmentVariable("JITDUMP_DIR");
                            string p2 = Path.Combine(bdir2, "m_" + m.MetadataToken.ToString("X8") + ".bin");
                            if (!File.Exists(p2))
                            {
                                var bout2 = new byte[24 + ilBytes.Length];
                                Put(bout2, 0, (uint)m.MetadataToken);
                                Put(bout2, 4, (uint)ilBytes.Length);
                                Put(bout2, 8, (uint)(body0?.MaxStackSize ?? 8));
                                Put(bout2, 12, 0);
                                Put(bout2, 16, 0);
                                Put(bout2, 20, 0);
                                Array.Copy(ilBytes, 0, bout2, 24, ilBytes.Length);
                                File.WriteAllBytes(p2, bout2);
                                dumped++;
                            }
                        }
                        catch { }
                    }
                }
            }
            // class constructors: RunClassConstructor JITs the cctor body too
            try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
            catch { }
        }

        Console.WriteLine("[fd] done: prepared=" + prepared +
                          " failed=" + failed + " skipped=" + skipped +
                          " eh=" + ehWritten + " dumped=" + dumped);
        try
        {
            string mdir = Environment.GetEnvironmentVariable("JITDUMP_DIR");
            if (!string.IsNullOrEmpty(mdir))
            {
var sb = new System.Text.StringBuilder("{\"methods\":[");
                for (int i = 0; i < manifest.Count; i++)
                {
                    if (i > 0) sb.Append(',');
sb.Append("{\"token\":").Append(manifest[i][0])
.Append(",\"ilSize\":").Append(manifest[i][1]).Append('}');
                }
                sb.Append("]}");
                File.WriteAllText(Path.Combine(mdir, "manifest.json"), sb.ToString());
                Console.WriteLine("[fd] manifest: " + manifest.Count + " methods");
            }
        }
        catch (Exception me) { Console.WriteLine("[fd] manifest failed: " + me.Message); }
        return 0;
    }
}
