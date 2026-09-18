using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

class NBWalk {
    static StringBuilder sb = new StringBuilder();
    static int prepared = 0;

    static void Main(string[] a) {
        var asm = Assembly.LoadFrom(Path.GetFullPath(a[0]));
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
            var n = new AssemblyName(e.Name).Name;
            foreach (var ext in new[] { ".dll", ".exe" }) {
                var p = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(a[0])), n + ext);
                if (File.Exists(p)) return Assembly.LoadFrom(p);
            }
            return null;
        };

        // 1) ctor'lar
        foreach (var mod in asm.Modules)
            try { RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle); } catch {}

        foreach (var t in SafeTypes(asm)) {
            if (t == null || t.ContainsGenericParameters) continue;
            try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); } catch {}
        }

        // 2) PrepareMethod bombardimani
        foreach (var t in SafeTypes(asm)) {
            if (t == null || t.ContainsGenericParameters) continue;
            var all = t.GetMethods(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance|BindingFlags.DeclaredOnly)
                .OfType<MethodBase>().Concat(t.GetConstructors(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance|BindingFlags.DeclaredOnly));
            foreach (var m in all) {
                try { RuntimeHelpers.PrepareMethod(m.MethodHandle); prepared++; } catch {}
            }
        }

        W("[PREPARED] " + prepared);

        // 3) scan ALL static fields — type + value type + size
        foreach (var t in SafeTypes(asm)) {
            if (t == null) continue;
            FieldInfo[] fs;
            try { fs = t.GetFields(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static); } catch { continue; }
            foreach (var f in fs) {
                object v = null;
                try { v = f.GetValue(null); } catch { continue; }
                if (v == null) continue;
                var vt = v.GetType();
                string desc = vt.FullName;
                if (v is IDictionary) { desc += " count=" + ((IDictionary)v).Count; }
                else if (v is Array arr) { desc += " len=" + arr.Length; }
                else if (v is System.Collections.ICollection c) { desc += " count=" + c.Count; }
                else if (vt == typeof(byte[])) { }
                if (v is byte[] ba) desc = "byte[] len=" + ba.Length;
                W(t.FullName + "::" + f.Name + " : " + desc);
            }
        }

        // 4) dump the byte[] fields to raw files + the policyCreatorDic contents
        foreach (var t in SafeTypes(asm)) {
            if (t == null) continue;
            FieldInfo[] fs;
            try { fs = t.GetFields(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static); } catch { continue; }
            foreach (var f in fs) {
                try {
                    var v = f.GetValue(null) as byte[];
                    if (v == null || v.Length == 0) continue;
                    var fn = (t.FullName + "_" + f.Name).Replace("`","_").Replace("+","_").Replace(".","_") + ".bin";
                    File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(a[1])), "dump_" + fn), v);
                    W("[DUMPED] " + fn + " len=" + v.Length);
                } catch {}
            }
        }
        // policyCreatorDic — STRUCTURAL lookup: obfuscated names break the 7.3
        // hardcoded "AuthenticatorState.policyCreatorDic" probe. The field is
        // the ONLY static Dictionary<int,int> in the runtime type, so find it by
        // shape: closed generic IDictionary with Int32 key + Int32 value.
        Type authenticator = null;
        FieldInfo dicField = null;
        foreach (var t in SafeTypes(asm)) {
            if (t == null) continue;
            FieldInfo[] fs;
            try { fs = t.GetFields(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static); } catch { continue; }
            foreach (var f in fs) {
                object dv = null;
                try { dv = f.GetValue(null); } catch { continue; }
                if (dv == null) continue;
                // exact Dictionary<int,int> shape test
                if (dv.GetType().IsGenericType &&
                    dv.GetType().GetGenericTypeDefinition() == typeof(System.Collections.Generic.Dictionary<,>) &&
                    dv.GetType().GetGenericArguments()[0] == typeof(int) &&
                    dv.GetType().GetGenericArguments()[1] == typeof(int) &&
                    ((System.Collections.ICollection)dv).Count > 0) {
                    authenticator = t; dicField = f;
                    W("[DICSHP] " + t.FullName + "::" + f.Name + " count=" + ((System.Collections.ICollection)dv).Count);
                }
            }
        }
        if (dicField != null) {
            var dic = dicField.GetValue(null);
            var sbd = new StringBuilder();
            foreach (var entry in (System.Collections.IEnumerable)dic) {
                var t2 = entry.GetType();
                var k = t2.GetProperty("Key").GetValue(entry);
                var v2 = t2.GetProperty("Value").GetValue(entry);
                sbd.AppendLine(k + " -> " + v2);
            }
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(a[1])), "policyCreatorDic.txt"), sbd.ToString());
            W("[DUMPED] policyCreatorDic.txt (structural, " + authenticator.FullName + "::" + dicField.Name + ")");
        }

        File.WriteAllText(a[1], sb.ToString());
        Console.WriteLine("WROTE " + a[1]);
    }

    static Type[] SafeTypes(Assembly asm) {
        try { return asm.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { return ex.Types.Where(x => x != null).ToArray(); }
    }
    static void W(string s) { sb.AppendLine(s); Console.WriteLine(s); }
}
