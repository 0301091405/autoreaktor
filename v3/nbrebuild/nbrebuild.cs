// nbrebuild.cs — v3 NecroBit call-site substitutor (delegate-shim reconstruction).
//
// TRUE mechanism (measured via dnlib inspection of the 7.3 challenge):
//   protected methods keep a VISIBLE body, but each protected operation is
//   `ldsfld <delegate field F>; ...; call Helper::UpdateTransaction(obj, F)`
//   where the delegate's DynamicMethod holds the real logic fragment:
//     ldarg.0 [ldarg.1..3] tail. call/callvirt <target> ret
//
// Rebuild transform (stack-neutral, provable):
//   (ldsfld F, call UpdateTransaction) -> (call/callvirt <fragment target>)
//   because UpdateTransaction(obj, F) == fragment(obj) == target(obj).
//   Fragments with N ldargs: H(obj1..objN, F) -> target(obj1..objN).
//
// Whole-body replacement (v3 pre-alpha) was WRONG — reverted; this is the
// call-site substitution that preserves the original method structure.
//
// Usage: nbrebuild <target.exe> <nb-inventory.json> <out.exe>
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NecrobitRebuild
{
    public sealed class InstructionJson
    {
        public string opcode;
        public string declType;
        public string memberName;
        public string memberSig;
        public string declAssembly;
        public int? intValue;
        public string stringValue;
    }

    public sealed class DynMethodJson
    {
        public string field;
        public int instructionCount;
        public List<InstructionJson> instructions;
    }

    public sealed class InventoryEntry
    {
        public string fieldToken;
        public string dicValue;
        public DynMethodJson dynMethod;
    }

    public static class Program
    {
        static ModuleDefMD module;
        static Importer importer;

        static int Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.Error.WriteLine("usage: nbrebuild <target.exe> <nb-inventory.json> <out.exe>");
                return 1;
            }
            string targetPath = Path.GetFullPath(args[0]);
            string invPath   = Path.GetFullPath(args[1]);
            string outPath   = Path.GetFullPath(args[2]);

            var invRoot = JsonConvert.DeserializeObject<Dictionary<string, object>>(File.ReadAllText(invPath));
            var entries = ((JArray)invRoot["inventory"]).ToObject<List<InventoryEntry>>();

            module = ModuleDefMD.Load(targetPath);
            importer = new Importer(module);

            // field-token -> FieldDef
            var byToken = new Dictionary<uint, FieldDef>();
            foreach (var f in module.GetTypes().SelectMany(t => t.Fields))
                if (!byToken.ContainsKey(f.MDToken.Raw)) byToken[f.MDToken.Raw] = f;

            // field-token -> fragment target instruction
            var fragByField = new Dictionary<uint, InstructionJson>();
            foreach (var e in entries)
            {
                uint tok = Convert.ToUInt32(e.fieldToken, 16);
                var dyn = e.dynMethod;
                if (dyn == null || dyn.instructions == null) continue;
                // fragment shape: ldarg.0..3 [tail.] call/callvirt T ret
                var call = dyn.instructions.FirstOrDefault(i =>
                    i.opcode == "call" || i.opcode == "callvirt");
                if (call != null) fragByField[tok] = call;
            }
            Console.WriteLine("fragments loaded: " + fragByField.Count + " / " + entries.Count);

            int sites = 0, methods = 0, unresolvable = 0;
            var report = new List<string>();

            foreach (var m in module.GetTypes().SelectMany(t => t.Methods))
            {
                if (!m.HasBody) continue;
                var instrs = m.Body.Instructions;
                bool touched = false;
                for (int k = 0; k + 1 < instrs.Count; k++)
                {
                    var a = instrs[k];
                    if (a.OpCode != OpCodes.Ldsfld) continue;
                    var fd = a.Operand as FieldDef;
                    if (fd == null) continue;

                    var b = instrs[k + 1];
                    if (b.OpCode != OpCodes.Call && b.OpCode != OpCodes.Callvirt) continue;
                    var helper = b.Operand as IMethod;
                    if (helper == null || helper.MethodSig == null) continue;
                    // NecroBit invoke-helpers are module-internal AND the
                    // delegate fields are module-internal annotation types —
                    // never Reflection MethodInfo/FieldInfo caches (DI library)
                    // and never BCL statics (ServiceProviderOptions etc).
                    if (!SameModule(helper, module)) continue;
                    var ftn = fd.FieldType.FullName;
                    if (ftn.StartsWith("System.Reflection.") ||
                        ftn.StartsWith("System.") || ftn.StartsWith("Microsoft."))
                        continue;
                    var hp = helper.MethodSig.Params;
                    if (hp.Count < 1) continue;
                    // NecroBit invoke-helper: last param == delegate field type
                    if (!SigEquals(hp[hp.Count - 1], fd.FieldType)) continue;

                    uint ftok = fd.MDToken.Raw;
                    InstructionJson fragCall;
                    if (!fragByField.TryGetValue(ftok, out fragCall))
                    {
                        unresolvable++;
                        report.Add("NO-FRAG " + m.FullName + " field 0x" + ftok.ToString("X8")
                                   + " (" + fd.FullName + " : " + (fd.FieldType?.FullName ?? "?") + ")");
                        continue;
                    }

                    // stack-neutral substitution: mutate the ldsfld opcode in place
                    // (never replace instruction objects — branch targets point here)
                    bool isVirt = fragCall.opcode == "callvirt";
                    var target = ResolveCall(fragCall);
                    if (target == null)
                    {
                        unresolvable++;
                        report.Add("UNRESOLVED " + m.FullName + " field 0x" + ftok.ToString("X8")
                                   + " -> " + fragCall.declType + "::" + fragCall.memberName);
                        continue;
                    }
                    a.OpCode = isVirt ? OpCodes.Callvirt : OpCodes.Call;
                    a.Operand = target;
                    b.OpCode = OpCodes.Nop;
                    b.Operand = null;
                    sites++;
                    touched = true;
                    report.Add("SUBST " + m.FullName + " +0x" + a.Offset.ToString("X")
                               + " field 0x" + ftok.ToString("X8")
                               + " -> " + (isVirt ? "callvirt " : "call ")
                               + fragCall.declType + "::" + fragCall.memberName);
                }
                if (touched) methods++;
            }

            // NecroBit dead-code dummy calls carry unresolvable tokens -> dnlib
            // null operands -> writer crash. They sit behind an unconditional
            // br.s (unreachable) so nopping is semantics-preserving.
            int sanitized = 0;
            foreach (var m in module.GetTypes().SelectMany(t => t.Methods))
            {
                if (!m.HasBody) continue;
                var instrs = m.Body.Instructions;
                for (int k = 0; k < instrs.Count; k++)
                {
                    var i = instrs[k];
                    if (i.Operand == null && OperandRequired(i.OpCode.OperandType))
                    {
                        // mutate in place — object identity is branch targets' anchor
                        i.OpCode = OpCodes.Nop;
                        i.Operand = null;
                        sanitized++;
                    }
                }
            }
            Console.WriteLine("call-sites substituted: " + sites + " in " + methods
                              + " methods; unresolved: " + unresolvable
                              + "; dead dummies nopped: " + sanitized);

            var opts = new ModuleWriterOptions(module);
            opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
            // Preserve tokens: the VM blob ("AnnotationDic.AnnotationServer") stores
            // ORIGINAL metadata tokens resolved at runtime via Module.ResolveMethod/
            // ResolveField/ResolveType. Renumbering rows on write silently retargets
            // those constants -> wrong methods invoked -> EditorPolicy anti-tamper
            // throw. Preserving tokens keeps the blob constants valid.
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            try { module.Write(outPath, opts); }
            catch (Exception wex)
            {
                Console.Error.WriteLine("WRITE FAILED: " + wex.Message);
                return 3;
            }

            File.WriteAllLines(Path.ChangeExtension(outPath, ".rebuild.log"), report);
            Console.WriteLine("wrote " + outPath);
            return sites > 0 ? 0 : 1;
        }

        static bool OperandRequired(OperandType ot)
        {
            return ot == OperandType.InlineMethod || ot == OperandType.InlineField
                || ot == OperandType.InlineTok || ot == OperandType.InlineString
                || ot == OperandType.InlineType || ot == OperandType.InlineSig
                || ot == OperandType.InlineVar || ot == OperandType.ShortInlineVar
                || ot == OperandType.InlineBrTarget || ot == OperandType.ShortInlineBrTarget
                || ot == OperandType.InlineSwitch || ot == OperandType.InlineI
                || ot == OperandType.ShortInlineI && false;
        }

        static bool SameModule(IMethod m, ModuleDef mod)
        {
            // helper must be declared in the target module itself (NecroBit
            // invoke-helpers like *::UpdateTransaction are module-internal)
            return m.DeclaringType != null && m.DeclaringType.Module == mod;
        }

        static bool SigEquals(TypeSig x, TypeSig y)
        {
            if (x == null || y == null) return false;
            // same type name in same module scope is enough for the delegate match
            return x.FullName == y.FullName;
        }

        // ---- fragment target resdeadtion --------------------------------
        // net48 console apps cannot Assembly.Load("System.Windows.Forms")
        // by simple name (fails with FileNotFoundException). Instead,
        // resolve BCL types through the TARGET's own AssemblyRefs and the
        // already-loaded GAC assemblies of this process.
        static IMethod ResolveCall(InstructionJson ins)
        {
            // target-module types first (reflection name uses '+')
            var local = module.Find(ins.declType.Replace('/', '+'), true);
            if (local != null)
            {
                var cand = local.Methods.FirstOrDefault(m => m.Name == ins.memberName);
                if (cand != null) return cand;
            }

            Type rt = null;
            var typeName = ins.declType.Replace('/', '+');

            // 1) already-loaded assemblies in THIS process
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
            {
                rt = a.GetType(typeName, false);
                if (rt != null) break;
            }

            // 2) GAC probe via full framework reference assemblies
            if (rt == null)
            {
                var fx = typeof(object).Assembly.Location;
                var fxDir = Path.GetDirectoryName(fx);
                var gacCandidates = new[] {
                    Path.Combine(fxDir, "System.Windows.Forms.dll"),
                    Path.Combine(fxDir, "System.Drawing.dll"),
                    Path.Combine(fxDir, "System.dll"),
                    Path.Combine(fxDir, "System.Core.dll"),
                };
                foreach (var p in gacCandidates)
                {
                    if (!File.Exists(p)) continue;
                    Assembly ga;
                    try { ga = Assembly.LoadFrom(p); } catch { continue; }
                    rt = ga.GetType(typeName, false);
                    if (rt != null) break;
                }
            }

            // 3) mono-style framework dir next to mscorlib (WPF machines)
            if (rt == null)
            {
                var probes = new[] { "System.Windows.Forms", "System.Drawing", "System", "System.Core" };
                foreach (var an in probes)
                {
                    try
                    {
                        var ga = Assembly.Load(an + ", Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
                        rt = ga.GetType(typeName, false);
                        if (rt != null) break;
                    }
                    catch { }
                }
            }

            if (rt == null) return null;

            int wantParams; string wantRet;
            ParseSig(ins.memberSig, out wantParams, out wantRet);
            var methods = rt.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                        BindingFlags.Instance | BindingFlags.Static |
                                        BindingFlags.FlattenHierarchy)
                           .Where(m => m.Name == ins.memberName).ToList();
            MethodInfo pick = null;
            // full sig match: param count AND per-param type names. Ambiguous
            // overloads (e.g. Array.SetValue(Object, Int32) vs (Object, Int32[]))
            // retarget silently when only the count is compared — an Int32[]
            // overload then throws ArgumentNullException("indices") at runtime.
            string[] wantTypes = ParseSigTypes(ins.memberSig);
            if (wantTypes != null)
            {
                foreach (var m in methods)
                {
                    var ps = m.GetParameters();
                    if (ps.Length != wantTypes.Length) continue;
                    bool ok = true;
                    for (int q = 0; q < ps.Length; q++)
                    {
                        string want = wantTypes[q].Trim();
                        string got = ps[q].ParameterType.Name;
                        // "Int32" matches both System.Int32 and the sig's Int32
                        if (!string.Equals(want, got, StringComparison.OrdinalIgnoreCase) &&
                            !want.EndsWith("." + got, StringComparison.OrdinalIgnoreCase))
                        { ok = false; break; }
                    }
                    if (ok) { pick = m; break; }
                }
            }
            if (pick == null && wantParams >= 0)
                pick = methods.FirstOrDefault(m => m.GetParameters().Length == wantParams);
            if (pick == null) pick = methods.FirstOrDefault();
            if (pick == null) return null;
            try { return importer.Import(pick); }
            catch { return null; }
        }

        // "instance System.Void (System.Object, System.Int32)" -> ["Object","Int32"]
        static string[] ParseSigTypes(string sig)
        {
            if (string.IsNullOrEmpty(sig)) return null;
            int open = sig.IndexOf('(');
            int close = sig.LastIndexOf(')');
            if (open < 0 || close <= open) return null;
            var body = sig.Substring(open + 1, close - open - 1).Trim();
            if (body.Length == 0) return new string[0];
            return body.Split(',').Select(s => s.Trim()).ToArray();
        }

        static void ParseSig(string sig, out int paramCount, out string retType)
        {
            paramCount = -1; retType = null;
            if (string.IsNullOrEmpty(sig)) return;
            int open = sig.IndexOf('(');
            if (open < 0) return;
            retType = sig.Substring(0, open).Trim();
            if (retType.StartsWith("instance ")) retType = retType.Substring(9).Trim();
            int close = sig.LastIndexOf(')');
            if (close <= open) return;
            var inner = sig.Substring(open + 1, close - open - 1).Trim();
            paramCount = inner.Length == 0 ? 0 : inner.Split(',').Length;
        }
    }
}
