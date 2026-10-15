// ccfix — cctor surgery for NecroBit-recovered PEs (stage 5, runnable class).
//
// The merged PE carries the real decoded bodies, but its <Module>.cctor still
// calls the antitamper checker, which reads the (now rewritten) .text and
// faults. nbfixctor2's generic nag-cut gets past the cctor but the strenc
// decrypter then NREs on its cctor-initialized table — check and init share
// the cctor, and a blunt ret kills both (the v44 finding).
//
// Modes:
//   ccfix analyze <asm>            — print <Module>.cctor's calls and every
//                                    static field it initializes, plus each
//                                    callee's size/AV-suspect pattern
//   ccfix fix <in> <out> <method>  — remove the call to <method> (simple name)
//                                    from <Module>.cctor only; everything
//                                    else stays byte-for-byte
//
// The fix loop is feedback-driven: run the output, parse the failing method
// from the stack, call fix again with the next name. No guessing.
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("ccfix analyze <asm> | ccfix fix <in> <out> <calleeName>"); return 1; }
        var mod = ModuleDefMD.Load(args[1]);

        TypeDef modType = null;
        MethodDef cctor = null;
        foreach (var t in mod.GetTypes())
        {
            if (t.Name != "<Module>") continue;
            modType = t;
            cctor = t.Methods.FirstOrDefault(m => m.IsStatic && m.Name == ".cctor");
            break;
        }
        if (cctor == null || !cctor.HasBody)
        {
            Console.WriteLine("[ccfix] no <Module>.cctor body");
            return 2;
        }

        if (args[0] == "analyze")
        {
            Console.WriteLine("[ccfix] <Module>.cctor instructions:");
            foreach (var ins in cctor.Body.Instructions)
            {
                var op = ins.Operand as IMethod;
                if (ins.OpCode == OpCodes.Call && op != null)
                    Console.WriteLine("  call " + op.Name + "  (declaring: " + (op.DeclaringType?.Name.String ?? "?") + ")");
                else if (ins.OpCode == OpCodes.Stsfld && ins.Operand is IField f)
                    Console.WriteLine("  stsfld " + f.Name);
                else
                    Console.WriteLine("  " + ins.OpCode + (ins.Operand == null ? "" : " " + ins.Operand));
            }
            Console.WriteLine("[ccfix] callees detail:");
            foreach (var ins in cctor.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call || !(ins.Operand is IMethod op)) continue;
                var def = op.ResolveMethodDef();
                if (def == null || !def.HasBody) { Console.WriteLine("  " + op.Name + ": unresolved/no body"); continue; }
                bool readsText = false;
                foreach (var i2 in def.Body.Instructions)
                    if (i2.OpCode == OpCodes.Ldstr && i2.Operand is string sv && sv.Contains("Eziriz")) readsText = true;
                Console.WriteLine("  " + op.Name + ": instrs=" + def.Body.Instructions.Count +
                                  " ezirizLdstr=" + readsText);
            }
            return 0;
        }

        if (args[0] == "fix")
        {
            if (args.Length < 4) { Console.WriteLine("ccfix fix <in> <out> <calleeName>"); return 1; }
            string callee = args[3];
            int removed = 0;
            // the antitamper checker is invoked from several module ctors —
            // nop every call site of the named method anywhere
            var toNop = new List<Tuple<MethodDef, Instruction>>();
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                {
                    if (!m.HasBody || !m.IsStatic || m.Name != ".cctor") continue;
                    foreach (var ins in m.Body.Instructions)
                        if (ins.OpCode == OpCodes.Call && ins.Operand is IMethod op &&
                            op.Name.String == callee)
                            toNop.Add(Tuple.Create(m, ins));
                }
            foreach (var pair in toNop)
            {
                pair.Item2.OpCode = OpCodes.Nop;
                pair.Item2.Operand = null;
                removed++;
                Console.WriteLine("[ccfix] nop'd in " + pair.Item1.DeclaringType?.Name + "..cctor");
            }
            if (removed == 0) { Console.WriteLine("[ccfix] no call to " + callee + " found in any cctor"); return 3; }

            // keep every token where it is — PreserveAll, same as nbilmerge
            var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            opts.MetadataLogger = DummyLogger.NoThrowInstance;
            opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
            opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], opts);
            Console.WriteLine("[ccfix] nop'd " + removed + " call(s) to " + callee + " -> " + args[2]);
            return 0;
        }

        Console.WriteLine("unknown mode");
        return 1;
    }
}
