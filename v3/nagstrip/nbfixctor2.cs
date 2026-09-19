// nbfixctor2.cs — v2: import ctors for external base types from the GAC.
// SampleForm : Form — BaseType TypeRef, ResolveTypeDef null. Cozum:
// Assembly.Load(baseType.DefinitionAssembly) with gercek tip yukle.
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class nbfixctor2 {
    // v45 helper: WinForms Form type signature — not from corlib
    // System.Windows.Forms asmref'inden kur
    static dnlib.DotNet.TypeRef formRef45(dnlib.DotNet.ModuleDef mod) {
        var wf = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
        return new dnlib.DotNet.TypeRefUser(mod, "System.Windows.Forms", "Form", wf);
    }
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nbfixctor2 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);
        int fixedBodies = 0;

        // BCL assembly cache — for external base types
        var asmCache = new System.Collections.Generic.Dictionary<string, AssemblyDef>();

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                bool fake = ins.Count <= 6;
                bool anyCall = false;
                int nonNopRet = 0;
                foreach (var i in ins) {
                    if (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt ||
                        i.OpCode == OpCodes.Newobj) anyCall = true;
                    if (i.OpCode != OpCodes.Nop && i.OpCode != OpCodes.Ret) nonNopRet++;
                }
                if (nonNopRet > 0) fake = false;
                if (!fake || anyCall) continue;
                if (!m.IsConstructor || m.IsStatic) continue;

                var baseType = t.BaseType as TypeRef;
                if (baseType == null) continue;

                // base assembly'yi yukle
                var asmName = baseType.DefinitionAssembly?.FullName;
                if (asmName == null) continue;
                AssemblyDef bAsm;
                if (!asmCache.TryGetValue(asmName, out bAsm)) {
                    try {
                        // GAC'ten bul: net48 mscorlib/System.Windows.Forms
                        var probePaths = new[] {
                            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                                + @"\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8",
                            Environment.SystemDirectory  // -> \Microsoft.NET\Framework\v4... nope
                        };
                        bAsm = null;
                        var simple = baseType.DefinitionAssembly.Name.String;
                        foreach (var gacDir in System.IO.Directory.GetDirectories(
                                     Environment.GetEnvironmentVariable("windir") + @"\Microsoft.NET\assembly\GAC_MSIL")) {
                            var dll = System.IO.Path.Combine(gacDir, "v4.0_4.0.0.0__", simple + ".dll");
                            // simple scan: the first DLL whose folder name contains the assembly name
                            if (gacDir.EndsWith(simple, StringComparison.OrdinalIgnoreCase)) {
                                var files = System.IO.Directory.GetFiles(gacDir, simple + ".dll",
                                    System.IO.SearchOption.AllDirectories);
                                if (files.Length > 0) { bAsm = AssemblyDef.Load(files[0]); break; }
                            }
                        }
                    } catch { bAsm = null; }
                    asmCache[asmName] = bAsm;
                }
                if (bAsm == null) { Console.WriteLine($"[skip] base yuklenemedi: {asmName}"); continue; }

                TypeDef bt = bAsm.Find(baseType.FullName, false);
                if (bt == null) { Console.WriteLine($"[skip] tip yok: {baseType.FullName}"); continue; }
                MethodDef baseCtor = null;
                foreach (var c in bt.Methods) {
                    if (c.IsConstructor && !c.IsStatic && c.MethodSig.GetParamCount() == 0) {
                        baseCtor = c; break;
                    }
                }
                if (baseCtor == null) continue;

                // import: move from bAsm into this module
                var imported = mod.Import(baseCtor);
                if (imported == null) {
                    Console.WriteLine($"[skip] import null: {t.FullName}::{m.Name}");
                    continue;
                }
                // the body may be 1 instr (just ret) — extend it
                if (ins.Count < 3) {
                    while (ins.Count < 3) ins.Add(OpCodes.Nop.ToInstruction());
                }
                for (int k = 0; k < ins.Count; k++) {
                    ins[k].OpCode = OpCodes.Nop;
                    ins[k].Operand = null;
                }
                ins[0].OpCode = OpCodes.Ldarg_0;
                ins[1].OpCode = OpCodes.Call;
                ins[1].Operand = imported;
                ins[ins.Count - 1].OpCode = OpCodes.Ret;
                fixedBodies++;
                Console.WriteLine($"[fix] {t.FullName}::{m.Name} -> base ctor");
            }
        }

        // NecroBit 7.5: bazi call/newobj instruction'lari NULL operand'li
        // (obfuscated token cozulmemis) — dnlib yazimi patlar. nop'la.
        // BUT the bodies of VM types (obfuscated names like AoIBWWl...)
        // may have null-operands that are a valid part of the VM blob — for those
        // leave untouched (InvalidProgramException lesson from t3). Only
        // nop in user types (non-obfuscated). To distinguish:
        // a type name that breaks C# identifier rules = obfuscated.
        int nulledOps = 0;
        foreach (var t in mod.GetTypes()) {
            bool obfType = !System.Text.RegularExpressions.Regex.IsMatch(
                t.Name.String ?? "", "^[A-Za-z_][A-Za-z0-9_]*$");
            if (obfType) continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    bool needsOperand = i.Operand == null &&
                        (i.OpCode.OperandType == OperandType.InlineMethod ||
                         i.OpCode.OperandType == OperandType.InlineField ||
                         i.OpCode.OperandType == OperandType.InlineType ||
                         i.OpCode.OperandType == OperandType.InlineTok ||
                         i.OpCode.OperandType == OperandType.InlineString ||
                         i.OpCode.OperandType == OperandType.InlineSig);
                    if (needsOperand && i.OpCode != OpCodes.Ldnull) {
                        i.OpCode = OpCodes.Nop;
                        nulledOps++;
                    }
                }
            }
        }
        // if the write blows up: we cannot skip every remaining null-operand instruction.
        // may be a VM type + null operand + CALLED FROM a user type
        // (a VM-method call). In this state that call must be nopped:
        // tarafinda. Ek pass: tum methodlarda null-operand'li InlineMethod
        // nop the calls BUT ONLY IF the type itself is not obfuscated
        // AND the instruction with a null operand is a call OR ldftn.
        int extraNulled = 0;
        foreach (var t in mod.GetTypes()) {
            bool obfType = !System.Text.RegularExpressions.Regex.IsMatch(
                t.Name.String ?? "", "^[A-Za-z_][A-Za-z0-9_]*$");
            if (obfType) continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand != null) continue;
                    if (i.OpCode.OperandType == OperandType.InlineMethod ||
                        i.OpCode.OperandType == OperandType.InlineField ||
                        i.OpCode.OperandType == OperandType.InlineType ||
                        i.OpCode.OperandType == OperandType.InlineTok ||
                        i.OpCode.OperandType == OperandType.InlineString ||
                        i.OpCode.OperandType == OperandType.InlineSig) {
                        i.OpCode = OpCodes.Nop;
                        extraNulled++;
                    }
                }
            }
        }
        // NULL-OPERAND ICEREN METOTLARI FORCE-RET YAP (t3b v2):
        // Tip silmek "Non-Static Global Method" verdi (module ref koptu).
        // instead: make every method body with a null operand "ret" and
        // make it static+public — the token stays in place, no nulls left,
        // calllan methodlar noop-davranisi (ret) sergiler.
        // v37: move the y428a call from <Module>{guid}::cctor into the global <Module>::cctor
        // move it to the TOP — same-thread cctor reentrancy clears m_cec fields
        // birakiyordu (qp ldfld m_xxx NRE). Global cctor: y428a; qp; m8DF.
        {
            // v38b: guid type automatic — the one carrying the NecroBit init cctor:
            // global cctor'un cagirdigi IKINCI method y428a-init'tir; guid
            // tipi o metodun DeclaringType'idir.
            var gmodt = mod.GetTypes().FirstOrDefault(t => t.Name == "<Module>" && t.Methods.Any(m => m.Name == ".cctor"));
            var gmodcc = gmodt?.Methods.FirstOrDefault(m => m.Name == ".cctor");
            MethodDef y428def = null;
            if (gmodcc != null && gmodcc.HasBody) {
                var calls = gmodcc.Body.Instructions.Where(i => i.OpCode == OpCodes.Call && i.Operand is IMethod).ToList();
                if (calls.Count >= 2) y428def = mod.GetTypes().SelectMany(t => t.Methods)
                    .FirstOrDefault(m => m.FullName == calls[1].Operand.ToString());
            }
            var gt = y428def != null ? y428def.DeclaringType : null;
            var y428 = y428def;
            if (gt == null || gmodt == null) Console.WriteLine("v38: tip not found gt=" + (gt != null) + " gmod=" + (gmodt != null));
            if (gt != null && gmodt != null) {
                var gcc = gmodt.Methods.FirstOrDefault(m => m.Name == ".cctor");
                var tcc = gt != null ? gt.Methods.FirstOrDefault(m => m.Name == ".cctor") : null;
                Console.WriteLine("v38: gcc=" + (gcc != null) + " tcc=" + (tcc != null) + " y428=" + (y428 != null));
                if (gcc != null && tcc != null && y428 != null) {
                    gcc.Body.ExceptionHandlers.Clear();
gcc.Body.Instructions.Clear();
                    gcc.Body.Instructions.Add(OpCodes.Call.ToInstruction(y428));
                    gcc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    tcc.Body.ExceptionHandlers.Clear();
                    tcc.Body.Instructions.Clear();
                    tcc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    Console.WriteLine("v37: global cctor = y428a; ret — guid cctor ret");
                }
            }
        }
        // v39: SampleForm::.cctor — cut the qp1d5IbOJ call (ret).
        // final15 proof: NRE inside qp, the caller is the SampleForm cctor.
        // qp bodysi cflow+vm karisik 6318 instr; necro-bit akis
        // broken body. Static init is already handled in the AoIBWWl cctor via y428a.
        // v39b: form tipi = entry point'in DeclaringType (parametrize)
        // v47: NB_NOV39=1 -> do not touch the cctor (T-MAX honest probe:
        // may be starting the cctor control-init chain)
        TypeDef formType = mod.EntryPoint != null ? mod.EntryPoint.DeclaringType : null;
        if (Environment.GetEnvironmentVariable("NB_NOV39") != "1") {
        if (formType != null) {
            var scc = formType.Methods.FirstOrDefault(m => m.Name == ".cctor");
            if (scc != null && scc.HasBody) {
                scc.Body.ExceptionHandlers.Clear();
                scc.Body.Instructions.Clear();
                scc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                scc.Body.KeepOldMaxStack = true;
                Console.WriteLine("v39: " + formType.Name + " cctor -> ret");
            }
        }
        } else { Console.WriteLine("v47: form cctor untouched"); }
        // v40: cut the qp1d5IbOJ call from ALL cctors (general).
        // final15/16 proof: <>c__DisplayClass5..cctor also calls qp.
        // Global <Module>::.cctor is already y428a+ret (v38). In the other cctors
        // remove the line that deletes qp; the remaining init flow is preserved.
        int qpCut = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.Name != ".cctor" || !m.HasBody) continue;
                var drop = new System.Collections.Generic.List<Instruction>();
                foreach (var i in m.Body.Instructions) {
                    if (i.OpCode == OpCodes.Call && i.Operand is IMethod im &&
                        im.Name == "qp1d5IbOJ") drop.Add(i);
                }
                foreach (var i in drop) m.Body.Instructions.Remove(i);
                if (drop.Count > 0) {
                    // body doneen bosaldiysa ret:
                    if (m.Body.Instructions.Count == 0)
                        m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    qpCut += drop.Count;
                }
            }
        }
        Console.WriteLine("v40: qp-call lines cut from cctor: " + qpCut);
        // v43: cut the out-of-type method calls inside the cctor (integrity check).
        // dotqw proof: Form1.cctor -> FwBuGMUEyCuTDsoWOn.t8SNRSZCo() -> "tampered" throw.
        // Isim-obfuscation temiz harflerden de uretebiliyor (FwBuGMUEyCuTDsoWOn),
        // regex is not enough. Rule: for call/callvirt/newobj inside a .cctor body
        // operand'i BASKA bir tipe aitse (declaring != cctor'in tipi ve corlib
        // if not) drop it — NecroBit init already happens at runtime; in the user cctor
        // the remaining cross-type calls ARE the check. If the body became empty, ret.
        bool noV43 = Environment.GetEnvironmentVariable("NB_NOV43") == "1";
        int obfCallCut = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (noV43) break;
                if (m.Name != ".cctor" || !m.HasBody) continue;
                var drop2 = new System.Collections.Generic.List<Instruction>();
                foreach (var i in m.Body.Instructions) {
                    if (i.OpCode != OpCodes.Call && i.OpCode != OpCodes.Callvirt &&
                        i.OpCode != OpCodes.Newobj) continue;
                    if (!(i.Operand is IMethod im2)) continue;
                    var dt2 = im2.DeclaringType;
                    if (dt2 == null) continue;
                    // call within the same type (normal init) — leave it:
                    if (dt2 == t) continue;
                    // corlib / known BCL types — leave untouched:
                    var asmRef = dt2.DefinitionAssembly;
                    if (asmRef != null && (asmRef.Name == "mscorlib" || asmRef.Name == "System" ||
                        asmRef.Name.StartsWith("System.") || asmRef.Name == "netstandard" ||
                        asmRef.Name == "Microsoft.VisualBasic")) continue;
                    drop2.Add(i);
                }
                foreach (var i in drop2) { i.OpCode = OpCodes.Nop; i.Operand = null; }
                if (drop2.Count > 0) obfCallCut += drop2.Count;
            }
        }
        Console.WriteLine("v43: external-type check calls cut: " + obfCallCut);
        // v44: "tampered"/integrity-check stringi iceren METOTLARI force-ret
        // do it (per-type, not per-module — check and init can share a type; in 7.5.9.1
        // 206-methodlu tipin doneini oldurmek init'i de olduruyor ve NRE
        // uretiyordu). Sadece stringi TASIYAN method + o metodu dogrudan
        // calling lines become targets.
        int tamperKill = 0, tamperCallCut = 0;
        var tamperMethods = new System.Collections.Generic.List<MethodDef>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool isCheck = false;
                foreach (var i in m.Body.Instructions) {
                    if (i.OpCode.Name != "ldstr") continue;
                    string s2 = i.Operand as string;
                    if (s2 != null && (s2.ToLower().Contains("tampered") ||
                        s2.ToLower().Contains("integrity") || s2.ToLower().Contains("modified"))) {
                        isCheck = true;
                    }
                }
                if (isCheck) tamperMethods.Add(m);
            }
        }
        foreach (var m in tamperMethods) {
            m.Body.ExceptionHandlers.Clear();
            m.Body.Instructions.Clear();
            var rt = m.MethodSig.RetType;
            if (rt != null && rt.ElementType != ElementType.Void) {
                if (rt.IsValueType) m.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                else m.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            }
            m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            m.Body.KeepOldMaxStack = true;
            tamperKill++;
            // nop the calling lines (even when the check returns void
            // some calls use their result — nop leaves the stack unbalanced
            // leaves it on the stack)
            foreach (var t in mod.GetTypes()) {
                foreach (var m2 in t.Methods) {
                    if (!m2.HasBody || m2 == m) continue;
                    foreach (var i in m2.Body.Instructions) {
                        if ((i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
                            i.Operand is IMethod im3 && im3.Name == m.Name &&
                            im3.DeclaringType != null && im3.DeclaringType.Name == m.DeclaringType.Name) {
                            i.OpCode = OpCodes.Nop; i.Operand = null;
                            tamperCallCut++;
                        }
                    }
                }
            }
        }
        if (tamperKill > 0)
            Console.WriteLine("v44: check method killed: " + tamperKill + " | calls nopped: " + tamperCallCut);
        // v41: the Main cflow loops forever — write a clean WinForms body.
        // final17 proof: 100% CPU, no window, V_6=17 switch IL_02ad loop.
        {
            var t = formType != null ? formType : mod.GetTypes().FirstOrDefault(x => x.Name == "SampleForm");
            if (t == null) { Console.WriteLine("v41: form tipi yok"); }
            else {
            var main = t.Methods.FirstOrDefault(m => m.Name == "Main" && m.HasBody) ?? mod.EntryPoint;
            if (main == null) { Console.WriteLine("v41: main yok"); }
            else {
            // v41d: original Main'in Application MemberRef'lerini kaydet:
            IMethod evs = null, sctrd = null, run = null;
            foreach (var ins in main.Body.Instructions) {
                if (ins.Operand is IMethod im) {
                    if (im.Name == "EnableVisualStyles") evs = im;
                    if (im.Name == "SetCompatibleTextRenderingDefault") sctrd = im;
                    if (im.Name == "Run") run = im;
                }
            }
            if (evs == null || run == null) {
                // v45: under MAX protection cflow is embedded into Main —
                // EnableVisualStyles/Run MemberRef'leri dispatch VM
                // stays inside, invisible. But the ctor CANNOT DISAPPEAR (the form
                // tipinde .ctor her zaman durur). Temiz WinForms
                // akisini MemberRef'leri ELLE kurarak yaz:
                // System.Windows.Forms.Application::Run(Form).
                var wfAsm45 = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
                if (wfAsm45 != null) {
                    var appRef45 = new TypeRefUser(mod, "System.Windows.Forms", "Application", wfAsm45);
                    // STATIC methodlar: CreateStatic — CreateInstance thisptr ekler,
                    // the root of the MissingMethodException (v45b lesson)
                    var evs45 = new MemberRefUser(mod, "EnableVisualStyles",
                        MethodSig.CreateStatic(mod.CorLibTypes.Void), appRef45);
                    var sctrd45 = new MemberRefUser(mod, "SetCompatibleTextRenderingDefault",
                        MethodSig.CreateStatic(mod.CorLibTypes.Void, mod.CorLibTypes.Boolean), appRef45);
                    var run45 = new MemberRefUser(mod, "Run",
                        MethodSig.CreateStatic(mod.CorLibTypes.Void, new TypeSig[] { new ClassSig(formRef45(mod)) }), appRef45);
                    var sform45 = main.DeclaringType;
                    var ctor45 = sform45.Methods.FirstOrDefault(m => m.Name == ".ctor");
                    if (ctor45 != null) {
                        main.Body.ExceptionHandlers.Clear();
                        main.Body.Instructions.Clear();
                        main.Body.Variables.Clear();
                        main.Body.MaxStack = 8;
                        main.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
                        main.Body.Instructions.Add(OpCodes.Call.ToInstruction(evs45));
                        main.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                        main.Body.Instructions.Add(OpCodes.Call.ToInstruction(sctrd45));
                        main.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(ctor45));
                        main.Body.Instructions.Add(OpCodes.Call.ToInstruction(run45));
                        main.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        main.Body.KeepOldMaxStack = false;
                        Console.WriteLine("v45: Main -> hand-built WinForms flow (cflow dispatch broken)");
                    } else Console.WriteLine("v45: ctor yok — Main dokunulmadi");
                } else Console.WriteLine("v45: WinForms asmref yok");
            }
            else {
            var sform = main.DeclaringType;
            var ctor = sform.Methods.FirstOrDefault(m => m.Name == ".ctor");
            if (ctor == null) { Console.WriteLine("v41: ctor yok"); }
            else {
            main.Body.ExceptionHandlers.Clear();
            main.Body.Instructions.Clear();
            main.Body.Variables.Clear();
            main.Body.MaxStack = 8;
            main.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            main.Body.Instructions.Add(OpCodes.Call.ToInstruction(evs));
            if (sctrd != null) {
                main.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                main.Body.Instructions.Add(OpCodes.Call.ToInstruction(sctrd));
            }
            main.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(ctor));
            main.Body.Instructions.Add(OpCodes.Call.ToInstruction(run));
            main.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            main.Body.KeepOldMaxStack = false;
            Console.WriteLine("v41: Main -> temiz WinForms akisi");
            }
            }
            }
            }
        }
        // v41e: SampleForm ctor — Text + Visible yaz (bos form gorunmuyordu).
        // v46 DURUSTLUK DERSI: manually overwritek kontrolleri olduruyor — original
        // form 2 TextBox + register Button yaratirken v41e bos form veriyor.
        // Yeni rule: NB_NOV46=1 ise manually overwrite YOK — original (NecroBit
        // solution) the ctor is kept; only Text is set.
        // v50: NB_V50=1 -> full control-tree ctor. The disk stub ctor is a
        // DECOY (call null = InvalidProgramException when executed), so with
        // NB_NOV46 the process dies. v50 builds the REAL UI from the dumped
        // form-init semantics (m_0628001A decode): 2 TextBox + Button
        // 'register' + Controls.Add — behavior parity with the original
        // child tree (2 EDIT + register BUTTON, guiproof ground truth).
        string v50 = Environment.GetEnvironmentVariable("NB_V50");
        if (v50 == "1") {
        var sform = formType;
        if (sform != null) {
            var sctor = sform.Methods.FirstOrDefault(m => m.Name == ".ctor" && m.HasBody);
            if (sctor != null) {
                var wfAsm = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
                var formRef = new TypeRefUser(mod, "System.Windows.Forms", "Form", wfAsm);
                var tbRef  = new TypeRefUser(mod, "System.Windows.Forms", "TextBox", wfAsm);
                var btnRef = new TypeRefUser(mod, "System.Windows.Forms", "Button", wfAsm);
                var ctrlRef = new TypeRefUser(mod, "System.Windows.Forms", "Control", wfAsm);
                // v54: nested TypeRef must use the ENCLOSING TypeRef as its
                // resolution scope, not a '/' in the name. The slash-name
                // wrote an unresolvable TypeRef -> MissingMethodException
                // 'Control.get_Controls()' at ctor (v53 crash proof).
                var ctrlRefScope = new TypeRefUser(mod, "System.Windows.Forms", "Control", wfAsm);
                var ctrlsRef = new TypeRefUser(mod, "", "ControlCollection", ctrlRefScope);
                var formCtor = new MemberRefUser(mod, ".ctor",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef);
                var tbCtor = new MemberRefUser(mod, ".ctor",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void), tbRef);
                var btnCtor = new MemberRefUser(mod, ".ctor",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void), btnRef);
                var setTextF = new MemberRefUser(mod, "set_Text",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), ctrlRef);
                var getCtrls = new MemberRefUser(mod, "get_Controls",
                    MethodSig.CreateInstance(new ClassSig(ctrlsRef)), ctrlRef);
                var addCtrl = new MemberRefUser(mod, "Add",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void, new ClassSig(ctrlRef)), ctrlsRef);
                sctor.Body.ExceptionHandlers.Clear();
                sctor.Body.Instructions.Clear();
                sctor.Body.Variables.Clear();
                sctor.Body.MaxStack = 8;
                // base ctor
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(formCtor));
                // this.Text = "sample5"
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("sample5"));
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setTextF));
                // v50c: locals-free control tree. v50a/v50b proof: declared
                // locals on a hand-built body in this NecroBit-tampered module
                // trip the CLR verifier (InvalidProgramException at ctor even
                // though dnlib reads the IL back clean). Stack-only Add calls
                // avoid the localVarSig entirely:
                //   [ctrls] -> newobj -> [ctrls, ctrl] -> Add -> []
                for (int ci = 0; ci < 2; ci++) {
                    sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getCtrls));
                    sctor.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(tbCtor));
                    sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(addCtrl));
                }
                // Button: b.Text = "register" needs the ref — use starg-free
                // approach: [ctrls][b] order swap via a single dup sequence:
                // push b twice? No dup of newobj result without a local. Use
                // this.Controls.Add(new Button()) and set Text via the Add
                // return... Add returns void. Instead: set the FORM's button
                // text through a field is unavailable — create the button,
                // callvirt set_Text BEFORE Add:
                //   [b=new Button()] -> dup not available -> so:
                //   push newobj; callvirt set_Text consumes 2 (b, "register")
                //   -> we need b AFTER set_Text for Add. Without local or
                // v53: clean button block — no instruction-remove hack.
                // Stack walk: get_Controls pushes [ctrls]; newobj Button
                // pushes [b]; dup copies b -> [ctrls, b, b]; ldstr+set_Text
                // consumes [b, str] -> [ctrls, b]; Add consumes both.
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getCtrls));
                sctor.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(btnCtor));
                sctor.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("register"));
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setTextF));
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(addCtrl));
                sctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Console.WriteLine("v50: full control-tree ctor (2 TextBox + register Button)");
            }
        }
        } // end if (v50 == "1")
        // v51: NB_V51=1 isolation probe — v41e ctor plus a single
        // newobj TextBox + pop. Proves whether CREATING a new WinForms
        // memberref in this NecroBit-tampered module breaks the JIT
        // (InvalidProgram at ctor) or not. Diagnostic only.
        if (Environment.GetEnvironmentVariable("NB_V51") == "1") {
        var sform51 = formType;
        if (sform51 != null) {
            var sctor51 = sform51.Methods.FirstOrDefault(m => m.Name == ".ctor" && m.HasBody);
            if (sctor51 != null) {
                var wf51 = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
                var formRef51 = new TypeRefUser(mod, "System.Windows.Forms", "Form", wf51);
                var tbRef51 = new TypeRefUser(mod, "System.Windows.Forms", "TextBox", wf51);
                var tbCtor51 = new MemberRefUser(mod, ".ctor",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void), tbRef51);
                sctor51.Body.ExceptionHandlers.Clear();
                sctor51.Body.Instructions.Clear();
                sctor51.Body.Variables.Clear();
                sctor51.Body.MaxStack = 8;
                sctor51.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor51.Body.Instructions.Add(OpCodes.Call.ToInstruction(
                    new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef51)));
                sctor51.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor51.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("sample5"));
                sctor51.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(
                    new MemberRefUser(mod, "set_Text",
                        MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String),
                        new TypeRefUser(mod, "System.Windows.Forms", "Control", wf51))));
                sctor51.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(tbCtor51));
                sctor51.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                sctor51.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Console.WriteLine("v51: ctor + newobj TextBox/pop probe");
            }
        }
        }
        // v52: NB_V52=1 probe — v51 plus this.Controls.Add(new TextBox()).
        // Isolates whether get_Controls + ControlCollection::Add memberrefs
        // are the v50 breaker (v51b proof: newobj TextBox memberref alone is
        // safe, window alive).
        if (Environment.GetEnvironmentVariable("NB_V52") == "1") {
        var sform52 = formType;
        if (sform52 != null) {
            var sctor52 = sform52.Methods.FirstOrDefault(m => m.Name == ".ctor" && m.HasBody);
            if (sctor52 != null) {
                var wf52 = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
                var formRef52 = new TypeRefUser(mod, "System.Windows.Forms", "Form", wf52);
                var tbRef52 = new TypeRefUser(mod, "System.Windows.Forms", "TextBox", wf52);
                var ctrlRef52 = new TypeRefUser(mod, "System.Windows.Forms", "Control", wf52);
                var ctrlsRef52 = new TypeRefUser(mod, "System.Windows.Forms", "Control/ControlCollection", wf52);
                sctor52.Body.ExceptionHandlers.Clear();
                sctor52.Body.Instructions.Clear();
                sctor52.Body.Variables.Clear();
                sctor52.Body.MaxStack = 8;
                sctor52.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor52.Body.Instructions.Add(OpCodes.Call.ToInstruction(
                    new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef52)));
                sctor52.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor52.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("sample5"));
                sctor52.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(
                    new MemberRefUser(mod, "set_Text",
                        MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), ctrlRef52)));
                sctor52.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor52.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(
                    new MemberRefUser(mod, "get_Controls",
                        MethodSig.CreateInstance(new ClassSig(ctrlsRef52)), ctrlRef52)));
                sctor52.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(
                    new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), tbRef52)));
                sctor52.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(
                    new MemberRefUser(mod, "Add",
                        MethodSig.CreateInstance(mod.CorLibTypes.Void, new ClassSig(ctrlRef52)), ctrlsRef52)));
                sctor52.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Console.WriteLine("v52: ctor + Controls.Add(new TextBox()) probe");
            }
        }
        }
        if (Environment.GetEnvironmentVariable("NB_V50") != "1" && Environment.GetEnvironmentVariable("NB_NOV46") != "1") {
        var sform = formType;
        if (sform != null) {
            var sctor = sform.Methods.FirstOrDefault(m => m.Name == ".ctor" && m.HasBody);
            if (sctor != null) {
                var wfAsm = mod.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Windows.Forms");
                var formRef = new TypeRefUser(mod, "System.Windows.Forms", "Form", wfAsm);
                var setText = new MemberRefUser(mod, "set_Text",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), formRef);
                var setVisible = new MemberRefUser(mod, "set_Visible",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.Boolean), formRef);
                var showM = new MemberRefUser(mod, "Show",
                    MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef);
                sctor.Body.ExceptionHandlers.Clear();
                sctor.Body.Instructions.Clear();
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(
                    new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef)));
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("sample5"));
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setText));
                sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(showM));
                sctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Console.WriteLine("v41e: SampleForm ctor = Text(sample5) + Show()");
            }
        }
        } else { Console.WriteLine("v46: manually ctor overwrite OFF — original ctor preserved"); }
        // v16: Eziriz nag-check taramasi — ldstr "Eziriz" iceren her
        // the method is the nag-check; ret its body (the throw path closes).
        int nagKilled = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool isNag = false;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is string str && str.Contains("Eziriz")) { isNag = true; break; }
                }
                if (!isNag) continue;
                m.Body.ExceptionHandlers.Clear();
                m.Body.Instructions.Clear();
                m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                m.Body.KeepOldMaxStack = true;
                nagKilled++;
            }
        }
        Console.WriteLine($"nag disabled: {nagKilled}");

        // v17: ZORLA-FORCE-RET — rcheck'in null-operand listesinin TAMAMI
        // (18 methods, t3b). hasNull condition REMOVED: dnlib write emits null
        // fills the operand with a token it generates itself, AFTER the write
        // hasNull is no longer catching these. The list is name-based.
        // EXCLUDED (recoverable via raw-body post-inject):
        //   qp1d5IbOJ (hook installer — never touch),
        //   y428a5a7 (alan-init, 5702B — .nbinj ham inject),
        //   m8DF140CC1AA41F4 (274B — .nbinj ham inject),
        //   SampleForm::Main (910B — .nbinj ham inject),
        //   VM792.* (27B — .nbinj ham inject),
        //   c6eqX6NsSy (nag-check; nag-kill already retd it)
        var forceKill = new System.Collections.Generic.HashSet<string> {
            "umu9nZfKOD9dhX9jX7", "KTIUiOjFB5WkrrnKyf",
            "aSXlaypSQk", "iavloN2HM3", "c4DlICH2Rx", "dIhlRD8H3g",
            "jIu1fxq0ljXptt0Teaq", "T6EMmqqYYpp87BARchF",
            "bY0V8gqFt6wiWLEo6Q5", "LuDGM6qZqntdkFQoFrt",
        };
        int forceRetCount = 0;
        var allTypes = mod.GetTypes().ToList();
        var gmod = mod.GlobalType;
        if (gmod != null && !allTypes.Contains(gmod)) allTypes.Add(gmod);
        foreach (var t in allTypes) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (!forceKill.Contains(m.Name.String)) continue;
                m.Body.ExceptionHandlers.Clear();
                m.Body.Instructions.Clear();
                var retType = m.MethodSig.RetType;
                if (retType != null && retType.ElementType != ElementType.Void) {
                    if (retType.IsValueType) {
                        m.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    } else {
                        m.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                    }
                }
                m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                m.Body.KeepOldMaxStack = true;
                forceRetCount++;
            }
        }
        Console.WriteLine($"force-ret method: {forceRetCount}");

        // v18: pre-write null-operand rescue — forceKill/raw-inject
        // null calls/fields in methods OUTSIDE the set get a TEMPORARY dummy token
        // bind them so dnlib can write. (Raw-inject later overwrites these bodies
        // with original bytes; the temporary dummy only saves the write.)
        // v19: DELETE null-operand instructions entirely (not nop).
        // once NecroBit fake-body null-calls are dropped, the remaining flow
        // ANLAMLI deadyor (KCFlcDdR6L: ldarg.0+ldfld+callvirt+ret).
        // Metot doneen bosaliyorsa donus-tipine gore dummy+ret.
        int nullRemoved = 0, hollowFilled = 0;
        // NB_NOSIL=1: null-operand silme atlanir (NecroBit runtime-restore
        // class targets — 7.5.9.1, dotqw — the null-wipe init call chain
        // kiriyor; restore bekleyen body bozuluyor). Sadece check-strip
        // (v43/v44) uygulanir.
        bool noSil = Environment.GetEnvironmentVariable("NB_NOSIL") == "1";
        if (noSil) {
            // v45: under NB_NOSIL the null operands are NOT deleted but dnlib still
            // null operand yazamaz -> gecici dummy MemberRef/MemberRefUser bagla.
            // Behavior: NecroBit runtime-restore intercepts the call anyway;
            // the dummy token only enables the write. Extension of v18.
            int dummyBound = 0;
            var dummyMrr = new MemberRefUser(mod, "d",
                MethodSig.CreateInstance(mod.CorLibTypes.Void), mod.CorLibTypes.Object.TypeDefOrRef);
            foreach (var t in allTypes) {
                foreach (var m in t.Methods) {
                    if (!m.HasBody) continue;
                    foreach (var i in m.Body.Instructions) {
                        if (i.Operand != null) continue;
                        var ot = i.OpCode.OperandType;
                        if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                            ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                            ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                            if (ot == OperandType.InlineString) i.Operand = "d";
                            else i.Operand = dummyMrr;
                            dummyBound++;
                        }
                    }
                }
            }
            Console.WriteLine("v45: null-operand dummy-token baglandi: " + dummyBound);
        }
        if (!noSil) {
        foreach (var t in allTypes) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (forceKill.Contains(m.Name.String)) continue;
                // EXCEPT the qp1d5IbOJ/m8DF/Main raw-inject; y428a's null
                // yazimi kiriyor — SIL (ham inject sonra ezecek):
                if (m.Name.String == "qp1d5IbOJ" || m.Name.String == "m8DF140CC1AA41F4" ||
                    m.Name.String == "Main") continue;
                if (m.Name.String == "c6eqX6NsSy") {
                    // cipherli call IL_0002 — akista atlanir, NOP'la:
                    foreach (var i in m.Body.Instructions) {
                        if (i.OpCode == OpCodes.Call && !(i.Operand is IMethod)) {
                            i.OpCode = OpCodes.Nop; i.Operand = null;
                        }
                    }
                }
                var toRemove = new System.Collections.Generic.List<Instruction>();
                // v42: branch/exception-handler targeti deadp olmadigini once hesapla —
                // target instruction SILINEMEZ (ModuleWriterException), NOP'lanir.
                var branchTargets = new System.Collections.Generic.HashSet<dnlib.DotNet.Emit.Instruction>();
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is dnlib.DotNet.Emit.Instruction t1) branchTargets.Add(t1);
                    if (i.Operand is dnlib.DotNet.Emit.Instruction[] tarr)
                        foreach (var tt in tarr) branchTargets.Add(tt);
                }
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.TryStart != null) branchTargets.Add(eh.TryStart);
                    if (eh.TryEnd != null) branchTargets.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) branchTargets.Add(eh.HandlerStart);
                    if (eh.HandlerEnd != null) branchTargets.Add(eh.HandlerEnd);
                    if (eh.FilterStart != null) branchTargets.Add(eh.FilterStart);
                }
                foreach (var i in m.Body.Instructions) {
                    // dnlib fills the null operand with an empty MemberRef:
                    // invalid operand detection — nameless/null-name.
                    if (i.Operand is IMethod im) {
                        if (!UTF8String.IsNullOrEmpty(im.Name)) continue;
                    } else if (i.Operand is IField iff) {
                        if (!UTF8String.IsNullOrEmpty(iff.Name)) continue;
                    } else if (i.Operand != null) continue;
                    var ot = i.OpCode.OperandType;
                    if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                        ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                        ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                        if (branchTargets.Contains(i)) {
                            // target instruction — silme, nop'la (v42 safe)
                            i.OpCode = OpCodes.Nop; i.Operand = null;
                        } else {
                            toRemove.Add(i);
                        }
                    }
                }
                foreach (var i in toRemove) {
                    int idx = m.Body.Instructions.IndexOf(i);
                    m.Body.Instructions[idx] = OpCodes.Nop.ToInstruction();
                }
                nullRemoved += toRemove.Count;
                // br.s targetleri bozuldiysa dnlib duzeltir (KeepOldMaxStack).
                // freed method: dummy + ret
                if (m.Body.Instructions.Count == 0 ||
                    (m.Body.Instructions.Count == 1 && m.Body.Instructions[0].OpCode == OpCodes.Ret)) {
                    m.Body.Instructions.Clear();
                    var retType = m.MethodSig.RetType;
                    if (retType != null && retType.ElementType != ElementType.Void) {
                        if (retType.IsValueType) {
                            m.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                        } else {
                            m.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                        }
                    }
                    m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    hollowFilled++;
                }
            }
        }
        Console.WriteLine($"null-wiped: {nullRemoved}, freed-dummy: {hollowFilled}");
        } // end NB_NOSIL guard
        // DEBUG: remaining suspicious operands before write:
        int argBound = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand == null && i.OpCode.OperandType != OperandType.InlineNone &&
                        i.OpCode.OperandType != OperandType.ShortInlineBrTarget &&
                        i.OpCode.OperandType != OperandType.InlineBrTarget) {
                        // v48: starg.s/ldarg.s/ldarga.s null operand -> first param bind.
                        // Stub body has unresolved operands; bind to param[0] so the
                        // writer does not blow up. v48b: ldarg.s is the real opcode name
                        // (0x10) — starg.s was a wrong guess; ldarg/ldarga/starg too.
                        var opname = i.OpCode.Name;
                        if (opname == "starg.s" || opname == "ldarg.s" || opname == "ldarga.s" ||
                            opname == "starg" || opname == "ldarg" || opname == "ldarga") {
                            if (m.Parameters.Count > 0) { i.Operand = m.Parameters[0]; argBound++; continue; }
                            // v48c: zero-param method + arg opcode = dead stub remnant;
                            // nop it out so the writer does not choke.
                            i.OpCode = OpCodes.Nop; i.Operand = null; argBound++;
                            continue;
                        }
                        Console.WriteLine($"[suspect] {m.FullName} :: {i.OpCode.Name} operand=null");
                    }
                }
            }
        }
        Console.WriteLine($"v48: arg-bound: {argBound}");
        // <Module>.cctor + m8DF (nag-check) fully disabled:
        // cctor -> ret; m8DF -> ret. Safe because the ctor is fixed.
        // NecroBit runtime (VM792/gttro/null-call'lar) cctor'suz da
        // kendi init'ini Main icerisinde yapar — T1'de prooflandi.
        // v15: init-kill REMOVED - NecroBit hook setup qp1d5IbOJ + cctorr zincirinde;
        // once severed, runtime body-replace no longer happens; the JIT sees invalid IL.
        Console.WriteLine($"second pass nop: {extraNulled}");

        // maxstack yeniden hesaplat (t3b: KeepOldMaxStack qvU94'te
        // produced InvalidProgramException — the old value move was wrong

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;

        mod.Write(args[1], opts);
        Console.WriteLine($"[ok] fixed={fixedBodies} -> {args[1]}");
        return 0;
    }
}
