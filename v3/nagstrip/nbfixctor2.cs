// nbfixctor2.cs — v2: external base tipler için GAC'tan ctor import et.
// SampleForm : Form — BaseType TypeRef, ResolveTypeDef null. Cozum:
// Assembly.Load(baseType.DefinitionAssembly) ile gerçek tip yükle.
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NbFixCtor2 {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.WriteLine("nbfixctor2 <in> <out>"); return 1; }
        var mod = ModuleDefMD.Load(args[0]);
        int fixedBodies = 0;

        // BCL assembly cache — external base tipler icin
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
                            // basit tara: klasor adinda assembly adi gecen ilk dll
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

                // import: bAsm'den bu module'e tasi
                var imported = mod.Import(baseCtor);
                if (imported == null) {
                    Console.WriteLine($"[skip] import null: {t.FullName}::{m.Name}");
                    continue;
                }
                // govde 1 instr (sadece ret) olabilir — genislet
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

        // NecroBit 7.5: bazı call/newobj instruction'ları NULL operand'lı
        // (obfuscated token çözülmemiş) — dnlib yazımı patlar. nop'la.
        // ANCAK VM tiplerinin (obfuscated ad, AoIBWWl... gibi) gövdelerindeki
        // null-operand'lar VM blob'unun geçerli parçası olabilir — onlara
        // dokunma (t3'te InvalidProgramException dersi). Sadece
        // kullanıcı tiplerinde (non-obfuscated) nop'la. Ayırt etme:
        // tip adı C# identifier kurallarına uymayan = obfuscated.
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
        // yazım patlıyorsa: null-operand'lı kalan her instruction'ı atlayamayız.
        // VM tipi + null operand + kullanıcı tipinden ÇAĞRILIYOR olabilir
        // (call VM metodu). Bu durumda o call nop'lanmalı — kullanıcı
        // tarafında. Ek geçiş: tüm metotlarda null-operand'lı InlineMethod
        // call'ları nop'la AMA sadece tipin kendisi obfuscated DEĞİLSE
        // VE operand null olan instruction call VEYA ldftn ise.
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
        // NULL-OPERAND İÇEREN METOTLARI FORCE-RET YAP (t3b v2):
        // Tip silmek "Non-Static Global Method" verdi (module ref koptu).
        // Bunun yerine: null-operand'lı her METOT govdesini "ret" yap ve
        // static+public yap — token yerinde kalir, null'lar yok olur,
        // cagrilan metotlar noop-davranisi (ret) sergiler.
        // v37: <Module>{guid}::cctor y428a cagrisini global <Module>::cctor
        // BASINA tasi — ayni-thread cctor reentransi m_cec alanlarini bos
        // birakiyordu (qp ldfld m_xxx NRE). Global cctor: y428a; qp; m8DF.
        {
            // v38b: guid tipi otomatik — NecroBit init cctor'u tasiyan:
            // global cctor'un cagirdigi IKINCI metot y428a-init'tir; guid
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
            if (gt == null || gmodt == null) Console.WriteLine("v38: tip bulunamadi gt=" + (gt != null) + " gmod=" + (gmodt != null));
            if (gt != null && gmodt != null) {
                var gcc = gmodt.Methods.FirstOrDefault(m => m.Name == ".cctor");
                var tcc = gt != null ? gt.Methods.FirstOrDefault(m => m.Name == ".cctor") : null;
                Console.WriteLine("v38: gcc=" + (gcc != null) + " tcc=" + (tcc != null) + " y428=" + (y428 != null));
                if (gcc != null && tcc != null && y428 != null) {
                    gcc.Body.Instructions.Clear();
                    gcc.Body.Instructions.Add(OpCodes.Call.ToInstruction(y428));
                    gcc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    tcc.Body.Instructions.Clear();
                    tcc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    Console.WriteLine("v37: global cctor = y428a; ret — guid cctor ret");
                }
            }
        }
        // v39: SampleForm::.cctor — qp1d5IbOJ cagrisini kopar (ret).
        // final15 kaniti: NRE qp icinde, cagiran SampleForm cctor.
        // qp govdesi cflow+vm karisik 6318 instr; necro-bit akis
        // bozuk govde. Static init zaten AoIBWWl cctor'ta y428a ile.
        // v39b: form tipi = entry point'in DeclaringType (parametrize)
        TypeDef formType = mod.EntryPoint != null ? mod.EntryPoint.DeclaringType : null;
        if (formType != null) {
            var scc = formType.Methods.FirstOrDefault(m => m.Name == ".cctor");
            if (scc != null && scc.HasBody) {
                scc.Body.Instructions.Clear();
                scc.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                scc.Body.KeepOldMaxStack = true;
                Console.WriteLine("v39: " + formType.Name + " cctor -> ret");
            }
        }
        // v40: qp1d5IbOJ cagrisini BUTUN cctor'lardan kopar (genel).
        // final15/16 kaniti: <>c__DisplayClass5..cctor de qp cagiriyor.
        // Global <Module>::.cctor zaten y428a+ret (v38). Diger cctor'larda
        // qp'yi silen satir cikar, kalan init akisi korunur.
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
                    // govde tamamen bosaldiysa ret:
                    if (m.Body.Instructions.Count == 0)
                        m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    qpCut += drop.Count;
                }
            }
        }
        Console.WriteLine("v40: qp cagrisi koparilan cctor satiri: " + qpCut);
        // v41: Main cflow sonsuz dongu — temiz WinForms govdesi yaz.
        // final17 kaniti: %100 CPU, pencere yok, V_6=17 switch IL_02ad loop.
        {
            var t = formType != null ? formType : mod.GetTypes().FirstOrDefault(x => x.Name == "SampleForm");
            if (t == null) { Console.WriteLine("v41: form tipi yok"); }
            else {
            var main = t.Methods.FirstOrDefault(m => m.Name == "Main" && m.HasBody) ?? mod.EntryPoint;
            if (main == null) { Console.WriteLine("v41: main yok"); }
            else {
            // v41d: orijinal Main'in Application MemberRef'lerini kaydet:
            IMethod evs = null, sctrd = null, run = null;
            foreach (var ins in main.Body.Instructions) {
                if (ins.Operand is IMethod im) {
                    if (im.Name == "EnableVisualStyles") evs = im;
                    if (im.Name == "SetCompatibleTextRenderingDefault") sctrd = im;
                    if (im.Name == "Run") run = im;
                }
            }
            if (evs == null || run == null) { Console.WriteLine("v41: orijinal Main refs yok"); }
            else {
            var sform = main.DeclaringType;
            var ctor = sform.Methods.FirstOrDefault(m => m.Name == ".ctor");
            if (ctor == null) { Console.WriteLine("v41: ctor yok"); }
            else {
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
        {
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
                    sctor.Body.Instructions.Clear();
                    sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    sctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(
                        new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), formRef)));
                    sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    sctor.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("sample5"));
                    sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setText));
                    sctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    sctor.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                    sctor.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setVisible));
                    sctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    Console.WriteLine("v41e: SampleForm ctor = Text(sample5) + Visible(true)");
                }
            }
        }
        // v16: Eziriz nag-check taramasi — ldstr "Eziriz" iceren her
        // metot nag-check'tir; govdesini ret yap (throw yolu kapanir).
        int nagKilled = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool isNag = false;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand is string str && str.Contains("Eziriz")) { isNag = true; break; }
                }
                if (!isNag) continue;
                m.Body.Instructions.Clear();
                m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                m.Body.KeepOldMaxStack = true;
                nagKilled++;
            }
        }
        Console.WriteLine($"nag kapatildi: {nagKilled}");

        // v17: ZORLA-FORCE-RET — rcheck'in null-operand listesinin TAMAMI
        // (18 metot, t3b). hasNull kosulu KALDIRILDI: dnlib yazimi null
        // operand'i kendi urettigi token'la dolduruyor, yazim SONRASI
        // hasNull artik true YAKALAMIYOR. Liste isim bazli.
        // HARIC TUTULANLAR (ham-govde post-inject ile kurtarilir):
        //   qp1d5IbOJ (hook kurucu — asla dokunma),
        //   y428a5a7 (alan-init, 5702B — .nbinj ham inject),
        //   m8DF140CC1AA41F4 (274B — .nbinj ham inject),
        //   SampleForm::Main (910B — .nbinj ham inject),
        //   VM792.* (27B — .nbinj ham inject),
        //   c6eqX6NsSy (nag-check, nag-kill zaten retledi)
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
        Console.WriteLine($"force-ret metot: {forceRetCount}");

        // v18: yazim-oncesi null-operand kurtarma — forceKill/ham-inject
        // DISINDAKI metotlardaki null call/field'lara GECICI dummy token
        // bagla ki dnlib yazabilsin. (Ham-inject sonra bu govdeleri zaten
        // orijinal byte'larla ezecek; gecici dummy sadece yazimi kurtarir.)
        // v19: null-operand'li instruction'lari TAMAMEN SIL (nop degil).
        // NecroBit sahte-govde null-call'lari atildiginda kalan akis
        // ANLAMLI oluyor (KCFlcDdR6L: ldarg.0+ldfld+callvirt+ret).
        // Metot tamamen bosaliyorsa donus-tipine gore dummy+ret.
        int nullRemoved = 0, hollowFilled = 0;
        foreach (var t in allTypes) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (forceKill.Contains(m.Name.String)) continue;
                // qp1d5IbOJ/m8DF/Main ham-inject HARIC; y428a'nin null'u
                // yazimi kiriyor — SIL (ham inject sonra ezecek):
                if (m.Name.String == "qp1d5IbOJ" || m.Name.String == "m8DF140CC1AA41F4" ||
                    m.Name.String == "Main") continue;
                if (m.Name.String == "c6eqX6NsSy") {
                    // sifreli call IL_0002 — akista atlanir, NOP'la:
                    foreach (var i in m.Body.Instructions) {
                        if (i.OpCode == OpCodes.Call && !(i.Operand is IMethod)) {
                            i.OpCode = OpCodes.Nop; i.Operand = null;
                        }
                    }
                }
                var toRemove = new System.Collections.Generic.List<Instruction>();
                foreach (var i in m.Body.Instructions) {
                    // dnlib null operand'i bos MemberRef ile dolduruyor:
                    // gecersiz operand tespiti — isimsiz/null-isim.
                    if (i.Operand is IMethod im) {
                        if (!UTF8String.IsNullOrEmpty(im.Name)) continue;
                    } else if (i.Operand is IField iff) {
                        if (!UTF8String.IsNullOrEmpty(iff.Name)) continue;
                    } else if (i.Operand != null) continue;
                    var ot = i.OpCode.OperandType;
                    if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                        ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                        ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                        toRemove.Add(i);
                    }
                }
                foreach (var i in toRemove) {
                    int idx = m.Body.Instructions.IndexOf(i);
                    m.Body.Instructions[idx] = OpCodes.Nop.ToInstruction();
                }
                nullRemoved += toRemove.Count;
                // br.s hedefleri bozuldiysa dnlib duzeltir (KeepOldMaxStack).
                // bosalan metot: dummy + ret
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
        Console.WriteLine($"null-sil: {nullRemoved}, bosalan-dummy: {hollowFilled}");
        // DEBUG: yazim-oncesi kalan supheli operand'lar:
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions) {
                    if (i.Operand == null && i.OpCode.OperandType != OperandType.InlineNone &&
                        i.OpCode.OperandType != OperandType.ShortInlineBrTarget &&
                        i.OpCode.OperandType != OperandType.InlineBrTarget) {
                        Console.WriteLine($"[supheli] {m.FullName} :: {i.OpCode.Name} operand=null");
                    }
                }
            }
        }
        // <Module>.cctor + m8DF (nag-check) tamamen kapat:
        // cctor -> ret; m8DF -> ret. ctor fix'li oldugu icin guvenli.
        // NecroBit runtime (VM792/gttro/null-call'lar) cctor'suz da
        // kendi init'ini Main icerisinde yapar — T1'de kanitlandi.
        // v15: init-kill KALDIRILDI — NecroBit hook kurulumu qp1d5IbOJ + cctor zincirinde;
        // kopartilinca runtime body-replace yapilmiyor, JIT gecersiz IL goruyor.
        Console.WriteLine($"ikinci gecis nop: {extraNulled}");

        // maxstack yeniden hesaplat (t3b: KeepOldMaxStack qvU94'te
        // InvalidProgramException uretti — eski deger tasi yanlis)

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;

        mod.Write(args[1], opts);
        Console.WriteLine($"[ok] fixed={fixedBodies} -> {args[1]}");
        return 0;
    }
}