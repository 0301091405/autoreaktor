// nbilmerge.cs v6 — token filter fixed: large rids
// (MethodDesc chunk artefaktlari) atlanir ama modul icindeki
// all tokens are tried; real problem: the byToken lookup misses 108's
// hepsinde miss — cunku dump token'lari & 0xFFFFFF ile modulun
// rids may not line up. full scan first:
// for every dump token: exists in module, else write without rid.
// AYRICA CreateCilBody callnda exception mesajlarini yaz.
using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NBIlMerge {
    // derive local count from raw CIL: ldloc.0-3/stloc.0-3 short
    // form indexleri + ldloc/ldloca/stloc/ldloc.s/... operand
    // bytes are scanned. Wrong count = writer error; therefore
    // over-estimating is not safe — BUFFER: largest observed
    // index + 1, at least 1 local (for null binding).
    static int CountLocalsFromCil(byte[] cil) {
        // ldloc.0-3 = 0x06-0x09, stloc.0-3 = 0x0A-0x0D,
        // ldloc.s=0x0E, ldloca.s=0x0F, stloc.s=0x13 (1-byte index),
        // 0xFE 06/09/0D ldloc/ldloca/stloc (2-byte u16 index).
        // Previous bug: short forms were skipped without recording.
        int maxIdx = -1;
        int i = 0, n = cil.Length;
        while (i < n) {
            byte op = cil[i];
            if (op == 0xFE) {
                if (i + 2 < n) {
                    byte op2 = cil[i + 1];
                    if (op2 == 0x06 || op2 == 0x09 || op2 == 0x0D) {
                        int v = cil[i + 2] | (cil[i + 3] << 8);
                        if (v > maxIdx) maxIdx = v;
                    }
                }
                i += 2; // operand taramasi altta yapilmaz — kaba atla
                continue;
            }
            if (op >= 0x06 && op <= 0x0D) { // ldloc.0-3 + stloc.0-3
                int v = (op <= 0x09) ? op - 0x06 : op - 0x0A;
                if (v > maxIdx) maxIdx = v;
                i += 1; continue;
            }
            if (op == 0x0E || op == 0x0F || op == 0x13) {
                if (i + 1 < n) { int v = cil[i + 1]; if (v > maxIdx) maxIdx = v; }
                i += 2; continue;
            }
            i += 1;
        }
        return maxIdx + 1;
    }

    static int Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: nbilmerge <in.exe> <dumpdir> <out.exe>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);

        var bodies = new List<byte[]>();
        var toks = new List<uint>();
        foreach (var f in Directory.GetFiles(a[1], "m_*.bin")) {
            var d = File.ReadAllBytes(f);
            uint tok = BitConverter.ToUInt32(d, 0);
            uint il = BitConverter.ToUInt32(d, 4);
            var body = new byte[il];
            Array.Copy(d, 20, body, 0, il);
            toks.Add(tok); bodies.Add(body);
        }
        Console.WriteLine("dump body: " + toks.Count);

        var byToken = new Dictionary<uint, MethodDef>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                byToken[(uint)m.MDToken.Raw] = m;
        Console.WriteLine("modul MethodDef: " + byToken.Count);

        int restored = 0, skipped = 0;
        bool noBodyWrite = Environment.GetEnvironmentVariable("NB_NOBODY") == "1";
        // SEQ-matching (for x64 targets): dumps with synthetic tokens
        // (out of rid range) in nb2 with the bodyless methods in metadata
        // bind by encounter order. Weak proof — only
        // rapor modunda kullan (NB_SEQ=1).
        bool seqMode = Environment.GetEnvironmentVariable("NB_SEQ") == "1";
        // NB_ILMATCH=1: sentetik tokenli dumplari bodyless methodlarla
        // match by IL signature (ilSize + first byte) similarity. ilSize
        // if unique it is a valid match; on collision the first
        // aday alinir ve RAPORLANIR (proof zayfligi acik).
        bool ilMatch = Environment.GetEnvironmentVariable("NB_ILMATCH") == "1";
        int ilMatchUsed = 0;
        var bodyless = new List<MethodDef>();
        if (seqMode) {
            foreach (var t in mod.GetTypes())
                foreach (var m2 in t.Methods)
                    if (!m2.HasBody) bodyless.Add(m2);
            Console.WriteLine("seq target havuz (bodyless method): " + bodyless.Count);
        }
        // NB_STUBMAP: manually stub=dump eslemesi (proofli rota).
        // Format: NB_STUBMAP="m_0000.bin=methodAdi;m_0001.bin=methodAdi2"
        var stubMap = new System.Collections.Generic.Dictionary<string,string>();
        string smEnv = Environment.GetEnvironmentVariable("NB_STUBMAP");
        if (!string.IsNullOrEmpty(smEnv))
            foreach (var pair in smEnv.Split(';')) {
                var kv = pair.Split('=');
                if (kv.Length == 2) stubMap[kv[0].Trim()] = kv[1].Trim();
                            }
                        // NB_STUBMAPTOK: token-precise stub mapping (universal route):
                        // format "m_0628001A.bin=06000006;m_06280015.bin=0600002B"
                        // binds a dump file to the module method with that MethodDef
                        // token. Token binding is unambiguous (unlike name binding).
                        var stubTokMap = new System.Collections.Generic.Dictionary<string,string>();
                        string stmEnv = Environment.GetEnvironmentVariable("NB_STUBMAPTOK");
                        if (!string.IsNullOrEmpty(stmEnv))
                            foreach (var pair in stmEnv.Split(';')) {
                                var kv = pair.Split('=');
                                if (kv.Length == 2) stubTokMap[kv[0].Trim()] = kv[1].Trim();
                            }
                        // NB_LDSTRMAP: rebind ldstr runtime tokens to literal strings
                        // (NecroBit string-enc removes literals from the US heap; the
                        // dumped IL keeps runtime-only tokens). Format:
                        //   NB_LDSTRMAP="70000352=sample5;7000039E=register"
                        // The literal is written into the OUT module's US heap by dnlib
                        // with a fresh token — content-true rebinding.
                        var ldstrMap = new System.Collections.Generic.Dictionary<uint,string>();
                        string lsEnv = Environment.GetEnvironmentVariable("NB_LDSTRMAP");
                        if (!string.IsNullOrEmpty(lsEnv))
                            foreach (var pair in lsEnv.Split(';')) {
                                var kv = pair.Split('=');
                                if (kv.Length == 2) {
                                    uint tk; if (!uint.TryParse(kv[0].Trim(), System.Globalization.NumberStyles.HexNumber, null, out tk)) continue;
                                    ldstrMap[tk] = kv[1];
                                }
                            }
                int seqIdx = 0;
                        int stubHit = 0;
                        int stubTokHit = 0, ldstrRebound = 0;
                        for (int i = 0; i < toks.Count; i++) {
                            // NB_STUBMAPTOK first (token-precise), then NB_STUBMAP (name).
                            string baseName = System.IO.Path.GetFileName(
                                Directory.GetFiles(a[1], "m_*.bin")[i]);
                            MethodDef stubTarget = null;
                            string dumpName = null;
                            string tokName = null;
                            if (stubTokMap.Count > 0 && stubTokMap.TryGetValue(baseName, out tokName)) {
                                uint mt; if (uint.TryParse(tokName, System.Globalization.NumberStyles.HexNumber, null, out mt)) {
                                    foreach (var t in mod.GetTypes())
                                        foreach (var mstub in t.Methods)
                                            if (mstub.MDToken.Raw == mt) { stubTarget = mstub; break; }
                                }
                                if (stubTarget != null) { stubTokHit++; }
                            }
                            if (stubTarget == null && stubMap.Count > 0 && stubMap.TryGetValue(baseName, out dumpName)) {
                foreach (var t in mod.GetTypes())
                    foreach (var mstub in t.Methods)
                        if (mstub.Name.String == dumpName) { stubTarget = mstub; break; }
                if (stubTarget != null) {
                    // the general write path handles this body:
                    // set m=stubTarget, have=true.
                    stubHit++;
                }
            }
            if (noBodyWrite) { skipped++; continue; }
            MethodDef m = stubTarget;
                        bool have = stubTarget != null;
                        if (!have) have = byToken.TryGetValue(toks[i], out m);
                        if (!have || m == null) {
                if (seqMode && seqIdx < bodyless.Count) {
                                    m = bodyless[seqIdx++];
                                    if (m == null) { skipped++; continue; }
                                    have = true;
                                } else if (ilMatch && bodyless.Count > 0) {
                                    // IL signature: dump (ilSize, first byte) — the module's
                                    // bodyless methods have no known IL; but this
                                    // matching runs in reverse: the dump's ilSize
                                    // cannot be predicted from module metadata. Therefore
                                    // ILMATCH is only an ilSize + call-count heuristic
                                    // eslemesi yapabilir ve SONUC RAPORLANIR:
                                    m = null; int bestScore = -1;
                                    // bodyless methodlarin param sayisi + statiklik
                                    // dump'tan bilinmiyor — en zayif bag: siradaki
                                    // uygun bodyless metodu al ama ETIKETLE:
                                    for (int bi = 0; bi < bodyless.Count; bi++) {
                                        var cand = bodyless[bi];
                                        if (cand == null || cand.HasBody) continue;
                                        m = cand; bodyless[bi] = null;
                                        ilMatchUsed++;
                                        break;
                                    }
                                    if (m == null) { skipped++; continue; }
                                    have = true;
                                } else {
                                    skipped++;
                                    if (i < 3) Console.WriteLine("  [miss] 0x" + toks[i].ToString("X8"));
                                    continue;
                                }
            }
            try {
                // CreateCilBody METHOD BODY HEADER'li akis bekler:
                // il<64 -> tiny (il<<2)|2, degilse 12-byte fat header.
                uint il = (uint)bodies[i].Length;
                byte[] all;
                if (il < 64) {
                    all = new byte[1 + il];
                    all[0] = (byte)((il << 2) | 2);
                    Array.Copy(bodies[i], 0, all, 1, il);
                } else {
                    var ms = new MemoryStream();
                    // fat header: word0 = (3 dwords << 12) | flags.
                    // flags 0x13 = FatFormat(0x3) | InitLocals(0x10).
                    // 0x3011 is the wrong bit layout — 0x3013 is correct (q20 proof).
                    ushort flags = 0x3013;
                    ms.Write(BitConverter.GetBytes(flags), 0, 2);
                    ms.Write(BitConverter.GetBytes((ushort)8), 0, 2);
                    ms.Write(BitConverter.GetBytes(il), 0, 4);
                    ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                    ms.Write(bodies[i], 0, bodies[i].Length);
                    all = ms.ToArray();
                }
                var dr = dnlib.IO.ByteArrayDataReaderFactory.CreateReader(all);
                var newBody = dnlib.DotNet.Emit.MethodBodyReader.CreateCilBody(
                    (dnlib.DotNet.Emit.IInstructionOperandResolver)mod,
                    dr, m.Parameters);
                if (newBody != null && newBody.Instructions.Count > 0) {
                    // v49 LDSTR REBIND: NecroBit string-enc leaves runtime-only
                    // ldstr tokens in the dumped IL. If NB_LDSTRMAP carries the
                    // literal, replace the operand with the real string — dnlib
                    // writes it into the OUT module's US heap content-true.
                    foreach (var ins in newBody.Instructions) {
                        if (ins.OpCode == OpCodes.Ldstr && ldstrMap.Count > 0) {
                            uint ltok = ins.Operand is uint ? (uint)ins.Operand : 0;
                            string lit;
                            if (ltok != 0 && ldstrMap.TryGetValue(ltok, out lit)) {
                                ins.Operand = lit;
                                ldstrRebound++;
                            }
                        }
                    }
                    // LOCALS: no localVarSig in the dump — ldloc/stloc
                    // operands stayed null (writer "Operand is not
                    // a local/arg" error). Reverse derivation from the body:
                    // fill Variables up to max local index + 1 and
                    // null operandli ldloc/stloc/ldloca'lari indexe
                    // bagla.
                    int maxLocal = -1;
                    var localOps = new List<dnlib.DotNet.Emit.Instruction>();
                    foreach (var ins in newBody.Instructions) {
                        var op = ins.OpCode.Code;
                        // ALL local opcodes — short forms included
                        // (q21: the cause of 272 null operands was short forms
                        // bu listede olmamasiydi):
                        bool isLocalOp = op == dnlib.DotNet.Emit.Code.Ldloc ||
                                         op == dnlib.DotNet.Emit.Code.Ldloca ||
                                         op == dnlib.DotNet.Emit.Code.Stloc ||
                                         (op >= dnlib.DotNet.Emit.Code.Ldloc_0 && op <= dnlib.DotNet.Emit.Code.Ldloc_3) ||
                                         (op >= dnlib.DotNet.Emit.Code.Ldloc_S && op <= dnlib.DotNet.Emit.Code.Ldloca_S) ||
                                         (op >= dnlib.DotNet.Emit.Code.Stloc_0 && op <= dnlib.DotNet.Emit.Code.Stloc_3) ||
                                         op == dnlib.DotNet.Emit.Code.Stloc_S;
                        if (isLocalOp && ins.Operand == null) localOps.Add(ins);
                        if (isLocalOp && ins.Operand is dnlib.DotNet.Emit.Local) {
                            var lv = (dnlib.DotNet.Emit.Local)ins.Operand;
                            int idx = newBody.Variables.IndexOf(lv);
                            if (idx > maxLocal) maxLocal = idx;
                        }
                    }
                    // CreateCilBody's variables list may be empty:
                    // local kullanan bodyde ldloc instr operand null
                    // otherwise dnlib already resolved it; if null, the index
                    // cannot be derived from instr order — safe path:
                    // not from method signature + body size,
                    // ham IL'den mini tarama:
                    if (localOps.Count > 0) {
                        string mwv = Environment.GetEnvironmentVariable("NB_MAXWRITE");
                    if (mwv != null && restored >= int.Parse(mwv)) { skipped++; continue; }
                    int nLocals = CountLocalsFromCil(bodies[i]);
                        if (nLocals < 1) nLocals = 1; // ldloc.0 en az 1 local gerektirir
                        for (int li = newBody.Variables.Count; li < nLocals; li++)
                            newBody.Variables.Add(new dnlib.DotNet.Emit.Local(mod.CorLibTypes.Object));
                        if (i < 3) Console.WriteLine("  [dbg] tok=0x" + toks[i].ToString("X8") +
                            " localOps=" + localOps.Count + " nLocals=" + nLocals +
                            " vars=" + newBody.Variables.Count);
                        // null operandli local opslari indexe bagla:
                        foreach (var ins in localOps) {
                            int idx2 = 0;
                            var c = ins.OpCode.Code;
                            if (c >= dnlib.DotNet.Emit.Code.Ldloc_0 && c <= dnlib.DotNet.Emit.Code.Ldloc_3)
                                idx2 = (int)c - (int)dnlib.DotNet.Emit.Code.Ldloc_0;
                            else if (c >= dnlib.DotNet.Emit.Code.Stloc_0 && c <= dnlib.DotNet.Emit.Code.Stloc_3)
                                idx2 = (int)c - (int)dnlib.DotNet.Emit.Code.Stloc_0;
                            else if (c == dnlib.DotNet.Emit.Code.Ldloc_S || c == dnlib.DotNet.Emit.Code.Ldloca_S ||
                                     c == dnlib.DotNet.Emit.Code.Stloc_S) {
                                // .S form: operand resolved as ushort in dnlib;
                                // null kaldiysa IL'den cikaramayiz — Variables son index:
                                idx2 = newBody.Variables.Count - 1;
                            } else idx2 = newBody.Variables.Count - 1;
                            if (idx2 >= 0 && idx2 < newBody.Variables.Count)
                                ins.Operand = newBody.Variables[idx2];
                        }
                        // post-assignment check (before Write):
                        int stillNull = 0;
                        foreach (var ins in localOps) if (ins.Operand == null) stillNull++;
                        if (i < 3) Console.WriteLine("  [post] tok=0x" + toks[i].ToString("X8") + " halaNull=" + stillNull);
                    }
                    m.Body = newBody;
                    restored++;
                } else skipped++;
            } catch (Exception e) {
                skipped++;
                Console.WriteLine("  [exc] 0x" + toks[i].ToString("X8") + ": " + e.GetType().Name + " " + e.Message);
            }
        }
        Console.WriteLine("stub-map hits: " + stubHit);
        Console.WriteLine("method actually written: " + restored + " | skipped: " + skipped);
        Console.WriteLine("ILMATCH (heuristic, unproven matching): " + ilMatchUsed);
        Console.WriteLine("stubTok hits: " + stubTokHit + " | ldstr rebound: " + ldstrRebound);
        string mw = Environment.GetEnvironmentVariable("NB_MAXWRITE");
        if (mw != null) Console.WriteLine("NB_MAXWRITE=" + mw + " (limit modu)");

        // null-operand write rescue (skip with NB_NOSIL=1)
        bool noSil2 = Environment.GetEnvironmentVariable("NB_NOSIL") == "1";
        var toRemove = new List<Instruction>();
        int nullSil = 0;
        if (!noSil2)
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                toRemove.Clear();
                var branchTargets = new HashSet<dnlib.DotNet.Emit.Instruction>();
                foreach (var ins in m.Body.Instructions) {
                    if (ins.Operand is dnlib.DotNet.Emit.Instruction) branchTargets.Add((dnlib.DotNet.Emit.Instruction)ins.Operand);
                    if (ins.Operand is dnlib.DotNet.Emit.Instruction[])
                        foreach (var x in (dnlib.DotNet.Emit.Instruction[])ins.Operand) branchTargets.Add(x);
                }
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.TryStart != null) branchTargets.Add(eh.TryStart);
                    if (eh.HandlerStart != null) branchTargets.Add(eh.HandlerStart);
                    if (eh.FilterStart != null) branchTargets.Add(eh.FilterStart);
                }
                foreach (var ins in m.Body.Instructions) {
                    if (ins.Operand != null) continue;
                    var ot = ins.OpCode.OperandType;
                    if (ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                        ot == OperandType.InlineType || ot == OperandType.InlineTok ||
                        ot == OperandType.InlineString || ot == OperandType.InlineSig) {
                        if (branchTargets.Contains(ins)) { ins.OpCode = OpCodes.Nop; ins.Operand = null; }
                        else toRemove.Add(ins);
                        nullSil++;
                    }
                }
                foreach (var ins in toRemove) m.Body.Instructions.Remove(ins);
            }
        }
        Console.WriteLine("null-wipe: " + nullSil);

        // AT-KILL disabled (NB_ATKILL=1 opt-in): PreserveTokens
        // write keeps nb2's CRC intact, no need;
        // if "tampered" reappears, v44 surgery with NB_ATKILL=1.
        int tamperKilled = 0, tamperNop = 0;
        bool doAtKill = Environment.GetEnvironmentVariable("NB_ATKILL") == "1";
        if (!doAtKill) { tamperKilled = 0; goto SkipAtKill; }
        var tamperMethods = new HashSet<MethodDef>();
        foreach (var t in mod.GetTypes())
            foreach (var mm in t.Methods) {
                if (!mm.HasBody) continue;
                foreach (var ins in mm.Body.Instructions) {
                    if (ins.OpCode == OpCodes.Ldstr) {
                        var sv = ins.Operand as string;
                        if (sv != null && sv.ToLower().Contains("tamper"))
                            tamperMethods.Add(mm);
                    }
                }
            }
        foreach (var tm in tamperMethods) {
            // LINE-SURGERY (not method-kill): only the "tampered"
            // cut the throw chain after ldstr; the method's init
            // part stays (v44 finding: check/init share one body).
            var instrs = tm.Body.Instructions;
            for (int ii = 0; ii < instrs.Count; ii++) {
                if (instrs[ii].OpCode == OpCodes.Ldstr) {
                    var sv = instrs[ii].Operand as string;
                    if (sv == null || !sv.ToLower().Contains("tamper")) continue;
                    // throw chain after ldstr: ldstr -> newobj -> throw
                    int cutEnd = Math.Min(ii + 4, instrs.Count);
                    for (int jj = ii; jj < cutEnd; jj++) {
                        if (instrs[jj].OpCode == OpCodes.Throw) {
                            cutEnd = jj + 1; break;
                        }
                    }
                    // ldstr..throw arasini nop, throw yerine ret:
                    for (int jj = ii; jj < cutEnd - 1; jj++) {
                        instrs[jj].OpCode = OpCodes.Nop; instrs[jj].Operand = null;
                    }
                    instrs[cutEnd - 1].OpCode = OpCodes.Ret; instrs[cutEnd - 1].Operand = null;
                    tamperKilled++;
                    break;
                }
            }
        }
        foreach (var t in mod.GetTypes())
            foreach (var mm in t.Methods) {
                if (!mm.HasBody || tamperMethods.Contains(mm)) continue;
                foreach (var ins in mm.Body.Instructions) {
                    if ((ins.Operand is MethodDef) && tamperMethods.Contains((MethodDef)ins.Operand)) {
                        ins.OpCode = OpCodes.Nop; ins.Operand = null; tamperNop++;
                    }
                }
            }
        Console.WriteLine("tamper-oldur: " + tamperKilled + " | call-nop: " + tamperNop);
        SkipAtKill: ;
        var wopts = new ModuleWriterOptions(mod);
        wopts.MetadataLogger = DummyLogger.NoThrowInstance;
        // PreserveAll: rid + heap offset hizalamasini korur — AT'nin
        // CRC coverage area stays intact (verified via q26, 32767).
        wopts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        wopts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], wopts);
        Console.WriteLine("[ok] written: " + a[2]);
        return 0;
    }
}