// nbilmerge.cs v6 — token filter fixed: large rids
// (MethodDesc chunk artifacts) are skipped, but the ones inside the module
// all tokens are tried; real problem: the byToken lookup misses 108's
// all miss: dump tokens are & 0xFFFFFF while the module's
// rids may not line up. full scan first:
// for every dump token: exists in module, else write without rid.
// Also log the exception messages from the CreateCilBody calls.
using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NBIlMerge {
    // CIL opcode operand sizes derived from System.Reflection.Emit.OpCodes —
    // no hand-maintained tables, no wrong skips. ScanLocalIndices walks a raw
    // body with exact instruction boundaries.
    static Dictionary<byte, int> _opLen1;
    static Dictionary<byte, int> _opLen2;   // second byte after 0xFE

    static void EnsureOpTables() {
        if (_opLen1 != null) return;
        _opLen1 = new Dictionary<byte, int>();
        _opLen2 = new Dictionary<byte, int>();
        foreach (var f in typeof(System.Reflection.Emit.OpCodes).GetFields()) {
            if (!f.IsStatic || f.FieldType != typeof(System.Reflection.Emit.OpCode)) continue;
            var op = (System.Reflection.Emit.OpCode)f.GetValue(null);
            int sz;
            switch (op.OperandType) {
                case System.Reflection.Emit.OperandType.InlineNone: sz = 0; break;
                case System.Reflection.Emit.OperandType.ShortInlineBrTarget:
                case System.Reflection.Emit.OperandType.ShortInlineI:
                case System.Reflection.Emit.OperandType.ShortInlineVar: sz = 1; break;
                case System.Reflection.Emit.OperandType.InlineVar: sz = 2; break;
                case System.Reflection.Emit.OperandType.InlineI8: sz = 8; break;
                case System.Reflection.Emit.OperandType.InlineR:
                    // net48 name: ldc.r4 AND ldc.r8 share one operand type —
                    // the opcode decides the size (0x22 = ldc.r4).
                    sz = (ushort)op.Value == 0x22 ? 4 : 8; break;
                case System.Reflection.Emit.OperandType.InlineSwitch: sz = 0; break;   // handled specially
                default: sz = 4; break; // InlineMethod/Field/Tok/String/Sig/BrTarget/I/R4
            }
            ushort v = (ushort)op.Value;
            if (v < 0x100) _opLen1[(byte)v] = sz;
            else _opLen2[(byte)(v & 0xFF)] = sz;
        }
    }

    static int OpLen(byte b0, byte[] cil, int i, int n) {
        if (b0 == 0xFE) {
            if (i + 1 >= n) return n - i;
            int sz;
            if (!_opLen2.TryGetValue(cil[i + 1], out sz)) sz = 0;
            return 2 + sz;
        }
        if (b0 == 0x43) {   // switch: 1 + u32 count + count*4 targets
            if (i + 5 > n) return n - i;
            uint cnt = BitConverter.ToUInt32(cil, i + 1);
            long len = 5 + (long)cnt * 4;
            return (int)Math.Min(len, n - i);
        }
        int sz2;
        if (_opLen1.TryGetValue(b0, out sz2)) return 1 + sz2;
        return 1;   // unknown byte: treat as operandless, keep walking
    }

    // Walk the raw CIL with exact instruction boundaries and record every
    // local-variable instruction as offset -> index. Fixes three defects of
    // the old CountLocalsFromCil: (a) the 0xFE prefix advanced by 2 instead
    // of the true opcode length, re-scanning operand bytes as opcodes;
    // (b) the FE family was matched against wrong second bytes (0x06/0x09/
    // 0x0D are ldftn/ldarg/ldloca — ldloc/ldloca/stloc are 0x0C/0x0D/0x0E),
    // so long-form locals were never recorded; (c) the 2-byte operand read
    // lacked a bounds check and could throw on a trailing instruction.
    // Returns the offset->index map; localCount = max index + 1 (>= 1).
    static Dictionary<uint, int> ScanLocalIndices(byte[] cil, out int localCount) {
        var map = new Dictionary<uint, int>();
        EnsureOpTables();
        int maxIdx = -1;
        int i = 0, n = cil.Length;
        while (i < n) {
            byte b0 = cil[i];
            int idx = -1, len;
            if (b0 == 0xFE) {
                len = OpLen(b0, cil, i, n);
                if (i + 1 < n) {
                    byte b1 = cil[i + 1];
                    if ((b1 == 0x0C || b1 == 0x0D || b1 == 0x0E) && i + 4 <= n)
                        idx = cil[i + 2] | (cil[i + 3] << 8);   // ldloc/ldloca/stloc
                }
            } else if (b0 >= 0x06 && b0 <= 0x09) { idx = b0 - 0x06; len = 1; }  // ldloc.0-3
            else if (b0 >= 0x0A && b0 <= 0x0D) { idx = b0 - 0x0A; len = 1; }    // stloc.0-3
            else if (b0 == 0x11 || b0 == 0x12 || b0 == 0x13) {                  // ldloc.s/ldloca.s/stloc.s
                if (i + 2 <= n) { idx = cil[i + 1]; len = 2; } else len = n - i;
            } else {
                len = OpLen(b0, cil, i, n);
            }
            if (idx >= 0 && !map.ContainsKey((uint)i)) {
                map[(uint)i] = idx;
                if (idx > maxIdx) maxIdx = idx;
            }
            if (len < 1) len = 1;
            i += len;
        }
        localCount = maxIdx + 1;
        if (localCount < 1) localCount = 1;
        return map;
    }

    // Exclusive end offset -> first instruction starting AFTER the region.
    // null (= end of method) is dnlib's convention for a region that runs to
    // the end of the body.
    static Instruction RegionEnd(Dictionary<uint, Instruction> map, IList<Instruction> body, uint endOff) {
        Instruction ins;
        if (map.TryGetValue(endOff, out ins)) return ins;
        for (int k = 0; k < body.Count; k++)
            if ((uint)body[k].Offset > endOff) return body[k];
        return null;
    }

    static int Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: nbilmerge <in.exe> <dumpdir> <out.exe>"); return 1; }
        var mod = ModuleDefMD.Load(a[0]);

        var files = Directory.GetFiles(a[1], "m_*.bin");
        var bodies = new List<byte[]>();
        var toks = new List<uint>();
        foreach (var f in files) {
            var d = File.ReadAllBytes(f);
            uint tok = BitConverter.ToUInt32(d, 0);
            uint il = BitConverter.ToUInt32(d, 4);
            var body = new byte[il];
            Array.Copy(d, 20, body, 0, il);
            toks.Add(tok); bodies.Add(body);
        }
        Console.WriteLine("dump body: " + toks.Count);

        // EH clauses captured by the clrjit_hook getEHinfo slot (NB_EHSLOT):
        // m_XXXXXXXX.eh = [u32 count][count x 28B CORINFO_EH_CLAUSE]. Attached
        // back onto the merged body so try/catch/finally survives write-back.
        var ehMap = new Dictionary<string, uint[]>();
        foreach (var ef in Directory.GetFiles(a[1], "m_*.eh")) {
            var d = File.ReadAllBytes(ef);
            if (d.Length < 4) continue;
            uint cnt = BitConverter.ToUInt32(d, 0);
            if (cnt == 0 || d.Length < 4L + cnt * 28) continue;
            var flat = new uint[cnt * 7];
            for (int k = 0; k < cnt * 7; k++)
                flat[k] = BitConverter.ToUInt32(d, 4 + k * 4);
            ehMap[System.IO.Path.GetFileNameWithoutExtension(ef)] = flat;
        }
        Console.WriteLine("dump eh tables: " + ehMap.Count);

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
        // use in report mode (NB_SEQ=1).
        bool seqMode = Environment.GetEnvironmentVariable("NB_SEQ") == "1";
        // NB_ILMATCH=1: sentetik tokenli dumplari bodyless methodlarla
        // match by IL signature (ilSize + first byte) similarity. ilSize
        // if unique it is a valid match; on collision the first
        // candidate is taken and REPORTED (weakness of the proof is stated).
        bool ilMatch = Environment.GetEnvironmentVariable("NB_ILMATCH") == "1";
        int ilMatchUsed = 0;
        var bodyless = new List<MethodDef>();
        if (seqMode) {
            foreach (var t in mod.GetTypes())
                foreach (var m2 in t.Methods)
                    if (!m2.HasBody) bodyless.Add(m2);
            Console.WriteLine("seq target havuz (bodyless method): " + bodyless.Count);
        }
        // NB_STUBMAP: manual stub=dump mapping (the proven route).
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
            string baseName = System.IO.Path.GetFileName(files[i]);
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
                                    // match and the RESULT IS REPORTED:
                                    m = null;
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
            // delegate-declaring methods must stay runtime-implemented —
            // writing an IL body onto them is illegal and the JIT rejects
            // the whole type ("runtime implemented delegate method")
            if (m != null && m.DeclaringType?.BaseType?.FullName != null)
            {
                var bfn = m.DeclaringType.BaseType.FullName;
                if (bfn.Contains("System.Delegate") || bfn.Contains("System.MulticastDelegate"))
                { skipped++; continue; }
            }
            // generic types load-validate every member; a body written with
            // Object-only locals can fail that check — leave generics to the
            // reflection-equivalence pass until locals carry real types
            if (m != null && m.DeclaringType != null && m.DeclaringType.HasGenericParameters)
            { skipped++; continue; }
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
                    // LOCALS: no localVarSig in the dump — local operands stay
                    // unresolved (null, or a raw int index depending on the
                    // dnlib parse path). Bind from the raw-IL offset map so
                    // every ldloc/stloc/ldloca (.S and long forms included)
                    // lands on the RIGHT slot, not on the last variable.
                    var localOps = new List<dnlib.DotNet.Emit.Instruction>();
                    var indexedOps = new List<KeyValuePair<dnlib.DotNet.Emit.Instruction, int>>();
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
                        if (!isLocalOp) continue;
                        object operand = ins.Operand;
                        if (operand is dnlib.DotNet.Emit.Local) continue;   // already bound
                        if (operand is int)
                            indexedOps.Add(new KeyValuePair<dnlib.DotNet.Emit.Instruction, int>(ins, (int)operand));
                        else if (operand is uint)
                            indexedOps.Add(new KeyValuePair<dnlib.DotNet.Emit.Instruction, int>(ins, unchecked((int)(uint)operand)));
                        else if (operand == null)
                            localOps.Add(ins);
                    }
                    if (localOps.Count > 0 || indexedOps.Count > 0) {
                        string mwv = Environment.GetEnvironmentVariable("NB_MAXWRITE");
                    if (mwv != null && restored >= int.Parse(mwv)) { skipped++; continue; }
                    int nLocals;
                        var localMap = ScanLocalIndices(bodies[i], out nLocals);
                        while (newBody.Variables.Count < nLocals)
                            newBody.Variables.Add(new dnlib.DotNet.Emit.Local(mod.CorLibTypes.Object));
                        if (i < 3) Console.WriteLine("  [dbg] tok=0x" + toks[i].ToString("X8") +
                            " localOps=" + localOps.Count + " indexed=" + indexedOps.Count +
                            " nLocals=" + nLocals + " vars=" + newBody.Variables.Count);
                        // operands dnlib kept as a raw index — bind directly:
                        foreach (var kv in indexedOps) {
                            int idx2 = kv.Value;
                            while (newBody.Variables.Count <= idx2)
                                newBody.Variables.Add(new dnlib.DotNet.Emit.Local(mod.CorLibTypes.Object));
                            kv.Key.Operand = newBody.Variables[idx2];
                        }
                        // null operands: exact index from the raw-IL scan via
                        // the instruction offset; implied-index forms (ldloc.N)
                        // come from the opcode itself. An offset with no scan
                        // entry falls back to the last variable and is counted.
                        int fallback = 0;
                        foreach (var ins in localOps) {
                            int idx2;
                            var c = ins.OpCode.Code;
                            if (c >= dnlib.DotNet.Emit.Code.Ldloc_0 && c <= dnlib.DotNet.Emit.Code.Ldloc_3)
                                idx2 = (int)(c - dnlib.DotNet.Emit.Code.Ldloc_0);
                            else if (c >= dnlib.DotNet.Emit.Code.Stloc_0 && c <= dnlib.DotNet.Emit.Code.Stloc_3)
                                idx2 = (int)(c - dnlib.DotNet.Emit.Code.Stloc_0);
                            else if (!localMap.TryGetValue((uint)ins.Offset, out idx2)) {
                                idx2 = newBody.Variables.Count - 1;
                                fallback++;
                            }
                            if (idx2 >= 0) {
                                while (newBody.Variables.Count <= idx2)
                                    newBody.Variables.Add(new dnlib.DotNet.Emit.Local(mod.CorLibTypes.Object));
                                ins.Operand = newBody.Variables[idx2];
                            }
                        }
                        if (fallback > 0)
                            Console.WriteLine("  [warn] tok=0x" + toks[i].ToString("X8") +
                                " " + fallback + " local op(s) bound by fallback (offset miss)");
                        // post-assignment check (before Write):
                        int stillNull = 0;
                        foreach (var ins in localOps) if (ins.Operand == null) stillNull++;
                        if (i < 3) Console.WriteLine("  [post] tok=0x" + toks[i].ToString("X8") + " halaNull=" + stillNull);
                    }
                    // v6.1 EH REBUILD: reattach the exception clauses captured
                    // from the getEHinfo hook (NB_EHSLOT). Clause offsets are
                    // IL offsets; dnlib's writer serializes the fat header +
                    // EH section on write, so no manual MoreSects surgery here.
                    string stem = System.IO.Path.GetFileNameWithoutExtension(files[i]);
                    uint[] flatEh;
                    if (ehMap.TryGetValue(stem, out flatEh)) {
                        int ehAdded = 0, ehDropped = 0;
                        try {
                            var off2ins = new Dictionary<uint, Instruction>();
                            foreach (var ins in newBody.Instructions)
                                off2ins[(uint)ins.Offset] = ins;
                            int cnt2 = flatEh.Length / 7;
                            for (int c = 0; c < cnt2; c++) {
                                uint cflags = flatEh[c * 7 + 0], tryOff = flatEh[c * 7 + 1],
                                     tryLen = flatEh[c * 7 + 2], hOff = flatEh[c * 7 + 3],
                                     hLen = flatEh[c * 7 + 4], clsTok = flatEh[c * 7 + 5],
                                     filtOff = flatEh[c * 7 + 6];
                                Instruction tryStart, hStart;
                                if (!off2ins.TryGetValue(tryOff, out tryStart)) { ehDropped++; continue; }
                                if (!off2ins.TryGetValue(hOff, out hStart)) { ehDropped++; continue; }
                                // CORINFO_EH_CLAUSE_FLAGS: 0 catch, 1 filter,
                                // 2 finally, 3 fault (mask off meta bits).
                                var htype =
                                    (cflags & 3) == 1 ? ExceptionHandlerType.Filter :
                                    (cflags & 3) == 2 ? ExceptionHandlerType.Finally :
                                    (cflags & 3) == 3 ? ExceptionHandlerType.Fault :
                                    ExceptionHandlerType.Catch;
                                var eh = new ExceptionHandler(htype);
                                eh.TryStart = tryStart;
                                eh.TryEnd = RegionEnd(off2ins, newBody.Instructions, tryOff + tryLen);
                                eh.HandlerStart = hStart;
                                eh.HandlerEnd = RegionEnd(off2ins, newBody.Instructions, hOff + hLen);
                                if (htype == ExceptionHandlerType.Filter) {
                                    Instruction fStart;
                                    if (!off2ins.TryGetValue(filtOff, out fStart)) { ehDropped++; continue; }
                                    eh.FilterStart = fStart;
                                }
                                if (htype == ExceptionHandlerType.Catch && clsTok != 0) {
                                    try {
                                        var resolved = ((ITokenResolver)mod).ResolveToken(clsTok, new GenericParamContext());
                                        eh.CatchType = resolved as ITypeDefOrRef;
                                    } catch { }
                                    if (eh.CatchType == null) { ehDropped++; continue; }
                                }
                                newBody.ExceptionHandlers.Add(eh);
                                ehAdded++;
                            }
                        } catch (Exception e2) {
                            Console.WriteLine("  [eh] " + stem + ": " + e2.GetType().Name + " " + e2.Message);
                        }
                        if (ehAdded > 0 || ehDropped > 0)
                            Console.WriteLine("  [eh] " + stem + " added=" + ehAdded + " dropped=" + ehDropped);
                    }
                    // NecroBit marks decoys as runtime-implemented; a real
                    // body replaces the stub, so the flag must go — keeping
                    // it makes the JIT throw TypeLoadException
                    // ("Runtime-implemented method with non-zero RVA").
                    if ((m.ImplAttributes & MethodImplAttributes.Runtime) != 0)
                        m.ImplAttributes &= ~MethodImplAttributes.Runtime;
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