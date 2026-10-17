// tokmap_builder — full original->slayer token translation map.
//
// The hybrid route transplants NecroBit-DECODED bodies into the Slayer
// output. Decoded IL carries ORIGINAL-module token operands; Slayer shifts
// rids (inlines/removes methods) and renames symbols, so every token operand
// in a transplanted body must be rewritten or the JIT rejects the method.
//
// Matching strategies, in dependency order:
//   1. methods    - name+signature, then UNIQUE body fingerprint (opcode
//                   stream, rename-invariant), then the entry-point anchor
//   2. types      - name match, plus declaring types of every matched method
//   3. typerefs   - (namespace,name) with the rename map applied
//   4. fields     - (mapped declaring type, name, signature)
//   5. memberrefs - (mapped class, name, signature)
//   6. typespec / standalonesig / methodspec - normalized signature text,
//                   collected from the instruction graph (ModuleDefMD 3.3.4
//                   has no per-table getters for these)
//
// Output lines: "<origTokenHex> <slayerTokenHex>" (the table id is part of
// the token, so one flat file serves every table). nbilmerge consumes it via
// NB_TOKENMAP and rewrites token operands while rebuilding bodies.
//
// Usage: tokmap_builder <orig.exe> <slayer.exe> <out.map> [--report]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 3)
        { Console.WriteLine("usage: tokmap_builder <orig> <slayer> <out.map> [--report]"); return 1; }
        var orig = ModuleDefMD.Load(args[0]);
        var slay = ModuleDefMD.Load(args[1]);
        bool report = args.Length > 3 && args[3] == "--report";

        var map = new Dictionary<uint, uint>();          // orig -> slayer
        var renames = new Dictionary<string, string>();  // orig full name -> slayer full name

        // ---- 1. methods -------------------------------------------------
        var slayMethods = new Dictionary<string, List<MethodDef>>();
        foreach (var t in slay.GetTypes())
            foreach (var m in t.Methods)
            {
                var k = m.Name.String + "#" + m.MethodSig.ToString();
                if (!slayMethods.TryGetValue(k, out var l)) slayMethods[k] = l = new List<MethodDef>();
                l.Add(m);
            }
        var bodyHash = new Dictionary<string, List<MethodDef>>();
        foreach (var t in slay.GetTypes())
            foreach (var m in t.Methods)
            {
                var h = BodyKey(m);
                if (h == null) continue;
                if (!bodyHash.TryGetValue(h, out var l)) bodyHash[h] = l = new List<MethodDef>();
                l.Add(m);
            }
        int byName = 0, byBody = 0;
        foreach (var t in orig.GetTypes())
            foreach (var m in t.Methods)
            {
                uint ot = (uint)m.MDToken.Raw;
                MethodDef hit = null;
                var k = m.Name.String + "#" + m.MethodSig.ToString();
                if (slayMethods.TryGetValue(k, out var l) && l.Count == 1) { hit = l[0]; byName++; }
                if (hit == null && m.HasBody)
                {
                    var h = BodyKey(m);
                    if (h != null && bodyHash.TryGetValue(h, out var bl) && bl.Count == 1)
                    { hit = bl[0]; byBody++; }
                }
                if (hit == null) continue;
                uint st = (uint)hit.MDToken.Raw;
                if (map.TryGetValue(ot, out var prev) && prev != st) continue;  // conflict -> keep first
                map[ot] = st;
                // declaring types ride with their methods: catch-type tokens
                // and member resolution need the type mapped even when the
                // slayer rename broke the name match
                uint ott = (uint)t.MDToken.Raw, stt = (uint)hit.DeclaringType.MDToken.Raw;
                if (!map.ContainsKey(ott)) map[ott] = stt;
                if (t.FullName != hit.DeclaringType.FullName)
                    renames[t.FullName] = hit.DeclaringType.FullName;
            }
        // entry anchor
        if (orig.EntryPoint != null && slay.EntryPoint != null)
        {
            map[(uint)orig.EntryPoint.MDToken.Raw] = (uint)slay.EntryPoint.MDToken.Raw;
            if (orig.EntryPoint.DeclaringType.FullName != slay.EntryPoint.DeclaringType.FullName)
                renames[orig.EntryPoint.DeclaringType.FullName] = slay.EntryPoint.DeclaringType.FullName;
        }

        // ---- 1b. order-preserving alignment fill -------------------------
        // Slayer preserves the original's method table ORDER (verified
        // monotonic on the 7.5.0.0 pair) while removing inlined methods.
        // Between consecutive anchors, align the survivor subsequence by
        // normalized signature - this maps methods whose names were
        // renamed AND whose bodies slayer changed (decoys vs real).
        var origM = new List<MethodDef>();
        foreach (var t in orig.GetTypes())
            foreach (var m in t.Methods) origM.Add(m);
        origM.Sort((a, b) => a.MDToken.Rid.CompareTo(b.MDToken.Rid));
        var slayM = new List<MethodDef>();
        foreach (var t in slay.GetTypes())
            foreach (var m in t.Methods) slayM.Add(m);
        slayM.Sort((a, b) => a.MDToken.Rid.CompareTo(b.MDToken.Rid));

        var anchors = map.Where(kv => (kv.Key >> 24) == 0x06 && (kv.Value >> 24) == 0x06)
                         .Select(kv => (o: (int)(kv.Key & 0xFFFFFF), s: (int)(kv.Value & 0xFFFFFF)))
                         .OrderBy(a => a.o).ToList();
        int aligned = 0;
        for (int ai = 0; ai + 1 < anchors.Count; ai++)
        {
            int oL = anchors[ai].o, oR = anchors[ai + 1].o;
            int sL = anchors[ai].s, sR = anchors[ai + 1].s;
            // orig segment candidates (between the anchored rids)
            var segO = origM.Where(m => m.MDToken.Rid > oL && m.MDToken.Rid < oR).ToList();
            var segS = slayM.Where(m => m.MDToken.Rid > sL && m.MDToken.Rid < sR).ToList();
            if (segO.Count == 0 || segS.Count == 0) continue;
            // match by normalized signature; unique candidates only
            var used = new HashSet<MethodDef>();
            foreach (var om in segO)
            {
                if (map.ContainsKey((uint)om.MDToken.Raw)) continue;
                string k = om.MethodSig.ToString() + "|" + om.IsStatic;
                var cands = segS.Where(sm => !used.Contains(sm) &&
                    sm.MethodSig.ToString() + "|" + sm.IsStatic == k).ToList();
                if (cands.Count == 1)
                {
                    map[(uint)om.MDToken.Raw] = (uint)cands[0].MDToken.Raw;
                    used.Add(cands[0]);
                    if (om.DeclaringType.FullName != cands[0].DeclaringType.FullName)
                        renames[om.DeclaringType.FullName] = cands[0].DeclaringType.FullName;
                    aligned++;
                }
            }
        }

        // ---- 2. typedefs (after alignment: matched methods bring their
        // declaring types in, so renamed types still map) -----------------
        var slayTypes = new Dictionary<string, TypeDef>();
        foreach (var t in slay.GetTypes()) slayTypes[t.FullName] = t;
        int typeDefs = 0;
        foreach (var t in orig.GetTypes())
        {
            if (slayTypes.TryGetValue(t.FullName, out var hit) && !map.ContainsKey((uint)t.MDToken.Raw))
            { map[(uint)t.MDToken.Raw] = (uint)hit.MDToken.Raw; typeDefs++; }
        }
        foreach (var kv in map.ToList())
        {
            if ((kv.Key >> 24) != 0x06) continue;
            var om = orig.ResolveToken(kv.Key) as MethodDef;
            var sm = slay.ResolveToken(kv.Value) as MethodDef;
            if (om?.DeclaringType == null || sm?.DeclaringType == null) continue;
            if (!map.ContainsKey((uint)om.DeclaringType.MDToken.Raw))
                map[(uint)om.DeclaringType.MDToken.Raw] = (uint)sm.DeclaringType.MDToken.Raw;
        }

        // ---- normalizer: renames longest-first --------------------------
        var renamesSorted = renames.OrderByDescending(kv => kv.Key.Length).ToList();
        string Norm(string fullName)
        {
            if (fullName == null) return null;
            foreach (var kv in renamesSorted)
                if (fullName == kv.Key) return kv.Value;
            foreach (var kv in renamesSorted)
                if (fullName.StartsWith(kv.Key + "/"))
                    return kv.Value + fullName.Substring(kv.Key.Length);
            return fullName;
        }

        // ---- 3. typerefs ------------------------------------------------
        var slayRefs = new Dictionary<string, uint>();
        foreach (var r in slay.GetTypeRefs())
            slayRefs[Norm(r.Namespace) + "." + r.Name] = (uint)r.MDToken.Raw;
        int typeRefs = 0;
        foreach (var r in orig.GetTypeRefs())
        {
            if (slayRefs.TryGetValue(Norm(r.Namespace) + "." + r.Name, out var st))
            { map[(uint)r.MDToken.Raw] = st; typeRefs++; }
        }

        // ---- 4. fields --------------------------------------------------
        var slayFields = new Dictionary<string, uint>();
        foreach (var t in slay.GetTypes())
        {
            string tn = Norm(t.FullName);
            foreach (var f in t.Fields)
                slayFields[tn + "::" + f.Name + "#" + f.FieldSig.ToString()] = (uint)f.MDToken.Raw;
        }
        int fields = 0;
        foreach (var t in orig.GetTypes())
        {
            string tn = Norm(t.FullName);
            foreach (var f in t.Fields)
            {
                if (slayFields.TryGetValue(tn + "::" + f.Name + "#" + f.FieldSig.ToString(), out var st))
                { map[(uint)f.MDToken.Raw] = st; fields++; }
            }
        }

        // ---- 5. memberrefs ----------------------------------------------
        var slayMrefs = new Dictionary<string, uint>();
        foreach (var mr in slay.GetMemberRefs())
            slayMrefs[ClassKey(mr.Class, Norm) + "::" + mr.Name + "#" + mr.Signature.ToString()] =
                (uint)mr.MDToken.Raw;
        int mrefs = 0;
        foreach (var mr in orig.GetMemberRefs())
        {
            if (slayMrefs.TryGetValue(ClassKey(mr.Class, Norm) + "::" + mr.Name + "#" + mr.Signature.ToString(),
                                      out var st))
            { map[(uint)mr.MDToken.Raw] = st; mrefs++; }
        }

        // ---- 6-8. typespecs / standalonesigs / methodspecs ---------------
        // (no table getters on ModuleDefMD 3.3.4 - collect from the
        // instruction graph + LocalVarSigTok, resolving through the module)
        var slaySpecs = new Dictionary<string, uint>();
        var slaySas = new Dictionary<string, uint>();
        var slayMspecs = new Dictionary<string, uint>();
        Collect(slay, Norm, slaySpecs, slaySas, slayMspecs);
        int specs = 0, sasN = 0, mspecs = 0;
        var origSpecs = new Dictionary<string, uint>();
        var origSas = new Dictionary<string, uint>();
        var origMspecs = new Dictionary<string, uint>();
        Collect(orig, Norm, origSpecs, origSas, origMspecs);
        foreach (var kv in origSpecs)
            if (slaySpecs.TryGetValue(kv.Key, out var st)) { map[kv.Value] = st; specs++; }
        foreach (var kv in origSas)
            if (slaySas.TryGetValue(kv.Key, out var st)) { map[kv.Value] = st; sasN++; }
        foreach (var kv in origMspecs)
            if (slayMspecs.TryGetValue(kv.Key, out var st)) { map[kv.Value] = st; mspecs++; }

        var lines = map.OrderBy(kv => kv.Key).Select(kv =>
            kv.Key.ToString("X8") + " " + kv.Value.ToString("X8"));
        System.IO.File.WriteAllLines(args[2], lines);

        if (report)
            Console.WriteLine("methods(byName=" + byName + ",byBody=" + byBody + ") typedefs=" + typeDefs +
                              " typerefs=" + typeRefs + " fields=" + fields + " memberrefs=" + mrefs +
                              " typespecs=" + specs + " standalonesig=" + sasN + " methodspecs=" + mspecs +
                              " renames=" + renames.Count);
        Console.WriteLine("[tokmap] " + map.Count + " tokens -> " + args[2]);
        return 0;
    }

    static void Collect(ModuleDefMD mod, Func<string, string> norm,
        Dictionary<string, uint> specs, Dictionary<string, uint> sas,
        Dictionary<string, uint> mspecs)
    {
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                try
                {
                    if (m.Body.LocalVarSigTok != 0)
                    {
                        var r = mod.ResolveToken(m.Body.LocalVarSigTok) as StandAloneSig;
                        if (r != null) sas[norm(r.Signature.ToString())] = (uint)r.MDToken.Raw;
                    }
                }
                catch { }
                foreach (var ins in m.Body.Instructions)
                {
                    try
                    {
                        if (ins.Operand is MethodSpec ms)
                            mspecs[norm(ms.Method.ToString()) + "!!" +
                                   norm(ms.Instantiation.ToString())] = (uint)ms.MDToken.Raw;
                        else if (ins.Operand is TypeSpec ts)
                            specs[norm(ts.TypeSig.ToString())] = (uint)ts.MDToken.Raw;
                    }
                    catch { }
                }
            }
    }

    static string ClassKey(IMemberRefParent parent, Func<string, string> norm)
    {
        switch (parent)
        {
            case ITypeDefOrRef tdor: return norm(tdor.FullName);
            default:
                // TypeSpec rides last: ITypeDefOrRef already matched the
                // TypeSpec-derived cases above
                try { return "spec:" + norm(((TypeSpec)parent).TypeSig.ToString()); }
                catch { return "other:" + parent.ToString(); }
        }
    }

    // Rename-invariant body fingerprint: opcode stream + size + EH count.
    // Slayer renames symbols without touching the opcode stream, so renamed
    // methods still match; identical tiny decoys are disambiguated by the
    // unique-candidate rule at the call site.
    static string BodyKey(MethodDef m)
    {
        try
        {
            if (!m.HasBody) return null;
            ulong h = 1469598103934665603UL;
            var ins = m.Body.Instructions;
            foreach (var i in ins) { h ^= (ulong)i.OpCode.Code; h *= 1099511628211UL; }
            return h.ToString("X16") + ":" + ins.Count + ":" + m.Body.ExceptionHandlers.Count;
        }
        catch { return null; }
    }
}
