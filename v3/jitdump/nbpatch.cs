// nbpatch.cs — raw byte patch route: dnlib Write breaks the AT's
// runtime CRC (nb2-rt NRE proof). This route never touches the PE:
// it writes the JIT-dump bodies directly as bytes into the MethodDef
// RVAs. The method body RVA is resolved via dnlib, the body is
// written to file as tiny/fat header + IL. The CRC coverage change
// uses the same mechanism as nb2's own change.
// Usage: nbpatch.exe <in.exe> <dumpdir> <out.exe>
using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class NbPatch {
    static int Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: nbpatch <in.exe> <dumpdir> <out.exe>"); return 1; }
        byte[] pe = File.ReadAllBytes(a[0]);
        var mod = ModuleDefMD.Load(a[0]);

        var byToken = new Dictionary<uint, MethodDef>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                byToken[(uint)m.MDToken.Raw] = m;

        int patched = 0, skipped = 0;
        foreach (var f in Directory.GetFiles(a[1], "m_*.bin")) {
            var d = File.ReadAllBytes(f);
            uint tok = BitConverter.ToUInt32(d, 0);
            uint il = BitConverter.ToUInt32(d, 4);
            MethodDef m;
            if (!byToken.TryGetValue(tok, out m) || m == null) { skipped++; continue; }
            if (!m.HasBody) { skipped++; continue; } // the RVA is not the stub anyway — NecroBit also changes stub RVAs
            var rva = (uint)m.RVA;
            if (rva == 0) { skipped++; continue; }

            // convert to file offset: from PE sections
            long off = RvaToOffset(pe, rva);
            if (off < 0) { skipped++; continue; }

            // decode old body size (tiny/fat)
            uint oldSize = OldBodySize(pe, off);
            if (oldSize == 0) { skipped++; continue; }

            // new body: header + IL
            byte[] body = new byte[il];
            Array.Copy(d, 20, body, 0, il);
            byte[] all;
            if (il < 64) {
                all = new byte[1 + il];
                all[0] = (byte)((il << 2) | 2);
                Array.Copy(body, 0, all, 1, il);
            } else {
                var ms = new MemoryStream();
                ushort flags = 0x3013;
                ms.Write(BitConverter.GetBytes(flags), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)8), 0, 2);
                ms.Write(BitConverter.GetBytes(il), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(body, 0, body.Length);
                all = ms.ToArray();
                if (all.Length % 4 != 0) { // fat body is 4-byte aligned
                    var pad = new byte[all.Length + (4 - all.Length % 4)];
                    Array.Copy(all, pad, all.Length);
                    all = pad;
                }
            }

            if (all.Length > oldSize) {
                // new body larger than old space — cannot write (would
                // overflow into the next method's area). Skip + report.
                skipped++;
                Console.WriteLine("  [too-large] 0x" + tok.ToString("X8") + " new=" + all.Length + " old=" + oldSize);
                continue;
            }

            Array.Copy(all, 0, pe, off, all.Length);
            // zero the remaining bytes (old body residue is harmless
            // ama temiz olsun):
            for (long z = off + all.Length; z < off + oldSize; z++) pe[z] = 0;
            patched++;
        }
        Console.WriteLine("HAM-PATCH method: " + patched + " | atlanan: " + skipped);
        File.WriteAllBytes(a[2], pe);
        Console.WriteLine("[ok] written: " + a[2]);
        return 0;
    }

    static long RvaToOffset(byte[] pe, uint rva) {
        uint peOff = BitConverter.ToUInt32(pe, 0x3C);
        ushort nsec = BitConverter.ToUInt16(pe, (int)peOff + 6);
        int optSize = BitConverter.ToUInt16(pe, (int)peOff + 20);
        int secTab = (int)peOff + 24 + optSize;
        for (int i = 0; i < nsec; i++) {
            int s = secTab + i * 40;
            uint vaddr = BitConverter.ToUInt32(pe, s + 12);
            uint vsize = BitConverter.ToUInt32(pe, s + 8);
            uint raw = BitConverter.ToUInt32(pe, s + 20);
            if (rva >= vaddr && rva < vaddr + vsize)
                return (long)rva - vaddr + raw;
        }
        return -1;
    }

    static uint OldBodySize(byte[] pe, long off) {
        byte b0 = pe[off];
        if ((b0 & 3) == 2) return (uint)((b0 >> 2) + 1); // tiny: boyut + header bayti
        if ((b0 & 3) == 3) { // fat
            ushort w0 = BitConverter.ToUInt16(pe, (int)off);
            uint hdrDwords = (uint)(w0 >> 12);
            uint codeSize = BitConverter.ToUInt32(pe, (int)off + 4);
            uint total = hdrDwords * 4 + codeSize;
            return total;
        }
        return 0;
    }
}