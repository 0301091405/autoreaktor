import os, sys
# Tokens DO exist in the module (rid 3 = ?.?::?, bodyless). So
# byToken is not a MISS — it should find it! Why does nbilmerge
# always skip 108? Re-read the code: TryGetValue(toks[i], out m) —
# toks[i] is the token IN THE FILE BODY, not the one in the
# filename! The file is named m_06000003.bin but its first 4 bytes
# are the token field: in the first dump round this was a synthetic
# counter, after the MethodDesc fix it is 0x06000003.
# nbilmerge reads toks[i] from the BODY field — correct.
# Wait: rid 3 = HasBody=False. nbilmerge flow:
#   TryGetValue OK -> m found -> CreateCilBody(...) ->
#   newBody null OR Instructions.Count==0 -> skipped++ !
# So not a miss: CreateCilBody returns empty. Reason: with
# m.HasBody=false, m.Parameters is OK but the resolver cast of 'mod'
# may fail (does ModuleDefMD implement IInstructionOperandResolver?).
# The cast must have passed or an exc line would print. The returned
# newBody has 0 instr — resolver ran but the IL disassembly came out
# empty? 0 instr for a 57-byte body is impossible. LIKELY: the
# CreateCilBody byte[] overload expects code+eh; eh=null may return
# empty without throwing.
# TEST: try CreateCilBody manually on a small sample:
code = r'''
using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
class Q5 {
    static void Main(string[] a) {
        var m = ModuleDefMD.Load(a[0]);
        var d = File.ReadAllBytes(a[1]);
        uint il = BitConverter.ToUInt32(d, 4);
        var body = new byte[il];
        Array.Copy(d, 20, body, 0, il);
        Console.WriteLine("il=" + il);
        foreach (var t in m.GetTypes())
            foreach (var mm in t.Methods)
                if ((uint)mm.MDToken.Raw == 0x06000003) {
                    try {
                        var nb = MethodBodyReader.CreateCilBody(
                            (IInstructionOperandResolver)m, body, null, mm.Parameters);
                        Console.WriteLine("rid3 body instr: " + (nb == null ? -1 : nb.Instructions.Count));
                        if (nb != null)
                            foreach (var i2 in nb.Instructions)
                                Console.WriteLine("   " + i2.OpCode.Name + " " + (i2.Operand ?? ""));
                    } catch (Exception e) {
                        Console.WriteLine("EXC: " + e.GetType().Name + " " + e.Message);
                    }
                    return;
                }
    }
}'''
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'q5.cs'), 'w').write(code)
import subprocess
JIT = os.path.dirname(os.path.abspath(__file__))
subprocess.run([r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe', '/nologo',
                '/r:dnlib.dll', '/out:q5.exe', 'q5.cs'], cwd=JIT, capture_output=True)
r = subprocess.run([JIT + r'\q5.exe',
                    sys.argv[1],
                    sys.argv[2]],
                   capture_output=True, cwd=JIT)
print((r.stdout or b'').decode('mbcs', 'replace'))
print((r.stderr or b'').decode('mbcs', 'replace')[-300:])