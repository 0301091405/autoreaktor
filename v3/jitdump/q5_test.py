# Tokenlar modulde VAR (rid 3 = ?.?::?, govdesiz). Yani byToken
# MISS DEGIL — bulmasi gerek! nbilmerge'de neden 108 hep skip?
# Kod tekrar bak: TryGetValue(toks[i], out m) — toks[i] dump
# dosyasinin ADINDAKI token degil ICINDEKI token! Dosya adi
# m_06000003.bin ama ICINDEKI ilk 4 bayt token alani: ilk dump
# turunda sentetik sayiydi, MethodDesc fix sonrasi 0x06000003.
# Ama nbilmerge toks[i]'yi ICINDEKI alandan okuyor — dogru.
# Bekle: rid 3 = HasBody=False. nbilmerge akisi:
#   TryGetValue OK -> m bulundu -> CreateCilBody(...) ->
#   newBody null VEYA Instructions.Count==0 -> skipped++ !
# Yani miss degil, CreateCilBody BOS donuyor. Sebep: m.HasBody=
# false iken m.Parameters OK ama resolver olarak 'mod' cast'i
# calismiyor olabilir (ModuleDefMD IInstructionOperandResolver
# implement eder mi?). Cast istisnasiz gecmis olmali yoksa exc
# yazilirdi. newBody donusunde 0 instr — resolver calisti ama
# IL cozumlemesi bos kaldi? 57 baytlik govde icin 0 instr
# olmaz. MUHTEMEL: CreateCilBody byte[] overload'i code+eh
// bekluyor; eh=null patlamadan bos donebilir.
# TEST: kucuk bir ornek ile CreateCilBody'yi manuel dene:
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
                        Console.WriteLine("rid3 govde instr: " + (nb == null ? -1 : nb.Instructions.Count));
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
open(r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\jitdump\q5.cs', 'w').write(code)
import subprocess
JIT = r'C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\jitdump'
subprocess.run([r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe', '/nologo',
                '/r:dnlib.dll', '/out:q5.exe', 'q5.cs'], cwd=JIT, capture_output=True)
r = subprocess.run([JIT + r'\q5.exe',
                    r"C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\NET Reactor Unpack Me.exe",
                    r"C:\Users\alt\Desktop\decodehub-week1\tools\autoreaktor\v3\multi-target\real-targets\t4y\jitdump\m_06000003.bin"],
                   capture_output=True, cwd=JIT)
print((r.stdout or b'').decode('mbcs', 'replace'))
print((r.stderr or b'').decode('mbcs', 'replace')[-300:])