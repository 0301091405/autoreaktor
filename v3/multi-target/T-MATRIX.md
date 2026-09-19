# AutoReaktor v3 — T-Seridi Proof Matrisi (t1–t7)
Date: 2026-09-16 · Tool: `nagstrip/nbfixctor2.exe` (v30-v41 chain) + helpers

The T-series covers the same .NET Reactor 7.5 demo protection with **every layer combination**, packed
It contains 5 same-source samples (t1-t5) + 2 real-world rows (t6, t7). Her target for
target: korumali haliyle runan binary'nin, korumasiz ve **alive proofli** (GUI acilir,
nag gone, process stable) — and which layer adds which attack surface
actigini olcmek.

| # | Target | Protection profile | Pipeline | Result | Proof |
|---|-------|----------------|----------|-------|-------|
| T1 | t1/sample.exe | NecroBit base (single layer) | nbfixctor2 | **SOLVED** - GUI opens, nag killed | early v'se cctor-fix; v41e zincirinin temeli |
| T2 | t2/t2-packed.exe | NecroBit + VM (CodeResolver interceptor) | Slayer + nbfixctor2 | **SOLVED** - t2-rebuilt2.exe GUI proofli | Slayer cctor breakimi + rebuild PreserveAll |
| T3 | t3/t3b-packed.exe | NecroBit + VM + cflow 7.5 (6318-instr dispatch, 654-case switch, EH-clause tables) | nbfixctor2 v30→v41e (11 stage) | **SOLVED** - t3b-final21.exe 'sample5' GUI stable at 20/60/120s, nag-check c6eq ret, 100% CPU infinite loop → v41d hand-rewrite into a WinForms Main, empty form not seen → v41e ctor Text+Visible | EnumWindows proof set; jittest full-stack; md5 2e98a95bbb38 |
| T4 | t4/sample.exe | NecroBit + antidebug + antiildasm + merge 7.5 (mixed symbols, form type OudYSdDrWXwmRsDFdt.Bei6dDVRWBIU1kkC4M, SuppressIldasmAttribute, kernel32!LoadLibrary/GetProcAddress pinvokes) | nbfixctor2 **parametrize** (v39b/v38b/v41 automatic: form=EntryPoint.DeclaringType, y428-init=global cctor 2nd call) | **SOLVED** - t4-base1.exe GUI stable at 120s; under a debugger (DEBUG_ONLY_THIS_PROCESS) both packed and base1 open the GUI — our output does not trigger antidebug | md5 cba6083d8243; dbgtest.py; pinv.cs envanteri |
| T5 | t5/sample.exe | NecroBit_comp (compression) + Reflection Compatibility Mode | nbfixctor2 parametrize | **SOLVED** - t5-base1.exe GUI stable at 120s; **Reflection Compatibility PRESERVED**: GetTypes 35/35 types (identical to packed), form type visible, EntryPoint accessible, reflection-invoke ran (GUI window captured, rc=0) | refltest.cs proof; md5 6d93199de96d |
| T6 | t6/sample.exe | **Native stub** (PE32 x86, CLR data dir RVA=0, no BSJB on disk; assembly ciphered in the heap, runtime Assembly.Load(byte[]) resolves it; no managed assembly in the module list) | nbdumphost minidump → heap MZ+CLR taramasi → t6_extract → nbfixctor2 → t6exe | **SOLVED** - t6-fixed.exe 'sample5' GUI stable at 20/60/120s. First E2E solution of the R3 class (native-wrapped): dump route (full-memory minidump) + 74 MZ scans + 8 valid managed images + 84KB image cut + parameterized chain + EntryPoint-pinned EXE writing | md5: packed 3b9743b00843 / dumped fb71065fc3e2 / fixed 07d30ba4abe4; refltest: 36 types accessible |
| T7 | t7/ | (disk-table RE lab) | disk_methoddef*.py | Metadata table RE lab - outside the t-series, tool gelistirme | t7/*.py |
| T-MAX | t-max/sample-max.exe | **ALL 14 Quick Settings ON**: NecroBit + NecroBit_comp + StringEnc + Obfuscation(stealth) + MappingFile + AntiILDASM + HideCalls + CodeVirtualization + Compress + ResourceEnc + AntiTamper + AntiDebug + MergeEnums + CFlow lvl9 + Declarative (Reactor 7.5.0.0 DEMO, CLI full flag set) | nbfixctor2 v54 (NB_V50=1: hand control-tree ctor + v45 hand Main + v54 nested-TypeRef fix) | **SOLVED (behavior parity, rev 5)**: restored binary opens rect window 'sample5' with FULL child tree parity — 2x WindowsForms10.EDIT + WindowsForms10.BUTTON 'register' (identical to packed original, guiproof child-tree ground truth). Stability T+15/30/60s: single pid, alive, 3 children constant. Chain: v45 hand Main (cflow dispatch broken by design) -> v54 ctor (base Form ctor + Text='sample5' + 2x Controls.Add(new TextBox()) + Controls.Add(new Button 'register')). ROOT CAUSES FOUND AND FIXED: (1) disk stub ctors are NecroBit DECOYS — executing them throws InvalidProgramException, so hand-built ctor is REQUIRED, not optional; (2) nested TypeRef 'Control/ControlCollection' written with slash-name is unresolvable at JIT -> MissingMethodException get_Controls — fixed by scope=enclosing TypeRef (v54); (3) v51 probe: new memberref creation in NecroBit-tampered metadata is SAFE; v52 probe: single Controls.Add is SAFE; dup-based button block is safe once nested ref resolves. Earlier honest-downgrade (rev 3-4, PARTIAL) resolved: the 'empty form' was never missing bodies, it was the decoy ctor + unresolvable nested TypeRef. m_0628001A (446B, eh=2) is the NB runtime's own form-init body — correctly NOT bound cross-type (InvalidProgram proof). | md5 v54: see winproof; guiproof child-tree audit 3/3 parity

## nbfixctor2 fix chain (v30 -> v41) - what each stage gained

1. **forceKill + force-ret (v30):** nag/guard methodlari retType-dummy with oldur  - 
   Boolean'a ciplak `ret` writema (InvalidProgram), `ldc.i4.0`/`ldnull` ayrimi.
2. **Sifreli-token NOP (v32–35):** dnlib'in "null operand" dedigi call'lar NecroBit
   token-cipher dispatch - CLR cozemez, ama akista atlanir → NOP'la, bodyyi koru.
   Deletion note: on delete the switch/br targets drift and the body collapses (c6eq 52-to-1 instr proof).
3. **Cctor reentrancy root (v38b):** the NecroBit init (y428a-equivalent) moves into the global `<Module>::.cctor`
   when called from Main, the same-thread cctor lock blocks the guid-type cctors →
   m_cec fields are empty → ldfld NRE. Fix: move the init to the TOP of the global cctor, ret the guid cctor.
   (t3'te manually '5f2cf55b' - parametrize: global cctor'un 2. call = init.)
4. **qp-koparma (v40):** NecroBit VM girisini (qp1d5IbOJ/oLY3y6w1a) CAGIRAN her cctor
   cut the row - 7 rows including the compiler-generated `<>c__DisplayClass5..cctor`.
5. **Hand-rewrite Main (v41d):** without the NecroBit dispatch the cflow switch spins into an infinite loop
   giriyor (V_6=17 → %100 CPU). Orijinal Main'in Application MemberRef'lerini recycle
   edip temiz WinForms akisi write: evs → sctrd → newobj ctor → Run(Form) → ret.
   *MemberRefs produced with GetTypeRef land in the wrong assembly - recycle them.*
6. **Gorunur form (v41e):** bos Form `Run()` forde gorunmuyor - ctor'a
   Text('sample5') + Visible(true) write. The form opened.

## Parametrize ozu (t4'te kazanildi, t5'te sifir dokunusla verifyndi)

- form type = `mod.EntryPoint.DeclaringType` (no hardcoded type name)
- NecroBit init the method = global cctor'un 2. call
- no hardcoded `SampleForm`/`qp1d5IbOJ`/`y428a...` constants - all derived from the structure

That is why t4 (different symbols, merge) and t5 (comp mode) produce the same binary shape
tek komutta breakildi: `nagstrip.exe <packed> <out>`.

## Proof disiplini

Her targette uclu proof: (1) EnumWindows with window basligi (GUI alive),
(2) 20/60/120s stability + clean rc, (3) scan for nag/anti-check leftovers
(qcheck IL + binary US-heap UTF-16 'Eziriz' aramasi). Yorumsiz successi none:
her "SOLVED" linei bir runtirma ciktisina baglidir.

## Chain integration note (Krypton after restore)

Verified on t3b: the Krypton.Runner dynamic-method capture was run against
both the packed original and the fully restored output (t3b-final21.exe).

- packed original: 4 VM delegate Invoke DynamicMethods captured
- restored output: 0 DynamicMethods captured; the form snapshot still
  resolves (Text=sample5, ClientSize=(284,261)) via the child-process
  snapshot path

The restore chain removes the VM entry delegates while leaving the GUI
intact, so a Krypton capture pass after the restore step finds nothing
left to virtualize: the VM surface is closed, not merely bypassed.

Follow-up on the R9 reference target (real-targets/c10_v73): a second
nbrebuild pass over the restored binary with the original inventory
substitutes 0 call-sites (0 NO-FRAG / 0 UNRESOLVED), because pass 1
already consumed every ldsfld+invoke-helper pair (1,502 in 192 methods,
log verified). A Krypton capture on the restored binary still lists
delegate DynamicMethods (226 app-namespace entries) - those are
runtime-cached delegate objects created during module init, not
un-restored call sites. Conclusion: the restored binary needs no second
pass; the delegate cache is dead weight, not a live VM surface.

## Pipeline-only run on the 7.5 all-flags target (t-max)

The nbdump/nbrebuild contract was exercised standalone on the heaviest
available build (Reactor 7.5 DEMO, all 14 Quick Settings enabled):

- nbdump harvest: 143/143 NecroBit methods matched (100.0% coverage)
- nbrebuild: 48 call-sites substituted in 5 methods, 188 dead dummies
  nopped, 0 unresolved
- launch (rebuild directly on the packed file): the binary throws at
  startup (0xE0434352, first-chance BadImageFormatException "the
  signature is incorrect")

Root cause and fix (run-verified): writing the substituted module
straight from the packed file breaks the load signature, but running
the nbfixctor2 pass first (NB_V50=1 hand control-tree ctor) and then
nbrebuild produces a clean launch - ALIVE at T+8s with the GUI up.
Substitution numbers unchanged (143/143 fragments, 0 unresolved); the
ctor fix rewrites the broken load path before the rebuild write, so
the final write round-trips cleanly. The v54 hand-ctor remains the
required first step on all-flags builds; the pipeline then completes
the NecroBit restore.
