# AutoReaktor

Batch .NET Reactor unpacking pipeline: entropy hunter → de4dot → NETReactorSlayer → Krypton (VM devirtualization), with per-file SHA-256 provenance, deterministic reruns, and a functional proof harness.

## Why

de4dot stops at "Unknown Obfuscator" on modern Reactor builds and its rc=0 does NOT mean unpacked. NETReactorSlayer (6.4, Dec 2022) fixes antitamper/cflow/proxies but cannot initialize its decrypter on 7.x and skips Code Virtualization entirely. Krypton devirtualizes the VM but its NecroBit runtime-dump needs a correctly-bitted runner. Nobody chains them, verifies the result, or reports honestly what each stage achieved. AutoReaktor is that chain.

## The discovery: feed Slayer's output to Krypton, not the original

Chaining in the naive order (de4dot → Krypton) breaks Krypton's resource parser. The working order, verified end-to-end on a real-world target, is:

    original → NETReactorSlayer → Slayed.exe → Krypton

On the Tuts4You ".NET Reactor v7.3" challenge this recovers **3/3 virtualized methods fully** — including the 2,852-instruction one — where Krypton alone stalls with "5 VM instructions are still unknown". (The 0x75→Call pin that the old revision exported automatically is now REMOVED from the pipeline: VM opcode bytes are randomized per protected build, so a pipeline-level pin is target-specific tuning that silently breaks other builds. If a build genuinely stalls on a tie, export KRYPTON_FORCE_VM_MAP yourself for that one target.)

## Stage 4 (new): universal NecroBit body recovery — the JIT dump route

Static strippers die on modern NecroBit because the CIL bodies never exist decrypted on disk. The route that does not care: hook `ICorJitCompiler::compileMethod` in clrjit.dll inside the target process and snapshot `CORINFO_METHOD_INFO::ILCode` at the moment NecroBit has just decrypted it for the JIT.

    v3/jitdump/clrjit_hook.cpp   x86 + x64 VMT hook DLL (early APC injection, deferred install thread)
    v3/jitdump/nbjit_launch.c    suspended CreateProcess + QueueUserAPC(LoadLibraryA) launcher (built per-target bitness)
    v3/jitdump/nbjitdump.py      orchestrator: detects target machine type, builds matching launcher, runs, reports
    v3/jitdump/nbilmerge.cs      write-back stage: loads dumped bodies, null-operand write-rescue, dnlib rewrite

Proof (real-world targets, not samples):

| Target | hook | bodies captured | total CIL |
|---|---|---|---|
| Tuts4You ".NET Reactor v7.5.9.1" (Apr 2026, NecroBit + custom anti-tamper) | HOOK-OK | 199 | 5,439 bytes |
| Tuts4You ".NET Reactor v7.3" (embedded DLLs + CV) | HOOK-OK | 66 | 1,925 bytes |
| Tuts4You t1 sample (AnyCPU → x64 process) | HOOK-OK | 84 | 19,308 bytes |

Two hard findings from the write-back work, kept honest:

1. **Body write-back into the PE is architecturally blocked on NecroBit RVA=0 methods.** On the 7.5.9.1 target the protected methods carry RVA=0 — the body exists only in JIT-decrypted memory, never on disk. Byte-patching can't work when there is no body on disk to patch, and any dnlib writer round-trip trips the runtime anti-tamper CRC: we verified a **zero-change** rewrite of the original still throws "tampered" (NB_MAXWRITE=0, bodies written: 0), so no merge output can ever run on this target family. Two further write-back routes were tried and measured, both fail for the same root cause: killing the tamper throw kills the initializer (the check and init live in ONE 2,420-instruction static-void method with a 28-way switch — 53 `.cctor` callers), and NOP-ing the 53 call sites corrupts the cctor stack (InvalidProgramException). The deliverable for NecroBit targets is therefore: **original exe (runs — it is the only build that passes its own check) + JIT-dumped bodies (199 CIL bodies on the 7.5.9.1 target) + an analysis PE** (`nbilmerge` writes the dumped bodies into a decompilable module — 1,334 methods with bodies, loads back clean in dnlib for ILSpy/dnSpy inspection). Not a single rewritten PE.

2. **Where a body DOES exist in the PE, the merge works end-to-end.** nbilmerge v6 resolved dnlib's `MethodBodyReader` contract (needs a tiny/fat method-body header — fat flags `0x3013`, not `0x3011`), back-filled locals from raw CIL (short/long ldloc-stloc forms), and wrote 41/41 in-range-token bodies into a module dnlib re-loads with all bodies structurally valid (1,334 methods with bodies on the analysis build). The 158 remaining dumps carry MethodDesc chunk-artifact tokens (offset read is chunk-relative in coreclr, not a flat +0x0C); on x86 the flat read happens to resolve 41 correctly, on x64 it doesn't. The `getMethodDefFromMethod` vtable slot was tested at index 105 (the CoreCLR 2.1 count from ManagedJit) and failed both ways: on x64 it crashes the target (0xC0000005, 0 bodies dumped), on x86 the call yields nothing usable (0 bodies). It stays opt-in (`NB_TOKENMODE=vt`), OFF by default; x64 dumps stay sequence-keyed, with `NB_ILMATCH=1` offering a heuristic (explicitly labeled, unproven) merge. `NB_SEQ=1` remains experimental — a sequence-matched t1 restore threw FieldAccessException, proving sequence ≠ metadata order.

3. **A correction to the earlier "nb2 runs" claim.** Previous notes stated the AT-killed nb2 build "runs". Re-testing under a stricter harness showed that measurement was wrong: `start /wait` returning 0 masked the process dying immediately. Direct `timeout` runs prove every rewritten build (old nb2, freshly generated nb2, nb2 roundtrip) throws at startup — `tampered` or NRE — while the **untouched original is the only build that stays alive** (rc=124 at 10s, GUI up). The v44 surgical kill therefore does NOT produce a runnable output on this target; its value is that it exposed the check+init interlock (one method does both), which is what makes the original-plus-dump deliverable the honest answer.

Target classification now happens before injection: unmanaged exes are rejected (exit 3), AnyCPU is routed to the x64 DLL/launcher (the t1 0-body failure was a 32-bit DLL in a 64-bit process), and ReadyToRun builds are flagged as clrjit-invisible.

## Pipeline

```
python hunt.py <dir>                    # classify: clean / carrier / runtime / protected / native
python autoreaktor.py <dir|file> --deep # full chain, per-file report.json
```

| Stage | What it does | Verified behavior |
|---|---|---|
| 0 hunt | entropy + marker + bitness-aware .NET detection | 10/10 ground-truth regression; 0 false positives on a 1,449-file desktop scan (PE32+ native packers correctly rejected) |
| 1 de4dot | partial pre-clean (relative-path invocation) | output treated as PARTIAL only — rc=0 ≠ unpacked |
| 2 Slayer | antitamper/cflow/proxy/inline on the ORIGINAL | 1,438 proxied calls fixed on the Tuts4You 7.3 target; **Slayed binary launches and shows the challenge GUI** (verified by UI automation: form "reactor73", 2 textboxes, register button) |
| 3 Krypton | VM devirtualization on the SLAYED output | 3/3 VM methods recompiled; register-check call flow fully mapped (see below) |

Requirements: `de4dot*.exe`, `NETReactorSlayer.CLI.exe`, `tools/krypton/` (built once via its `build-all.ps1`) under `./tools/`. **Krypton.Runner must be built with `<Prefer32Bit>true</Prefer32Bit>`** for 32-bit-required targets - without it the NecroBit stage dies with BadImageFormatException (verified: 12 errors → 0 after the fix).

## Real-world verification - Tuts4You ".NET Reactor v7.3" unpackme

Target: community challenge (whoknows, June 2025), .NET Framework 4.x, 32-bit-required, Code Virtualization enabled, embedded DI assemblies. 2,836 views / 83 downloads / no posted solution at time of writing.

**Register-check flow, fully recovered (this is the challenge's protection logic):**

```
register click
  → GetRequiredService(IServiceProvider)
  → textBox1.Text.Trim(), textBox2.Text.Trim()        (name, key)
  → ConvertiblePolicy.DefineAdjustableDefinition(name, key)
      [virtualized - 47 instructions, recompiled to CIL]
  → PolicyFinalizer::IncludeSpec → EnforcePassiveMap   (VM interpreter, 2,462-byte IL)
  → result string → MessageBox::Show
```

Run matrix (all numbers from actual runs):

1. **Determinism** - Slayed sha256 `177d1d73…` identical across 5+ runs; Krypton reports identical per-method results (3/3 recompiled) on repeat runs.
2. **VM devirtualization proven at IL level** - `DefineAdjustableDefinition`:
   - protected original: 62-byte IL body, zero `ldstr` opcodes - a pure VM stub
   - Slayer+Krypton output: full 47-instruction CIL body, recompiled and replaced
3. **Functional proof** - the Slayed binary runs the original GUI (the devirtualized-by-Krypton-alone build previously died at startup with NullReferenceException; the Slayer-first chain fixes that because the working VM stays intact for methods the recompiler skips).
4. **Hunter classifies the target `protected`** before any tool runs - the Reactor 7.3 build carries no readable marker, so a plain string scan would have missed it (entropy window 6.0+ catches it).

## Honest limits (measured on the same target)

- **NecroBit bodies**: Krypton's runtime dump produces 0 rows on this target - the Reactor 7.3 NecroBit layout doesn't expose its body table as the Runner expects. Methods whose bodies live only in NecroBit (e.g. `FilteredPolicy.RunPolicy`'s dependency chain) keep their protection-runtime-dependent stubs; the report says `krypton-devirt`, never `success`.
- **PE write-back**: Krypton recompiles the 2,852-instruction method successfully but its IL safety gate rejects writing it (4,241 CIL issues from merged-ValueTaskAwaiter stack imbalances - a dnlib writer limitation, not a mapping failure). The recompiled body is fully readable in the `-Devirtualized-report.txt`; it just isn't patched into a new binary.
- **VM string table**: extracted the 10,580-byte `AnnotationPool.SeparatedAnnotation` resource and fully reversed its container format (58 operand defs, encrypted-LEB128 framing) - the embedded strings are themselves encrypted by a runtime decryptor, so they stay opaque without executing it.
- **Registration strings**: same consequence - the strings behind the register flow are in that last encrypted layer.

## Reproduce the whole matrix yourself

```
# 1. build Krypton (once)
cd tools/krypton && powershell -ExecutionPolicy Bypass -File build-all.ps1 -Configuration Release
#    + add <Prefer32Bit>true</Prefer32Bit> to Krypton.Runner/Krypton.Runner.csproj, rebuild Runner
# 2. run the chain on any directory
python autoreaktor.py <dir> --deep
# 3. the Slayer→Krypton order on a virtualized target
NETReactorSlayer.CLI.exe ... target.exe
KRYPTON_FORCE_VM_MAP="0x75=Call" tools/krypton/Krypton/bin/Release/net8.0/Krypton.exe target_Slayed.exe --no-pause
# 4. verify on your own build (no protected binaries redistributed here)
#    protect verify_target/ with the .NET Reactor demo using verify_target/protect-flags.txt,
#    then compare IL sizes + ldstr counts with proof_loader/
```

## Upstream fixes contributed by this work

The AutoReaktor lab runs Krypton hard enough to hit its own bugs; all three fixes are in `tools/krypton/` as patches and documented here for upstreaming:

1. `Krypton.Runner.csproj` - `<Prefer32Bit>true</Prefer32Bit>` so the net48 Runner can load 32-bit-required targets (was: BadImageFormatException, 12 silent stage errors).
2. `MethodRecompiling.cs` - null-guard on `method.Parent?.FullName` in the recompile catch-block (was: the *logger* threw NullReferenceException while reporting a recompile failure, killing the whole pipeline).
3. `KRYPTON_FORCE_VM_MAP=0x75=Call` - documents the env override as the recovery path when the semantic validator prunes a correct mapping over a 1-in-152 operand edge case.

## Repo layout

| File | Purpose |
|---|---|
| `autoreaktor.py` | 4-stage pipeline (stdlib only, Python 3.8+) |
| `hunt.py` | classifier: bitness-aware .NET detection + measured entropy boundaries |
| `hunt_list.py` | hunter CLI with JSON dump |
| `vmres_extract.py` | standalone VM resource string-table extractor (Krypton layout port) |
| `proof_loader/` | net8 reflection proofer + net48 PowerShell proofer + run/target reports |
| `verify_target/` | reproducible test target + exact Reactor console flags |

## Credits

de4dot (0xd4d) · de4dot-cex (ViRb3) · NETReactorSlayer (SychicBoy) · Krypton (PeterG75 upstream, dawwinci continuation fork) · dnlib · AsmResolver. Each keeps its own license; binaries are never redistributed here.

AutoReaktor: MIT.
