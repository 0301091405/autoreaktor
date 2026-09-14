# AutoReaktör

Batch .NET Reactor unpacking pipeline: entropy hunter → de4dot → NETReactorSlayer → Krypton (VM devirtualization), with per-file SHA-256 provenance, deterministic reruns, and a functional proof harness.

## Why

de4dot stops at "Unknown Obfuscator" on modern Reactor builds and its rc=0 does NOT mean unpacked. NETReactorSlayer (6.4, Dec 2022) fixes antitamper/cflow/proxies but cannot initialize its decrypter on 7.x and skips Code Virtualization entirely. Krypton devirtualizes the VM but its NecroBit runtime-dump needs a correctly-bitted runner. Nobody chains them, verifies the result, or reports honestly what each stage achieved. AutoReaktör is that chain.

## The discovery: feed Slayer's output to Krypton, not the original

Chaining in the naive order (de4dot → Krypton) breaks Krypton's resource parser. The working order, verified end-to-end on a real-world target, is:

    original → NETReactorSlayer → Slayed.exe → Krypton (KRYPTON_FORCE_VM_MAP=0x75=Call)

On the Tuts4You ".NET Reactor v7.3" challenge this recovers **3/3 virtualized methods fully** — including the 2,852-instruction one — where Krypton alone stalls with "5 VM instructions are still unknown". The single unknown opcode 0x75 is a `Call` that Krypton's own semantic validator prunes over a 1/152 operand edge case; the `KRYPTON_FORCE_VM_MAP` env override (an upstream feature) pins it.

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

Requirements: `de4dot*.exe`, `NETReactorSlayer.CLI.exe`, `tools/krypton/` (built once via its `build-all.ps1`) under `./tools/`. **Krypton.Runner must be built with `<Prefer32Bit>true</Prefer32Bit>`** for 32-bit-required targets — without it the NecroBit stage dies with BadImageFormatException (verified: 12 errors → 0 after the fix).

## Real-world verification — Tuts4You ".NET Reactor v7.3" unpackme

Target: community challenge (whoknows, June 2025), .NET Framework 4.x, 32-bit-required, Code Virtualization enabled, embedded DI assemblies. 2,836 views / 83 downloads / no posted solution at time of writing.

**Register-check flow, fully recovered (this is the challenge's protection logic):**

```
register click
  → GetRequiredService(IServiceProvider)
  → textBox1.Text.Trim(), textBox2.Text.Trim()        (name, key)
  → ConvertiblePolicy.DefineAdjustableDefinition(name, key)
      [virtualized — 47 instructions, recompiled to CIL]
  → PolicyFinalizer::IncludeSpec → EnforcePassiveMap   (VM interpreter, 2,462-byte IL)
  → result string → MessageBox::Show
```

Run matrix (all numbers from actual runs):

1. **Determinism** — Slayed sha256 `177d1d73…` identical across 5+ runs; Krypton reports identical per-method results (3/3 recompiled) on repeat runs.
2. **VM devirtualization proven at IL level** — `DefineAdjustableDefinition`:
   - protected original: 62-byte IL body, zero `ldstr` opcodes — a pure VM stub
   - Slayer+Krypton output: full 47-instruction CIL body, recompiled and replaced
3. **Functional proof** — the Slayed binary runs the original GUI (the devirtualized-by-Krypton-alone build previously died at startup with NullReferenceException; the Slayer-first chain fixes that because the working VM stays intact for methods the recompiler skips).
4. **Hunter classifies the target `protected`** before any tool runs — the Reactor 7.3 build carries no readable marker, so a plain string scan would have missed it (entropy window 6.0+ catches it).

## Honest limits (measured on the same target)

- **NecroBit bodies**: Krypton's runtime dump produces 0 rows on this target — the Reactor 7.3 NecroBit layout doesn't expose its body table as the Runner expects. Methods whose bodies live only in NecroBit (e.g. `FilteredPolicy.RunPolicy`'s dependency chain) keep their protection-runtime-dependent stubs; the report says `krypton-devirt`, never `success`.
- **PE write-back**: Krypton recompiles the 2,852-instruction method successfully but its IL safety gate rejects writing it (4,241 CIL issues from merged-ValueTaskAwaiter stack imbalances — a dnlib writer limitation, not a mapping failure). The recompiled body is fully readable in the `-Devirtualized-report.txt`; it just isn't patched into a new binary.
- **VM string table**: extracted the 10,580-byte `AnnotationPool.SeparatedAnnotation` resource and fully reversed its container format (58 operand defs, encrypted-LEB128 framing) — the embedded strings are themselves encrypted by a runtime decryptor, so they stay opaque without executing it.
- **Registration strings**: same consequence — the strings behind the register flow are in that last encrypted layer.

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

The AutoReaktör lab runs Krypton hard enough to hit its own bugs; all three fixes are in `tools/krypton/` as patches and documented here for upstreaming:

1. `Krypton.Runner.csproj` — `<Prefer32Bit>true</Prefer32Bit>` so the net48 Runner can load 32-bit-required targets (was: BadImageFormatException, 12 silent stage errors).
2. `MethodRecompiling.cs` — null-guard on `method.Parent?.FullName` in the recompile catch-block (was: the *logger* threw NullReferenceException while reporting a recompile failure, killing the whole pipeline).
3. `KRYPTON_FORCE_VM_MAP=0x75=Call` — documents the env override as the recovery path when the semantic validator prunes a correct mapping over a 1-in-152 operand edge case.

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

AutoReaktör: MIT.
