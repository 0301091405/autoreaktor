# AutoReaktor

A batch .NET Reactor unpacking pipeline: entropy hunter → de4dot → NETReactorSlayer → Krypton (VM devirtualization), with per-file SHA-256 provenance, deterministic reruns, and an honest per-stage verification report.

## What it solves

Modern .NET Reactor (6.x–7.x, NecroBit era) packing defeats every public tool at a different layer:

- **de4dot** calls it "Unknown Obfuscator"; its rc=0 does not mean unpacked.
- **NETReactorSlayer** (last release Dec 2022) removes anti-tamper/cflow/proxies but cannot initialize its NecroBit decrypter on 7.x and skips Code Virtualization entirely.
- **Krypton** devirtualizes the VM but does nothing about NecroBit bodies.

AutoReaktor chains them in the order that actually works, adds what none of them has — a JIT-entry body dump that recovers NecroBit-encrypted method bodies without any static key derivation — and verifies every stage's output instead of trusting exit codes.

For a target protected with Reactor 7.x (NecroBit + anti-tamper + obfuscation), the pipeline either produces a runnable, decompilable assembly or an honest report that says exactly which layer stopped it and why.

## Install

```
git clone https://github.com/0301091405/autoreaktor.git
cd autoreaktor
tools/setup.sh        # fetches de4dotEx, NETReactorSlayer, Krypton
```

Requirements: Windows with .NET Framework 4.8 (targets are WinForms-era), Python 3.8+, the .NET SDK (C# tools + Krypton), and MSVC BuildTools with a Windows SDK for stage 4 — the JIT hook DLLs and the merger are built automatically on the first protected target (`v3/jitdump/msvc_env.py` discovers the toolchain; no hardcoded paths).

## Use

```
python hunt.py <dir>                     # classify: clean / carrier / runtime / protected / native
python autoreaktor.py <dir> --hunt       # same classification, writes _ar_out/hunt.json
python autoreaktor.py <dir|file> --deep  # full chain, per-file report.json
```

`--deep` runs the full chain per file: de4dot → NETReactorSlayer → runnable-probe → Krypton (VM) → NecroBit JIT recovery (+ VM devirtualization of the recovered binary). Stage 4 launches suspected protected targets under the clrjit hook with the `--force` companion — every resolvable MethodDef is JIT'd and dumped, not just the ones the target executes — and writes the bodies back via `nbilmerge`; hook DLLs, the companion and the merger are built on demand (MSVC + .NET SDK required). Pass `--no-nb` to skip it; every outcome lands in `report.json`, including what was NOT recovered.

The report records every stage's exit code, the hashes in and out, and the verification result — including what was NOT recovered. No stage failure is masked.


## Prove it on your own target (5 minutes, no binaries downloaded)

The repo ships a pack-and-verify harness so nobody has to trust a protected sample:

```
# 1. build the test target — the net48 leg is the primary Reactor class (x86)
cd verify_target && dotnet publish -c Release -f net48 -o out48 && cd ..

# 2. protect it with the free .NET Reactor demo console (7.5.0.0 verified)
dotNET_Reactor.Console.exe -file verify_target\out48\verify_target.exe ^
  -necrobit 1 -stringencryption 1 -antitamp 1 -antidebug 1 ^
  -control_flow 1 -flow_level 9 -obfuscation 1 -resourceencryption 1 ^
  -suppressildasm 1 -hide_calls 1 -nodialog -q

# 3. run the pipeline on the protected output (lands in verify_target_Secure/)
python autoreaktor.py verify_target_Secure --deep

# 4. inspect the per-stage report — stage 4 shows hook status, dumped bodies,
#    EH tables and the merge restore count; stage 5 runs a feedback loop that
#    strips the leftover antitamper writer from the Slayer output
```

Verified end-to-end on a fresh 7.5.0.0 demo target (T-MATRIX row T8): hunt `protected` → 267 decrypted bodies dumped → 220/411 methods restored into the analysis PE by real tokens → 9 EH clause tables → stage 5 produced a **running** assembly that prints the two secrets the packer encrypted:

```
hello from test target
DH-VERIFY-PLAINTEXT-MARKER-7F3A
DH-VERIFY-SECRET-<hex>
```

Per-file results, reported honestly in `report.json`: `run-recovered` (running rebuilt binary), `necrobit-recovered` / `necrobit-partial` / `necrobit-dumped` (analysis PE tiers), `slayer-clean`, `krypton-devirt`, `incomplete`.

If your own target needs NecroBit body recovery instead, stage 4 handles it in the chain — or see `v3/README.md` for the manual deep-dive route.

## How the NecroBit recovery works

Static strippers fail on modern NecroBit because the CIL bodies never exist decrypted on disk: `MethodDef.RVA` points at a decoy stub, and the real body is only assembled in memory at JIT time. The route that does not race the packer:

1. `v3/jitdump/clrjit_hook.cpp` — VMT hook on `ICorJitCompiler::compileMethod`, injected at process start. With `NB_SCOPE_DIRS=1` bodies are grouped per owning CLR module, so foreign JIT never mixes into the target's dump.
2. `v3/jitdump/nbjit_launch.c` — suspended `CreateProcess` + `QueueUserAPC(LoadLibraryA)` launcher (built per-target bitness).
3. `v3/jitdump/nbjitdump.py` — orchestrator: detects the target's machine type, builds the matching launcher (MSVC discovered via `v3/jitdump/msvc_env.py` — no hardcoded versions), runs it, collects the bodies. `--force` runs the companion below instead of a bare run.
4. `v3/forcedump/` — force-JIT companion: loaded into the hooked process, it runs the module initializers (anti-tamper init completes clean), then `RuntimeHelpers.PrepareMethod`-walks every resolvable MethodDef. The dump stops depending on what the target happens to execute — one pass covers everything the runtime can JIT. Exception clauses are read from the same decoded body and written as `m_*.eh` next to the dump.
5. `v3/jitdump/nbilmerge.cs` — write-back: merges dumped bodies into a module dnSpy/ILSpy can open, reattaches the captured EH clauses and binds every local instruction to its true index from a raw-IL scan. `auto_stubmap.py` trial-merges each scope dir and keeps the strongest write count.

There is no key-derivation emulation, no per-version offset tables — the pipeline takes the bodies at the moment the runtime itself hands them to the JIT, so it is structurally immune to Reactor version bumps that break static decrypters.

## Stage order matters (the non-obvious discovery)

Feeding Slayer's output to Krypton — not the original — is what makes the VM stage work at all:

```
original → NETReactorSlayer → Slayed.exe → Krypton
```

Running Krypton directly on the original breaks its resource parser.

## Honest limits

Documented in the READMEs, measured on real targets, no inflation:

- **RVA=0 NecroBit methods cannot be written back into the PE** — the body only exists in JIT-decrypted memory, and any metadata rewrite trips the runtime anti-tamper CRC. On this class the deliverable is: original exe + JIT-dumped bodies + an analysis PE with all bodies inlined for decompilation.
- **Code Virtualization** methods never pass `compileMethod` as IL — that layer stays with Krypton, and stage 4b now applies it directly to the recovered binary (one file through NecroBit recovery AND VM devirtualization; the `krypton-on-merged` report stage).
- **Coverage**: with `--force`, the dump is a `PrepareMethod` walk over every resolvable MethodDef — no longer bounded by what the target executes. The remaining limit is bodies the runtime refuses to prepare (open generics need an instantiation). `v3/jitdump/jitdrive.py` stays for GUI-behavior proof passes.
- **Scope separation**: process-wide JIT (framework, the companion itself) lands in its own `scope*/` dir per CLR module; `auto_stubmap` trial-merges each and keeps the strongest write count, so foreign rids can never bind into the target.
- Demo-packed binaries older than 14 days refuse to run (Eziriz demo timer) — neutralize the timer check first.
- **Ordering on all-flags 7.5 builds**: running `nbrebuild` directly on the packed file can produce a module that throws `BadImageFormatException` at load. Run the `nbfixctor2` ctor repair first (`NB_V50=1`), then `nbrebuild`; the combined output launches clean (verified T+8s with GUI on the all-flags target in `v3/multi-target/T-MATRIX.md`).
- **Runtime slot hooks** (`NB_EHSLOT`, `NB_STRSLOT`, `NB_VTSLOT`) are vtable-slot indices that vary across CLR builds — they default to safe/off values and every one is documented with its discovery recipe in `docs/ENV-VARS.md`.

## The universality matrix

One sample proves nothing. `tools/matrix.py` generates a diverse corpus
(runtimes x architectures x app shapes x flag combos), protects every target
with the free demo console, runs the full chain on each and writes the result
matrix — the project's universality claim, reproducible by anyone:

```
python tools/matrix.py            # full grid
python tools/matrix.py --quick    # one flag-set per shape
```

Requires Windows, the .NET SDK and the .NET Reactor demo console
(auto-discovered; or point `REACTOR_CONSOLE` at it). Cells report the honest
result class per sample — `run-recovered`, `necrobit-recovered`,
`slayer-clean`, ... — so regressions and open classes are visible, never
hidden. First published grid (7.5.0.0 demo, all cells full flags):

| cell | result | restored | runnable |
|---|---|---|---|
| console net48 x86 | run-recovered | 220 | yes |
| console net48 x64 | necrobit-recovered | 220/386 | no (stage-5 x64 iterations open) |
| console net8 (anycpu) | slayer-clean | 230 | no |
| console + generics/delegates net48 x86 | run-recovered | 221 | yes |
| WinForms net48 x86 | slayer-clean | 225 | no |

## Machinery self-test

The unpacking machinery is CI-enforced with zero protected inputs — no license, no sample, no trust required:

```
python tools/selftest.py     # build target → build hook → force-dump → scope merge
```

The GitHub workflow runs the same script on every push (the `selftest` job): if the hook stops installing or bodies stop reaching disk, the repo goes red, not silent.

## Repo layout

| Path | Purpose |
|---|---|
| `autoreaktor.py`, `hunt.py` | pipeline entry (stage 4 + 4b included), target classification |
| `tools/setup.sh` | fetch third-party dependencies (not committed) |
| `tools/selftest.py` | end-to-end machinery proof, runs in CI |
| `v3/jitdump/` | JIT-entry NecroBit recovery (hook, launcher, orchestrator, merge) |
| `v3/forcedump/` | force-JIT full-coverage companion |
| `v3/nbdump.py`, `v3/nbwalk/`, `v3/nbrebuild/` | NecroBit reflection harvest + call-site rebuild |
| `v3/nagstrip/` | nag/tamper/ctor repair tools |
| `verify_target/`, `proof_loader/` | pack-and-verify harness (own binaries only) |
| `docs/ENV-VARS.md` | every `NB_*` knob: default, effect, when to use |
| `v3/RESEARCH-necrobit.md` | NecroBit mechanism, evidence-backed |

## How it compares

The field: NETReactorSlayer (Reactor-focused deobfuscator - our stage 2),
JitUnpacker-Framework (general JIT-hook dump framework, no 4.8, stale),
Cursed.Reactor (dormant, skips NecroBit), de4dotEx (generic), Krypton (VM
only - our stage 3/4b). AutoReaktor is the pipeline that composes them,
adds automated JIT-entry NecroBit recovery with verified typed write-back
and a runnable-output feedback loop, and proves it with CI and a
reproducible matrix. Honest comparison with per-capability evidence:
[COMPETITORS.md](COMPETITORS.md).

## License

MIT. The third-party tools the pipeline drives (de4dot, NETReactorSlayer, Krypton, dnlib) keep their own licenses and are fetched by `tools/setup.sh`, never redistributed here.