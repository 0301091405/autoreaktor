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
tools/setup.sh        # fetches dnlib, de4dotEx, NETReactorSlayer, Krypton
```

Requirements: Windows with .NET Framework 4.8 (targets are WinForms-era), Python 3.8+, and the .NET SDK for building Krypton.

## Use

```
python hunt.py <dir>                 # classify: clean / carrier / runtime / protected / native
python autoreaktor.py <dir|file> --deep   # full chain, per-file report.json
```

The report records every stage's exit code, the hashes in and out, and the verification result — including what was NOT recovered. No stage failure is masked.


## Prove it on your own target (5 minutes, no binaries downloaded)

The repo ships a pack-and-verify harness so nobody has to trust a protected sample:

```
# 1. build the test target (a 20-line console app with string-encryption bait)
cd verify_target && dotnet publish -c Release -o out

# 2. protect it with the free .NET Reactor demo console
dotNET_Reactor.Console.exe -file outerify_target.dll ^
  -necrobit 1 -stringencryption 1 -antitamp 1 -antidebug 1 ^
  -control_flow 1 -flow_level 9 -obfuscation 1 -resourceencryption 1 ^
  -compression 1 -suppressildasm 1 -hide_calls 1 -nodialog -q

# 3. run the pipeline on the protected build
python autoreaktor.py <that-dir> --deep

# 4. invoke the unpacked assembly via proof_loader
cd ../proof_loader && dotnet run -- <...>erify_target_Slayed.dll
```

Expected proof output (the two secrets the packer encrypted, back in plaintext):

```
hello from test target
DH-VERIFY-PLAINTEXT-MARKER-7F3A
DH-VERIFY-SECRET-<hex>
exit: 0
```

If your own target needs NecroBit body recovery instead, see `v3/README.md`.

## How the NecroBit recovery works

Static strippers fail on modern NecroBit because the CIL bodies never exist decrypted on disk: `MethodDef.RVA` points at a decoy stub, and the real body is only assembled in memory at JIT time. The route that does not race the packer:

1. `v3/jitdump/clrjit_hook.cpp` — VMT hook on `ICorJitCompiler::compileMethod`, injected at process start.
2. `v3/jitdump/nbjit_launch.c` — suspended `CreateProcess` + `QueueUserAPC(LoadLibraryA)` launcher (built per-target bitness).
3. `v3/jitdump/nbjitdump.py` — orchestrator: detects the target's machine type, builds the matching launcher, runs it, collects the bodies.
4. `v3/jitdump/nbilmerge.cs` — write-back: merges dumped bodies into a module dnSpy/ILSpy can open.

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
- **Code Virtualization** methods never pass `compileMethod` as IL — that layer stays with Krypton, and only the protection-method subset is reliably devirtualized.
- **Coverage** is bounded by what the process JITs during the dump window; a GUI driver (`v3/jitdump/jitdrive.py`) grows it but 100% on arbitrary targets is not guaranteed.
- Demo-packed binaries older than 14 days refuse to run (Eziriz demo timer) — neutralize the timer check first.

## Repo layout

| Path | Purpose |
|---|---|
| `autoreaktor.py`, `hunt.py` | pipeline entry, target classification |
| `tools/setup.sh` | fetch third-party dependencies (not committed) |
| `v3/jitdump/` | JIT-entry NecroBit recovery (hook, launcher, orchestrator, merge) |
| `v3/nbdump.py`, `v3/nbwalk/`, `v3/nbrebuild/` | NecroBit reflection harvest + call-site rebuild |
| `v3/nagstrip/` | nag/tamper/ctor repair tools |
| `verify_target/`, `proof_loader/` | pack-and-verify harness (own binaries only) |
| `v3/RESEARCH-necrobit.md` | NecroBit mechanism, evidence-backed |

## License

MIT. The third-party tools the pipeline drives (de4dot, NETReactorSlayer, Krypton, dnlib) keep their own licenses and are fetched by `tools/setup.sh`, never redistributed here.