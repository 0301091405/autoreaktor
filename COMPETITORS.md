# Competitive landscape

AutoReaktor's field: automated unpacking of Eziriz .NET Reactor-protected
assemblies. This page is an honest inventory of the public tools we measured
ourselves against, what each does well, and where the open ground is. Claims
marked "measured" come from our own runs on a fresh Reactor 7.5.0.0 demo
target (see `v3/multi-target/T-MATRIX.md` rows T8/T9 and
`tools/matrix.py`); claims about other tools come from their documentation
and repos at the time of writing.

## The field

| Tool | Scope | NecroBit bodies | Runnable output | 4.8 | .NET Core | Status |
|---|---|---|---|---|---|---|
| **AutoReaktor** | full automated chain: classify -> Slayer -> Krypton (VM) -> JIT-entry NecroBit recovery -> token-mapped hybrid write-back -> antitamper feedback loop | **yes** — JIT-entry dump + reflection decoded view, written back by real tokens with real local types and EH clauses | **yes** for the console class (`run-recovered`, secrets verified in output) | yes | analysis tier (net8 leg builds) | active, CI-proven |
| [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) (SychicBoy, GPLv3) | Reactor-focused deobfuscator/unpacker: dec-methods/strings/rsrc/bools, deob-cflow, deob-tokens, rem-antis, proxies, inlining | claims decryption; on our 7.5.0.0 full-flag target the output kept decoy bodies and failed at the antitamper writer (measured) | its `_Slayed` output is the input to our stage 5 — runnable only after our antitamper cut | yes | yes | last release v6.4.0.0 (2022-12); repo alive |
| [JitUnpacker-Framework](https://github.com/wwh1004/JitUnpacker-Framework) (wwh1004, MIT) | general JIT-hook unpacker framework — covers all four JIT-era encryption points (IL, tokens, EH, locals) and writes bodies into a memory-dumped module | yes in principle (framework, per-protector configs) | dumps a rebuilt assembly; runnable proof and end-to-end automation not demonstrated in the repo | **explicitly unsupported** | no | stale (13 commits, 2023 era) |
| [Cursed.Reactor](https://github.com/CursedLand/Cursed.Reactor) | Reactor unpacker | **explicitly skipped** (VM & NecroBit) | — | yes | — | dormant (2022) |
| [de4dotEx](https://github.com/GDATAAdvancedAnalytics/de4dotEx) (GDATA) | generic deobfuscator ("Unknown obfuscator" on modern Reactor) | no | — | yes | yes | active |
| [Krypton](https://github.com/dawwinci/krypton-devirtualizer) (dawwinci) | Code Virtualization devirtualization ONLY | no | — | yes | — | active; we chain it (stage 3 / 4b) |
| forum scripts / per-target handwork (Tuts4You, UC, blogs) | one-off unpackers per challenge | ad hoc | ad hoc | varies | varies | the baseline we replace with a pipeline |

## Where AutoReaktor is ahead

1. **End-to-end automation with honest grading.** One command runs
   classification through recovery and grades every stage into
   `report.json` — no competitor ships a per-stage verified report.
2. **CI-proven machinery.** `tools/selftest.py` proves hook install,
   body dump and merge on every push; `tools/matrix.py` reproduces the
   universality grid. Nothing comparable exists in the field.
3. **Fresh-version proof.** Verified against a Reactor 7.5.0.0 demo
   target end-to-end (T8), including the NecroBit+antitamper+strenc
   combination other tools measure as their limit.
4. **Recovery quality.** Real-token write-back with true local types
   (from the module's own StandAloneSig rows) and EH clauses captured
   from the decoded view; bodies verified against the reflection view.
5. **Runnable-recovered class.** The antitamper feedback loop turns the
   Slayer output into a running binary — demonstrated with the target's
   own encrypted secrets printed back in plaintext.

## Where the field is ahead — our backlog

1. **x64 alive-with-output**: our x64 leg reaches a live process; the
   NecroBit runtime's table-init needs line surgery (keep init, cut the
   embedded check) instead of whole-method cuts. Addressed next.
2. **JitUnpacker's runtime breadth**: it covers Framework 2.0-3.5;
   our hook targets 4.x. Low priority (Reactor 7.x targets are 4.x),
   but noted for completeness.
3. **Token deobfuscation depth**: Slayer ships a dedicated
   `deob-tokens` stage (already run inside our chain — its CLI
   defaults enable it); JitUnpacker's token handling covers
   protector-level token encryption systematically. We inherit Slayer's
   coverage and extend it through the token-map translator.
4. **Generic methods**: open generics refuse PrepareMethod; our dump
   skips them (counted honestly). JitUnpacker's framework advertises
   broader generic handling. Backlog: instantiate-and-dump walks.

## Positioning

AutoReaktor is not a better de4dot or a better Krypton — it is the
pipeline that composes the field's best pieces, adds the layer none of
them automate (JIT-entry NecroBit recovery with verified, token-mapped,
typed write-back and a runnable-output feedback loop), and proves the
claim on every push. Contributions welcome: a new matrix cell is a
sample template plus a flag set.
