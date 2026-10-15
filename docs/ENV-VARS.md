# Environment-variable map

Every knob the AutoReaktor tools read from the environment, in one place.
Variables are grouped by the tool that reads them. Unless stated otherwise:
unset = feature off / default path.

## clrjit_hook.cpp (injected JIT hook — set BEFORE launching nbjitdump.py)

| Variable | Default | Effect |
|---|---|---|
| `NB_DLL` | — (required) | Full path of `clrjit_dump32/64.dll`; set by `nbjitdump.py`, read by `nbjit_launch.exe`. |
| `JITDUMP_DIR` | `.` | Dump output directory for `m_*.bin` / `m_*.eh` / `marker.txt` / `jitdump.log`. |
| `NB_SCOPE_DIRS` | off | `1` (set by `nbjitdump.py`) = bodies are grouped into `scope<N>/` subdirectories, one per owning CLR module. The merge consumes only the target's dir, so framework/companion JIT can never collide on MethodDef rids. |
| `NB_TOKENMODE` | auto | `vt` = resolve the real MethodDef token through the `getMethodDefFromMethod` vtable slot; otherwise chunk-derived offset read (x86: `+0x0C`, x64: `+0x14`). |
| `NB_VTSLOT` | `112` | Vtable slot used when `NB_TOKENMODE=vt`. Runtime-dependent — see "slot discovery" below. |
| `NB_EHSLOT` | off | Vtable slot of `ICorJitInfo::getEHinfo`. When set, the hook captures every method's exception clauses during the original compile and writes `m_XXXXXXXX.eh` next to the body (`[u32 count][count x 28-byte clause]`). `nbilmerge` reattaches them on write-back. |
| `NB_STRSLOT` | `118` | Vtable slot of `getStringLiteral` (CoreCLR .NET 8 count; Framework differs). Only read when `NB_STRDUMP=1`. |
| `NB_STRDUMP` | off | `1` = dump ldstr literal contents to `us_XXXXXX.txt` while bodies compile. SEH-guarded, but a wrong slot can destabilize some hosts — default off. |
| `NB_NOINLINE` | off | `1` = `nbjitdump.py` exports `COMPlus_JitNoInline=1` so tiny methods JIT as separate entries instead of being inlined into ctors. |

Design note: module filtering by probing vtable slots at runtime was tried and
rejected — wrong-slot calls corrupt live JIT state and kill the process. Scope
grouping achieves the same isolation with pointer bookkeeping only.

### Vtable slot discovery

Slot indices shift between CLR builds. Recipe used on the reference targets:
in dnSpy, load `clrjit.dll`/the runtime, find `ICorJitInfo`'s interface map in
`corinfo.h` for the matching CoreCLR/Framework tag and count to the method —
or brute-force a slot range in a throwaway process (`NB_VTSLOT`/
`NB_STRSLOT`/`NB_EHSLOT` accept any number; wrong slots are SEH-guarded and
simply produce no data). Confirmed working values are recorded per target in
`v3/multi-target/T-MATRIX.md`.

## nbjitdump.py / build_hook.py

| Variable | Default | Effect |
|---|---|---|
| `NB_NOINLINE` | off | See above (this script reads it and forwards `COMPlus_JitNoInline`). |
| `COMPlus_JitNoInline` | off | CLR-wide JIT inline breaker, set by `nbjitdump.py` when `NB_NOINLINE=1`. |

MSVC / Windows SDK locations are discovered at runtime by `msvc_env.py`
(vswhere, then glob) — no environment variables needed.

## nbilmerge.cs (write-back)

| Variable | Default | Effect |
|---|---|---|
| `NB_STUBMAPTOK` | — | Token-precise bind: `m_0628001A.bin=06000006;...`. Built automatically by `auto_stubmap.py`. |
| `NB_STUBMAP` | — | Name-based bind: `m_0000.bin=methodName;...` (weaker; kept for old dumps). |
| `NB_LDSTRMAP` | — | Rebind runtime-only ldstr tokens to literal strings: `70000352=sample5;...` (NecroBit string-enc removes literals from the US heap). |
| `NB_SEQ` | off | `1` = bind synthetic-token dumps to bodyless methods by encounter order. Weak proof — report mode only. |
| `NB_ILMATCH` | off | `1` = heuristic bind of synthetic-token dumps to bodyless methods. Result is reported as unproven. |
| `NB_NOBODY` | off | `1` = skip all body writes (inventory/pass-through mode). |
| `NB_MAXWRITE` | — | Integer cap: stop writing bodies after N restores (bisecting a bad dump). |
| `NB_NOSIL` | off | `1` = skip the null-operand write rescue (the pass that NOPs/removes unresolvable token instructions). |
| `NB_ATKILL` | off | `1` = opt-in anti-tamper line surgery (ldstr "tamper" → ret). PreserveAll normally makes this unnecessary. |

## nbfixctor2.cs (all-flags 7.5 ctor repair)

| Variable | Default | Effect |
|---|---|---|
| `NB_V50` | off | `1` = build the REAL control-tree ctor from dumped form-init semantics (the disk stub ctor is a decoy: `call null` → `InvalidProgramException`). The README "all-flags ordering" rule pairs this with `nbrebuild`. |
| `NB_V51` / `NB_V52` | off | Isolation probes (create one TextBox / add it to Controls). Diagnostic only. |
| `NB_NOV39` | off | `1` = do not touch the cctor (honest probe: the cctor may run the control-init chain). |
| `NB_NOV43` | off | `1` = skip the obfuscated-call cut stage. |
| `NB_NOV46` | off | `1` = no manual ctor overwrite — keep the original (NecroBit-solution) ctor, set only `Text`. |

## autoreaktor.py (stage gating)

No environment variables — stage 4 (NecroBit recovery) is gated by
`--deep` / `--no-nb` and the per-target suspicion rule (Reactor marker, or
Slayer produced nothing / produced a non-runnable output). See `README.md`.

## Krypton (third-party)

The bundled Krypton build reads dozens of its own `KRYPTON_*` variables.
They are documented in the upstream checkout (`tools/krypton/`); the
pipeline itself only relies on the CLI invocation
`Krypton.Runner.exe <asm> --no-pause`. The historical `KRYPTON_FORCE_VM_MAP`
pin is deliberately NOT set by the pipeline anymore — VM opcode bytes are
randomized per protected build and the pin silently broke other targets.
