# AutoReaktor v3 — NecroBit Solved: harvest → rebuild → runnable binary

v3 is the deep-research release. It closes the gap every existing tool leaves open:
**NecroBit method bodies** — the layer de4dot, NETReactorSlayer, and Cursed.Reactor
all explicitly skip ("except VM & NecroBit"). v3 doesn't just dump them; it rebuilds
a **runnable, NecroBit-free binary** from the harvested fragments - verified live
against the original's GUI behavior.

## What v3 adds on top of v2.2

| Layer | Tool | What it does | Verified result |
|---|---|---|---|
| Research | `v3/RESEARCH-necrobit.md` | Full NecroBit 7.3 mechanism, measured on-target | 201/201 inventory, JIT-hook dead-ends documented with evidence |
| Harvest | `v3/nbdump.py` | Reflection harvest: policyCreatorDic + delegate-chain DynamicMethod IL | 204 fragments, 201/201 cross-match, rc=0 |
| Rebuild | `v3/nbrebuild/` | dnlib patcher: inline delegate fragments, sanitize dead dummies, write | 1,438 call-sites substituted in 187 methods, 0 unresolved, **0 NecroBit pairs remain** |
| Proof | `v3/test-rebuild/` | Live GUI equivalence harness | Rebuilt binary opens the identical `reactor73` GUI; register-click behavior byte-identical (`error` box on empty fields, same as original) |

## The three bugs between "writes a binary" and "runs a binary"

All three were found by live verification, not by reading code:

1. **Token renumbering kills the VM blob.** The virtualized-method blob
   (`AnnotationDic.AnnotationServer` resource) stores *original metadata tokens*
   resolved at runtime via `Module.ResolveMethod/ResolveField/ResolveType`. dnlib's
   default writer renumbers rows → the VM silently invokes the wrong methods →
   the `EditorPolicy` anti-tamper exception fires from inside the VM loop.
   Fix: `MetadataFlags.PreserveAll` on write. Symptom died instantly.
2. **Overload resdeadtion by arity retargets calls.** `Array.SetValue(Object, Int32)`
   vs `(Object, Int32[])` - same param count, different method. The rebuild picked
   the array overload and died at runtime with `ArgumentNullException: indices`.
   Fix: per-parameter type-name matching from the harvested member signature.
3. **IL injection tooling must preserve tokens too.** A diagnostic logging
   injector rebuilt without `PreserveAll` reintroduced bug #1 - the logging build
   threw `EditorPolicy` while the untouched rebuild ran clean. Diagnostic builds
   are not exempt from the VM's token discipline.

## Reproduce

```
# harvest (needs the target + .NET Framework 4.8, 32-bit process)
python v3/nbdump.py <target.exe> <outdir>          # nb-inventory.json

# rebuild (net48, dnlib 3.3.4)
cd v3/nbrebuild && dotnet build -c Release
dotnet bin/Release/net48/nbrebuild.dll <target.exe> <nb-inventory.json> <out.exe>

# verify: run <out.exe> - the original GUI must appear and behave identically
```

No protected binaries are redistributed. The reference target is the public
Tuts4You ".NET Reactor v7.3" unpackme (whoknows, June 2025).

## Scope honestly stated

- Verified on the Reactor 7.3 reference target end-to-end (GUI launch + click-path
  behavior + IL equivalence on the decrypt chain). The harvest/rebuild layers are
  structural (no hardcoded opcode tables, no per-build offsets), but multi-version
  coverage (6.x / 7.0 / 7.5, .NET Core targets) is future work - the harvest and
  rebuild contracts are version-agnostic by design, coverage claims are not.
- NecroBit + anti-tamper are solved here; **Code Virtualization** methods are still
  handled by the v2.2 Slayer→Krypton chain (3/3 on this target). A single binary
  passing through both (rebuild first, then devirtualization) is the v3.x roadmap.

## Repo layout addition (v3)

| File | Purpose |
|---|---|
| `v3/RESEARCH-necrobit.md` | NecroBit 7.3 internal mechanism, evidence-backed |
| `v3/nbdump.py` | Reflection harvester (policyCreatorDic + fragment IL) |
| `v3/nbdump-walk/` | nbwalk helper (module-ctor forcing + delegate enumeration) |
| `v3/nbrebuild/` | dnlib patcher with token-preserving write + sig-matched overload resdeadtion |
| `v3/test-rebuild/` | verification harness tools (IL dump, subst audit, injectors) |

AutoReaktor: MIT. v3 tools: MIT.

## Multi-target T-strip (t1–t7) - layer-combination proof

`multi-target/T-MATRIX.md` - same-source samples packed with every .NET Reactor 7.5
layer combination (NecroBit / +VM / +cflow / +antidebug+antiildasm+merge /
+compression+Reflection-Compat), plus the real-world strip (t6/t7).
**All five solved with live GUI proof** - the t3 11-stage chain (nbfixctor2 v30→v41e)
was then **parametrized** (v39b/v38b/v41) and solved t4 and t5 zero-touch.
Key mechanisms: same-thread cctor reentrans (init moved to global cctor head),
NecroBit entry cut from ALL ctors (incl. compiler-generated), Main rewritten by
recycling original MemberRefs, ctor Text+Visible for form visibility.
