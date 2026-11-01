# autoreaktor — Development Plan

This document tracks the recovery roadmap, completed architectural fixes, and modular refactoring phases for .NET Reactor 7.x unpacking.

---

## Completed Phases

1. **Behaviour Oracle & Verdict Cleanliness**
   - Replaced fragile string/exit-code heuristics with a true behaviour oracle: execution of the protected binary sets the stdout/stderr baseline.
   - GUI/blocking targets correctly recognized via alive grace windows (`ALIVE_GRACE`).
   - Separation of `run-recovered` vs `run-recovered-base-only` (slayer/de4dot shell vs real body recovery).

2. **x64 Hook & Dump Stability**
   - Corrected attach-time JIT framework discrimination (`mscoree.dll` vs `clr.dll`).
   - Integrated the `--force` `forcedump` companion (`PrepareMethod` walk), achieving stable body acquisition (**270 bodies** on `con48x64`).
   - Quantified the PE anti-tamper scope via `pe_tamper_scope.py`: proved that any in-place mapped image mutation is caught by Reactor's cctor check, making offset-preserving rewrites impossible without anti-tamper neutralization.

3. **Artifact Survivability & Process Tree Safety**
   - Base64 inert snapshots (`NB_B64_OUT`) written *before* PE serialization to survive Windows Defender quarantine.
   - Robust process tree termination (`kill_tree` with `taskkill /F /T` on Windows) to prevent orphaned GUI processes.

4. **String Literal Re-binding (`NB_LDSTRMAP`)** — *consumer only, no producer yet*
   - `nbilmerge.cs` can ingest a `token=literal` map and write the literals into
     the output US heap, and `auto_stubmap.py` now forwards the variable (the
     merge is normally driven through it, so without forwarding the consumer
     was unreachable).
   - **There is no generator.** Producing the map requires running the
     packer's own string decrypter; that is not implemented, so in practice the
     map is always empty and no string has been recovered by this route. An
     earlier `gen_ldstrmap` stub was deleted rather than left in the tree
     pretending to work.

---

## Active Phase: Modular Passes (`Passes/`)

`nbilmerge.cs` now calls three passes after the body write-back:
- **`Passes/AntiDebugPass.cs`**: rewrites `Debugger.get_IsAttached` calls to `ldc.i4.0`.
- **`Passes/ProxyCallPass.cs`**: two-phase — collect one-call stubs, then retarget
  `call`/`callvirt`/`ldftn` operands at the real target.
- **`Passes/TamperPass.cs`**: rewrites `throw` in `<Module>.cctor` to `ret` and
  nops calls to `smethod_*`/`Class3*` helpers.

Measured caveat: these are pattern passes with no test target of their own.
`AntiDebugPass` matches the managed `Debugger` property; Reactor's anti-debug is
mostly native/unmanaged, so a zero count is the expected result on this corpus,
not a failure. `TamperPass` is off by default in the pipeline (`NB_ATKILL`
opt-in) and its `Class3` name match was derived from an older sample.

## Known gap: generic-declaring types

`nbilmerge.cs` skips every method whose declaring type has generic parameters
("generic types load-validate every member; a body written with Object-only
locals can fail that check"). Measured on `con48x64` (7.5.0.0 demo):

- the protected module contains exactly **one** generic type,
  `.../fFeHXD5jGvWG4hfURs0/YdkCTU5h0ANEMgBcfNi<BXMso55QofondnoEPXl>`,
  a nested attribute helper with 4 methods (`.ctor`, `.cctor`,
  `BkXgT4XQdFEapb0BZnj`, `l0FbJaX1gsoBlb3e8CC`);
- the merge log confirms the guard firing on it (`[skip] generic: ...`), so
  those 4 bodies stay decoys while 254 other bodies are restored.

So the "generics" item is real but narrow: one type, four methods, in this
corpus. The `Class3`1` name quoted in `v3/multi-target/T-MATRIX.md` T9 does not
exist in the current 7.5 samples (`Class3` appears 0 times), so that specific
claim is stale and should not be used as the target of new work.

## Future Phases

- **T9 hybrid re-measurement**: the T9 row cites `report.json` + hybrid run
  logs, and neither artifact is in the repository — the claim cannot be
  reproduced from this checkout. Re-running the hybrid on `verify_forms` and
  storing the log is the prerequisite for any further T9 work.
- **Full Matrix CI Enforcement**: complete green run across all 10 cells
  (`matrix_out/matrix.json`).
