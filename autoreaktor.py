#!/usr/bin/env python3
"""autoreaktor.py v3.2 — the Reactor pipeline.

Stage 0  hunt       — classify .NET assemblies (clean/carrier/runtime/protected)
Stage 1  de4dot     — partial cleanup (kept as fallback candidate)
Stage 2  Slayer     — antitamper/cflow/proxy/inline on the ORIGINAL file
Stage 2b probe      — Slayer output is RUNNABLE-PROBED; if it crashes
                      (interceptor/cctor breakage class), the de4dot-cleaned
                      output is promoted as the runnable candidate (fallback)
Stage 3  Krypton    — VM devirtualization ON THE SLAYED OUTPUT
Stage 4  NecroBit   — JIT-entry body recovery: launch under the clrjit hook,
                      dump the decrypted bodies (+EH clauses), write them back
                      with nbilmerge (token-precise route). Runs on suspected
                      protected targets; disable with --no-nb.

Usage:
  python autoreaktor.py <dir|file> [--dry-run] [--deep] [--keep-work]
                        [--hunt] [--no-nb]

v3.2 changes:
- Stage 4 runs the forcedump companion (--force): a PrepareMethod walk forces
  every resolvable MethodDef through the hooked JIT, so dump coverage no
  longer depends on what the target executes. Bodies are grouped per owning
  CLR module (NB_SCOPE_DIRS) and auto_stubmap trial-merges each scope dir,
  keeping the strongest write count - foreign rids can never bind.
- Stage 4b: Krypton devirtualization runs directly on the recovered binary
  (one file through NecroBit recovery AND VM - the v3.x roadmap item).
- Coverage numbers land in report.json (bodies, module_methods, restored).

v3.1 changes:
- Stage 4 wired into the chain: NecroBit recovery is no longer a manual
  detour. Hook DLLs and nbilmerge.exe are built on demand; every outcome
  (hook fail, 0 bodies, merge counts, probe result) lands in report.json.
- probe stage drains child pipes via reader threads (a chatty child filling
  the OS pipe buffer used to block on write and masquerade as "alive"),
  reaps the killed process, and records probe_executed honestly.
- --hunt mode: classification-only pass writing hunt.json.
- KRYPTON_FORCE_VM_MAP default pin REMOVED (v3.0): VM opcode bytes are
  randomized per protected build; mapping is resolved by Krypton's own
  discovery pass. Per-target overrides remain possible via the env var.
- de4dot is no longer an idle step: its cleaned output is the verified
  fallback candidate (R5 class: Slayer breaks the CodeResolver cctor,
  de4dot-cleaned output runs, GUI-proven).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

VERSION = "3.2.0"
ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
MARKERS = (b"Eziriz", b".NET Reactor")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_is_dotnet(p: Path) -> bool:
    try:
        d = open(p, "rb").read(0x2000)
        if len(d) < 0x200 or d[:2] != b"MZ":
            return False
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if pe + 24 + 2 > len(d):
            return False
        magic = struct.unpack_from("<H", d, pe + 24)[0]
        if magic not in (0x10B, 0x20B):  # must be a valid PE32 / PE32+ optional header
            return False
        dd_off = 96 if magic == 0x10B else 112  # data-directory table offset differs PE32 vs PE32+
        need = pe + 24 + dd_off + 14 * 8 + 8
        if need > len(d):
            return False
        cli_rva = struct.unpack_from("<I", d, pe + 24 + dd_off + 14 * 8)[0]
        cli_sz = struct.unpack_from("<I", d, pe + 24 + dd_off + 14 * 8 + 4)[0]
        return cli_rva != 0 and cli_sz != 0
    except Exception:
        return False


def pe_cor_flags(p: Path) -> int:
    """Return COR flags (bit1=32BITREQUIRED, bit17=32BITPREFERRED) or -1."""
    try:
        d = open(p, "rb").read(1 << 20)
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        dd_off = 96 if magic == 0x10b else 112
        cli_rva = struct.unpack_from("<I", d, opt + dd_off + 14 * 8)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        so = opt + (224 if magic == 0x10b else 240)
        for i in range(nsec):
            base = so + i * 40
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, base + 8)
            if vaddr <= cli_rva < vaddr + vsize:
                co = raddr + (cli_rva - vaddr)
                return struct.unpack_from("<I", d, co + 16)[0]
        return -1
    except Exception:
        return -1


def reactor_marker(p: Path):
    try:
        data = open(p, "rb").read(1 << 20)
        for m in MARKERS:
            i = data.find(m)
            if i >= 0:
                return data[max(0, i - 20):i + 60].decode("latin1", "replace")
    except Exception:
        pass
    return ""


def find_tool(name: str) -> str:
    exts = [".exe", ".bat", ".cmd", ""]
    stem = name.lower().replace(".exe", "")

    def consider(d: Path):
        if d.is_dir():
            for f in sorted(d.rglob("*")):
                if f.is_file() and f.suffix.lower() in exts and stem in f.name.lower():
                    if stem.startswith("krypton"):
                        if "bin" in f.parts and "release" in [x.lower() for x in f.parts]:
                            return str(f)
                        continue
                    return str(f)
        elif d.is_file() and stem in d.name.lower():
            return str(d)
        return None

    hits = [consider(TOOLS / "bin"), consider(TOOLS), consider(ROOT)]
    for h in hits:
        if h:
            return h
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        h = consider(Path(entry))
        if h:
            return h
    return ""


def run_stage(cmd, cwd, timeout=600, env=None, probe=False):
    t0 = time.time()
    if probe:
        # runnable-probe: launch, wait up to timeout, treat still-alive as
        # success (GUI apps block on purpose). Reader threads drain both
        # pipes: a child that fills the OS pipe buffer would otherwise block
        # on write and be misread as "still alive".
        acc = []
        try:
            p = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def _drain(pipe):
                try:
                    acc.append(pipe.read() or b"")
                except Exception:
                    acc.append(b"")

            th1 = threading.Thread(target=_drain, args=(p.stdout,), daemon=True)
            th2 = threading.Thread(target=_drain, args=(p.stderr,), daemon=True)
            th1.start(); th2.start()
            try:
                rc = p.wait(timeout=timeout)
                th1.join(5); th2.join(5)
                return rc, b"".join(acc).decode("utf-8", "replace"), time.time() - t0
            except subprocess.TimeoutExpired:
                p.kill()
                try:
                    p.wait(timeout=10)
                except Exception:
                    pass
                return None, "ALIVE", time.time() - t0
        except Exception as e:
            return 125, f"SPAWN-ERROR {e}", time.time() - t0
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, env=env)
        out = (r.stdout or b"") + (r.stderr or b"")
        return r.returncode, out.decode("utf-8", "replace"), time.time() - t0
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT", time.time() - t0
    except Exception as e:
        return 125, f"SPAWN-ERROR {e}", time.time() - t0


def necrobit_tools() -> dict:
    jd = ROOT / "v3" / "jitdump"
    return {
        "dir": jd,
        "dll32": jd / "clrjit_dump32.dll",
        "dll64": jd / "clrjit_dump64.dll",
        "build_hook": jd / "build_hook.py",
        "nbjitdump": jd / "nbjitdump.py",
        "auto_stubmap": jd / "auto_stubmap.py",
        "merge_csproj": jd / "nbilmerge.csproj",
        "merge_exe": jd / "bin" / "Release" / "nbilmerge.exe",
        "ccfix_csproj": ROOT / "v3" / "ccfix" / "ccfix.csproj",
        "ccfix_exe": ROOT / "v3" / "ccfix" / "bin" / "Release" / "ccfix.exe",
    }


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--deep", action="store_true", help="run Slayer + Krypton + NecroBit stages")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument("--hunt", action="store_true", help="classification only, writes hunt.json")
    ap.add_argument("--no-nb", action="store_true",
                    help="skip stage 4 (NecroBit JIT recovery) even on suspected targets")
    args = ap.parse_args()

    tgt = Path(args.target).resolve()
    outroot = tgt / "_ar_out" if tgt.is_dir() else tgt.parent / "_ar_out"

    if args.hunt:
        from hunt import hunt as hunt_dir
        root = tgt if tgt.is_dir() else tgt.parent
        results = hunt_dir(root)
        counts = {}
        for r in results:
            counts[r["class"]] = counts.get(r["class"], 0) + 1
            if r["class"] in ("carrier", "protected", "error"):
                print(f"[{r['class']:>9}] {r['file']}")
        outroot.mkdir(exist_ok=True)
        (outroot / "hunt.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"--- total: {len(results)} | " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        print(f"[*] hunt.json -> {outroot / 'hunt.json'}")
        return 0

    files = []
    if tgt.is_dir():
        for p in sorted(tgt.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".exe", ".dll") and "_ar_out" not in p.parts:
                if pe_is_dotnet(p):
                    files.append(p)
    else:
        files = [tgt]
    if not files:
        print("[-] no .NET assemblies found")
        return 1

    print(f"[*] .NET assemblies found: {len(files)}")
    slayer = find_tool("NETReactorSlayer.CLI.exe")
    krypton = find_tool("Krypton.exe")
    if args.deep:
        print(f"[*] slayer : {slayer or 'NOT FOUND (stage skipped)'}")
        print(f"[*] krypton: {krypton or 'NOT FOUND (stage skipped)'}")

    report = {"version": VERSION, "files": []}
    outroot.mkdir(exist_ok=True)

    nb_tools = necrobit_tools()
    nb_dlls_ok = None  # built lazily on the first suspected target

    for src in files:
        rel = src.name
        print(f"[*] processing {rel} ...")
        entry = {"input": str(src), "sha256_in": sha256(src),
                 "reactor_marker": reactor_marker(src), "stages": [], "result": "incomplete"}
        flags = pe_cor_flags(src)
        entry["cor_flags"] = f"{flags:#x}" if flags >= 0 else "n/a"
        entry["bits"] = ("32-bit-required" if flags & 2 else
                         "32-bit-pref" if flags & 0x20000 else "any")
        if args.dry_run:
            entry["result"] = "dry"
            report["files"].append(entry)
            continue

        work = outroot / "work" / src.stem
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        base = work / src.name
        shutil.copy2(src, base)
        # The work dir must be RUNNABLE: the probe, nbjitdump's apphost route
        # and the merged-output probe all launch the copied assembly, and a
        # bare .dll copy has no host. Bring the sibling apphost + Core runtime
        # config along when the target is a library.
        if src.suffix.lower() == ".dll":
            for pat in (src.stem + ".exe", src.stem + ".deps.json", src.stem + ".runtimeconfig.json"):
                sib = src.parent / pat
                if sib.exists():
                    shutil.copy2(sib, work / sib.name)

        # ---- stage 1: de4dot (partial pre-clean, relative path invocation)
        de4dot = find_tool("de4dot.exe")
        if de4dot:
            rc, out, dur = run_stage([de4dot, base.name], cwd=work)
            cleaned = list(work.glob("*cleaned*"))
            entry["stages"].append({"stage": "de4dot", "rc": rc, "secs": round(dur, 1),
                                    "log_tail": out[-600:],
                                    "partial_output": str(cleaned[0]) if cleaned else ""})

        # ---- stage 2: Slayer on the ORIGINAL (verified: de4dot output breaks decrypter init)
        slayer_out = ""
        if args.deep and slayer:
            cmd = [slayer,
                   "--dec-methods", "True", "--dec-strings", "True", "--dec-rsrc", "True",
                   "--dec-bools", "True", "--deob-cflow", "True", "--fix-proxy", "True",
                   "--rem-antis", "True", "--dump-asm", "True", "--no-pause", "True",
                   base.name]
            rc, out, dur = run_stage(cmd, cwd=work)
            slayed = sorted(work.glob("*[Ss]layed*"))
            entry["stages"].append({"stage": "NETReactorSlayer", "rc": rc, "secs": round(dur, 1),
                                    "log_tail": out[-800:]})
            if slayed:
                slayer_out = str(slayed[0])
                entry["slayer_output"] = slayer_out
                entry["sha256_slayer_output"] = sha256(slayed[0])

        # ---- stage 2b: SLAYER FALLBACK CHECK
        # Slayer produced no output, or its output crashes on first run
        # (R5/R4 class: interceptor/cctor breakage) => the de4dot
        # partial-cleaned output is the runnable candidate. Honest
        # fallback, verified on R5 where de4dot-cleaned GUI runs.
        if slayer_out:
            entry["probe_executed"] = True
            fr_rc, fr_out, _ = run_stage([str(work / Path(slayer_out).name)],
                                         cwd=work, timeout=60, probe=True)
            slayer_ok = fr_rc == 0 or fr_rc is None  # None = still alive = GUI blocking
            entry["slayer_output_runnable"] = bool(slayer_ok)
            if not slayer_ok:
                cleaned = list(work.glob("*cleaned*"))
                if cleaned:
                    entry["fallback_output"] = str(cleaned[0])
                    entry["sha256_fallback_output"] = sha256(cleaned[0])
                    entry["stages"].append({"stage": "de4dot-fallback", "rc": 0,
                                            "note": "slayer output not runnable; de4dot-cleaned promoted"})
        else:
            cleaned = list(work.glob("*cleaned*"))
            if cleaned:
                entry["fallback_output"] = str(cleaned[0])
                entry["sha256_fallback_output"] = sha256(cleaned[0])
                entry["stages"].append({"stage": "de4dot-fallback", "rc": 0,
                                        "note": "slayer produced no output; de4dot-cleaned promoted"})

        # ---- stage 3: Krypton VM devirtualization on the SLAYED output
        # (verified chain order on the Reactor 7.3 challenge: original→Krypton
        # stalls on unknown opcode 0x75 + logger NRE; Slayer→Krypton recovers
        # 3/3 virtualized methods)
        # NOTE: no KRYPTON_FORCE_VM_MAP pin anymore — VM opcode bytes are
        # randomized per build; the old "0x75=Call" default was a target-
        # specific pin (7.3 challenge) and breaks other builds. Mapping is
        # resolved by Krypton's own discovery pass; if a tie stalls, the
        # per-target pin can still be exported MANUALLY by the operator.
        if args.deep and krypton and entry.get("slayer_output"):
            kdir = work / "krypton"
            kdir.mkdir(exist_ok=True)
            slayed_name = Path(entry["slayer_output"]).name
            shutil.copy2(entry["slayer_output"], kdir / slayed_name)
            rc, out, dur = run_stage([krypton, slayed_name, "--no-pause"],
                                     cwd=kdir, timeout=1800)
            recompiled = out.count("Recompiled method body")
            kstage = {"stage": "Krypton", "rc": rc, "secs": round(dur, 1),
                      "vm_methods_recompiled": recompiled,
                      "log_tail": out[-800:]}
            report_files = sorted(kdir.glob("*Devirtualized-report.txt"))
            if report_files:
                kstage["report"] = str(report_files[0])
            devirt = sorted(kdir.glob("*Devirtualized*.exe"))
            if devirt:
                entry["krypton_output"] = str(devirt[0])
                entry["sha256_krypton_output"] = sha256(devirt[0])
            if recompiled > 0:
                entry["result"] = "krypton-devirt"
            entry["stages"].append(kstage)
            if entry["result"] == "incomplete" and entry.get("slayer_output"):
                entry["result"] = "slayer-clean"
        elif entry.get("slayer_output") and entry["result"] == "incomplete":
            entry["result"] = "slayer-clean"

        # ---- stage 4: NecroBit JIT-entry recovery -------------------------
        # The static chain cannot touch NecroBit method bodies. On suspected
        # protected targets (Reactor marker, or Slayer produced nothing /
        # produced something that does not run) launch under the clrjit hook,
        # dump the decrypted bodies + EH clauses, and write them back through
        # nbilmerge (token-precise route, auto_stubmap). THIS STAGE EXECUTES
        # THE TARGET on the analyst machine — recorded in probe_executed.
        nb_suspect = (bool(entry.get("reactor_marker"))
                      or not entry.get("slayer_output")
                      or entry.get("slayer_output_runnable") is False)
        if args.deep and args.no_nb:
            entry["stages"].append({"stage": "necrobit-jitdump", "status": "skipped",
                                    "reason": "--no-nb"})
        elif args.deep and nb_suspect and sys.platform == "win32":
            entry["probe_executed"] = True
            nb = {"stage": "necrobit-jitdump"}
            if not (nb_tools["dll32"].exists() and nb_tools["dll64"].exists()):
                rc, out, dur = run_stage([sys.executable, str(nb_tools["build_hook"])],
                                         cwd=nb_tools["dir"], timeout=600)
                nb["dll_build_rc"] = rc
                nb["dll_build_log_tail"] = out[-400:]
            if not (nb_tools["dll32"].exists() and nb_tools["dll64"].exists()):
                nb["status"] = "skipped"
                nb["reason"] = "clrjit_dump{32,64}.dll missing and build failed (MSVC/SDK absent?)"
                entry["stages"].append(nb)
            else:
                if not nb_tools["merge_exe"].exists():
                    rc, out, dur = run_stage(["dotnet", "build", str(nb_tools["merge_csproj"]),
                                              "-c", "Release", "-v", "q", "--nologo"],
                                             cwd=nb_tools["dir"], timeout=600)
                    nb["merge_build_rc"] = rc
                if not nb_tools["ccfix_exe"].exists():
                    run_stage(["dotnet", "build", str(nb_tools["ccfix_csproj"]),
                               "-c", "Release", "-v", "q", "--nologo"],
                              cwd=nb_tools["ccfix_csproj"].parent, timeout=600)
                if not nb_tools["merge_exe"].exists():
                    nb["status"] = "skipped"
                    nb["reason"] = "nbilmerge.exe build failed"
                    entry["stages"].append(nb)
                else:
                    ddir = work / "jitdump"
                    # --force: the forcedump companion PrepareMethod-walks every
                    # resolvable MethodDef inside the hooked process, so dump
                    # coverage no longer depends on what the target executes.
                    # Falls back to a bare run when the companion cannot build.
                    rc, out, dur = run_stage([sys.executable, str(nb_tools["nbjitdump"]),
                                              str(base), "--out", str(ddir),
                                              "--force", "--wait", "120"],
                                             cwd=work, timeout=900)
                    bins = (sorted(ddir.glob("scope*/m_*.bin")) or sorted(ddir.glob("m_*.bin"))) \
                        if ddir.exists() else []
                    ehs = (sorted(ddir.glob("scope*/m_*.eh")) or sorted(ddir.glob("m_*.eh"))) \
                        if ddir.exists() else []
                    marker = ddir / "marker.txt"
                    hooked = marker.exists() and "HOOK-OK" in marker.read_text(errors="replace")
                    nb.update({"rc": rc, "secs": round(dur, 1), "hook": hooked,
                               "bodies": len(bins), "eh_tables": len(ehs),
                               "log_tail": out[-600:]})
                    entry["stages"].append(nb)
                    if bins:
                        outdir = work / "nbmerge"
                        outdir.mkdir(exist_ok=True)
                        outexe = outdir / (src.stem + "_nbmerged" + src.suffix)
                        # dual-base trial: bodies merge into the original AND
                        # (when it exists) into the Slayer output — the write
                        # count picks the base, so no target class is assumed
                        # (the slayer base carries decrypted strings; the
                        # original keeps pristine metadata)
                        bases = [("original", base)]
                        if entry.get("slayer_output"):
                            bases.append(("slayer", Path(entry["slayer_output"])))
                        best = None
                        trial_logs = []
                        for bname, bpath in bases:
                            tout = outdir / (src.stem + "_nb_" + bname + src.suffix)
                            rc2, out2, dur2 = run_stage([sys.executable, str(nb_tools["auto_stubmap"]),
                                                         str(bpath), str(ddir), str(tout)],
                                                        cwd=work, timeout=900)
                            m = re.search(r"method actually written:\s*(\d+)", out2)
                            mres = int(m.group(1)) if m else -1
                            trial_logs.append({"base": bname, "rc": rc2, "restored": mres,
                                               "written": tout.exists(),
                                               "written_path": str(tout) if tout.exists() else None})
                            if tout.exists() and (best is None or mres > best[0]):
                                best = (mres, bname, tout, rc2, out2, dur2)
                        if best is None:
                            best = (-1, bases[0][0], None, 1, "no merge output", 0)
                        mrestored, base_used, outexe, rc2, out2, dur2 = best
                        mm = re.search(r"modul MethodDef:\s*(\d+)", out2)
                        module_methods = int(mm.group(1)) if mm else None
                        # keep the slayer-base product even when it loses the
                        # trial: it is the runnable-class input (real bodies
                        # + decrypted strings + slayer-clean cctor)
                        slayer_out_exe = next((t["written_path"] for t in trial_logs
                                               if t["base"] == "slayer" and t.get("written_path")), None)
                        entry["stages"].append({"stage": "necrobit-merge", "rc": rc2,
                                                "restored": mrestored,
                                                "module_methods": module_methods,
                                                "merge_base": base_used,
                                                "trials": trial_logs,
                                                "secs": round(dur2, 1),
                                                "log_tail": out2[-600:]})
                        if outexe.exists():
                            entry["necrobit_output"] = str(outexe)
                            entry["sha256_necrobit_output"] = sha256(outexe)
                            entry["probe_executed"] = True
                            prc, pout, _ = run_stage([str(outexe)], cwd=outdir,
                                                     timeout=60, probe=True)
                            nb_runnable = prc == 0 or prc is None
                            entry["necrobit_output_runnable"] = bool(nb_runnable)
                            if nb_runnable and entry["result"] in ("incomplete", "slayer-clean"):
                                entry["result"] = "necrobit-recovered"
                            elif entry["result"] == "incomplete":
                                entry["result"] = "necrobit-partial"
                            # ---- stage 4b: VM devirtualization ON the recovered
                            # binary (the v3.x roadmap item: one binary through
                            # NecroBit recovery AND VM devirtualization)
                            if krypton:
                                kdir2 = outdir / "krypton"
                                kdir2.mkdir(exist_ok=True)
                                mname = outexe.name
                                shutil.copy2(outexe, kdir2 / mname)
                                rc3, out3, dur3 = run_stage([krypton, mname, "--no-pause"],
                                                            cwd=kdir2, timeout=1800)
                                rec2 = out3.count("Recompiled method body")
                                stage4b = {"stage": "krypton-on-merged", "rc": rc3,
                                           "secs": round(dur3, 1),
                                           "vm_methods_recompiled": rec2,
                                           "log_tail": out3[-400:]}
                                dev2 = sorted(kdir2.glob("*Devirtualized*.exe"))
                                if dev2:
                                    entry["necrobit_vm_output"] = str(dev2[0])
                                    entry["sha256_necrobit_vm_output"] = sha256(dev2[0])
                                    stage4b["output"] = str(dev2[0])
                                entry["stages"].append(stage4b)
                        else:
                            if entry["result"] == "incomplete":
                                entry["result"] = "necrobit-dumped"
                    elif entry["result"] == "incomplete":
                        nb["status"] = "no-bodies"
        elif args.deep:
            entry["stages"].append({"stage": "necrobit-jitdump", "status": "skipped",
                                    "reason": "target not suspected (no Reactor marker and slayer output ran)"})

        # ---- stage 5: runnable recovery (feedback loop) --------------------
        # The Slayer output usually carries DECRYPTED strings but still faults
        # in its module cctor: Reactor's antitamper writes through
        # Marshal.* into the (rewritten) image. The failure surfaces one
        # method at a time, so the fix is feedback-driven: run, parse the
        # top frame from the stack trace, nop every cctor call to it, repeat.
        # Success = the program exits without an unhandled exception.
        if args.deep and slayer_out and nb_tools["ccfix_exe"].exists():
            # hybrid-aware input: when the winning merge base was the slayer
            # module, the merged PE already carries the real bodies AND the
            # decrypted strings — start the loop from there
            slayer_merged = next((st.get("slayer_out_exe") for st in entry["stages"]
                                  if st.get("stage") == "necrobit-merge"), None)
            if slayer_merged and Path(slayer_merged).exists():
                src5 = Path(slayer_merged)   # hybrid: real bodies + decrypted strings
            else:
                src5 = Path(entry["slayer_output"])
            work5 = work / "runfix"
            work5.mkdir(exist_ok=True)
            cur = work5 / src5.name
            shutil.copy2(src5, cur)
            iters = []
            gen = 0
            rc5 = None
            out5 = ""
            for it in range(6):
                entry["probe_executed"] = True
                rc5, out5, _ = run_stage([str(cur)], cwd=work5,
                                         timeout=60, probe=False)
                if "Unhandled Exception" not in out5:
                    break
                meth = None
                for l in out5.splitlines():
                    l = l.strip()
                    if not l.startswith("at "):
                        continue
                    full = l[3:].split("(")[0].strip()
                    # skip BCL frames — the culprit is always the protected
                    # module's own method
                    if full.startswith("System.") or full.startswith("Microsoft."):
                        continue
                    meth = full.split(".")[-1].strip()
                    break
                if not meth:
                    break
                gen += 1
                nxt = work5 / (src5.stem + f"_r{gen}" + src5.suffix)
                rc, outc, _ = run_stage([str(nb_tools["ccfix_exe"]), "fix",
                                         str(cur), str(nxt), meth, "all"],
                                        cwd=work5, timeout=300)
                iters.append({"method": meth, "rc": rc,
                              "log_tail": outc[-200:]})
                if rc != 0:
                    break
                cur = nxt
            else:
                pass
            runnable = rc5 is not None and "Unhandled Exception" not in out5
            stage5 = {"stage": "runnable-recovery", "iterations": iters,
                      "final_rc": rc5, "runnable": bool(runnable),
                      "output_tail": out5[-400:]}
            if runnable:
                entry["runnable_output"] = str(cur)
                entry["sha256_runnable_output"] = sha256(cur)
                if entry["result"] in ("incomplete", "slayer-clean", "necrobit-recovered"):
                    entry["result"] = "run-recovered"
            entry["stages"].append(stage5)

        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        report["files"].append(entry)
        print(f"    -> {entry['result']}")

    (outroot / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    ok = sum(1 for e in report["files"] if e["result"] != "incomplete")
    print(f"[*] done: {ok}/{len(files)} processed. report: {outroot / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
