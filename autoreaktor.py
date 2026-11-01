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


def kill_tree(p):
    """Terminate a probe/target AND anything it spawned.

    `Popen.kill()` only reaps the direct child. A GUI target that starts
    worker processes, or one that outlives a parent killed from outside
    (Windows does not cascade termination), would keep running and hold
    handles - a leftover `*-cleaned.exe` from an aborted matrix run did
    exactly that. On Windows /T takes the whole tree down; elsewhere the
    process group is used.
    """
    if p is None:
        return
    try:
        p.kill()
    except Exception:
        pass
    try:
        p.wait(timeout=10)
        return
    except Exception:
        pass
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                           capture_output=True, timeout=30)
        else:
            os.killpg(os.getpgid(p.pid), 9)
    except Exception:
        pass


def run_stage(cmd, cwd, timeout=600, env=None, probe=False):
    t0 = time.time()
    if probe:
        # runnable-probe: launch, wait up to timeout, treat still-alive as
        # success (GUI apps block on purpose). Reader threads drain both
        # pipes: a child that fills the OS pipe buffer would otherwise block
        # on write and be misread as "still alive".
        acc = []
        popen_kw = {}
        if os.name != "nt":
            popen_kw["start_new_session"] = True
        try:
            p = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 **popen_kw)

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
                kill_tree(p)
                return None, "ALIVE", time.time() - t0
        except Exception as e:
            return 125, f"SPAWN-ERROR {e}", time.time() - t0
    # blocking run: same tree-kill discipline, so a run that overruns cannot
    # leave the target (or its children) behind
    popen_kw = {}
    if os.name != "nt":
        popen_kw["start_new_session"] = True
    try:
        p = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             **popen_kw)
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, (out or b"").decode("utf-8", "replace"), time.time() - t0
    except subprocess.TimeoutExpired:
        kill_tree(p)
        return 124, "TIMEOUT", time.time() - t0
    except Exception as e:
        return 125, f"SPAWN-ERROR {e}", time.time() - t0


# Probe arguments handed to every candidate AND to the protected reference:
# the behaviour oracle only works when both sides run the same command line.
# The corpus exposes its payload behind an argument (matrix.py sets
# AR_PROBE_ARGS=dump), so an argument-less probe can miss whole code paths.
PROBE_ARGS = [a for a in os.environ.get("AR_PROBE_ARGS", "").split() if a]
# non-empty stdout lines the protected target produced under PROBE_ARGS
_REF_LINES = []
# set by set_reference(): the protected target blocked instead of exiting
_REF_ALIVE = False
# grace window for an alive-shaped (GUI) probe - a blocking target will never
# exit, so a full console timeout per candidate is pure loss
ALIVE_GRACE = 10
# True when the protected target itself never exits (GUI shape). Every probe
# of such a target is judged by "still alive after the grace window" instead
# of waiting the full console timeout - otherwise a single GUI cell burns
# ~60 s per candidate probe and the matrix stops finishing at all.
_REF_ALIVE = False
ALIVE_GRACE = float(os.environ.get("AR_ALIVE_GRACE", "8"))

# --- probe verdicts ---------------------------------------------------------
# A probe must NEVER be judged by an English-only string: the CLR prints its
# unhandled-exception banner in the HOST's locale (ru-RU here), so a crashed
# x64 recovery was previously read as "still running / runnable". Classify by
# the OS exit status first (locale-proof) and fall back to the trace text.
_CRASH_CODES = (0xE0434352,   # CLR unhandled managed exception
                0xC0000005,   # STATUS_ACCESS_VIOLATION
                0xC0000094,   # STATUS_INTEGER_DIVIDE_BY_ZERO
                0xC00000FD,   # STATUS_STACK_OVERFLOW
                0xC0000409,   # STATUS_STACK_BUFFER_OVERRUN
                0x80131623)   # CLR fatal (fatal execution engine error)
_TEXT_FRAME = re.compile(r"^\s*(?:at|[вvу])\s+([^\s(]+)")
_EXC_TEXT = re.compile(r"(?:Unhandled Exception|Необработанное исключение|"
                       r"Unbehandelte Ausnahme|Exception non gérée|"
                       r"TypeInitializationException|AccessViolationException|"
                       r"NullReferenceException|InvalidProgramException|"
                       r"BadImageFormatException|MissingMethodException)")


def probe_crashed(rc, out):
    """True when the probe process died with an exception (or is a crash).

    rc is None only for the still-alive (GUI) case and is NOT a failure.
    """
    if rc is None:
        return False
    u = rc & 0xFFFFFFFF
    if u in _CRASH_CODES or u >= 0xC0000000:
        return True
    if rc != 0 and _EXC_TEXT.search(out or ""):
        return True
    return False


def probe_ok(rc, out):
    """Positive runnable verdict: the file ran and behaved like the original.

    Covers both target shapes without knowing their marker text:
      * still alive (rc None, GUI blocking)                -> pass
      * exited non-zero but said something and did NOT die
        with an exception (this harness' Main returns 1)   -> pass
      * exited 0                                           -> pass
      * died with an exception, or fell silent             -> fail

    The BEHAVIOUR ORACLE is the protected target itself: _REF_LINES holds the
    non-empty stdout lines the original produced under the same probe
    arguments, and a candidate must reproduce every one of them. Without it a
    candidate that merely prints its banner before faulting on a later code
    path passes as recovered - exactly how an arg-sensitive Main (one that
    only dereferences its payload when handed "dump") looked "runnable"
    while it still crashed with InvalidProgramException.
    """
    if rc is None:
        return True
    if probe_crashed(rc, out):
        return False
    o = out or ""
    if _REF_LINES:
        return all(line in o for line in _REF_LINES)
    return bool(o.strip())


def probe_argv(path):
    """Probe command line: the same arguments the reference run used."""
    return [str(path)] + PROBE_ARGS


def probe_timeout():
    """How long a probe waits before calling the process alive.

    A GUI target never exits on its own, so waiting the console timeout on
    every candidate is pure loss. The grace window is only shortened when the
    PROTECTED REFERENCE itself never exited, which is exactly the evidence
    that the shape is a blocking GUI.
    """
    return ALIVE_GRACE if _REF_ALIVE else 60


def set_reference(rc, out):
    """Register the protected target's own output as the behaviour oracle."""
    global _REF_LINES, _REF_ALIVE
    _REF_ALIVE = rc is None
    if rc is None or probe_crashed(rc, out):
        _REF_LINES = []
        return
    _REF_LINES = [l.strip() for l in (out or "").splitlines() if l.strip()]


def probe_top_frame(out):
    """First non-BCL frame name from a trace (locale-independent).

    The CLR localizes the banner but not the frame lines themselves; ru-RU
    prints them as "   в Type.Method()" where en-US prints "   at Type.Method()".
    """
    for line in (out or "").splitlines():
        m = _TEXT_FRAME.match(line)
        if not m:
            continue
        full = m.group(1).strip()
        # the exception header line ("Необработанное исключение: System...")
        # also matches the frame regex in ru-RU - skip anything that is a
        # type name only (no dot-separated member)
        if full.startswith("System.") or full.startswith("Microsoft."):
            continue
        if "." not in full:
            continue
        if full.endswith(":") or full.endswith("Exception"):
            continue
        return full
    return None


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

        # BEHAVIOUR ORACLE. Run the PROTECTED binary itself first and record
        # what it prints: every later "does it still work" answer is measured
        # against that, not against a guess about marker text. This also
        # records the packer's own baseline (it runs fine, it is the packer).
        entry["probe_executed"] = True
        ref_rc, ref_out, _ = run_stage(probe_argv(base), cwd=work,
                                       timeout=ALIVE_GRACE, probe=True)
        set_reference(ref_rc, ref_out)
        entry["reference_run"] = {"rc": ref_rc,
                                  "argv": PROBE_ARGS,
                                  "stdout_lines": list(_REF_LINES)}

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
            fr_rc, fr_out, _ = run_stage(probe_argv(work / Path(slayer_out).name),
                                         cwd=work, timeout=probe_timeout(), probe=True)
            slayer_ok = probe_ok(fr_rc, fr_out)
            entry["slayer_output_runnable"] = bool(slayer_ok)
            if not slayer_ok:
                cleaned = list(work.glob("*cleaned*"))
                if cleaned:
                    entry["fallback_output"] = str(cleaned[0])
                    entry["sha256_fallback_output"] = sha256(cleaned[0])
                    # PROBE THE FALLBACK TOO. Promoting de4dot-cleaned on the
                    # strength of the slayer probe alone was a silent false
                    # positive: it was never executed, and its baseline (the
                    # protected binary) already prints its banner, so "some
                    # output" is packer chatter, not evidence.
                    fb_rc, fb_out, _ = run_stage(probe_argv(cleaned[0]),
                                                 cwd=work, timeout=probe_timeout(), probe=True)
                    fb_ok = probe_ok(fb_rc, fb_out)
                    entry["fallback_output_runnable"] = bool(fb_ok)
                    entry["stages"].append({"stage": "de4dot-fallback", "rc": 0,
                                            "runnable": bool(fb_ok),
                                            "final_rc": fb_rc,
                                            "output_tail": (fb_out or "")[-300:],
                                            "note": "slayer output not runnable; "
                                                    "de4dot-cleaned promoted"
                                                    + ("" if fb_ok else
                                                       " (also not runnable)")})
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
                        # THIRD BASE: the de4dot-cleaned module. It is the one
                        # that still STARTS (its cctors were rewritten, not
                        # cut), so it can carry the dumped real bodies where
                        # neither the pristine original nor the slayer module
                        # can. This is the body-level merge the convergence
                        # note asks for, applied to a runnable base.
                        if (entry.get("fallback_output")
                                and Path(entry["fallback_output"]).exists()):
                            bases.append(("cleaned", Path(entry["fallback_output"])))
                        best = None
                        trial_logs = []
                        for bname, bpath in bases:
                            tout = outdir / (src.stem + "_nb_" + bname + src.suffix)
                            tenv = None
                            if bname != "original":
                                # slayer can shift rids and rename symbols —
                                # build a FULL token translation map (all
                                # tables: methods by name/body-fingerprint/
                                # entry anchor, typerefs, fields, memberrefs,
                                # typespecs, standalonesigs, methodspecs)
                                mapf = outdir / ("tokmap_" + bname + ".txt")
                                tbuild = nb_tools["dir"] / "bin" / "Release" / "tokmap_builder.exe"
                                if not tbuild.exists():
                                    run_stage(["dotnet", "build",
                                               str(nb_tools["dir"] / "tokmap_builder.csproj"),
                                               "-c", "Release", "-v", "q", "--nologo"],
                                              cwd=nb_tools["dir"], timeout=600)
                                if tbuild.exists():
                                    run_stage([str(tbuild), str(base), str(bpath),
                                               str(mapf), "--report"],
                                              cwd=work, timeout=600)
                                if mapf.exists():
                                    tenv = dict(os.environ)
                                    tenv["NB_TOKENMAP"] = str(mapf)
                            rc2, out2, dur2 = run_stage([sys.executable, str(nb_tools["auto_stubmap"]),
                                                         str(bpath), str(ddir), str(tout)],
                                                        cwd=work, timeout=900, env=tenv)
                            m = re.search(r"method actually written:\s*(\d+)", out2)
                            mres = int(m.group(1)) if m else -1
                            # PROBE EVERY TRIAL. A merge product is a claim
                            # until it is executed: the "restored" count says
                            # how many bodies were written, not whether the
                            # module still starts.
                            trc, trun = None, ""
                            if tout.exists():
                                trc, trun, _ = run_stage(probe_argv(tout), cwd=outdir,
                                                         timeout=probe_timeout(), probe=True)
                            tout_probe_ok = bool(tout.exists() and probe_ok(trc, trun))
                            trial_logs.append({"base": bname, "rc": rc2, "restored": mres,
                                               "written": tout.exists(),
                                               "written_path": str(tout) if tout.exists() else None,
                                               "final_rc": trc,
                                               "runnable": tout_probe_ok,
                                               "output_tail": (trun or "")[-300:]})
                            # The merge stage reports the BODY-RICHEST product
                            # (that is the recovery claim); picking between
                            # runnable candidates is stage 5's job, and it
                            # sees every trial via `trials`.
                            if tout.exists() and (best is None or mres > best[0]):
                                best = (mres, bname, tout, rc2, out2, dur2, tout_probe_ok)
                        if best is None:
                            best = (-1, bases[0][0], None, 1, "no merge output", 0, False)
                        mrestored, base_used, outexe, rc2, out2, dur2, _best_probe = best
                        mm = re.search(r"modul MethodDef:\s*(\d+)", out2)
                        module_methods = int(mm.group(1)) if mm else None
                        # keep the slayer-base product even when it loses the
                        # trial: it is the runnable-class input (real bodies
                        # + decrypted strings + slayer-clean cctor)
                        slayer_out_exe = next((t["written_path"] for t in trial_logs
                                               if t["base"] == "slayer" and t.get("written_path")), None)
                        entry["stages"].append({"stage": "necrobit-merge", "rc": rc2,
                                                "restored": mrestored,
                                                "slayer_out_exe": slayer_out_exe,
                                                "module_methods": module_methods,
                                                "merge_base": base_used,
                                                "trials": trial_logs,
                                                "secs": round(dur2, 1),
                                                "log_tail": out2[-600:]})
                        if outexe.exists():
                            entry["necrobit_output"] = str(outexe)
                            entry["sha256_necrobit_output"] = sha256(outexe)
                            entry["probe_executed"] = True
                            prc, pout, _ = run_stage(probe_argv(outexe), cwd=outdir,
                                                     timeout=probe_timeout(), probe=True)
                            nb_runnable = probe_ok(prc, pout)
                            entry["necrobit_output_runnable"] = bool(nb_runnable)
                            entry["necrobit_output_probe"] = {"final_rc": prc,
                                                              "output_tail": (pout or "")[-300:]}
                            # hand stage 5 every merge product, not just the
                            # one with the biggest restored count
                            entry["runnable_candidates"] = [
                                {"path": t["written_path"],
                                 "source": "merge-" + t["base"],
                                 "restored": t.get("restored"),
                                 "runnable": bool(t.get("runnable"))}
                                for t in trial_logs if t.get("written_path")]
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
        # Success = the process neither dies with an exception nor falls
        # silent: the verdict is the OS exit status first (the CLR banner is
        # localized, so an English-only text probe reads a crash as success).
        if args.deep and slayer_out and nb_tools["ccfix_exe"].exists():
            # Input preference for the feedback loop. Candidates are ranked by
            # EVIDENCE (a probe that actually executed the file), never by
            # restored-body count: a merged PE carrying 251 real bodies that
            # still faults is worth less than one that opens and runs.
            merged_stage = next((st for st in entry["stages"]
                                 if st.get("stage") == "necrobit-merge"), None)
            # Build candidates from the MERGE TRIAL RECORDS, not from the
            # "best product" pointer: every written merge (original-base,
            # slayer-base, cleaned-base) is its own recovery class, and the
            # body-rich original-base merge is exactly the one that needs the
            # cctor feedback loop. Labelling the single best-product path
            # "merge-original" hid the 254-body merge behind the 2-body shell.
            cands = []
            seen_paths = set()
            for t in (merged_stage or {}).get("trials", []):
                p = t.get("written_path")
                if not p or p in seen_paths:
                    continue
                seen_paths.add(p)
                cands.append(("merge-" + (t.get("base") or "?"), Path(p),
                              t.get("restored") or 0))
            if entry.get("necrobit_output") and entry["necrobit_output"] not in seen_paths:
                seen_paths.add(entry["necrobit_output"])
                cands.append(("merge-best", Path(entry["necrobit_output"]),
                              merged_stage.get("restored") if merged_stage else 0))
            if entry.get("fallback_output_runnable") and entry.get("fallback_output"):
                # the slayer output crashes and the promoted de4dot-cleaned
                # candidate PROBED OK: that is the runnable-class input, not
                # the crashed slayer file. It carries no recovered bodies of
                # its own - recorded as 0, so stage 5 can tell a real
                # body-recovery apart from "a runnable shell was found".
                cands.append(("de4dot-cleaned", Path(entry["fallback_output"]), 0))
            cands.append(("slayer", Path(entry["slayer_output"]), 0))
            work5 = work / "runfix"
            work5.mkdir(exist_ok=True)
            # EVERY candidate goes through the free-call feedback loop, richest
            # body count FIRST. The point of the loop is to make the body-rich
            # merge runnable (the x64 class needed exactly this: the 254-body
            # merge carries the real Main, the 2-body cleaned shell only
            # prints its banner). Stopping at the first candidate that merely
            # opens would settle for the shell and never try the real thing.
            trials5 = []
            for nm, p, rs in sorted(cands, key=lambda c: -(c[2] or 0)):
                if p is None or not Path(p).exists():
                    continue
                # CHEAP PATH FIRST: a candidate that already runs needs no
                # ccfix loop at all. Probing before copying keeps the loop
                # budget for the candidates that actually fault.
                entry["probe_executed"] = True
                q_rc, q_out, _ = run_stage(probe_argv(p), cwd=work5,
                                           timeout=probe_timeout(), probe=True)
                if probe_ok(q_rc, q_out):
                    trials5.append({"candidate": nm, "restored": rs,
                                    "iterations": [], "final_rc": q_rc,
                                    "runnable": True, "output": str(p),
                                    "output_tail": (q_out or "")[-400:]})
                    continue
                cur = work5 / (nm + "_" + Path(p).name)
                shutil.copy2(p, cur)
                iters = []
                rc5, out5 = q_rc, q_out
                for it in range(6):
                    entry["probe_executed"] = True
                    rc5, out5, _ = run_stage(probe_argv(cur), cwd=work5,
                                             timeout=probe_timeout(), probe=True)
                    if probe_ok(rc5, out5):
                        break
                    # the culprit is always the protected module's own top
                    # frame; probe_top_frame skips BCL frames and the
                    # localized exception header line
                    full = probe_top_frame(out5) or ""
                    meth = full.split(".")[-1].strip() if full else None
                    if not meth:
                        break
                    nxt = work5 / (cur.stem + f"_r{len(iters) + 1}" + cur.suffix)
                    rc, outc, _ = run_stage([str(nb_tools["ccfix_exe"]), "fix",
                                             str(cur), str(nxt), meth, "all"],
                                            cwd=work5, timeout=300)
                    iters.append({"method": meth, "rc": rc,
                                  "log_tail": outc[-200:]})
                    if rc != 0:
                        break
                    cur = nxt
                ok5 = probe_ok(rc5, out5)
                cur_out = cur if ok5 else None
                trials5.append({"candidate": nm, "restored": rs,
                                "iterations": iters, "final_rc": rc5,
                                "runnable": bool(ok5),
                                "output": str(cur_out) if cur_out else None,
                                "output_tail": (out5 or "")[-400:]})
            # winner = the runnable candidate that carries the MOST recovered
            # bodies; a shell that opens but recovered almost nothing loses
            win5 = max((t for t in trials5 if t["runnable"]),
                       key=lambda t: (t["restored"] or 0), default=None)
            runnable = win5 is not None
            rc5 = win5["final_rc"] if win5 else (trials5[-1]["final_rc"]
                                                 if trials5 else None)
            out5 = win5["output_tail"] if win5 else (trials5[-1]["output_tail"]
                                                     if trials5 else "")
            iters = win5["iterations"] if win5 else []
            src5_restored = (win5["restored"] or 0) if win5 else 0
            if win5:
                entry["stage5_input"] = win5["candidate"]
                entry["stage5_input_restored"] = src5_restored
            # convergence note: when the same top frame repeats without a
            # cuttable caller, the blocker is inside the method body itself
            # (e.g. a call to a member the base module no longer has) - that
            # needs a string/body-level merge, not more call cuts
            meths = [i["method"] for i in iters]
            note = None
            if not runnable and meths and meths[-1] in meths[:-1]:
                note = ("fixed point: top frame " + meths[-1] +
                        " repeats - its own body references a member the base "
                        "module lost; needs body-level merge")
            stage5 = {"stage": "runnable-recovery", "trials": trials5,
                      "iterations": iters,
                      "final_rc": rc5, "runnable": bool(runnable),
                      "convergence_note": note,
                      "output_tail": out5}
            if runnable:
                cur = Path(win5["output"])
                entry["runnable_output"] = str(cur)
                entry["sha256_runnable_output"] = sha256(cur)
                # HOW MUCH of the recovery is actually inside the runnable
                # file? A runnable shell with 2 written bodies is not the same
                # claim as a runnable merge carrying most of the dump, so the
                # two get different result labels.
                bodies = next((st.get("bodies") for st in entry["stages"]
                               if st.get("stage") == "necrobit-jitdump"), None) or 0
                entry["runnable_output_restored"] = src5_restored
                entry["runnable_body_share"] = (round(src5_restored / bodies, 3)
                                                if bodies else None)
                if src5_restored and (not bodies or src5_restored / bodies >= 0.25):
                    entry["result"] = "run-recovered"
                else:
                    entry["result"] = "run-recovered-base-only"
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
