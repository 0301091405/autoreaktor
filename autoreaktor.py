#!/usr/bin/env python3
"""autoreaktor.py v2.1 — the Reactor pipeline.

Stage 0  hunt       — classify .NET assemblies (clean/carrier/runtime/protected)
Stage 1  de4dot     — partial cleanup (relative-path invocation)
Stage 2  Slayer     — antitamper/cflow/proxy/inline on the ORIGINAL file
Stage 3  Krypton    — VM devirtualization ON THE SLAYED OUTPUT (the verified
                      chain order; KRYPTON_FORCE_VM_MAP="0x75=Call" is applied
                      automatically for virtualized targets)

Usage:
  python autoreaktor.py <dir|file> [--dry-run] [--deep] [--keep-work]

v2.1 changes:
- CHAIN ORDER FIX (the big one): Krypton now runs on the Slayer output, not the
  original. Verified on the Tuts4You Reactor 7.3 challenge: original→Krypton
  stalls with unknown VM opcode 0x75 and dies with a NullReferenceException in
  its own logger; Slayer→Krypton recovers 3/3 virtualized methods (47 + 2,852
  + 872 instructions) and replaces the registration-check method body.
- KRYPTON_FORCE_VM_MAP=0x75=Call is exported automatically for the Krypton
  stage (upstream env override; the semantic validator prunes this mapping over
  a 1-in-152 operand edge case).
- de4dot stage stays first but its output is still treated as PARTIAL —
  feeding de4dot output to Krypton breaks the resource parser (verified).
- Exit classification: 'krypton-devirt' when Krypton recompiled ≥1 VM method,
  'slayer-clean' when only Slayer ran, 'incomplete' otherwise.
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

VERSION = "2.1"
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


def run_stage(cmd, cwd, timeout=600, env=None):
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, env=env)
        out = (r.stdout or b"") + (r.stderr or b"")
        return r.returncode, out.decode("utf-8", "replace"), time.time() - t0
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT", time.time() - t0
    except Exception as e:
        return 125, f"SPAWN-ERROR {e}", time.time() - t0


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--deep", action="store_true", help="run Slayer + Krypton stages")
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()

    tgt = Path(args.target).resolve()
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
    outroot = tgt / "_ar_out" if tgt.is_dir() else tgt.parent / "_ar_out"
    outroot.mkdir(exist_ok=True)

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

        # ---- stage 1: de4dot (partial pre-clean, relative path invocation)
        de4dot = find_tool("de4dot.exe")
        if de4dot:
            rc, out, dur = run_stage([de4dot, base.name], cwd=work)
            cleaned = list(work.glob("*cleaned*"))
            entry["stages"].append({"stage": "de4dot", "rc": rc, "secs": round(dur, 1),
                                    "log_tail": out[-600:],
                                    "partial_output": str(cleaned[0]) if cleaned else ""})

        # ---- stage 2: Slayer on the ORIGINAL (verified: de4dot output breaks decrypter init)
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
                entry["slayer_output"] = str(slayed[0])
                entry["sha256_slayer_output"] = sha256(slayed[0])

        # ---- stage 3: Krypton VM devirtualization on the SLAYED output
        # (verified chain order on the Reactor 7.3 challenge: original→Krypton
        # stalls on unknown opcode 0x75 + logger NRE; Slayer→Krypton recovers
        # 3/3 virtualized methods)
        if args.deep and krypton and entry.get("slayer_output"):
            kdir = work / "krypton"
            kdir.mkdir(exist_ok=True)
            slayed_name = Path(entry["slayer_output"]).name
            shutil.copy2(entry["slayer_output"], kdir / slayed_name)
            # upstream env override: pin opcode 0x75=Call (the semantic
            # validator prunes this mapping over a 1-in-152 operand edge case)
            env = dict(os.environ)
            env.setdefault("KRYPTON_FORCE_VM_MAP", "0x75=Call")
            rc, out, dur = run_stage([krypton, slayed_name, "--no-pause"],
                                     cwd=kdir, timeout=1800, env=env)
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

        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        report["files"].append(entry)
        print(f"    -> {entry['result']}")

    (outroot / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    ok = sum(1 for e in report["files"] if e["result"] != "incomplete")
    print(f"[*] done: {ok}/{len(files)} processed. report: {outroot / 'report.json'}")
    return 0


if __name__ == "__main__":
    main()
