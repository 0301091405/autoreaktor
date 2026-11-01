#!/usr/bin/env python3
"""t9_remeasure.py — re-measure the T9 hybrid claim and store the evidence.

T-MATRIX.md row T9 describes a hybrid run (real-token bodies transplanted into
the Slayer module for `verify_forms`) and cites `report.json` + hybrid run logs
as its evidence. Those artifacts are not in the repository, so the row cannot be
reproduced from a clean checkout. This driver regenerates them:

    python tools/t9_remeasure.py [--outdir v3/multi-target/T9]

It builds the repo's own `verify_forms` target (WinForms net48 x86), protects it
with the full Reactor flag set, runs the deep chain with --keep-work, and copies
the resulting report.json plus a plain-text summary into the outdir.

Windows only: it needs the .NET Reactor console and a Framework runtime.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from matrix import FLAGSETS, find_reactor, sh  # noqa: E402


def build_target(work):
    """Build the repo's verify_forms project (the T9 target) in place."""
    proj = ROOT / "verify_forms" / "verify_forms.csproj"
    rc, log = sh(["dotnet", "build", str(proj), "-c", "Release"], ROOT)
    if rc != 0:
        return None, log
    hits = list((ROOT / "verify_forms").rglob("verify_forms.exe"))
    hits = [h for h in hits if "Release" in str(h)]
    if not hits:
        return None, log
    dst = work / "verify_forms.exe"
    shutil.copy2(hits[0], dst)
    return dst, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=str(ROOT / "v3" / "multi-target" / "T9"))
    args = ap.parse_args()
    if os.name != "nt":
        print("t9_remeasure: Windows only")
        return 1

    rcon = find_reactor()
    if not rcon:
        print("t9_remeasure: Reactor console not found (set REACTOR_CONSOLE)")
        return 1

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="ar_t9_"))
    t0 = time.time()
    summary = {"target": "verify_forms", "reactor": str(rcon)}

    exe, log = build_target(work)
    if exe is None:
        print("t9_remeasure: build failed")
        print(log.decode("utf-8", "replace")[-600:])
        return 1
    summary["build"] = "ok"
    print("[1] verify_forms built")

    rc, plog = sh([rcon, "-file", str(exe), "-nodialog", "-q"] + FLAGSETS["full"], work)
    target = work / "verify_forms_Secure" / "verify_forms.exe"
    if not target.exists():
        hits = [h for h in work.rglob("verify_forms*.exe") if "_Secure" in str(h)]
        target = hits[0] if hits else None
    if target is None:
        print("t9_remeasure: protection failed")
        print(plog.decode("utf-8", "replace")[-600:])
        return 1
    summary["protect"] = {"rc": rc, "path": str(target),
                          "bytes": target.stat().st_size}
    print("[2] protected:", target.stat().st_size, "bytes")

    env = dict(os.environ)
    # verify_forms is a GUI: it never exits, so the oracle judges candidates on
    # staying alive (ALIVE_GRACE), not on a full console timeout.
    env.pop("AR_PROBE_ARGS", None)
    rc, clog = sh([sys.executable, str(ROOT / "autoreaktor.py"), "--deep",
                   "--keep-work", str(target)], work, timeout=3600, env=env)
    text = clog.decode("utf-8", "replace")
    summary["chain_rc"] = rc
    summary["chain_tail"] = text[-4000:]
    print("[3] chain rc:", rc)

    report = target.parent / "_ar_out" / "report.json"
    if report.exists():
        shutil.copy2(report, outdir / "report.json")
        data = json.loads(report.read_text(encoding="utf-8"))
        files = data.get("files", [])
        if files:
            stages = files[0].get("stages", [])
            summary["stages"] = [
                {k: v for k, v in s.items() if k != "log_tail"} for s in stages]
            summary["result"] = files[0].get("result")
            summary["runnable_output"] = files[0].get("runnable_output")
        print("[4] report.json copied")
    else:
        print("[4] no report.json produced")

    summary["secs"] = round(time.time() - t0, 1)
    (outdir / "summary.json").write_text(
        json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    (outdir / "run.log").write_text(text, encoding="utf-8")
    print("[5] wrote", outdir / "summary.json")
    print("    result:", summary.get("result"), "| runnable:",
          bool(summary.get("runnable_output")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
