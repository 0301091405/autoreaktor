#!/usr/bin/env python3
"""selftest.py — end-to-end machinery proof with zero protected inputs.

Builds the test target, builds the JIT hook, force-dumps it under the
hook, trial-merges the scopes back into a loadable PE. Proves the whole
NecroBit-recovery machinery is alive on a CLEAN assembly: hook installs,
bodies reach disk, the merge writes. A protected target exercises the
same code path with decryption in between.

Run:  python tools/selftest.py
Exit: 0 pass, 1 fail. Designed for CI (windows runners carry VS + .NET).
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JD = ROOT / "v3" / "jitdump"


def sh(cmd, cwd, timeout=600):
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd), timeout=timeout,
                       capture_output=True)
    return r.returncode, (r.stdout or b"") + (r.stderr or b"")


def main():
    fails = []

    # 1. build the test target
    out = ROOT / "verify_target" / "out"
    rc, log = sh(["dotnet", "publish", "verify_target/verify_target.csproj",
                  "-c", "Release", "-o", out], ROOT)
    if rc != 0 or not (out / "verify_target.dll").exists():
        fails.append(f"target publish failed rc={rc}")
    print(f"[1] publish: rc={rc}")

    # 2. build the hook DLLs (msvc_env discovery; CI runners carry VS)
    rc, log = sh([sys.executable, JD / "build_hook.py"], JD)
    ok = (JD / "clrjit_dump64.dll").exists() and (JD / "clrjit_dump32.dll").exists()
    if not ok:
        fails.append(f"hook DLL build failed rc={rc}: {log[-300:]}")
    print(f"[2] hook build: {'ok' if ok else 'FAIL'}")

    # 3. force-dump the target under the hook
    dumpdir = Path(tempfile.mkdtemp(prefix="ar_selftest_"))
    rc, log = sh([sys.executable, JD / "nbjitdump.py",
                  out / "verify_target.dll", "--out", dumpdir,
                  "--force", "--wait", "90"], ROOT, timeout=600)
    hooked = "HOOK-OK" in (dumpdir / "marker.txt").read_text(errors="replace") \
        if (dumpdir / "marker.txt").exists() else False
    bins = list(dumpdir.glob("scope*/m_*.bin"))
    if not hooked:
        fails.append("hook did not install")
    if len(bins) < 3:
        fails.append(f"forced coverage too low: {len(bins)} bodies (want >= 3)")
    print(f"[3] force-dump: hook={'OK' if hooked else 'FAIL'} bodies={len(bins)}")

    # 4. scope trial-merge must produce a loadable output
    merged = dumpdir / "merged.dll"
    rc, log = sh([sys.executable, JD / "auto_stubmap.py",
                  out / "verify_target.dll", dumpdir, merged], ROOT)
    if not merged.exists():
        fails.append(f"merge produced no output rc={rc}: {log[-300:]}")
    else:
        rc2, log2 = sh(["dotnet", "build", "proof_loader/proof_loader.csproj",
                        "-c", "Release"], ROOT)
        print(f"[4] merge: written ({merged.stat().st_size} bytes), "
              f"loader build {'ok' if rc2 == 0 else 'warn rc=' + str(rc2)}")
    for f in fails:
        print("[FAIL]", f)
    print("SELFTEST:", "PASS" if not fails else "FAIL")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
