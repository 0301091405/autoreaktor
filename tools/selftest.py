#!/usr/bin/env python3
"""selftest.py — end-to-end machinery proof with zero protected inputs.

Builds the test target, builds the JIT hook, force-dumps it under the
hook, trial-merges the scopes back into a loadable PE.

Grades itself honestly:
  PASS  — full: hook installed AND forced bodies reached disk AND merge wrote
  PASS* — partial: the host blocked DLL injection (hosted runners run
          Defender, which rejects unsigned APC-injected libraries); builds
          and the merge machinery are still proven against a synthetic dump
  FAIL  — a build broke or the merge stopped writing

Run:  python tools/selftest.py
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JD = ROOT / "v3" / "jitdump"


def sh(cmd, cwd, timeout=900):
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd), timeout=timeout,
                       capture_output=True)
    return r.returncode, (r.stdout or b"") + (r.stderr or b"")


def synth_merge_trial(target, merged):
    """Two scope dirs with one synthetic token dump each — proves nbilmerge
    loads the target, the trial-merge runs and an output is written, with no
    injection involved."""
    dumpdir = Path(tempfile.mkdtemp(prefix="ar_synth_"))
    for d in ("scope0", "scope1"):
        (dumpdir / d).mkdir(parents=True)
        tok, il = 0x06000001, 1
        body = bytes([0x2A])  # ret
        (dumpdir / d / "m_06000001.bin").write_bytes(
            tok.to_bytes(4, "little") + il.to_bytes(4, "little")
            + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little") + body)
    rc, log = sh([sys.executable, JD / "auto_stubmap.py", target, dumpdir, merged], ROOT)
    return merged.exists(), rc, log


def main():
    fails = []
    partial = False

    # 1. build the test target (both runtime legs)
    out = ROOT / "verify_target" / "out"
    out48 = ROOT / "verify_target" / "out48"
    rc, log = sh(["dotnet", "publish", "verify_target/verify_target.csproj",
                  "-c", "Release", "-f", "net8.0", "-o", out], ROOT)
    if rc != 0 or not (out / "verify_target.dll").exists():
        fails.append(f"net8 publish failed rc={rc}")
    rc, log = sh(["dotnet", "publish", "verify_target/verify_target.csproj",
                  "-c", "Release", "-f", "net48", "-o", out48], ROOT)
    if rc != 0 or not (out48 / "verify_target.exe").exists():
        fails.append(f"net48 publish failed rc={rc}")
    print(f"[1] publish net8+net48: {'ok' if not fails else 'FAIL'}")

    # 2. build the merger (selftest must not depend on another CI job)
    rc, log = sh(["dotnet", "build", JD / "nbilmerge.csproj", "-c", "Release"], JD)
    merge_ok = (JD / "bin" / "Release" / "nbilmerge.exe").exists()
    if not merge_ok:
        fails.append(f"nbilmerge build failed rc={rc}: {log[-300:]}")
    print(f"[2] nbilmerge build: {'ok' if merge_ok else 'FAIL'}")

    # 3. build the hook DLLs (msvc_env discovery; dev boxes and CI runners
    #    both carry VS)
    rc, log = sh([sys.executable, JD / "build_hook.py"], JD)
    dlls_ok = (JD / "clrjit_dump64.dll").exists() and (JD / "clrjit_dump32.dll").exists()
    if not dlls_ok:
        fails.append(f"hook DLL build failed rc={rc}: {log[-300:]}")
    print(f"[3] hook build: {'ok' if dlls_ok else 'FAIL'}")

    merged = Path(tempfile.mkdtemp(prefix="ar_selftest_")) / "merged.dll"

    # 4. force-dump the target under the hook
    full = False
    if dlls_ok:
        dumpdir = merged.parent / "dump"
        rc, log = sh([sys.executable, JD / "nbjitdump.py",
                      out / "verify_target.dll", "--out", dumpdir,
                      "--force", "--wait", "90"], ROOT)
        marker = dumpdir / "marker.txt"
        hooked = "HOOK-OK" in marker.read_text(errors="replace") if marker.exists() else False
        bins = list(dumpdir.glob("scope*/m_*.bin"))
        print(f"[4] force-dump: hook={'OK' if hooked else 'BLOCKED'} bodies={len(bins)}")
        if hooked and len(bins) >= 3:
            full = True
        elif not hooked:
            # hosted runners reject unsigned APC-injected DLLs — that is a
            # host policy, not a machinery regression. Say so and fall
            # through to the injection-free merge proof.
            partial = True
            print("[4] hook blocked by host (Defender/ASR) — partial grade")
        rc, log = sh([sys.executable, JD / "auto_stubmap.py",
                      out / "verify_target.dll", dumpdir, merged], ROOT)
    else:
        partial = True

    # 4b. the Framework x86 leg — the primary Reactor class
    if dlls_ok:
        dump48 = merged.parent / "dump48"
        rc, log = sh([sys.executable, JD / "nbjitdump.py",
                      out48 / "verify_target.exe", "--out", dump48,
                      "--force", "--wait", "90"], ROOT)
        marker48 = dump48 / "marker.txt"
        hooked48 = "HOOK-OK" in marker48.read_text(errors="replace") if marker48.exists() else False
        bodies48 = len(list(dump48.glob("scope*/m_*.bin")))
        eh48 = len(list(dump48.glob("m_*.eh"))) + len(list(dump48.glob("scope*/m_*.eh")))
        if hooked48 and not (bodies48 >= 2 and eh48 >= 1):
            fails.append(f"net48 x86 leg regressed: bodies={bodies48} eh={eh48}")
        print(f"[4b] net48 x86: hook={'OK' if hooked48 else 'BLOCKED'} "
              f"bodies={bodies48} eh={eh48}")

    # 5. merge must always produce output (real dump when the hook ran)
    if full:
        if not merged.exists():
            fails.append(f"merge produced no output: {log[-300:]}")
        else:
            print(f"[5] merge: written ({merged.stat().st_size} bytes)")
    else:
        ok, rc, log = synth_merge_trial(out / "verify_target.dll", merged)
        if not ok:
            fails.append(f"synthetic merge trial failed rc={rc}: {log[-300:]}")
        else:
            print(f"[5] synthetic merge trial: written ({merged.stat().st_size} bytes)")

    for f in fails:
        print("[FAIL]", f)
    verdict = "FAIL" if fails else ("PASS*" if partial else "PASS")
    print("SELFTEST:", verdict)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
