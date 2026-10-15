# build_hook.py: compile clrjit_hook.cpp -> clrjit_dump{32,64}.dll
# Toolchain is discovered at runtime (vswhere/glob) via msvc_env —
# no hardcoded MSVC/SDK versions.
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from msvc_env import toolchain_env


def build(arch):
    cl, env = toolchain_env(arch)
    if not cl:
        print("[!] no MSVC x86/x64 toolchain + Windows SDK found (arch=%s). "
              "Install VS BuildTools with the VC++ workload, or check vswhere." % arch)
        return False
    out = os.path.join(HERE, "clrjit_dump32.dll" if arch == "x86" else "clrjit_dump64.dll")
    src = os.path.join(HERE, "clrjit_hook.cpp")
    r = subprocess.run([cl, "/nologo", "/O2", "/LD", src, "/Fe:" + out, "/link"],
                       capture_output=True, cwd=HERE, env=env)
    print(arch, "->", out, "rc=%d" % r.returncode)
    if r.returncode != 0:
        print((r.stdout or b"").decode("mbcs", "replace")[-800:])
        print((r.stderr or b"").decode("mbcs", "replace")[-800:])
        return False
    return os.path.exists(out)


if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else None
    if only in ("x86", "x64"):
        ok = build(only)
        print("DONE %s=%s" % (only, ok))
        sys.exit(0 if ok else 1)
    ok1 = build("x64")
    ok2 = build("x86")
    print("DONE x64=%s x86=%s" % (ok1, ok2))
    sys.exit(0 if (ok1 and ok2) else 1)
