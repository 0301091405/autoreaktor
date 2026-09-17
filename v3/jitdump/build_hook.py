# build_hook.py: compile clrjit_hook.cpp -> clrjit_dump{32,64}.dll
import os, subprocess, sys

MSVC = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
WK = r"C:\Program Files (x86)\Windows Kits\10"
HERE = os.path.dirname(os.path.abspath(__file__))

def build(arch):
    if arch == "x86":
        cl = MSVC + r"\bin\Hostx64\x86\cl.exe"
        lib = ";".join([MSVC + r"\lib\x86", WK + r"\Lib\10.0.26100.0\ucrt\x86", WK + r"\Lib\10.0.26100.0\um\x86"])
        out = os.path.join(HERE, "clrjit_dump32.dll")
    else:
        cl = MSVC + r"\bin\Hostx64\x64\cl.exe"
        lib = ";".join([MSVC + r"\lib\x64", WK + r"\Lib\10.0.26100.0\ucrt\x64", WK + r"\Lib\10.0.26100.0\um\x64"])
        out = os.path.join(HERE, "clrjit_dump64.dll")
    env = dict(os.environ)
    env["INCLUDE"] = ";".join([MSVC + r"\include", WK + r"\Include\10.0.26100.0\ucrt",
                               WK + r"\Include\10.0.26100.0\um", WK + r"\Include\10.0.26100.0\shared"])
    env["LIB"] = lib
    env["PATH"] = os.path.dirname(cl) + ";" + env["PATH"]
    src = os.path.join(HERE, "clrjit_hook.cpp")
    r = subprocess.run([cl, "/nologo", "/O2", "/LD", src, "/Fe:" + out, "/link"],
                       capture_output=True, cwd=HERE, env=env)
    print(arch, "->", out, "rc=%d" % r.returncode)
    if r.returncode != 0:
        print((r.stdout or b"").decode("mbcs", "replace")[-800:])
        print((r.stderr or b"").decode("mbcs", "replace")[-800:])
        return False
    return os.path.exists(out)

ok1 = build("x64")
ok2 = build("x86")
print("DONE x64=%s x86=%s" % (ok1, ok2))
sys.exit(0 if (ok1 and ok2) else 1)