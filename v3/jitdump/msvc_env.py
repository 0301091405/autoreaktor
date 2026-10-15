"""msvc_env.py — locate the newest MSVC toolchain + Windows SDK at runtime.

build_hook.py and nbjitdump.py both need cl.exe with INCLUDE/LIB set. No two
dev boxes carry the same versions, and the old hardcoded
"14.44.35207 / 10.0.26100.0" paths only ever worked on one machine.

Discovery order (first hit wins):
  1. vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64
  2. glob over the two standard VS roots, highest MSVC version directory
Windows SDK: glob %ProgramFiles(x86)%\\Windows Kits\\10\\Include\\10.*,
highest version that carries um/ and ucrt/. The matching Lib\\ tree is used
for LIB (Include and Lib version dirs are siblings under the "10" root).
"""
import glob
import os
import subprocess


def _program_files_x86():
    return os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")


def _vswhere_instance():
    vswhere = os.path.join(_program_files_x86(),
                           "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if not os.path.exists(vswhere):
        return None
    try:
        r = subprocess.run(
            [vswhere, "-latest", "-products", "*",
             "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath"],
            capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and os.path.isdir(line):
                return line
    except Exception:
        pass
    return None


def _version_key(path):
    parts = []
    for x in os.path.basename(path.rstrip("\\/")).split("."):
        try:
            parts.append((0, int(x), ""))
        except ValueError:
            parts.append((1, 0, x))
    return parts


def find_msvc():
    """Return the newest .../VC/Tools/MSVC/<ver> root carrying Hostx64 cl.exe."""
    patterns = []
    inst = _vswhere_instance()
    if inst:
        patterns.append(os.path.join(inst, "VC", "Tools", "MSVC", "*"))
    pf = _program_files_x86()
    pf64 = os.environ.get("ProgramFiles", r"C:\Program Files")
    for root in (pf, pf64):
        patterns.append(os.path.join(root, "Microsoft Visual Studio", "*",
                                     "*", "VC", "Tools", "MSVC", "*"))
        patterns.append(os.path.join(root, "Microsoft Visual Studio", "*",
                                     "VC", "Tools", "MSVC", "*"))
    hits = []
    seen = set()
    for pat in patterns:
        for d in glob.glob(pat):
            if d in seen:
                continue
            seen.add(d)
            if os.path.exists(os.path.join(d, "bin", "Hostx64", "x64", "cl.exe")):
                hits.append(d)
    if not hits:
        return None
    hits.sort(key=_version_key, reverse=True)
    return hits[0]


def find_sdk():
    """Return the newest Windows Kits 10 Include/<ver> dir with um/ + ucrt/."""
    base = os.path.join(_program_files_x86(), "Windows Kits", "10", "Include", "10.*")
    hits = [d for d in glob.glob(base)
            if os.path.isdir(os.path.join(d, "um")) and os.path.isdir(os.path.join(d, "ucrt"))]
    if not hits:
        return None
    hits.sort(key=_version_key, reverse=True)
    return hits[0]


def toolchain_env(arch="x64"):
    """(cl_path, env) for cl.exe at the given bitness, or (None, None)."""
    msvc = find_msvc()
    sdk_inc = find_sdk()
    if not msvc or not sdk_inc:
        return None, None
    host = "Hostx64" if arch == "x64" else "Hostx86"
    archdir = "x64" if arch == "x64" else "x86"
    cl = os.path.join(msvc, "bin", host, archdir, "cl.exe")
    if not os.path.exists(cl):
        return None, None
    # Include\\10.0.x.y -> Lib\\10.0.x.y (sibling version dirs)
    lib_root = sdk_inc.replace(os.sep + "Include" + os.sep, os.sep + "Lib" + os.sep)
    env = dict(os.environ)
    env["INCLUDE"] = ";".join([
        os.path.join(msvc, "include"),
        os.path.join(sdk_inc, "ucrt"),
        os.path.join(sdk_inc, "um"),
        os.path.join(sdk_inc, "shared"),
    ])
    env["LIB"] = ";".join([
        os.path.join(msvc, "lib", archdir),
        os.path.join(lib_root, "ucrt", archdir),
        os.path.join(lib_root, "um", archdir),
    ])
    env["PATH"] = os.path.dirname(cl) + ";" + env["PATH"]
    return cl, env
