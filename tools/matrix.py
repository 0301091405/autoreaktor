#!/usr/bin/env python3
"""matrix.py — the universality harness.

Generates a DIVERSE corpus of test targets (runtimes x architectures x
app shapes x flag combos), protects every one with the .NET Reactor demo
console, runs the full AutoReaktor chain on each, and prints/writes the
result matrix. The project's universality claim is this file: anyone with
the free demo can reproduce the whole matrix, and any regression on any
cell is visible.

No sample is privileged: sources are generated, flags are enumerated, the
chain receives zero per-target hints. Add a row by adding a template.

Usage:
  python tools/matrix.py [--outdir DIR] [--quick]

  --quick   4 cells instead of the full grid (one per runtime x shape)

Requires: .NET SDK, the .NET Reactor demo console (auto-discovered from
%USERPROFILE%\\Desktop\\reactor75 or $REACTOR_CONSOLE), Windows.
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

# ---------------------------------------------------------------------------
# sample templates: (name, kind, tfm, platform, extra-files)
# Each covers a different real-world shape; combined with the flag sets below
# they span the matrix without privileging any single sample.

CONSOLE_SRC = r'''
using System;
class Program {
    const string MARK = "MK-{NAME}-7E5";
    static int Main(string[] args) {
        Console.WriteLine("alive: {NAME}");
        int acc = 0;
        try {
            for (int i = 0; i < 12; i++) acc += i * (i + 1);
            if (args.Length > 0 && args[0] == "dump") Console.WriteLine(MARK);
        } catch (Exception ex) { Console.WriteLine("unexpected " + ex.Message); return 2; }
        finally { acc += 0; }
        return acc == 264 ? 0 : 1;
    }
    static int Helper(int x) { try { return x * 2; } catch { return -1; } }
}
'''

GENERIC_SRC = r'''
using System;
using System.Collections.Generic;
class Store<T> {
    List<T> items = new List<T>();
    public void Add(T x) { items.Add(x); }
    public int Count() { try { return items.Count; } catch { return -1; } }
}
class Program {
    delegate int Fn(int a, int b);
    static int Add(int a, int b) { return a + b; }
    static int Main() {
        var s = new Store<int>();
        for (int i = 0; i < 5; i++) s.Add(i);
        Fn f = Add;
        int r = f(2, 3) + s.Count();
        Console.WriteLine("gen-result " + r);
        return r == 12 ? 0 : 1;
    }
}
'''

FORMS_SRC = r'''
using System;
using System.Windows.Forms;
class MainForm : Form {
    public MainForm() {
        Text = "{NAME}";
        var b = new Button { Text = "ok", Left = 10, Top = 10 };
        b.Click += (s, e) => MessageBox.Show("clicked {NAME}");
        Controls.Add(b);
    }
}
static class Program {
    [STAThread]
    static void Main() {
        Application.EnableVisualStyles();
        Application.Run(new MainForm());
    }
}
'''

SAMPLES = [
    # (name, kind, tfm, platform)
    ("con48x86",  "console", "net48", "x86"),
    ("con48x64",  "console", "net48", "x64"),
    ("con8",      "console", "net8.0", "AnyCPU"),
    ("gen48x86",  "generic", "net48", "x86"),
    ("forms48x86", "forms",  "net48", "x86"),
]

FLAGSETS = {
    "necro":   ["-necrobit", "1"],
    "full":    ["-necrobit", "1", "-stringencryption", "1", "-antitamp", "1",
                "-antidebug", "1", "-control_flow", "1", "-flow_level", "9",
                "-obfuscation", "1", "-resourceencryption", "1",
                "-suppressildasm", "1", "-hide_calls", "1"],
}

PROJ = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>{outtype}</OutputType>
    <TargetFramework>{tfm}</TargetFramework>
    <PlatformTarget>{platform}</PlatformTarget>
    <LangVersion>7.3</LangVersion>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>{name}</AssemblyName>{usewf}
  </PropertyGroup>
</Project>
'''


def sh(cmd, cwd, timeout=900):
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd), timeout=timeout,
                       capture_output=True)
    return r.returncode, (r.stdout or b"") + (r.stderr or b"")


def find_reactor():
    p = os.environ.get("REACTOR_CONSOLE")
    if p and Path(p).exists():
        return Path(p)
    for base in (Path.home() / "Desktop" / "reactor75",
                 Path(r"C:\Program Files (x86)\Eziriz\.NET Reactor"),
                 Path(r"C:\Program Files\Eziriz\.NET Reactor")):
        exe = base / "dotNET_Reactor.Console.exe"
        if exe.exists():
            return exe
    return None


def build_sample(work, name, kind, tfm, platform):
    src = CONSOLE_SRC.replace("{NAME}", name)
    if kind == "generic":
        src = GENERIC_SRC
    elif kind == "forms":
        src = FORMS_SRC.replace("{NAME}", name)
    sdir = work / name
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / f"{name}.cs").write_text(src, encoding="utf-8")
    usewf = "\n    <UseWindowsForms>true</UseWindowsForms>" if kind == "forms" else ""
    outtype = "WinExe" if kind == "forms" else "Exe"
    (sdir / f"{name}.csproj").write_text(
        PROJ.format(outtype=outtype, tfm=tfm, platform=platform,
                    name=name, usewf=usewf), encoding="utf-8")
    if tfm == "net8.0":
        (sdir / f"{name}.runtimeconfig.json").write_text("", encoding="utf-8")
    rc, log = sh(["dotnet", "build", f"{name}.csproj", "-c", "Release"], sdir)
    exe = sdir / "bin" / "Release" / (tfm if tfm != "net8.0" else "") / f"{name}.exe"
    if not exe.exists():
        hits = list(sdir.rglob(f"{name}.exe"))
        exe = hits[0] if hits else None
    return (rc == 0 and exe is not None), exe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=str(ROOT / "matrix_out"))
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if sys.platform != "win32":
        print("matrix: Windows only")
        return 1

    rcon = find_reactor()
    if not rcon:
        print("matrix: .NET Reactor demo console not found "
              "(set REACTOR_CONSOLE or install to Desktop\\reactor75)")
        return 1
    print(f"[matrix] reactor console: {rcon}")

    work = Path(tempfile.mkdtemp(prefix="ar_matrix_"))
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    rows = []
    combos = []
    for (name, kind, tfm, platform) in SAMPLES:
        for fs in (["necro", "full"] if not args.quick else ["full"]):
            combos.append((name, kind, tfm, platform, fs))
    if args.quick:
        seen = set()
        combos = [c for c in combos if not (c[0] in seen or seen.add(c[0]))]

    for (name, kind, tfm, platform, fs) in combos:
        cell = f"{name}|{fs}"
        print(f"\n=== {cell} ===")
        ok, exe = build_sample(work, name, kind, tfm, platform)
        if not ok:
            rows.append({"cell": cell, "result": "BUILD-FAIL"})
            print("  build failed")
            continue
        # the demo ignores -output; it always writes <stem>_Secure next to
        # the input — give each combo its own directory to avoid collisions
        pbase = work / f"{name}_{fs}"
        pbase.mkdir(parents=True, exist_ok=True)
        # net8: the managed module is the .dll (the exe is a native apphost);
        # Framework: the exe IS the managed module
        if tfm == "net8.0":
            payload = pbase / f"{name}.dll"
            shutil.copy2(exe.parent / f"{name}.dll", payload)
        else:
            payload = pbase / exe.name
            shutil.copy2(exe, payload)
        rc, log = sh([rcon, "-file", str(payload), "-nodialog", "-q"] +
                     FLAGSETS[fs], pbase)
        target = pbase / f"{name}_Secure" / payload.name
        if not target.exists():
            hits = list(pbase.rglob(f"{name}*.*"))
            hits = [h for h in hits if h.suffix.lower() in ('.exe', '.dll')
                    and '_Secure' in str(h)]
            target = hits[0] if hits else None
        if not target:
            rows.append({"cell": cell, "result": "PROTECT-FAIL"})
            print("  protect failed")
            print("  log:", log.decode("utf-8", "replace")[-300:])
            print("  pbase:", list(pbase.rglob("*"))[:8])
            continue
        t0 = time.time()
        rc, log = sh([sys.executable, ROOT / "autoreaktor.py",
                      str(target.parent), "--deep"], ROOT, timeout=1800)
        rep = target.parent / "_ar_out" / "report.json"
        entry = {}
        if rep.exists():
            data = json.loads(rep.read_text(encoding="utf-8"))
            if data["files"]:
                e = data["files"][0]
                entry = {"result": e.get("result"),
                         "restored": next((s.get("restored") for s in e["stages"]
                                           if s.get("stage") == "necrobit-merge"), None),
                         "bodies": next((s.get("bodies") for s in e["stages"]
                                         if s.get("stage") == "necrobit-jitdump"), None),
                         "runnable": e.get("runnable_output") is not None,
                         "secs": round(time.time() - t0, 1)}
        else:
            entry = {"result": "NO-REPORT"}
        rows.append({"cell": cell, **entry})
        print("  ->", entry.get("result"), "| restored:", entry.get("restored"),
              "| runnable:", entry.get("runnable"))

    (outdir / "matrix.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    print("\n=== MATRIX ===")
    for r in rows:
        print(f"  {r['cell']:24s} {r.get('result','?'):22s} "
              f"restored={r.get('restored')} runnable={r.get('runnable')}")
    print(f"[matrix] written: {outdir / 'matrix.json'}")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
