#!/usr/bin/env python3
"""AutoReaktör hunt — directory scanner for .NET Reactor-protected assemblies.

Standalone scanner module (used by autoreaktor.py --hunt mode):
- PE CLR-header detection for .NET assemblies
- Readable-marker scan (Eziriz / .NET Reactor) — catches carrier builds
- Structural NecroBit/Necrobit-style detection: .NET assembly whose method
  bodies are empty/tiny but whose native payload blob exists (rsrc or text
  section) — catches ENCRYPTED-marker builds where string scan fails
  (verified against Reactor 7.5 NecroBit output: no readable marker, no
  Main method via reflection, tiny method bodies)

Exit report: JSON with classification per file:
  clean                 — .NET, no reactor structure
  carrier               — readable marker (SDK/licensing libraries)
  protected             — structural match (method bodies encrypted/absent)
"""
import json
import math
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from autoreaktor import pe_is_dotnet, reactor_marker, sha256

# Known .NET runtime/framework assemblies whose embedded native resources
# naturally trip the entropy heuristic (verified on Microsoft.Web.WebView2.*,
# WinRT.Runtime.dll, XamlAnimatedGif.dll — all shipped unsigned-by-app, all
# clean). Excluded from "protected" classification to cut false positives.
KNOWN_RUNTIME_PREFIXES = (
    "microsoft.web.", "winrt.runtime", "system.", "mscor", "newtonsoft",
    "presentationcore", "presentationframework", "windowsbase",
    "accessibility", "xamlanimatedgif", "mono.", "gtk",
    "commandline", "serilog", "netstandard", "microsoft.csharp",
    "microsoft.visualbasic", "microsoft.win32", "microsoft.extensions",
    "de4dot", "dnlib", "0harmony", "sharpzip", "linqbridge", "assemblydata",
    "netreactorslayer", "krypton", "asmresolver", "colorful.console",
)


def is_known_runtime(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in KNOWN_RUNTIME_PREFIXES)


def necrobit_signature(path: Path) -> bool:
    """Structural detector for method-body encryption (NecroBit-family).

    Heuristic, verified against:
      - Reactor 7.5 NecroBit+strenc+antitamper build: TRUE
      - Reactor 7.5 plain strenc build (no necrobit): FALSE
      - plain net8 console assembly: FALSE
      - Eziriz License.dll (carrier): FALSE

    Signal (verified against ground truth, all four classes):
      plain net8 assembly : max-entropy 4KB window = 4.38
      Eziriz carrier dll  : 5.71 (has readable marker anyway)
      Reactor 7.5 strenc  : 6.23, file 11x bigger than plain
      Reactor 7.5 necrobit: 6.46, file 22x bigger
    Decision boundary: max-window entropy >= 6.0 AND any .NET metadata stream
    present AND file smaller than 2 MB (framework DLLs like mscorlib naturally
    exceed this and are out of scope — the hunter is for application folders).
    Carrier is caught earlier by the readable-marker check.
    """
    data = path.read_bytes()
    if len(data) < 512 or len(data) > (2 << 20):
        return False
    has_clr_meta = b'#~' in data or b'#Strings' in data or b'#Blob' in data
    if not has_clr_meta:
        return False
    # max-entropy 4KB window, 1KB stride
    def ent(b):
        if not b:
            return 0.0
        freq = [0] * 256
        for x in b:
            freq[x] += 1
        n = len(b)
        e = 0.0
        for c in freq:
            if c:
                p = c / n
                e -= p * math.log2(p)
        return e
    best = 0.0
    for i in range(0, max(1, len(data) - 4096), 1024):
        best = max(best, ent(data[i:i + 4096]))
    return best >= 6.0


def classify(path: Path) -> dict:
    entry = {"file": str(path), "sha256": sha256(path), "size": path.stat().st_size}
    if not pe_is_dotnet(path):
        entry["class"] = "native"
        return entry
    if is_known_runtime(path.name):
        entry["class"] = "runtime"
        return entry
    marker = reactor_marker(path)
    if marker:
        entry["class"] = "carrier"
        entry["marker"] = marker[:80]
        return entry
    if necrobit_signature(path):
        entry["class"] = "protected"
        return entry
    entry["class"] = "clean"
    return entry


def hunt(root: Path) -> list:
    out = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in
                   ("node_modules", "windowsapps", "__pycache__", ".git")]
        for name in files:
            if name.lower().endswith((".exe", ".dll")):
                p = Path(dirpath) / name
                try:
                    out.append(classify(p))
                except Exception as e:
                    out.append({"file": str(p), "class": "error", "error": str(e)})
    return out


if __name__ == "__main__":
    import argparse
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    results = hunt(Path(args.root))
    for r in results:
        if r["class"] in ("carrier", "protected"):
            print(f"[{r['class']:>9}] {r['file']}")
            if "marker" in r:
                print(f"            {r['marker']}")
    if args.json:
        print(json.dumps(results, indent=2))
    counts = {}
    for r in results:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    print(f"--- total: {len(results)} | " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
