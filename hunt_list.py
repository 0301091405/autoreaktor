#!/usr/bin/env python3
"""hunt CLI with JSON dump — debug-friendly variant for listing protected hits."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from pathlib import Path
from hunt import hunt

results = hunt(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
prot = [r for r in results if r["class"] == "protected"]
print(f"protected hits: {len(prot)}")
for r in prot:
    print(" ", r["file"], r["size"])
