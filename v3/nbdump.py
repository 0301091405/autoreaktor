#!/usr/bin/env python3
"""nbdump.py — v3 NecroBit harvester (Reflection path, no JIT hook needed).

Proven on the Reactor 7.3 Tuts4You challenge:
  * policyCreatorDic      : 201 field-token -> MethodSpec/MemberRef token map
  * dynamic-dump          : 204 DynamicMethods, full IL (Krypton.Runner harvest)
  * cross-match           : 201/201 dic keys == dump SourceField tokens

Stages
  1. run nbwalk (net48, same-bitness as target)   -> reflection walk
  2. run Krypton.Runner (net48 x86)               -> dynamic-dump.json
  3. merge into nb-inventory.json:
       {fieldToken, dicValue, dynMethod {il, sizes}, resolved target names}

Usage: python nbdump.py <target.exe> <outdir>
Exit codes: 0 = inventory complete; 2 = target clean (no NecroBit); 1 = error.
"""
import json
import subprocess
import sys
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
NBWALK = HERE / "nbwalk" / "bin" / "Release" / "net48" / "nbwalk.exe"
RUNNER = HERE.parent.parent / "tools" / "krypton" / "Krypton.Runner" / "bin" / "Release" / "net48" / "Krypton.Runner.exe"


def sh(cmd, cwd, timeout=240):
    p = subprocess.run(cmd, cwd=str(cwd), timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def main():
    if len(sys.argv) != 3:
        print("usage: nbdump.py <target.exe> <outdir>", file=sys.stderr)
        return 1
    target = Path(sys.argv[1]).resolve()
    outdir = Path(sys.argv[2]).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        print(f"target not found: {target}", file=sys.stderr)
        return 1

    # ---- stage 1: reflection walk (same dir as target for deps)
    rc, log = sh([str(NBWALK), str(target), str(outdir / "walk.txt")], target.parent)
    if rc != 0:
        print(f"nbwalk rc={rc}", file=sys.stderr)
        return 1
    dic_file = outdir / "policyCreatorDic.txt"
    dic_map = {}
    if dic_file.exists():
        for line in dic_file.read_text().splitlines():
            m = re.match(r"(\d+) -> (\d+)", line.strip())
            if m:
                dic_map[int(m.group(1))] = int(m.group(2))
    if not dic_map:
        print("no policyCreatorDic -> target likely has no NecroBit (clean)")
        return 2

    # ---- stage 2: dynamic-method harvest (Runner default mode: <exe> <out.json>)
    dyn_file = outdir / "dyn.json"
    rc, log = sh([str(RUNNER), str(target), str(dyn_file)], target.parent)
    if not dyn_file.exists():
        print(f"runner produced no dynamic dump (rc={rc}):\n{log[:400]}",
              file=sys.stderr)
        return 1
    dyn = {}
    raw = json.loads(dyn_file.read_text(encoding="utf-8-sig"))
    for m in raw.get("Methods", []):
        sf = m.get("SourceField", "")
        if "|" in sf:
            try:
                tok = int(sf.split("|")[1], 16)
                dyn[tok] = m
            except ValueError:
                pass

    # ---- stage 3: merge inventory
    inventory = []
    matched = 0
    for ftok, mtok in sorted(dic_map.items()):
        entry = {"fieldToken": f"0x{ftok:08X}", "dicValue": f"0x{mtok:08X}"}
        dm = dyn.get(ftok)
        if dm:
            matched += 1
            entry["dynMethod"] = {
                "field": dm.get("SourceField", "").split("|")[0],
                "returnType": dm.get("ReturnType"),
                "paramTypes": dm.get("ParameterTypes"),
                "instructionCount": len(dm.get("Instructions") or []),
                # ordered full instruction stream — consumed by nbrebuild
                "instructions": [
                    {"opcode": i.get("Opcode"),
                     "declType": i.get("DeclType"),
                     "memberName": i.get("MemberName"),
                     "memberSig": i.get("MemberSig"),
                     "declAssembly": i.get("DeclAssembly"),
                     "intValue": i.get("IntValue"),
                     "stringValue": i.get("StringValue")}
                    for i in (dm.get("Instructions") or [])
                ],
                "calls": [
                    {"op": i.get("Opcode"),
                     "target": f"{i.get('DeclType','')}.{i.get('MemberName','')}",
                     "sig": i.get("MemberSig", "")}
                    for i in (dm.get("Instructions") or [])
                    if i.get("Opcode") in ("call", "callvirt")
                ],
                "ldstr": [
                    {"index": i.get("IntValue"), "value": i.get("StringValue")}
                    for i in (dm.get("Instructions") or [])
                    if i.get("Opcode") == "ldstr"
                ],
            }
        inventory.append(entry)

    result = {
        "target": target.name,
        "necrobitMethods": len(dic_map),
        "dynamicMethodsHarvested": len(dyn),
        "matched": matched,
        "coverage": round(matched / len(dic_map), 4) if dic_map else 0,
        "inventory": inventory,
    }
    (outdir / "nb-inventory.json").write_text(
        json.dumps(result, indent=1), encoding="utf-8")
    print(f"necrobit methods: {len(dic_map)}  harvested: {len(dyn)}  "
          f"matched: {matched} ({result['coverage']*100:.1f}%)")
    print(f"inventory -> {outdir / 'nb-inventory.json'}")
    return 0 if matched == len(dic_map) else 1


if __name__ == "__main__":
    sys.exit(main())
