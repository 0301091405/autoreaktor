#!/usr/bin/env python3
"""Measure WHAT the packer's self-check covers, before trying to rewrite a PE.

The x64 body merge faults in `<Module>.cctor` even with zero bodies written,
so the open question was: can an *offset-preserving* write (same size, same
section table, same RVAs, bodies patched in place) slip past NecroBit's
anti-tamper where dnlib's full rewrite cannot?

This script answers it with a control experiment instead of an assumption.
It takes an already-protected sample and mutates exactly one byte in each
region of the file, then runs the target and records whether it survives:

  * header padding          (inside SizeOfHeaders, unused bytes)
  * .text raw padding       (inside SizeOfImage, past VirtualSize)
  * .rsrc raw padding       (same, resource section)
  * PE checksum field       (OptionalHeader.CheckSum)
  * one byte APPENDED to the file (outside SizeOfImage - an overlay)

Verdict rule: a case "survives" when the target exits with the same status
and same stdout as the pristine run. Everything inside SizeOfImage that
faults proves the check is a whole-image validation, which means an
in-place body write is detected just like a dnlib rewrite - only bytes
outside the mapped image (the overlay) are free, and the loader never maps
those, so bodies cannot be placed there.

Usage:
    python v3/jitdump/pe_tamper_scope.py <protected.exe> [--args dump]
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("not a PE: %s" % pe)
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    size_img = struct.unpack_from("<I", data, opt + 56)[0]
    size_hdr = struct.unpack_from("<I", data, opt + 60)[0]
    out = []
    for i in range(nsec):
        o = opt + opt_size + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", data, o + 8)
        out.append({"name": name, "vsz": vsz, "va": va, "rsz": rsz, "ro": ro})
    return {"opt": opt, "size_img": size_img, "size_hdr": size_hdr,
            "sections": out}


def run(exe, args):
    p = subprocess.run([exe] + args, capture_output=True, timeout=180)
    return p.returncode, (p.stdout or b"") + (p.stderr or b"")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--args", default="", help="probe arguments (space separated)")
    ap.add_argument("--out", default=None, help="work dir (default: temp)")
    args = ap.parse_args()
    argv = [a for a in args.args.split() if a]

    src = os.path.abspath(args.target)
    data = open(src, "rb").read()
    info = sections(data)

    work = args.out or tempfile.mkdtemp(prefix="ar_tamper_")
    os.makedirs(work, exist_ok=True)
    base = os.path.join(work, "pristine.exe")
    shutil.copy2(src, base)
    ref = run(base, argv)
    print("pristine : %r" % (ref[0],))
    print("           size=0x%x SizeOfImage=0x%x SizeOfHeaders=0x%x" %
          (len(data), info["size_img"], info["size_hdr"]))

    cases = []
    # header padding: last byte before the first section's raw data
    cases.append(("hdr-pad", info["size_hdr"] - 1))
    # section raw padding: last byte of each section that has raw slack
    for s in info["sections"]:
        slack = s["rsz"] - s["vsz"]
        if slack > 0:
            cases.append((("%s-pad" % s["name"]).strip("."), s["ro"] + s["rsz"] - 1))
    # PE checksum field
    cases.append(("checksum", info["opt"] + 64))

    verdicts = []
    for name, off in cases:
        b = bytearray(data)
        old = b[off]
        b[off] ^= 0xFF
        dst = os.path.join(work, name + ".exe")
        open(dst, "wb").write(bytes(b))
        got = run(dst, argv)
        same = got == ref
        verdicts.append((name, off, old, same))
        print("%-12s off=0x%06x %02x->%02x  %s" %
              (name, off, old, b[off], "SURVIVES" if same else "CAUGHT rc=%r" % (got[0],)))

    # overlay: append one byte past the end of the file (outside SizeOfImage)
    dst = os.path.join(work, "overlay.exe")
    open(dst, "wb").write(data + b"\xCC")
    got = run(dst, argv)
    verdicts.append(("overlay", len(data), 0, got == ref))
    print("%-12s off=0x%06x appended   %s" %
          ("overlay", len(data), "SURVIVES" if got == ref else "CAUGHT rc=%r" % (got[0],)))

    caught = [v for v in verdicts if v[0] != "overlay" and not v[3]]
    overlay_ok = [v for v in verdicts if v[0] == "overlay" and v[3]]
    print()
    if caught and overlay_ok:
        print("verdict: the self-check covers the whole mapped image "
              "(%d/%d in-image probes caught) and ignores the overlay. "
              "An offset-preserving in-place body write is therefore "
              "detected exactly like a dnlib rewrite." % (len(caught), len(cases)))
        print("         The overlay is writable but never mapped by the "
              "loader, so method bodies cannot live there.")
    elif not caught:
        print("verdict: in-image bytes are NOT validated - in-place rewriting "
              "is viable for this sample.")
    else:
        print("verdict: inconclusive (overlay probe was caught too) - "
              "the run/compare harness needs attention.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
