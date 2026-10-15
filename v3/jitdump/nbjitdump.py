"""nbjitdump.py — Universal NecroBit JIT dump route (v3).

Starts the target suspended via CreateProcess, injects
clrjit_dump{32,64}.dll via APC; the JIT hook installs when clrjit.dll
loads and dumps the CIL body NecroBit decodes at JIT time as
m_XXXXXXXX.bin to disk (plus m_XXXXXXXX.eh when NB_EHSLOT is set:
captured exception clauses for the write-back).

Usage:
  python nbjitdump.py <target.exe> [--out DIR] [--wait 30] [--force-run]

Output:
  DIR/m_XXXXXXXX.bin — 20B header (token, ilSize, maxStack, ehCount,
                       options) + raw CIL body
  DIR/m_XXXXXXXX.eh  — [u32 count][count x 28B clause] (NB_EHSLOT only)
  DIR/marker.txt     — DLL attach + hook setup proof
  DIR/jitdump.log    — body list
Token note: the file order is the JIT order (synthesis); in the write-back stage
MethodDef matching is done via IL-pattern matching (nbilmerge).
"""
import argparse
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def pe_machine(path):
    try:
        with open(path, "rb") as f:
            d = f.read(4096)
        if len(d) < 0x40 + 4:
            return 0
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if pe + 6 > len(d):
            return 0
        return struct.unpack_from("<H", d, pe + 4)[0]  # 0x14c x86, 0x8664 x64
    except Exception:
        return 0


def corflags_of(path):
    """(flags, is_managed) — for AnyCPU/R2R/native detection."""
    try:
        with open(path, "rb") as f:
            d = f.read(65536)
        if len(d) < 0x40 + 4:
            return None, False
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if pe + 24 + 2 > len(d):
            return None, False
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic not in (0x10B, 0x20B):
            return None, False
        ddoff = opt + (96 if magic == 0x10B else 112)
        cdir_rva = struct.unpack_from("<I", d, ddoff + 14 * 8)[0]
        if not cdir_rva:
            return None, False
        # cdir_rva is a VIRTUAL address - comparing to file size is WRONG:
        # in small DLLs RVA can exceed file size (alignment). The
        # resolution is below; here the 0 check alone is correct (g5 bug fix).
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt_size = struct.unpack_from("<H", d, pe + 20)[0]
        sec_tab = pe + 24 + opt_size
        off = None
        for i in range(nsec):
            s = sec_tab + i * 40
            if s + 40 > len(d):
                break
            vaddr = struct.unpack_from("<I", d, s + 12)[0]
            vsize = struct.unpack_from("<I", d, s + 8)[0]
            raw = struct.unpack_from("<I", d, s + 20)[0]
            if vaddr <= cdir_rva < vaddr + vsize:
                off = cdir_rva - vaddr + raw
                break
        if off is None or off + 20 > len(d):
            return None, False
        flags = struct.unpack_from("<I", d, off + 16)[0]
        return flags, True
    except Exception:
        return None, False


def is_readytorun(path):
    """R2R/NGen targets do not run through clrjit - the hook is useless.

    ReadyToRunHeader.Signature = 0x00525452 -> the bytes 'RTR\\0' open the
    R2R section; crossgen output also tends to carry a 'ReadyToRun' string.
    Either signal counts (the old check was INVERTED: it required 'RTR' to
    be ABSENT, so genuinely precompiled images passed as JIT targets).
    """
    try:
        with open(path, "rb") as f:
            d = f.read(262144)
    except OSError:
        return False
    return b"RTR\x00" in d or b"ReadyToRun" in d or b"readytorun" in d.lower()


def build_launcher(arch, out_dir):
    """Compiles nbjit_launch.exe in the target's bitness (required for x86 processes)."""
    from msvc_env import toolchain_env
    src = HERE / "nbjit_launch.c"
    launcher = out_dir / "nbjit_launch.exe"
    cl, env = toolchain_env(arch)
    if not cl:
        print("[!] no MSVC %s toolchain + Windows SDK found (vswhere) - launcher not built" % arch)
        return None
    r = subprocess.run([cl, "/nologo", "/O2", str(src), "/Fe:" + str(launcher),
                        "/Fo:" + str(out_dir / "nbjit_launch.obj"), "/link", "advapi32.lib", "user32.lib"],
                       capture_output=True, cwd=str(out_dir), env=env)
    if r.returncode != 0:
        print((r.stdout or b"").decode("mbcs", "replace")[-500:])
        print((r.stderr or b"").decode("mbcs", "replace")[-500:])
        return None
    return launcher


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--out", default=None)
    ap.add_argument("--wait", type=int, default=30)
    ap.add_argument("--force-run", action="store_true",
                    help="still accept the dump early in GUI targets")
    args = ap.parse_args()

    tgt = Path(args.target).resolve()
    out = Path(args.out).resolve() if args.out else tgt.parent / "jitdump"
    out.mkdir(exist_ok=True)

    # --- target classification (critical for generality) ---
    flags, managed = corflags_of(tgt)
    if not managed:
        # .NET Core/5+ apphost exe: a native-looking stub, the managed dll
        # <stem>.dll is the real managed module. If the DLL exists, route to it.
        stem = tgt.with_suffix(".dll")
        if stem.exists():
            print(f"[info] apphost — managed module: {stem.name}")
            tgt = stem.resolve()
            flags, managed = corflags_of(tgt)
        if not managed:
            print("[!] unmanaged exe (no CLR) — JIT dump out of scope")
            return 3
    # R2R check must cover ALL managed targets: an AnyCPU R2R binary used to
    # skip the check (it lived in the non-AnyCPU branch) and enter the hook
    # path, which then sat idle at 0 bodies.
    if is_readytorun(tgt):
        print("[!] ReadyToRun - clrjit is not used, JIT dump is useless")
        return 3
    if flags is not None and not (flags & 0x2) and not (flags & 0x10000):
        # no 32BITREQUIRED(0x2) AND no 32BITPREF(0x10000) = AnyCPU
        # -> on a 64-bit OS this is an x64 process; an x86 DLL never loads (t1
        # hatasinin kaynagi). x64 rota zorunlu:
        arch = "x64"
        print("[info] AnyCPU — 64-bit process modu")
    else:
        mach = pe_machine(tgt)
        arch = "x86" if mach == 0x14C else "x64"

    dll = (HERE / ("clrjit_dump32.dll" if arch == "x86" else "clrjit_dump64.dll")).resolve()
    if not dll.exists():
        print(f"[!] {dll.name} yok — once build"); return 1

    launcher = build_launcher(arch, out)
    if not launcher:
        print("[!] launcher derlenemedi"); return 1

    env = dict(os.environ)
    env["NB_DLL"] = str(dll)
    env["JITDUMP_DIR"] = str(out)
    # tiered-inline breaker: small methods like Magic drop into the dump as
    # separate JIT entries instead of being inlined into the ctor (g5). Active with NB_NOINLINE=1.
    if os.environ.get("NB_NOINLINE") == "1":
        env["COMPlus_JitNoInline"] = "1"
        print("[info] COMPlus_JitNoInline=1 — tiered inline disabled")
    # calistirilabilir sec: target .dll ise apphost .exe'sini bul
    run_tgt = tgt
    if tgt.suffix.lower() == ".dll":
        host = tgt.with_suffix(".exe")
        if host.exists():
            run_tgt = host.resolve()
            print(f"[info] calistirilan: apphost {run_tgt.name}")
        else:
            print("[!] no apphost exe for DLL — dotnet host required")
            return 3
    p = subprocess.Popen([str(launcher), f'"{str(run_tgt)}"'], cwd=str(tgt.parent), env=env)
    try:
        p.wait(timeout=args.wait)
        print(f"target exited rc={p.returncode}")
    except subprocess.TimeoutExpired:
        # kill by the RUNNING image name (run_tgt, not tgt: after the apphost
        # route tgt is the managed DLL, which never matches a process image)
        subprocess.run(["taskkill", "/IM", run_tgt.name, "/F"], capture_output=True)
        p.kill()
        try:
            p.wait(timeout=10)
        except Exception:
            pass
        print(f"target {args.wait}s sonunda disabled (GUI yasar — normal)")

    time.sleep(1)
    bins = sorted(out.glob("m_*.bin"))
    ehs = sorted(out.glob("m_*.eh"))
    marker = out / "marker.txt"
    log = out / "jitdump.log"
    hooked = marker.exists() and "HOOK-OK" in marker.read_text(errors="replace")
    eh_note = f" | eh={len(ehs)}" if ehs else ""
    print(f"status: hook={'OK' if hooked else 'FAIL'} | body={len(bins)}{eh_note} | toplam IL={sum(b.stat().st_size - 20 for b in bins)}")
    if log.exists():
        lines = log.read_text(errors="replace").strip().splitlines()
        print(f"log: {len(lines)} line")
    return 0 if bins else 2


if __name__ == "__main__":
    sys.exit(main())
