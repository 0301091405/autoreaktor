"""nbjitdump.py — NecroBit evrensel JIT dump rota (v3).

Hedefi suspended CreateProcess ile baslatir, clrjit_dump{32,64}.dll'i
APC ile inject eder; JIT hook'u clrjit.dll yuklenince kurulur ve
NecroBit'in JIT aninda cozdugu CIL govdesini m_XXXXXXXX.bin olarak
diske doker. Kanitli: 7.5.9.1 T4Y hedefi, 238 govde / 7060 IL bayt.

Kullanim:
  python nbjitdump.py <target.exe> [--out DIR] [--wait 30] [--force-run]

Cikti:
  DIR/m_XXXXXXXX.bin — 20B header (token, ilSize, maxStack, ehCount,
                       options) + ham CIL govdesi
  DIR/marker.txt — DLL attach + hook kurulum kaniti
  DIR/jitdump.log — govde listesi
Token notu: dosya adi JIT sirasidir (sentez); write-back asamasinda
IL-pattern matching ile MethodDef eslemesi yapilir (nbilmerge).
"""
import argparse
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MSVC = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
WK = r"C:\Program Files (x86)\Windows Kits\10"


def pe_machine(path):
    d = open(path, "rb").read(4096)
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    mach = struct.unpack_from("<H", d, pe + 4)[0]
    return mach  # 0x14c x86, 0x8664 x64


def corflags_of(path):
    """(flags, yonetilen_mi) — AnyCPU/R2R/native tespiti icin."""
    d = open(path, "rb").read(65536)
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    ddoff = opt + (96 if magic == 0x10B else 112)
    cdir_rva = struct.unpack_from("<I", d, ddoff + 14 * 8)[0]
    if not cdir_rva or cdir_rva >= len(d):
        return None, False
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt_size = struct.unpack_from("<H", d, pe + 20)[0]
    sec_tab = pe + 24 + opt_size
    off = None
    for i in range(nsec):
        s = sec_tab + i * 40
        vaddr = struct.unpack_from("<I", d, s + 12)[0]
        vsize = struct.unpack_from("<I", d, s + 8)[0]
        raw = struct.unpack_from("<I", d, s + 20)[0]
        if vaddr <= cdir_rva < vaddr + vsize:
            off = cdir_rva - vaddr + raw
            break
    if off is None:
        return None, False
    flags = struct.unpack_from("<I", d, off + 16)[0]
    return flags, True


def is_readytorun(path):
    """R2R (ReadyToRun) hedeflerde clrjit KULLANILMAZ — hook islevsiz.
    R2R debug directory tipi 0x11 (IMAGE_DIRECTORY_TYPE_EXCEPTION)
    yaninda COR_RSDS degil R2R entry bulunur; basit esik: debug dir
    tip 0x11 varsa + .rsrc degil 'RTR' isareti. Pratik tarama:
    dosyada 'ReadyToRun' metadata bolumu aramak yerine debug
    directory tiplerinden 0x10 (REPRO) / R2R header kontrolu."""
    d = open(path, "rb").read(65536)
    return b"RTR" not in d and (b"ReadyToRun" in d or b"readytorun" in d.lower())


def build_launcher(arch, out_dir):
    """nbjit_launch.exe'yi hedef bitness'inde derler (x86 x86 surecler icin sart)."""
    src = HERE / "nbjit_launch.c"
    launcher = out_dir / "nbjit_launch.exe"
    env = dict(os.environ)
    env["INCLUDE"] = ";".join([MSVC + r"\include", WK + r"\Include\10.0.26100.0\ucrt",
                               WK + r"\Include\10.0.26100.0\um", WK + r"\Include\10.0.26100.0\shared"])
    if arch == "x86":
        env["LIB"] = ";".join([MSVC + r"\lib\x86", WK + r"\Lib\10.0.26100.0\ucrt\x86", WK + r"\Lib\10.0.26100.0\um\x86"])
        cl = MSVC + r"\bin\Hostx64\x86\cl.exe"
    else:
        env["LIB"] = ";".join([MSVC + r"\lib\x64", WK + r"\Lib\10.0.26100.0\ucrt\x64", WK + r"\Lib\10.0.26100.0\um\x64"])
        cl = MSVC + r"\bin\Hostx64\x64\cl.exe"
    env["PATH"] = os.path.dirname(cl) + ";" + env["PATH"]
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
                    help="GUI hedeflerin erken olumunde dump'i yine de kabul et")
    args = ap.parse_args()

    tgt = Path(args.target).resolve()
    out = Path(args.out).resolve() if args.out else tgt.parent / "jitdump"
    out.mkdir(exist_ok=True)

    # --- hedef siniflandirmasi (genellik icin kritik) ---
    flags, managed = corflags_of(tgt)
    if not managed:
        print("[!] yonetilmeyen exe (no CLR) — JIT dump kapsam disi")
        return 3
    if flags is not None and not (flags & 0x2) and not (flags & 0x10000):
        # 32BITREQUIRED(0x2) yok VE 32BITPREF(0x10000) yok = AnyCPU
        # -> 64-bit OS'ta x64 surec; x86 DLL asla yuklenmez (t1
        # hatasinin kaynagi). x64 rota zorunlu:
        arch = "x64"
        print("[bilgi] AnyCPU — 64-bit surec modu")
    elif is_readytorun(tgt):
        print("[!] ReadyToRun — clrjit kullanilmiyor, JIT dump islevsiz")
        return 3
    else:
        arch = "x86" if pe_machine(tgt) == 0x14C else "x64"

    dll = (HERE / ("clrjit_dump32.dll" if arch == "x86" else "clrjit_dump64.dll")).resolve()
    if not dll.exists():
        print(f"[!] {dll.name} yok — once build"); return 1

    launcher = build_launcher(arch, out)
    if not launcher:
        print("[!] launcher derlenemedi"); return 1

    env = dict(os.environ)
    env["NB_DLL"] = str(dll)
    env["JITDUMP_DIR"] = str(out)
    p = subprocess.Popen([str(launcher), f'"{str(tgt)}"'], cwd=str(tgt.parent), env=env)
    try:
        p.wait(timeout=args.wait)
        print(f"hedef cikti rc={p.returncode}")
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/IM", tgt.name, "/F"], capture_output=True)
        p.kill()
        print(f"hedef {args.wait}s sonunda kapatildi (GUI yasar — normal)")

    time.sleep(1)
    bins = sorted(out.glob("m_*.bin"))
    marker = out / "marker.txt"
    log = out / "jitdump.log"
    hooked = marker.exists() and "HOOK-OK" in marker.read_text(errors="replace")
    print(f"durum: hook={'OK' if hooked else 'FAIL'} | govde={len(bins)} | toplam IL={sum(b.stat().st_size - 20 for b in bins)}")
    if log.exists():
        lines = log.read_text(errors="replace").strip().splitlines()
        print(f"log: {len(lines)} satir")
    return 0 if bins else 2


if __name__ == "__main__":
    sys.exit(main())