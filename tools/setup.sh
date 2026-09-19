#!/usr/bin/env bash
# setup.sh — fetch the third-party tools AutoReaktor drives.
# Everything here is an external dependency: kept out of the repo tree,
# pinned to the builds the pipeline was verified against.
#
# Layout produced:
#   tools/dnlib.dll                     (dnlib 3.3.4 - .NET Framework builds)
#   tools/de4dot.exe                    (de4dot / de4dotEx build)
#   tools/slayer/NETReactorSlayer.CLI.exe
#   tools/krypton/...                   (Krypton.Runner build; if you already
#                                        have a local checkout, place it here)
#
# Requires: curl (or wget), tar/unzip. Windows: run under git-bash/WSL.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
mkdir -p tools/slayer tools/bin

DL() {  # DL <url> <out>
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 2 -o "$2" "$1"
  else wget -O "$2" "$1"; fi
}

# --- dnlib (dnlib 3.3.4, the version the nb* tools reference) ----------
DNLIB_URL="https://github.com/0xd4d/dnlib/releases/download/v3.3.4/dnlib-nuget.zip"
if [ ! -f tools/dnlib.dll ]; then
  echo "[setup] dnlib 3.3.4..."
  DL "$DNLIB_URL" tools/dnlib-nuget.zip
  unzip -j -o tools/dnlib-nuget.zip "*/netstandard2.0/dnlib.dll" "*/net45/dnlib.dll" -d tools >/dev/null 2>&1 || true
  [ -f tools/dnlib.dll ] || { echo "dnlib extract failed - open tools/dnlib-nuget.zip manually"; exit 1; }
  # the nb* .csproj files expect dnlib.dll at repo root and per-dir copies
  cp -f tools/dnlib.dll ./dnlib.dll
  cp -f tools/dnlib.dll v3/jitdump/dnlib.dll 2>/dev/null || true
fi

# --- de4dot (GDATA de4dotEx releases build the modern fixes) ------------
DE4DOT_URL="https://github.com/GDATAAdvancedAnalytics/de4dot/releases/latest/download/de4dot.zip"
if [ ! -f tools/de4dot.exe ]; then
  echo "[setup] de4dot (de4dotEx)..."
  DL "$DE4DOT_URL" tools/de4dot.zip
  unzip -j -o tools/de4dot.zip "de4dot.exe" -d tools >/dev/null 2>&1 \
    || unzip -j -o tools/de4dot.zip "*de4dot.exe" -d tools >/dev/null 2>&1
  [ -f tools/de4dot.exe ] || { echo "de4dot extract failed - open tools/de4dot.zip manually"; exit 1; }
fi

# --- NETReactorSlayer (SychicBoy release build) -------------------------
SLAYER_URL="https://github.com/SychicBoy/NETReactorSlayer/releases/latest/download/NETReactorSlayer-windows.zip"
if [ ! -f tools/slayer/NETReactorSlayer.CLI.exe ]; then
  echo "[setup] NETReactorSlayer..."
  DL "$SLAYER_URL" tools/slayer.zip
  unzip -j -o tools/slayer.zip "*NETReactorSlayer.CLI.exe" "*NETReactorSlayer.Core.dll" -d tools/slayer >/dev/null 2>&1
  [ -f tools/slayer/NETReactorSlayer.CLI.exe ] || { echo "slayer extract failed - open tools/slayer.zip manually"; exit 1; }
fi

# --- Krypton devirtualizer (dawwinci) -----------------------------------
# Built from source (no release binaries shipped). If tools/krypton already
# exists (local checkout), skip.
if [ ! -d tools/krypton ]; then
  echo "[setup] Krypton devirtualizer (build from source)..."
  git clone --depth 1 https://github.com/dawwinci/krypton-devirtualizer.git tools/krypton
  ( cd tools/krypton && dotnet build -c Release )
fi

echo "[setup] done."
echo "[setup] Verify: python autoreaktor.py --help"