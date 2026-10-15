#!/usr/bin/env bash
# setup.sh — fetch the third-party tools AutoReaktor drives.
# Everything here is an external dependency: kept out of the repo tree,
# pinned to the builds the pipeline was verified against.
#
# Layout produced:
#   tools/de4dot/de4dot.exe             (de4dotEx net48 build + its DLLs)
#   tools/slayer/NETReactorSlayer.CLI.exe
#   tools/krypton/...                   (Krypton devirtualizer, built from source)
#
# dnlib is NOT fetched here: every C# tool in the repo references it via
# PackageReference (dotnet restore pulls it at build time).
#
# Requires: curl (or wget), unzip, git, python, .NET SDK. Windows: run
# under git-bash.

set -euo pipefail
cd "$(dirname "$0")/.."      # repo root (this script lives in tools/)
mkdir -p tools/slayer tools/bin

DL() {  # DL <url> <out>
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 2 -o "$2" "$1"
  else wget -O "$2" "$1"; fi
}

# --- de4dot (GDATA de4dotEx — the actively maintained fork) -------------
# The repo is GDATAAdvancedAnalytics/de4dotEx (NOT .../de4dot — that path
# does not exist). Resolve the latest release's net48 asset via the GitHub
# API; fall back to the pinned v3.11.0 asset when the API is unreachable.
if [ ! -f tools/de4dot.exe ]; then
  echo "[setup] de4dot (de4dotEx net48)..."
  DE4DOT_URL=""
  if command -v python >/dev/null 2>&1; then
    DE4DOT_URL=$(python -c "import json,urllib.request; d=json.load(urllib.request.urlopen('https://api.github.com/repos/GDATAAdvancedAnalytics/de4dotEx/releases/latest', timeout=30)); print(next(a['browser_download_url'] for a in d['assets'] if a['name'].endswith('-net48.zip')))" 2>/dev/null || true)
  fi
  [ -n "${DE4DOT_URL:-}" ] || DE4DOT_URL="https://github.com/GDATAAdvancedAnalytics/de4dotEx/releases/download/v3.11.0/de4dotEx-3.11.0-net48.zip"
  DL "$DE4DOT_URL" tools/de4dot.zip
  # extract the WHOLE archive: de4dot.exe needs its satellite DLLs
  # (de4dot.cui.dll, de4dot.code.dll, ...) next to it or it dies with
  # FileNotFoundException on first run.
  rm -rf tools/de4dot && mkdir -p tools/de4dot
  unzip -o tools/de4dot.zip -d tools/de4dot >/dev/null
  [ -f tools/de4dot/de4dot.exe ] || { echo "de4dot extract failed - open tools/de4dot.zip manually"; exit 1; }
fi

# --- NETReactorSlayer (SychicBoy release build) -------------------------
SLAYER_URL="https://github.com/SychicBoy/NETReactorSlayer/releases/latest/download/NETReactorSlayer-windows.zip"
if [ ! -f tools/slayer/NETReactorSlayer.CLI.exe ]; then
  echo "[setup] NETReactorSlayer..."
  DL "$SLAYER_URL" tools/slayer.zip
  # full archive: the CLI needs NETReactorSlayer.Core.dll AND
  # NETReactorSlayer.De4dot.dll (+ deps) beside it.
  unzip -o tools/slayer.zip -d tools/slayer >/dev/null
  [ -f tools/slayer/NETReactorSlayer.CLI.exe ] || { echo "slayer extract failed - open tools/slayer.zip manually"; exit 1; }
fi

# --- Krypton devirtualizer (dawwinci) -----------------------------------
# Built from source (no release binaries shipped). If tools/krypton already
# exists (local checkout), skip.
if [ ! -d tools/krypton ]; then
  echo "[setup] Krypton devirtualizer (build from source)..."
  git clone --depth 1 https://github.com/dawwinci/krypton-devirtualizer.git tools/krypton
  ( cd tools/krypton && dotnet build Krypton.Runner -c Release )
fi
KRUNNER=$(find tools/krypton/Krypton.Runner/bin -name "Krypton.Runner.exe" 2>/dev/null | head -1 || true)
if [ -n "$KRUNNER" ]; then
  echo "[setup] Krypton.Runner: $KRUNNER"
else
  echo "[setup] WARNING: Krypton.Runner.exe not found after build - Krypton stage will be skipped by the pipeline"
fi

echo "[setup] done."
echo "[setup] Verify: python autoreaktor.py --help"
