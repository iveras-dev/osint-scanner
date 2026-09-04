#!/bin/bash
# =============================================================================
# OSINT Scanner - Bouw standalone app (Mac/Linux)
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Activeer venv
if [ -d "$SCRIPT_DIR/.venv" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

# Check PyInstaller
if ! command -v pyinstaller &>/dev/null; then
    echo "PyInstaller niet gevonden. Installeren..."
    pip install pyinstaller
fi

# --- macOS Xcode CLT check ---
if [[ "$OSTYPE" == "darwin"* ]]; then
    SYS_ARCH=$(uname -m)
    CLT_PATH=$(xcode-select -p 2>/dev/null)
    CLT_OK=true

    if [ -z "$CLT_PATH" ] || [ ! -d "$CLT_PATH" ]; then
        CLT_OK=false
    elif [ ! -f "$CLT_PATH/usr/bin/xcrun" ]; then
        CLT_OK=false
    elif ! file "$CLT_PATH/usr/bin/xcrun" 2>/dev/null | grep -q "$SYS_ARCH"; then
        CLT_OK=false
    fi

    if ! $CLT_OK; then
        echo "FOUT: Xcode Command Line Tools ontbreken of zijn beschadigd."
        echo "  PyInstaller kan niet bouwen zonder werkende CLT."
        echo ""
        echo "Fix:"
        echo "  sudo rm -rf /Library/Developer/CommandLineTools"
        echo "  xcode-select --install"
        echo ""
        echo "Of bouw op een andere Mac / in een CI-pipeline."
        exit 1
    fi
fi

echo ">> Bouwen van standalone OSINT Scanner..."
echo ""

cd "$SCRIPT_DIR"

pyinstaller \
    --name "OSINT-Scanner" \
    --onefile \
    --console \
    --clean \
    --noconfirm \
    --collect-submodules holehe \
    --collect-submodules ddgs \
    --collect-submodules duckduckgo_search \
    --collect-submodules socid_extractor \
    --collect-submodules maigret \
    --collect-data maigret \
    --hidden-import harvest_client \
    --hidden-import pycountry \
    --hidden-import certifi \
    --hidden-import httpx \
    --hidden-import trio \
    --hidden-import rich \
    --hidden-import requests \
    --add-data "requirements.txt:." \
    --add-data ".env.example:." \
    osint_scanner.py

echo ""
echo "================================================================="
echo "  BUILD VOLTOOID!"
echo ""
echo "  Executable:  $SCRIPT_DIR/dist/OSINT-Scanner"
echo ""
echo "  Kopieer naar een nieuwe map samen met:"
echo "    - .env.example (template voor API-keys)"
echo ""
echo "  Of deel de hele gdorks/ map."
echo "================================================================="
