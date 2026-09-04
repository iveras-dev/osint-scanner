#!/bin/bash
# =============================================================================
# OSINT Scanner - Installatie Mac/Linux
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON=""
VENV_DIR="$SCRIPT_DIR/.venv"

# --- Zoek Python 3 ---
for cmd in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        VERSION=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        MAJOR=$(echo "$VERSION" | cut -d. -f1)
        MINOR=$(echo "$VERSION" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "FOUT: Geen Python 3.10+ gevonden."
    echo "Installeer Python via: https://www.python.org/downloads/"
    exit 1
fi

echo "Python gevonden: $($PYTHON --version)"
echo ""

# --- Maak virtual environment ---
if [ ! -d "$VENV_DIR" ]; then
    echo ">> Virtual environment aanmaken..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

# --- Activeer venv ---
source "$VENV_DIR/bin/activate"

# --- Installeer dependencies ---
echo ">> Dependencies installeren..."
pip install --upgrade pip --quiet
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
pip install pyinstaller --quiet 2>/dev/null || true

# Playwright-browser (optioneel; nodig voor de WAF-tolerantie laag "Playwright")
if python -c "import playwright" 2>/dev/null; then
    echo ">> Playwright-browser installeren (optioneel; kan een moment duren)..."
    python -m playwright install chromium --with-deps >/dev/null 2>&1 || \
        python -m playwright install chromium >/dev/null 2>&1 || true
fi

echo ""
echo ">> Installatie voltooid!"
echo ""

# --- Kopieer .env.example naar .env als die niet bestaat ---
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    if [ -f "$SCRIPT_DIR/.env.example" ]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        echo ">> .env aangemaakt vanuit .env.example"
        echo "   Vul je API-keys in: $SCRIPT_DIR/.env"
    else
        touch "$SCRIPT_DIR/.env"
        echo ">> Leeg .env aangemaakt (geen .env.example gevonden)"
    fi
    echo ""
fi

# --- Chrome check ---
echo ">> Chrome checken voor PDF-ondersteuning..."
CHROME_FOUND=false
for path in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/usr/bin/google-chrome" \
    "/usr/bin/chromium"; do
    if [ -f "$path" ]; then
        CHROME_FOUND=true
        break
    fi
done

if $CHROME_FOUND; then
    echo "   Chrome gevonden - PDF-export werkt."
else
    echo "   Chrome niet gevonden - PDF-export werkt niet."
    echo "   Installeer Chrome: https://www.google.com/chrome/"
fi
echo ""

# --- Start ---
echo "================================================================="
echo "  Starten:  ./start.sh"
echo "  Bouwen:   ./bouw_standalone.sh"
echo "================================================================="
