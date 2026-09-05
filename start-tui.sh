#!/bin/bash
# OSINT Scanner — Textual desktop-versie startscript
# Zelfhelend: installeert textual automatisch als die ontbreekt.

SCRIPT="osint_tui.py"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "🔍 OSINT Scanner (desktop) starten..."

# Kill eventueel draaiende instanties
PIDS=$(pgrep -f "python.*$SCRIPT" 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "⚠️  Oud proces gevonden (PID: $PIDS) — killen..."
    kill $PIDS 2>/dev/null
    sleep 1
    kill -9 $PIDS 2>/dev/null
    echo "✔️  Oud proces gestopt"
fi

# __pycache__ opruimen zodat Python de verse code laadt
if [ -d "$DIR/__pycache__" ]; then
    rm -f "$DIR/__pycache__/"*.pyc 2>/dev/null
    echo "✔️  Cache opgeschoond"
fi

# Python bepalen: venv heeft voorrang
if [ -x "$DIR/.venv/bin/python3" ]; then
    PYTHON="$DIR/.venv/bin/python3"
else
    PYTHON="python3"
fi

# Installatie-check: engine-dependencies aanwezig (incl. phonenumbers voor
# telefoon-verrijking)? Zo niet, installeer de volledige requirements.
if ! "$PYTHON" -c "import requests, rich, phonenumbers" &>/dev/null; then
    echo "⚠️  Dependencies ontbreken (eerste keer starten?)."
    echo ">> Installatie wordt automatisch gestart..."
    if [ -f "$DIR/install_mac.sh" ]; then
        chmod +x "$DIR/install_mac.sh" 2>/dev/null
        "$DIR/install_mac.sh" || echo "⚠️  Installatie gaf waarschuwingen, hertoetsen..."
        if [ -x "$DIR/.venv/bin/python3" ]; then
            PYTHON="$DIR/.venv/bin/python3"
        fi
        if ! "$PYTHON" -c "import requests, rich, phonenumbers" &>/dev/null; then
            echo ""
            echo "FOUT: dependencies nog steeds niet geinstalleerd. Probeer handmatig:"
            echo "  pip install -r requirements.txt"
            exit 1
        fi
        echo "✔️  Installatie gereed"
    else
        echo "FOUT: install_mac.sh niet gevonden. Installeer handmatig:"
        echo "  pip install -r requirements.txt"
        exit 1
    fi
fi

# Textual (TUI-modus) zelfhelend installeren
if ! "$PYTHON" -c "import textual" &>/dev/null; then
    echo "⚠️  Textual ontbreekt (nodig voor de desktop-versie)."
    echo ">> Textual wordt geinstalleerd..."
    if "$PYTHON" -m pip install --quiet --upgrade textual; then
        echo "✔️  Textual gereed"
    else
        echo "FOUT: textual kon niet geinstalleerd worden. Probeer handmatig:"
        echo "  $PYTHON -m pip install textual"
        exit 1
    fi
fi

echo "🚀 Desktop-versie starten..."
exec "$PYTHON" "$SCRIPT"