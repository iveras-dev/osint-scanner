#!/bin/bash
# OSINT Scanner startscript
# Kill oude processen → start vers

SCRIPT="osint_scanner.py"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🔍 OSINT Scanner starten..."

# Kill eventueel draaiende instanties
PIDS=$(pgrep -f "python.*$SCRIPT" 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "⚠️  Oud proces gevonden (PID: $PIDS) — killen..."
    kill $PIDS 2>/dev/null
    sleep 1
    # Force kill als nodig
    kill -9 $PIDS 2>/dev/null
    echo "✔️  Oud proces gestopt"
fi

# __pycache__ opruimen zodat Python de verse code laadt
CACHE="$DIR/__pycache__"
if [ -d "$CACHE" ]; then
    rm -f "$CACHE/osint_scanner.cpython-"*.pyc 2>/dev/null
    echo "✔️  Cache opgeschoond"
fi

echo "🚀 Scanner starten..."
cd "$DIR"
python3 "$SCRIPT"
