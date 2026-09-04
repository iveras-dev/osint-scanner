#!/bin/bash
# OSINT Scanner starten
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -d "$SCRIPT_DIR/.venv" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
fi
python3 "$SCRIPT_DIR/osint_scanner.py" "$@"
