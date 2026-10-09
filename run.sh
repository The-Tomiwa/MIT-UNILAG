#!/usr/bin/env sh
# GPON Malware Framework Generator - one-click start (macOS / Linux)
set -e
cd "$(dirname "$0")"

PY=$(command -v python3 || command -v python || true)
[ -z "$PY" ] && { echo "Python 3.10+ is required: https://www.python.org/downloads/"; exit 1; }

if ! .venv/bin/python -c "import flask, fitz" >/dev/null 2>&1; then
  echo "First run on this computer: setting up Python environment and dependencies..."
  rm -rf .venv   # a Windows .venv (or one from another machine) cannot run here
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet flask pymupdf
  .venv/bin/python -m pip install --quiet yara-python >/dev/null 2>&1 || true
fi

echo "Starting on http://127.0.0.1:5057  (Ctrl+C to stop)"
( sleep 2; (open http://127.0.0.1:5057 || xdg-open http://127.0.0.1:5057) >/dev/null 2>&1 ) &
.venv/bin/python app.py
