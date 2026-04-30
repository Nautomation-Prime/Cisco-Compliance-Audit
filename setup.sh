#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Cisco Compliance Audit - First-Time Setup (Linux / WSL)
# # SPDX-License-Identifier: GPL-3.0-only
# # Copyright (c) 2026 Christopher Davies
#
# Creates a Python virtual environment and installs all required packages.
# Runs automatically from run.sh when .venv/ is missing. Requires Python 3.12+
# and an internet connection (one-time only).
#
# To upgrade dependencies: delete .venv/ and run this script again.
# ------------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=12

echo
echo "================================================================================"
echo " Cisco Compliance Audit - First-Time Setup"
echo "================================================================================"
echo
echo " Python $PYTHON_MIN_MAJOR.$PYTHON_MIN_MINOR+ and all required packages will be installed"
echo " into a local virtual environment (.venv/).  An internet connection is required."
echo " This only runs once."
echo
echo " NOTE: PyATS/Genie are large packages. This may take several minutes."
echo
read -r -p " Press Enter to begin, or Ctrl+C to cancel."

# ── Find a suitable Python interpreter ────────────────────────────────────────

_find_python() {
    for cmd in python3.13 python3.12 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || continue
            major="${ver%%.*}"
            minor="${ver#*.}"
            if [ "$major" -gt "$PYTHON_MIN_MAJOR" ] || \
               { [ "$major" -eq "$PYTHON_MIN_MAJOR" ] && [ "$minor" -ge "$PYTHON_MIN_MINOR" ]; }; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON_CMD=$(_find_python || true)
if [ -z "$PYTHON_CMD" ]; then
    echo
    echo " [ERROR] Python $PYTHON_MIN_MAJOR.$PYTHON_MIN_MINOR or later is required but was not found."
    echo "         Install it with your package manager, e.g.:"
    echo "           sudo apt install python3.12"
    echo "           sudo dnf install python3.12"
    echo
    exit 1
fi

echo
echo " Using: $PYTHON_CMD ($(${PYTHON_CMD} --version))"
echo

# ── Create virtual environment ─────────────────────────────────────────────────

echo "[1/3] Creating virtual environment in .venv/ ..."
"$PYTHON_CMD" -m venv "$VENV"

# ── Upgrade pip ───────────────────────────────────────────────────────────────

echo "[2/3] Upgrading pip ..."
"$VENV/bin/pip" install --upgrade pip --quiet

# ── Install dependencies ───────────────────────────────────────────────────────

echo "[3/3] Installing dependencies (this may take several minutes) ..."
"$VENV/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"

echo
echo "================================================================================"
echo " Setup complete.  Run ./run.sh to launch the tool."
echo "================================================================================"
echo
