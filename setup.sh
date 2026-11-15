#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Cisco Compliance Audit - First-Time Setup (Linux / WSL)
# # SPDX-License-Identifier: Apache-2.0
# # Copyright (c) 2026 Christopher Davies
#
# Creates a Python virtual environment and installs all required packages.
# Runs automatically from run.sh when .venv/ is missing. Requires Python 3.12+
# and an internet connection (one-time only).
#
# To upgrade dependencies: delete .venv/ and run this script again.
# ------------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=12

echo
echo "============================================================"
echo " Cisco Compliance Audit - First-Time Setup"
echo "============================================================"
echo
echo " Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ and all required"
echo " packages will be installed into:"
echo " $VENV"
echo
echo " An internet connection is required."
echo " NOTE: PyATS/Genie are large packages."
echo

read -r -p " Press Enter to begin, or Ctrl+C to cancel."

find_python() {
    local cmd
    local ver
    local major
    local minor

    for cmd in python3.13 python3.12 python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ver="$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" || continue
            major="${ver%%.*}"
            minor="${ver#*.}"

            if [[ "$major" -gt "$PYTHON_MIN_MAJOR" ]] ||
               [[ "$major" -eq "$PYTHON_MIN_MAJOR" &&
                  "$minor" -ge "$PYTHON_MIN_MINOR" ]]; then
                printf '%s\n' "$cmd"
                return 0
            fi
        fi
    done

    return 1
}

PYTHON_CMD="$(find_python || true)"

if [[ -z "$PYTHON_CMD" ]]; then
    echo
    echo " [ERROR] Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} or later"
    echo "         is required but was not found."
    echo
    echo " Examples:"
    echo "   sudo dnf install python3.12"
    echo "   sudo apt install python3.12"
    exit 1
fi

echo
echo " Using: $("$PYTHON_CMD" --version)"
echo

echo "[1/3] Creating virtual environment in $VENV ..."

if [[ -d "$VENV" ]]; then
    echo " Existing virtual environment found."
else
    "$PYTHON_CMD" -m venv "$VENV"
fi

if [[ ! -x "$VENV/bin/python" ]]; then
    echo
    echo " [ERROR] Virtual environment Python was not created:"
    echo "         $VENV/bin/python"
    echo
    echo " On some Linux distributions the venv package must be installed separately."
    exit 1
fi

echo "[2/3] Upgrading pip ..."
"$VENV/bin/python" -m pip install --upgrade pip

if [[ ! -f "$SCRIPT_DIR/requirements.txt" ]]; then
    echo
    echo " [ERROR] requirements.txt was not found:"
    echo "         $SCRIPT_DIR/requirements.txt"
    exit 1
fi

echo "[3/3] Installing dependencies ..."
"$VENV/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo
echo "============================================================"
echo " Setup complete"
echo "============================================================"
echo
echo " Run ./run.sh to launch the tool."
echo