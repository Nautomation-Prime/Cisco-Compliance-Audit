#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Cisco Compliance Audit - Portable Launcher (Linux / WSL)
# # SPDX-License-Identifier: GPL-3.0-only
# # Copyright (c) 2026 Christopher Davies
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
PYTHON="$VENV/bin/python"

echo
echo "================================================================================"
echo "               CISCO COMPLIANCE AUDIT TOOL"
echo "================================================================================"
echo
echo " Starting pre-flight checks..."
echo

# Bootstrap virtual environment on first run
if [ ! -f "$PYTHON" ]; then
    echo " Virtual environment not found - running first-time setup..."
    echo
    bash "$SCRIPT_DIR/setup.sh" || {
        echo
        echo " [FAILED] Setup did not complete. Cannot continue."
        exit 1
    }
    echo
fi

# Check package is present
if [ ! -f "$SCRIPT_DIR/compliance_audit/__init__.py" ]; then
    echo " [ERROR] Package not found at: $SCRIPT_DIR/compliance_audit"
    exit 1
fi

# Check compliance config exists
if [ ! -d "$SCRIPT_DIR/compliance_audit/compliance_config" ]; then
    echo " [ERROR] Missing: compliance_audit/compliance_config/"
    exit 1
fi

echo " [OK] Pre-flight checks passed"
echo

# Launch the TUI
cd "$SCRIPT_DIR"
"$PYTHON" -m compliance_audit --tui "$@"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo
    echo " [ERROR] Exited with code $EXIT_CODE. Review logs/debug.log for details."
    echo
fi

exit $EXIT_CODE
