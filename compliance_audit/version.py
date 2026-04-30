"""Version helpers for Cisco Compliance Audit."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_VERSION_FILE = _ROOT / "VERSION.txt"


def get_version_info() -> str:
    """Return the full contents of VERSION.txt, or a safe fallback string."""
    try:
        return _VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return "Cisco Compliance Audit\nVersion: unknown"


def get_version() -> str:
    """Return just the version number string (e.g. '4.0.0')."""
    for line in get_version_info().splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"
