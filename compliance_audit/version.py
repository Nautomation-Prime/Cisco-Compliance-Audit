"""Version helpers for Cisco Compliance Audit."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT_FILE = _ROOT / "pyproject.toml"
_APP_NAME = "Cisco Compliance Audit"


def _read_project_metadata() -> dict:
    try:
        data = tomllib.loads(_PYPROJECT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

    project = data.get("project")
    return project if isinstance(project, dict) else {}


def get_version() -> str:
    """Return the canonical project version string from pyproject.toml."""
    project = _read_project_metadata()
    version = project.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return "unknown"


def get_version_info() -> str:
    """Return a user-facing version summary including Python and platform details."""
    import platform
    import sys

    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    plat = f"{platform.system()} {platform.release()}"
    arch = platform.machine()
    return "\n".join([
        f"{_APP_NAME} v{get_version()}",
        f"Python:   {py}",
        f"Platform: {plat} ({arch})",
    ])
