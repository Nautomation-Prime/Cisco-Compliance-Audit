"""Unit tests for version metadata helpers."""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from compliance_audit.__about__ import __version__
from compliance_audit.version import get_version, get_version_info


def _expected_version_from_pyproject() -> str:
    project_root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


def test_get_version_matches_pyproject_version():
    assert get_version() == _expected_version_from_pyproject()


def test_about_version_matches_helper_version():
    assert __version__ == get_version()


def test_get_version_info_includes_app_name_and_version():
    info = get_version_info()
    assert "Cisco Compliance Audit" in info
    assert _expected_version_from_pyproject() in info
