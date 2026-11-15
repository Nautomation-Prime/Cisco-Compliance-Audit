"""
Regression tests for malformed-YAML handling and dependency-manifest parity.

These cover the gap that let the TUI crash slip through: a real-world
``devices.yaml`` containing a literal TAB made ``yaml.safe_load`` raise a raw
``yaml.scanner.ScannerError`` that propagated out of ``load_device_inventory``
unhandled. The fixtures used by the rest of the suite are all clean YAML, so the
failure mode was invisible. We now assert a clear, actionable error is raised
instead, plus a happy-path parse, plus a check that every runtime dependency in
``pyproject.toml`` is also declared in ``requirements.txt`` (the omission of
``pydantic`` from ``requirements.txt`` is exactly this class of bug).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compliance_audit.auditor import load_device_inventory

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]


_REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Malformed YAML -> clear error
# ---------------------------------------------------------------------------

class TestInventoryYamlErrors:
    def test_tab_indented_inventory_raises_clear_error(self, tmp_path):
        # A literal TAB used for indentation is illegal YAML and is the exact
        # corruption reported from the field.
        bad = tmp_path / "devices.yaml"
        bad.write_text("devices:\n\t- hostname: sw1\n", encoding="utf-8")

        with pytest.raises(ValueError) as exc_info:
            load_device_inventory(str(bad), "assets/compliance_config")

        message = str(exc_info.value)
        # Actionable: names the file, gives a line/column, and mentions tabs.
        assert str(bad) in message
        assert "line" in message and "column" in message
        assert "tab" in message.lower()

    def test_tab_error_is_not_raw_scanner_error(self, tmp_path):
        import yaml

        bad = tmp_path / "devices.yaml"
        bad.write_text("devices:\n\t- hostname: sw1\n", encoding="utf-8")

        with pytest.raises(ValueError) as exc_info:
            load_device_inventory(str(bad), "assets/compliance_config")

        # The raw parser error must be wrapped, not surfaced directly.
        assert not isinstance(exc_info.value, yaml.YAMLError)

    def test_valid_inventory_parses(self, tmp_path):
        good = tmp_path / "devices.yaml"
        good.write_text(
            "devices:\n"
            "  - hostname: sw1\n"
            "    ip: 10.0.0.1\n"
            "  - hostname: sw2\n"
            "    ip: 10.0.0.2\n",
            encoding="utf-8",
        )

        devices = load_device_inventory(str(good), "assets/compliance_config")

        assert len(devices) == 2
        assert {d["hostname"] for d in devices} == {"sw1", "sw2"}
        assert {d["ip"] for d in devices} == {"10.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# Dependency-manifest parity (pyproject.toml -> requirements.txt)
# ---------------------------------------------------------------------------

def _canonical_name(spec: str) -> str | None:
    """Return the PEP 503-normalised distribution name from a requirement spec.

    Strips environment markers (after ``;``), extras (``[...]``) and any version
    specifier, then normalises runs of ``-``, ``_`` and ``.`` to a single ``-``
    and lowercases. Returns ``None`` for blank/comment lines.
    """
    spec = spec.split(";", 1)[0].strip()
    if not spec or spec.startswith("#"):
        return None
    spec = re.sub(r"\[.*?\]", "", spec)  # drop extras
    name = re.split(r"[<>=!~ ]", spec, maxsplit=1)[0].strip()
    if not name:
        return None
    return re.sub(r"[-_.]+", "-", name).lower()


def _pyproject_runtime_deps() -> set[str]:
    data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    return {n for dep in deps if (n := _canonical_name(dep))}


def _requirements_deps() -> set[str]:
    names: set[str] = set()
    for line in (_REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        name = _canonical_name(line)
        if name:
            names.add(name)
    return names


def test_every_pyproject_runtime_dep_is_in_requirements():
    missing = _pyproject_runtime_deps() - _requirements_deps()
    assert not missing, (
        "Runtime dependencies declared in pyproject.toml but missing from "
        f"requirements.txt (the bundled runtime is built from requirements.txt): {sorted(missing)}"
    )


def test_pydantic_present_in_both_manifests():
    # Explicit guard for the specific omission that broke --validate-config /
    # --dry-run / --health on the bundled runtime.
    assert "pydantic" in _pyproject_runtime_deps()
    assert "pydantic" in _requirements_deps()
