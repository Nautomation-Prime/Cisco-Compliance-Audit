"""
Tests for device-inventory path resolution and config loading after the
config files were relocated to assets/.
"""

from pathlib import Path

from compliance_audit.auditor import (
    _resolve_inventory_path,
    load_compliance_config,
    load_device_inventory,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "assets" / "compliance_config"
DEVICES = REPO_ROOT / "assets" / "devices" / "devices.yaml"


class TestResolveInventoryPath:
    def test_absolute_path_returned_as_is(self):
        abs_path = DEVICES
        assert _resolve_inventory_path(str(abs_path), CONFIG_DIR) == abs_path

    def test_repo_root_relative_resolves(self, tmp_path):
        # cfg_dir is unrelated; path resolves via the project root candidate.
        resolved = _resolve_inventory_path("assets/devices/devices.yaml", tmp_path)
        assert resolved is not None
        assert resolved.exists()
        assert resolved.name == "devices.yaml"

    def test_config_dir_relative_resolves(self, tmp_path):
        # Create an inventory file inside a fake config dir and resolve it
        # relative to that dir.
        inv = tmp_path / "devices.yaml"
        inv.write_text("devices: []\n", encoding="utf-8")
        resolved = _resolve_inventory_path("devices.yaml", tmp_path)
        assert resolved == inv

    def test_missing_returns_cwd_candidate(self, tmp_path):
        resolved = _resolve_inventory_path("does/not/exist.yaml", tmp_path)
        # Falls back to a CWD-relative path (does not raise, does not exist)
        assert resolved is not None
        assert not resolved.exists()


class TestConfigAndInventoryLoad:
    def test_config_loads_from_assets(self):
        cfg = load_compliance_config(str(CONFIG_DIR))
        assert "compliance" in cfg
        assert cfg.get("inventory_file") == "assets/devices/devices.yaml"

    def test_inventory_loads_via_config_pointer(self):
        devices = load_device_inventory(None, str(CONFIG_DIR))
        assert isinstance(devices, list)
        assert len(devices) >= 1
