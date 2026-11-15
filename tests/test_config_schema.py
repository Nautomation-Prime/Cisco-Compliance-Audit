"""
Tests for compliance_audit.config_schema — the Pydantic validation of the
merged compliance YAML.

The cases that matter are the silent ones: a typo or misplaced key that the
engine would ignore, quietly changing what the audit checks.
"""

import copy
import re
from pathlib import Path

import pytest

from compliance_audit.auditor import (
    load_compliance_config,
    read_compliance_config,
)
from compliance_audit.config_schema import (
    CHECK_SCHEMAS,
    ROLE_CHECK_SCHEMAS,
    ConfigValidationError,
    ensure_valid_config,
    validate_compliance_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "assets" / "compliance_config"
CHECKS_DIR = REPO_ROOT / "compliance_audit" / "checks"

_SHIPPED = read_compliance_config(str(CONFIG_DIR), validate=False)


@pytest.fixture
def cfg():
    return copy.deepcopy(_SHIPPED)


def errors_for(cfg) -> str:
    return "\n".join(validate_compliance_config(cfg))


def mp(cfg):
    return cfg["compliance"]["management_plane"]


# ---------------------------------------------------------------------------
# The shipped config, and the check registry staying in step with the engine
# ---------------------------------------------------------------------------

class TestShippedConfig:
    def test_shipped_config_is_valid(self):
        assert validate_compliance_config(_SHIPPED) == []

    def test_every_shipped_check_is_registered_in_its_section(self):
        for section, schemas in CHECK_SCHEMAS.items():
            shipped = set(_SHIPPED["compliance"][section])
            assert shipped <= set(schemas), shipped - set(schemas)


class TestRegistryMatchesEngine:
    """CHECK_SCHEMAS must list exactly the checks the engine implements."""

    source = "".join(p.read_text(encoding="utf-8") for p in CHECKS_DIR.glob("*.py"))

    def registered(self) -> set[str]:
        keys = {k for schemas in CHECK_SCHEMAS.values() for k in schemas}
        return keys | {k for schemas in ROLE_CHECK_SCHEMAS.values() for k in schemas}

    def test_every_enabled_lookup_is_registered(self):
        looked_up = set(re.findall(r'_enabled\(\s*\w+,\s*"(\w+)"', self.source))
        assert looked_up <= self.registered(), looked_up - self.registered()

    def test_every_implemented_check_appears_in_the_engine(self):
        # Checks driven from tables (banner_*, aaa lists …) appear as string
        # literals or f-string prefixes rather than _enabled() calls.
        for section, schemas in CHECK_SCHEMAS.items():
            for key in schemas:
                prefix = key.rsplit("_", 1)[0] + "_"
                assert f'"{key}"' in self.source or f'f"{prefix}{{' in self.source, key


# ---------------------------------------------------------------------------
# Typos and misplaced keys
# ---------------------------------------------------------------------------

class TestUnknownKeys:
    def test_unknown_top_level_key_suggests_fix(self, cfg):
        cfg["inventory_files"] = "x"
        assert "inventory_files: unknown top-level key — did you mean 'inventory_file'?" in errors_for(cfg)

    def test_unknown_audit_setting(self, cfg):
        cfg["audit_settings"]["max_worker"] = 10
        assert "audit_settings.max_worker: unknown key — did you mean 'max_workers'?" in errors_for(cfg)

    def test_unknown_nested_setting(self, cfg):
        cfg["audit_settings"]["remediation"]["execution"]["allow_bulk_aply"] = False
        assert "execution.allow_bulk_aply: unknown key — did you mean 'allow_bulk_apply'?" in errors_for(cfg)

    def test_unknown_check_parameter(self, cfg):
        mp(cfg)["ntp_servers"]["expected_server"] = ["192.0.2.1"]
        assert "ntp_servers.expected_server: unknown key — did you mean 'expected_servers'?" in errors_for(cfg)

    def test_mistyped_enabled_is_reported_twice(self, cfg):
        node = mp(cfg)["ssh_version"]
        node["enabld"] = node.pop("enabled")
        out = errors_for(cfg)
        assert "ssh_version.enabled: Field required" in out
        assert "ssh_version.enabld: unknown key — did you mean 'enabled'?" in out

    def test_unknown_check_key_would_never_run(self, cfg):
        mp(cfg)["ntp_server"] = mp(cfg).pop("ntp_servers")
        assert "ntp_server: unknown check — it would never run — did you mean 'ntp_servers'?" in errors_for(cfg)

    def test_check_in_wrong_section(self, cfg):
        mp(cfg)["stp_mode"] = cfg["compliance"]["control_plane"].pop("stp_mode")
        assert "'stp_mode' is a control_plane check — move it under compliance.control_plane" in errors_for(cfg)

    def test_unknown_compliance_section(self, cfg):
        cfg["compliance"]["managment_plane"] = cfg["compliance"].pop("management_plane")
        assert "compliance.managment_plane: unknown section — did you mean 'management_plane'?" in errors_for(cfg)

    def test_untrusted_port_kind_typo(self, cfg):
        cfg["compliance"]["data_plane"]["dhcp_snooping_trust"]["untrusted"]["acess_ports"] = True
        assert "untrusted.acess_ports: unknown key — did you mean 'access_ports'?" in errors_for(cfg)

    def test_unknown_role_in_applies_to_roles(self, cfg):
        mp(cfg)["ssh_version"]["applies_to_roles"] = ["acess_switch"]
        assert "unknown role 'acess_switch'" in errors_for(cfg)

    def test_contradictory_checks_cannot_both_be_enabled(self, cfg):
        mp(cfg)["logging_console"]["enabled"] = True
        mp(cfg)["no_logging_console"]["enabled"] = True
        assert "'logging_console' and 'no_logging_console' are both enabled" in errors_for(cfg)

    def test_role_specific_checks(self, cfg):
        node = {"enabled": True, "severity": "high", "tags": []}
        cfg["compliance"]["role_specific"] = {"access_switch": {"stp_not_root": node}}
        assert errors_for(cfg) == ""
        cfg["compliance"]["role_specific"] = {"core_switch": {"stp_not_root": node}}
        assert "role_specific.core_switch: no role-specific checks exist" in errors_for(cfg)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

class TestValues:
    @pytest.mark.parametrize(
        "hosts",
        [["192.0.2.70"], ["2001:db8::1"], ["ntp1.corp.example"], []],
    )
    def test_expected_servers_accept_ips_and_hostnames(self, cfg, hosts):
        mp(cfg)["ntp_servers"]["expected_servers"] = hosts
        assert errors_for(cfg) == ""

    @pytest.mark.parametrize("bad", ["10.0.0.256", "192.0.2", "fe80::zz", "bad host"])
    def test_expected_hosts_reject_bad_addresses(self, cfg, bad):
        mp(cfg)["logging_host"]["expected_hosts"] = ["192.0.2.70", bad]
        assert "logging_host.expected_hosts[1]:" in errors_for(cfg)

    def test_jump_host_must_be_an_address(self, cfg):
        cfg["connection"]["jump_host"] = "192.0.2.600"
        assert "connection.jump_host: '192.0.2.600' is not a valid IP address" in errors_for(cfg)

    def test_use_jump_host_needs_a_jump_host(self, cfg):
        cfg["connection"].update(use_jump_host=True, jump_host="")
        assert "use_jump_host is true but jump_host is empty" in errors_for(cfg)

    def test_device_type_must_be_a_netmiko_type(self, cfg):
        cfg["connection"]["device_type"] = "cisco_iosxe"
        assert "'cisco_iosxe' is not a Netmiko device_type (did you mean" in errors_for(cfg)

    def test_severity(self, cfg):
        mp(cfg)["ssh_version"]["severity"] = "urgent"
        assert "ssh_version.severity:" in errors_for(cfg)

    def test_invalid_filter_regex(self, cfg):
        mp(cfg)["ssh_version"]["exclude_hostnames"] = ["^LAB["]
        assert "exclude_hostnames[0]: invalid regex '^LAB['" in errors_for(cfg)

    def test_invalid_endpoint_regex(self, cfg):
        cfg["endpoint_neighbors"]["platform_patterns"] = ["AIR-("]
        assert "endpoint_neighbors.platform_patterns[0]: invalid regex" in errors_for(cfg)

    @pytest.mark.parametrize("spec", ["10,20-x", "0", "4095", "30-10"])
    def test_invalid_vlan_spec(self, cfg, spec):
        cfg["compliance"]["control_plane"]["dhcp_snooping_vlans"]["vlans"] = spec
        assert "dhcp_snooping_vlans.vlans:" in errors_for(cfg)

    @pytest.mark.parametrize("spec", ["", "10", "10,20,30-40", "10 20", 99])
    def test_valid_vlan_spec(self, cfg, spec):
        cfg["compliance"]["control_plane"]["dhcp_snooping_vlans"]["vlans"] = spec
        assert errors_for(cfg) == ""

    def test_storm_falling_above_rising(self, cfg):
        tier = cfg["compliance"]["data_plane"]["storm_control"]["thresholds_by_speed"][1000]
        tier["broadcast"] = {"rising": 1.0, "falling": 5.0}
        assert "falling (5.0) must not exceed rising (1.0)" in errors_for(cfg)

    def test_storm_legacy_bare_threshold_is_valid(self, cfg):
        tier = cfg["compliance"]["data_plane"]["storm_control"]["thresholds_by_speed"][1000]
        tier["broadcast"] = 1.0
        assert errors_for(cfg) == ""

    def test_syslog_level(self, cfg):
        mp(cfg)["logging_trap"]["level"] = 6
        assert errors_for(cfg) == ""
        mp(cfg)["logging_trap"]["level"] = "informative"
        assert "logging_trap.level: must be a syslog level" in errors_for(cfg)

    def test_duplicate_hostname_role_code(self, cfg):
        cfg["hostname_roles"].append({"code": "asw", "role": "other"})
        assert "duplicate role code 'ASW'" in errors_for(cfg)

    def test_stp_priority_must_be_a_bridge_priority(self, cfg):
        cfg["compliance"]["control_plane"]["stp_priority"]["access_priority"] = 36863
        assert "access_priority: must be a multiple of 4096" in errors_for(cfg)

    def test_origin_id_string_needs_text(self, cfg):
        mp(cfg)["logging_origin_id"]["type"] = "string"
        assert "type 'string' needs the origin text" in errors_for(cfg)

    def test_post_report_formats(self, cfg):
        cfg["audit_settings"]["remediation"]["execution"]["post_report_formats"] = ["pdf"]
        assert "post_report_formats[0]:" in errors_for(cfg)


# ---------------------------------------------------------------------------
# Loader integration
# ---------------------------------------------------------------------------

def _write_config(tmp_path: Path, cfg: dict) -> Path:
    import yaml

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "all.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return cfg_dir


class TestLoader:
    def test_ensure_valid_config_raises(self, cfg):
        cfg["audit_settings"]["max_worker"] = 10
        with pytest.raises(ConfigValidationError) as exc_info:
            ensure_valid_config(cfg)
        assert len(exc_info.value.errors) == 1

    def test_read_rejects_invalid_config(self, tmp_path, cfg):
        cfg["audit_settings"]["max_worker"] = 10
        cfg_dir = _write_config(tmp_path, cfg)
        with pytest.raises(ConfigValidationError):
            read_compliance_config(str(cfg_dir))
        assert read_compliance_config(str(cfg_dir), validate=False)

    def test_load_exits_2_on_invalid_config(self, tmp_path, cfg):
        cfg["audit_settings"]["max_worker"] = 10
        cfg_dir = _write_config(tmp_path, cfg)
        with pytest.raises(SystemExit) as exc_info:
            load_compliance_config(str(cfg_dir))
        assert exc_info.value.code == 2

    def test_remediation_loads_the_config_directory(self):
        # Regression: _load_config used to open() the directory as a file,
        # so single-pack apply failed with the default --config value.
        from compliance_audit.remediation_workflow import _load_config

        assert "compliance" in _load_config(str(CONFIG_DIR))
        with pytest.raises(RuntimeError, match="not found"):
            _load_config("does/not/exist")
