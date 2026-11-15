"""
Tests for check settings that used to be ignored or matched too loosely.

Every case here was either a false PASS (a prefix match, or a configured
value that was never compared) or a setting the engine never read.
"""

from pathlib import Path

import pytest

from compliance_audit.auditor import _parse_ip_filter, filter_devices_by_ip
from compliance_audit.checks.base import _enabled, _setting
from compliance_audit.collector import DeviceData, parse_running_config
from compliance_audit.compliance_engine import ComplianceEngine, Status
from compliance_audit.config_schema import CHECK_SCHEMAS, CheckNodeSchema
from compliance_audit.hostname_parser import parse_hostname
from compliance_audit.port_classifier import PortInfo, PortRole

CHECKS_DIR = Path(__file__).resolve().parent.parent / "compliance_audit" / "checks"


def run(section, method, config_text, host="SW1", data=None, **checks):
    policy = {section: {k: {"enabled": True, **(v or {})} for k, v in checks.items()}}
    cfg = parse_running_config(config_text)
    data = data or DeviceData(hostname=host, ip="192.0.2.1", running_config=config_text)
    data.parsed_config = cfg
    return getattr(ComplianceEngine(policy), method)(cfg, data, parse_hostname(host), {})


def mgmt(method, config_text, **checks):
    return run("management_plane", method, config_text, **checks)


def ctrl(method, config_text, **kw):
    return run("control_plane", method, config_text, **kw)


def status(findings, name):
    matches = [f for f in findings if f.check_name == name]
    assert len(matches) == 1, f"expected one {name}, got {matches}"
    return matches[0].status


# ---------------------------------------------------------------------------
# Engine plumbing
# ---------------------------------------------------------------------------

class TestEnabledAndDefaults:
    def test_absent_check_is_disabled(self):
        assert not _enabled({}, "ntp_servers")
        assert not _enabled({"ntp_servers": {"severity": "low"}}, "ntp_servers")
        assert _enabled({"ntp_servers": {"enabled": True}}, "ntp_servers")

    def test_only_enabled_checks_run(self):
        findings = mgmt("_check_logging", "", logging_console={})
        assert {f.check_name for f in findings} == {"logging_console"}

    def test_setting_falls_back_to_schema_default(self):
        mp = {"logging_console": {"enabled": True}}
        assert _setting(mp, "logging_console", "level") == "critical"
        mp["logging_console"]["level"] = "errors"
        assert _setting(mp, "logging_console", "level") == "errors"

    def test_every_declared_setting_is_read_by_the_engine(self):
        """A setting in the schema that no check reads would do nothing."""
        source = "".join(p.read_text(encoding="utf-8") for p in CHECKS_DIR.glob("*.py"))
        common = set(CheckNodeSchema.model_fields)
        unread = sorted(
            f"{check}.{field}"
            for schemas in CHECK_SCHEMAS.values()
            for check, model in schemas.items()
            for field in set(model.model_fields) - common
            if f'"{field}"' not in source
        )
        assert not unread, unread


# ---------------------------------------------------------------------------
# Whole-value matches (previously prefix matches)
# ---------------------------------------------------------------------------

class TestExactMatches:
    @pytest.mark.parametrize(
        "check, command",
        [
            ("ssh_source_interface", "ip ssh source-interface"),
            ("ntp_source_interface", "ntp source"),
            ("logging_source_interface", "logging source-interface"),
            ("tacacs_source_interface", "ip tacacs source-interface"),
        ],
    )
    def test_source_interface_is_compared_whole(self, check, command):
        method = {
            "ssh_source_interface": "_check_ssh",
            "ntp_source_interface": "_check_ntp",
            "logging_source_interface": "_check_logging",
            "tacacs_source_interface": "_check_aaa",
        }[check]
        wrong = mgmt(method, f"{command} Vlan10\n", **{check: {"interface": "Vlan1"}})
        assert status(wrong, check) == Status.FAIL
        right = mgmt(method, f"{command} Loopback0\n", **{check: {"interface": "Lo0"}})
        assert status(right, check) == Status.PASS
        missing = mgmt(method, "", **{check: {"interface": ""}})
        assert status(missing, check) == Status.FAIL

    def test_tacacs_source_inside_server_group(self):
        config = "aaa group server tacacs+ NOC\n ip tacacs source-interface Loopback0\n"
        findings = mgmt("_check_aaa", config, tacacs_source_interface={"interface": "Loopback0"})
        assert status(findings, "tacacs_source_interface") == Status.PASS

    @pytest.mark.parametrize(
        "line, expected",
        [
            ("ip http access-class 10\n", Status.FAIL),
            ("ip http access-class 1\n", Status.PASS),
            ("ip http access-class ipv4 1\n", Status.PASS),
        ],
    )
    def test_http_access_class(self, line, expected):
        findings = mgmt("_check_ip_settings", line, ip_http_access_class={"acl_name": "1"})
        assert status(findings, "ip_http_access_class") == expected

    @pytest.mark.parametrize(
        "line, expected",
        [
            ("ip domain name corp.example.com\n", Status.PASS),
            ("ip domain-name corp.example.com\n", Status.PASS),
            ("ip domain name corp.example.com.evil\n", Status.FAIL),
        ],
    )
    def test_domain_name(self, line, expected):
        findings = mgmt(
            "_check_ip_settings", line, ip_domain_name={"expected": "corp.example.com"}
        )
        assert status(findings, "ip_domain_name") == expected

    @pytest.mark.parametrize(
        "line, node, expected",
        [
            ("clock timezone GMT 0 0\n", {"timezone": "GMT"}, Status.PASS),
            ("clock timezone GMT0 0 0\n", {"timezone": "GMT"}, Status.FAIL),
            ("clock timezone EST -5 0\n", {"timezone": "EST", "offset": -5}, Status.PASS),
            ("clock timezone EST -4 0\n", {"timezone": "EST", "offset": -5}, Status.FAIL),
            ("clock timezone IST 5 30\n", {"timezone": "IST", "offset": 5, "offset_minutes": 30}, Status.PASS),
        ],
    )
    def test_clock_timezone(self, line, node, expected):
        findings = mgmt("_check_ip_settings", line, clock_timezone=node)
        assert status(findings, "clock_timezone") == expected

    def test_aaa_expected_line_is_exact(self):
        expected = "aaa authorization exec default group NOC local"
        findings = mgmt(
            "_check_aaa", expected + " if-authenticated\n",
            aaa_authorization_exec={"expected": expected},
        )
        assert status(findings, "aaa_authorization_exec") == Status.FAIL

    def test_errdisable_interval(self):
        node = {"interval": 30}
        assert status(ctrl("_check_errdisable", "errdisable recovery interval 300\n",
                           errdisable_recovery=node), "errdisable_recovery_interval") == Status.FAIL
        assert status(ctrl("_check_errdisable", "errdisable recovery interval 30\n",
                           errdisable_recovery=node), "errdisable_recovery_interval") == Status.PASS


# ---------------------------------------------------------------------------
# Logging levels and settings
# ---------------------------------------------------------------------------

class TestLoggingLevels:
    @pytest.mark.parametrize(
        "config, expected",
        [
            ("logging console critical\n", Status.PASS),
            ("logging console emergencies\n", Status.PASS),
            ("logging console debugging\n", Status.FAIL),
            ("logging console\n", Status.FAIL),  # no level shown = debugging
            ("no logging console\n", Status.PASS),
            ("", Status.FAIL),
        ],
    )
    def test_console_level_is_a_ceiling(self, config, expected):
        findings = mgmt("_check_logging", config, logging_console={"level": "critical"})
        assert status(findings, "logging_console") == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ("logging trap informational\n", Status.PASS),
            ("logging trap debugging\n", Status.PASS),
            ("logging trap warnings\n", Status.FAIL),
            ("logging trap\n", Status.PASS),  # no level shown = informational
        ],
    )
    def test_trap_level_is_a_floor(self, config, expected):
        findings = mgmt("_check_logging", config, logging_trap={"level": "informational"})
        assert status(findings, "logging_trap") == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ("logging buffered 64000 informational\n", Status.PASS),
            ("logging buffered 64000\n", Status.PASS),       # default level debugging
            ("logging buffered 8192 informational\n", Status.FAIL),
            ("logging buffered 64000 warnings\n", Status.FAIL),
            ("", Status.FAIL),
        ],
    )
    def test_buffered_size_and_level(self, config, expected):
        findings = mgmt(
            "_check_logging", config,
            logging_buffered={"min_size": 64000, "level": "informational"},
        )
        assert status(findings, "logging_buffered") == expected

    @pytest.mark.parametrize(
        "config, node, expected",
        [
            ("logging origin-id hostname\n", {"type": "hostname"}, Status.PASS),
            ("logging origin-id ip\n", {"type": "hostname"}, Status.FAIL),
            ('logging origin-id string "SITE-A"\n', {"type": "string", "string": "SITE-A"}, Status.PASS),
        ],
    )
    def test_origin_id(self, config, node, expected):
        findings = mgmt("_check_logging", config, logging_origin_id=node)
        assert status(findings, "logging_origin_id") == expected


# ---------------------------------------------------------------------------
# Access control and login
# ---------------------------------------------------------------------------

class TestLineAccess:
    @pytest.mark.parametrize(
        "line, expected",
        [
            (" access-class MGMT in\n", Status.PASS),
            (" access-class MGMT in vrf-also\n", Status.PASS),
            (" access-class OTHER in\n", Status.FAIL),
            (" access-class MGMT out\n", Status.FAIL),
        ],
    )
    def test_vty_access_class_uses_acl_name(self, line, expected):
        findings = mgmt(
            "_check_vty_lines", "line vty 0 4\n" + line,
            vty_access_class={"acl_name": "MGMT"},
        )
        assert status(findings, "vty_access_class") == expected

    def test_login_authentication_list_must_match(self):
        config = "line vty 0 4\n login authentication LOCAL_ONLY\n"
        findings = mgmt("_check_vty_lines", config, vty_login_authentication={"method_list": "NOC"})
        assert status(findings, "vty_login_authentication") == Status.FAIL

    def test_default_list_applies_implicitly(self):
        config = (
            "aaa new-model\naaa authentication login default group NOC local\n"
            "line vty 0 4\n transport input ssh\n"
        )
        findings = mgmt("_check_vty_lines", config, vty_login_authentication={})
        assert status(findings, "vty_login_authentication") == Status.PASS

    @pytest.mark.parametrize(
        "line, expected",
        [
            ("login block-for 120 attempts 3 within 60\n", Status.PASS),
            ("login block-for 300 attempts 2 within 120\n", Status.PASS),
            ("login block-for 30 attempts 3 within 60\n", Status.FAIL),
            ("login block-for 120 attempts 10 within 60\n", Status.FAIL),
        ],
    )
    def test_login_block_for_values(self, line, expected):
        findings = mgmt("_check_login_security", line, login_block_for={})
        assert status(findings, "login_block_for") == expected

    def test_login_delay_minimum(self):
        assert status(mgmt("_check_login_security", "login delay 1\n", login_delay={"seconds": 2}),
                      "login_delay") == Status.FAIL
        assert status(mgmt("_check_login_security", "login delay 3\n", login_delay={"seconds": 2}),
                      "login_delay") == Status.PASS

    def test_aaa_commands_check_each_level(self):
        config = "aaa authorization commands 15 default group NOC local\n"
        findings = mgmt(
            "_check_aaa", config,
            aaa_authorization_commands={
                "levels": [1, 15],
                "expected_prefix": "aaa authorization commands 15 default group NOC local",
            },
        )
        assert status(findings, "aaa_authorization_commands_15") == Status.PASS
        assert status(findings, "aaa_authorization_commands_1") == Status.FAIL


# ---------------------------------------------------------------------------
# Newly implemented checks
# ---------------------------------------------------------------------------

class TestNewChecks:
    @pytest.mark.parametrize(
        "check, line",
        [
            ("no_service_finger", "service finger"),
            ("no_service_tcp_small_servers", "service tcp-small-servers"),
            ("no_service_udp_small_servers", "service udp-small-servers"),
        ],
    )
    def test_legacy_services(self, check, line):
        assert status(mgmt("_check_services", line + "\n", **{check: {}}), check) == Status.FAIL
        assert status(mgmt("_check_services", "", **{check: {}}), check) == Status.PASS

    def test_no_ip_finger(self):
        assert status(mgmt("_check_ip_settings", "ip finger\n", no_ip_finger={}), "no_ip_finger") == Status.FAIL
        assert status(mgmt("_check_ip_settings", "", no_ip_finger={}), "no_ip_finger") == Status.PASS

    @pytest.mark.parametrize("check", ["stp_backbonefast", "stp_uplinkfast"])
    def test_fast_features_skip_under_rapid_pvst(self, check):
        findings = ctrl("_check_stp", "spanning-tree mode rapid-pvst\n", **{check: {}})
        assert status(findings, check) == Status.SKIP

    def test_uplinkfast_checked_under_pvst(self):
        config = "spanning-tree mode pvst\n"
        assert status(ctrl("_check_stp", config, stp_uplinkfast={}), "stp_uplinkfast") == Status.FAIL
        config += "spanning-tree uplinkfast\n"
        assert status(ctrl("_check_stp", config, stp_uplinkfast={}), "stp_uplinkfast") == Status.PASS

    def test_vtp_domain(self):
        data = DeviceData(hostname="SW1", vtp={"vtp": {"operating_mode": "off", "domain_name": "CORP"}})
        assert status(ctrl("_check_vtp", "", data=data, vtp_domain={"expected": "CORP"}), "vtp_domain") == Status.PASS
        data.vtp["vtp"]["domain_name"] = "LAB"
        assert status(ctrl("_check_vtp", "", data=data, vtp_domain={"expected": "CORP"}), "vtp_domain") == Status.FAIL
        assert status(ctrl("_check_vtp", "", vtp_domain={"expected": "CORP"}), "vtp_domain") == Status.WARN

    def test_arp_validate_is_a_subset(self):
        config = "ip arp inspection validate src-mac dst-mac ip\n"
        node = {"checks": ["ip"]}
        assert status(ctrl("_check_arp_inspection", config, arp_inspection_validate=node),
                      "arp_inspection_validate") == Status.PASS
        node = {"checks": ["src-mac", "ip"]}
        assert status(ctrl("_check_arp_inspection", "ip arp inspection validate ip\n",
                           arp_inspection_validate=node), "arp_inspection_validate") == Status.FAIL


class TestStpPriority:
    ASW = "ZZ-LAB1-001ASW001"
    CSW = "ZZ-LAB1-001CSW001"

    def _run(self, host, config, roles=None):
        policy = {"control_plane": {"stp_priority": {"enabled": True}}}
        cfg = parse_running_config(config)
        data = DeviceData(hostname=host, parsed_config=cfg)
        role_config = roles or [
            {"code": "ASW", "role": "access_switch", "trunk_signal": "downlink"},
            {"code": "CSW", "role": "core_switch", "trunk_signal": "uplink"},
        ]
        info = parse_hostname(host, role_config=role_config)
        return ComplianceEngine(policy)._check_stp(cfg, data, info, {})

    def test_access_switch_must_not_be_preferred(self):
        findings = self._run(self.ASW, "spanning-tree vlan 1-100 priority 4096\n")
        assert status(findings, "stp_priority") == Status.FAIL

    def test_access_switch_at_default_passes(self):
        assert status(self._run(self.ASW, ""), "stp_priority") == Status.PASS

    def test_core_switch_must_be_preferred(self):
        assert status(self._run(self.CSW, ""), "stp_priority") == Status.FAIL
        findings = self._run(self.CSW, "spanning-tree vlan 1-100 priority 4096\n")
        assert status(findings, "stp_priority") == Status.PASS

    def test_structured_priority_strips_system_id(self):
        policy = {"control_plane": {"stp_priority": {"enabled": True}}}
        data = DeviceData(
            hostname=self.ASW,
            stp={"rapid_pvst": {"vlans": {"10": {"bridge": {"priority": 32778}}}}},
        )
        cfg = parse_running_config("")
        findings = ComplianceEngine(policy)._check_stp(cfg, data, parse_hostname(self.ASW), {})
        assert status(findings, "stp_priority") == Status.PASS


# ---------------------------------------------------------------------------
# Port security
# ---------------------------------------------------------------------------

class TestPortSecurity:
    def _run(self, node, *lines):
        dp = {"port_security": {"enabled": True, **node}}
        pi = PortInfo(name="GigabitEthernet1/0/1", role=PortRole.ACCESS, config_lines=list(lines))
        return ComplianceEngine({"data_plane": dp})._port_security_settings(dp, pi)

    def test_defaults_apply_when_lines_are_absent(self):
        # IOS omits "maximum 1" and "violation shutdown" from the running-config.
        findings = self._run({"max_mac": 2, "violation": "shutdown"}, "switchport port-security")
        assert status(findings, "port_security_max") == Status.PASS
        assert status(findings, "port_security_violation") == Status.PASS

    def test_aging(self):
        node = {"aging_time": 60, "aging_type": "inactivity"}
        good = self._run(node, "switchport port-security aging time 60",
                         "switchport port-security aging type inactivity")
        assert status(good, "port_security_aging") == Status.PASS
        bad = self._run(node, "switchport port-security aging time 60")
        assert status(bad, "port_security_aging") == Status.FAIL

    def test_maximum_without_enable_is_not_enabled(self):
        dp = {"port_security": {"enabled": True}}
        pi = PortInfo(name="Gi1/0/1", role=PortRole.ACCESS,
                      config_lines=["switchport port-security maximum 2"])
        findings = ComplianceEngine({"data_plane": dp})._check_access_port(None, dp, pi)
        assert status(findings, "port_security") == Status.FAIL


# ---------------------------------------------------------------------------
# --ip-filter
# ---------------------------------------------------------------------------

class TestIpFilter:
    def test_large_and_ipv6_ranges_are_cheap(self):
        assert "10.200.1.1" in _parse_ip_filter("10.0.0.0/8")
        assert "2001:db8::5" in _parse_ip_filter("2001:db8::/64")
        assert "10.0.0.1" not in _parse_ip_filter("2001:db8::/64")

    def test_range(self):
        flt = _parse_ip_filter("192.0.2.1-192.0.2.10")
        assert "192.0.2.10" in flt and "192.0.2.11" not in flt

    def test_bad_range(self):
        with pytest.raises(ValueError):
            _parse_ip_filter("192.0.2.10-192.0.2.1")
        with pytest.raises(ValueError):
            _parse_ip_filter("192.0.2.1-2001:db8::1")

    def test_hostname_only_devices_are_resolved(self, monkeypatch):
        import compliance_audit.auditor as auditor

        monkeypatch.setattr(
            auditor, "_resolve_addresses",
            lambda name: {"sw1.corp": ["192.0.2.5"]}.get(name, []),
        )
        devices = [
            {"hostname": "sw1.corp", "ip": "sw1.corp"},
            {"hostname": "gone.corp", "ip": "gone.corp"},
            {"hostname": "x", "ip": "198.51.100.1"},
        ]
        kept, unresolved = filter_devices_by_ip(devices, "192.0.2.0/24")
        assert [d["hostname"] for d in kept] == ["sw1.corp"]
        assert unresolved == ["gone.corp"]
