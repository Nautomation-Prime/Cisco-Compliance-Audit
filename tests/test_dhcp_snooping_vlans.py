"""
Unit tests for VLAN-aware DHCP snooping / ARP inspection checks and the
VLAN range helpers in compliance_audit.compliance_engine.
"""

from compliance_audit.collector import parse_running_config
from compliance_audit.compliance_engine import (
    ComplianceEngine,
    Status,
    _expand_vlan_ranges,
    _format_vlan_set,
    _configured_vlans,
)


# ---------------------------------------------------------------------------
# VLAN range helpers
# ---------------------------------------------------------------------------

class TestExpandVlanRanges:
    def test_single_range(self):
        assert _expand_vlan_ranges("1-5") == {1, 2, 3, 4, 5}

    def test_full_range(self):
        assert len(_expand_vlan_ranges("1-4094")) == 4094

    def test_comma_list(self):
        assert _expand_vlan_ranges("10,20,30") == {10, 20, 30}

    def test_mixed_list_and_range(self):
        assert _expand_vlan_ranges("10,20,30-32") == {10, 20, 30, 31, 32}

    def test_whitespace_separated(self):
        assert _expand_vlan_ranges("10 20 30") == {10, 20, 30}

    def test_reversed_range_normalised(self):
        assert _expand_vlan_ranges("5-1") == {1, 2, 3, 4, 5}

    def test_empty_and_none(self):
        assert _expand_vlan_ranges("") == set()
        assert _expand_vlan_ranges(None) == set()
        assert _expand_vlan_ranges("   ") == set()

    def test_integer_input(self):
        assert _expand_vlan_ranges(100) == {100}

    def test_invalid_tokens_skipped(self):
        assert _expand_vlan_ranges("10,foo,20") == {10, 20}


class TestFormatVlanSet:
    def test_empty(self):
        assert _format_vlan_set(set()) == ""

    def test_contiguous(self):
        assert _format_vlan_set({1, 2, 3}) == "1-3"

    def test_mixed(self):
        assert _format_vlan_set({1, 2, 3, 5, 6, 10}) == "1-3,5-6,10"

    def test_singletons(self):
        assert _format_vlan_set({10, 20, 30}) == "10,20,30"


class TestConfiguredVlans:
    def test_single_line(self):
        cfg = parse_running_config("ip dhcp snooping vlan 10,20,30-32\n")
        assert _configured_vlans(cfg, r"ip dhcp snooping vlan") == {10, 20, 30, 31, 32}

    def test_split_across_lines(self):
        cfg = parse_running_config(
            "ip dhcp snooping vlan 10,20\n"
            "ip dhcp snooping vlan 30-32\n"
        )
        assert _configured_vlans(cfg, r"ip dhcp snooping vlan") == {10, 20, 30, 31, 32}

    def test_no_lines(self):
        cfg = parse_running_config("hostname SW1\n")
        assert _configured_vlans(cfg, r"ip dhcp snooping vlan") == set()


# ---------------------------------------------------------------------------
# _check_dhcp_snooping — VLAN-aware behaviour
# ---------------------------------------------------------------------------

def _engine(vlans):
    policy = {
        "control_plane": {
            "dhcp_snooping_vlans": {"enabled": True, "vlans": vlans},
        }
    }
    return ComplianceEngine(policy)


def _find(findings, name):
    return next(f for f in findings if f.check_name == name)


class TestDhcpSnoopingVlans:
    def test_specific_vlans_all_present_pass(self):
        eng = _engine("10,20")
        cfg = parse_running_config("ip dhcp snooping vlan 10,20,30\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.PASS

    def test_specific_vlans_missing_fail(self):
        eng = _engine("10,20,40")
        cfg = parse_running_config("ip dhcp snooping vlan 10,20\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.FAIL
        assert "40" in result.detail
        assert result.remediation == "ip dhcp snooping vlan 10,20,40"

    def test_range_spec_matches_range_config(self):
        eng = _engine("1-4094")
        cfg = parse_running_config("ip dhcp snooping vlan 1-4094\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.PASS

    def test_range_spec_partial_config_fail(self):
        eng = _engine("1-100")
        cfg = parse_running_config("ip dhcp snooping vlan 1-50\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.FAIL

    def test_empty_vlans_falls_back_to_presence_pass(self):
        eng = _engine("")
        cfg = parse_running_config("ip dhcp snooping vlan 10\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.PASS

    def test_empty_vlans_no_config_fail(self):
        eng = _engine("")
        cfg = parse_running_config("hostname SW1\n")
        result = _find(eng._check_dhcp_snooping(cfg, None, None, {}), "dhcp_snooping_vlans")
        assert result.status is Status.FAIL
