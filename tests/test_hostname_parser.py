"""
Unit tests for compliance_audit.hostname_parser.

Covers: parse_hostname (defaults, case-insensitivity, explicit_role, custom
role_config), HostnameInfo.is_access, get_trunk_signal_map.
"""

import pytest
from compliance_audit.hostname_parser import (
    parse_hostname,
    get_trunk_signal_map,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CUSTOM_ROLES = [
    {"code": "ASW", "role": "access_switch", "display": "Access Switch", "trunk_signal": "downlink"},
    {"code": "CSW", "role": "core_switch",   "display": "Core Switch",   "trunk_signal": "uplink"},
]


# ---------------------------------------------------------------------------
# parse_hostname — default (built-in ASW only) config
# ---------------------------------------------------------------------------

class TestParseHostnameDefaults:
    def test_valid_asw_all_fields(self):
        info = parse_hostname("ZZ-LAB1-005ASW001")
        assert info.parsed is True
        assert info.country == "ZZ"
        assert info.site_code == "LAB"
        assert info.site_instance == "1"
        assert info.comms_room == "005"
        assert info.role_code == "ASW"
        assert info.role == "access_switch"
        assert info.role_display == "Access Switch"
        assert info.device_number == "001"

    def test_raw_field_preserved(self):
        info = parse_hostname("ZZ-LAB1-005ASW001")
        assert info.raw == "ZZ-LAB1-005ASW001"

    def test_lowercase_input_parsed(self):
        info = parse_hostname("zz-lab1-005asw001")
        assert info.parsed is True
        assert info.role_code == "ASW"

    def test_mixed_case_input_parsed(self):
        info = parse_hostname("Zz-Lab1-005Asw001")
        assert info.parsed is True

    def test_leading_trailing_whitespace_stripped(self):
        info = parse_hostname("  ZZ-LAB1-005ASW001  ")
        assert info.parsed is True

    def test_unparseable_sets_parsed_false(self):
        info = parse_hostname("not-a-device")
        assert info.parsed is False
        assert info.role_code is None
        assert info.role is None

    def test_partial_hostname_not_parsed(self):
        info = parse_hostname("ZZ-LAB1-005ASW")
        assert info.parsed is False

    def test_unknown_role_code_not_parsed(self):
        # CSW is not in default config
        info = parse_hostname("ZZ-LAB1-005CSW001")
        assert info.parsed is False

    def test_is_access_true_for_asw(self):
        info = parse_hostname("ZZ-LAB1-005ASW001")
        assert info.is_access is True

    def test_is_access_false_when_unparsed(self):
        info = parse_hostname("not-a-device")
        assert info.is_access is False


# ---------------------------------------------------------------------------
# parse_hostname — explicit_role override
# ---------------------------------------------------------------------------

class TestParseHostnameExplicitRole:
    def test_explicit_role_code_overrides(self):
        info = parse_hostname("ZZ-LAB1-005ASW001", explicit_role="ASW")
        assert info.role == "access_switch"
        assert info.role_code == "ASW"

    def test_explicit_role_name_reverse_lookup(self):
        info = parse_hostname("ZZ-LAB1-005ASW001", explicit_role="access_switch")
        assert info.role == "access_switch"
        assert info.role_code == "ASW"

    def test_explicit_unknown_role_sets_role_only(self):
        # No matching code — role is stored as-is
        info = parse_hostname("ZZ-LAB1-005ASW001", explicit_role="custom_role")
        assert info.role == "custom_role"

    def test_explicit_role_on_unparsed_hostname(self):
        info = parse_hostname("GENERIC-DEVICE", explicit_role="access_switch")
        assert info.parsed is False
        assert info.role == "access_switch"


# ---------------------------------------------------------------------------
# parse_hostname — custom role_config
# ---------------------------------------------------------------------------

class TestParseHostnameCustomRoleConfig:
    def test_csw_parsed_with_custom_config(self):
        info = parse_hostname("ZZ-LAB1-005CSW001", role_config=_CUSTOM_ROLES)
        assert info.parsed is True
        assert info.role_code == "CSW"
        assert info.role == "core_switch"
        assert info.role_display == "Core Switch"

    def test_asw_still_works_with_custom_config(self):
        info = parse_hostname("ZZ-LAB1-005ASW001", role_config=_CUSTOM_ROLES)
        assert info.parsed is True
        assert info.role == "access_switch"

    def test_code_absent_from_custom_config_not_parsed(self):
        # SDW not in custom config
        info = parse_hostname("ZZ-LAB1-005SDW001", role_config=_CUSTOM_ROLES)
        assert info.parsed is False


# ---------------------------------------------------------------------------
# get_trunk_signal_map
# ---------------------------------------------------------------------------

class TestGetTrunkSignalMap:
    def test_default_map_asw_is_downlink(self):
        m = get_trunk_signal_map()
        assert m["ASW"] == "downlink"

    def test_default_map_contains_only_asw(self):
        m = get_trunk_signal_map()
        assert list(m.keys()) == ["ASW"]

    def test_custom_config_returns_correct_signals(self):
        m = get_trunk_signal_map(_CUSTOM_ROLES)
        assert m["ASW"] == "downlink"
        assert m["CSW"] == "uplink"

    def test_custom_config_without_trunk_signal_defaults_none(self):
        roles = [{"code": "XSW", "role": "x_switch", "display": "X"}]
        m = get_trunk_signal_map(roles)
        assert m["XSW"] == "none"
