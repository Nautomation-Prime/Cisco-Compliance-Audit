"""
Unit tests for the inventory helpers in compliance_audit.auditor.

Covers: _normalise_device_entry (string entries, dict entries, error cases)
        _flatten_inventory (flat list, groups, mixed, dedup, validation errors).
"""

import pytest
from compliance_audit.auditor import _flatten_inventory, _normalise_device_entry


# ---------------------------------------------------------------------------
# _normalise_device_entry
# ---------------------------------------------------------------------------

class TestNormaliseDeviceEntry:
    # -- string inputs -------------------------------------------------------

    def test_ip_address_string(self):
        entry = _normalise_device_entry("192.0.2.1")
        assert entry == {"ip": "192.0.2.1", "hostname": "192.0.2.1"}

    def test_hostname_string(self):
        entry = _normalise_device_entry("ZZ-LAB1-005ASW001")
        assert entry == {"hostname": "ZZ-LAB1-005ASW001", "ip": "ZZ-LAB1-005ASW001"}

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Empty string"):
            _normalise_device_entry("   ")

    # -- dict inputs ---------------------------------------------------------

    def test_dict_with_both_fields(self):
        entry = _normalise_device_entry({"hostname": "sw1", "ip": "10.0.0.1"})
        assert entry["hostname"] == "sw1"
        assert entry["ip"] == "10.0.0.1"

    def test_dict_hostname_only_fills_ip(self):
        entry = _normalise_device_entry({"hostname": "sw1"})
        assert entry["ip"] == "sw1"
        assert entry["hostname"] == "sw1"

    def test_dict_ip_only_fills_hostname(self):
        entry = _normalise_device_entry({"ip": "10.0.0.1"})
        assert entry["hostname"] == "10.0.0.1"
        assert entry["ip"] == "10.0.0.1"

    def test_dict_missing_both_raises(self):
        with pytest.raises(ValueError, match="must contain at least"):
            _normalise_device_entry({"name": "switch1"})

    def test_dict_extra_fields_preserved(self):
        entry = _normalise_device_entry({"hostname": "sw1", "ip": "10.0.0.1", "platform": "ios"})
        assert entry["platform"] == "ios"

    # -- invalid type --------------------------------------------------------

    def test_integer_raises(self):
        with pytest.raises(ValueError, match="expected string or mapping"):
            _normalise_device_entry(42)

    def test_none_raises(self):
        with pytest.raises(ValueError, match="expected string or mapping"):
            _normalise_device_entry(None)


# ---------------------------------------------------------------------------
# _flatten_inventory
# ---------------------------------------------------------------------------

class TestFlattenInventory:
    # -- flat device list ----------------------------------------------------

    def test_flat_string_entries(self):
        data = {"devices": ["ZZ-LAB1-005ASW001", "ZZ-LAB1-005ASW002"]}
        result = _flatten_inventory(data)
        assert len(result) == 2
        assert result[0]["hostname"] == "ZZ-LAB1-005ASW001"
        assert result[1]["hostname"] == "ZZ-LAB1-005ASW002"

    def test_flat_dict_entries(self):
        data = {"devices": [{"hostname": "sw1", "ip": "10.0.0.1"}]}
        result = _flatten_inventory(data)
        assert result[0]["hostname"] == "sw1"
        assert result[0]["ip"] == "10.0.0.1"

    def test_flat_devices_have_no_group_key(self):
        data = {"devices": [{"hostname": "sw1", "ip": "10.0.0.1"}]}
        result = _flatten_inventory(data)
        assert "_group" not in result[0]

    # -- grouped devices -----------------------------------------------------

    def test_grouped_devices_receive_group_tag(self):
        data = {
            "groups": {
                "site_lab": {
                    "devices": [{"hostname": "sw1", "ip": "10.0.0.1"}]
                }
            }
        }
        result = _flatten_inventory(data)
        assert len(result) == 1
        assert result[0]["_group"] == "site_lab"

    def test_multiple_groups_all_loaded(self):
        data = {
            "groups": {
                "site_lab": {"devices": [{"hostname": "sw1", "ip": "10.0.0.1"}]},
                "site_brn": {"devices": [{"hostname": "sw2", "ip": "10.0.0.2"}]},
            }
        }
        result = _flatten_inventory(data)
        assert len(result) == 2
        groups = {r["_group"] for r in result}
        assert groups == {"site_lab", "site_brn"}

    # -- mixed flat + groups -------------------------------------------------

    def test_flat_and_grouped_merged(self):
        data = {
            "devices": [{"hostname": "flat-sw", "ip": "10.0.0.1"}],
            "groups": {
                "site_lab": {"devices": [{"hostname": "group-sw", "ip": "10.0.0.2"}]}
            },
        }
        result = _flatten_inventory(data)
        assert len(result) == 2

    # -- deduplication -------------------------------------------------------

    def test_duplicate_ip_first_entry_wins(self):
        data = {
            "devices": [
                {"hostname": "switch-a", "ip": "10.0.0.1"},
                {"hostname": "switch-b", "ip": "10.0.0.1"},  # duplicate
            ]
        }
        result = _flatten_inventory(data)
        assert len(result) == 1
        assert result[0]["hostname"] == "switch-a"

    def test_flat_takes_precedence_over_group_duplicate(self):
        data = {
            "devices": [{"hostname": "flat-sw", "ip": "10.0.0.1"}],
            "groups": {
                "site_lab": {"devices": [{"hostname": "group-sw", "ip": "10.0.0.1"}]}
            },
        }
        result = _flatten_inventory(data)
        assert len(result) == 1
        assert result[0]["hostname"] == "flat-sw"

    # -- edge cases ----------------------------------------------------------

    def test_empty_dict_returns_empty_list(self):
        assert _flatten_inventory({}) == []

    def test_none_devices_list_returns_empty(self):
        assert _flatten_inventory({"devices": None}) == []

    def test_none_groups_returns_empty(self):
        assert _flatten_inventory({"groups": None}) == []

    def test_extra_fields_on_entries_preserved(self):
        data = {"devices": [{"hostname": "sw1", "ip": "10.0.0.1", "custom_tag": "prod"}]}
        result = _flatten_inventory(data)
        assert result[0]["custom_tag"] == "prod"

    # -- validation errors ---------------------------------------------------

    def test_empty_string_entry_raises(self):
        data = {"devices": [""]}
        with pytest.raises(ValueError, match="Inventory validation failed"):
            _flatten_inventory(data)

    def test_dict_without_hostname_or_ip_raises(self):
        data = {"devices": [{"name": "switch1"}]}
        with pytest.raises(ValueError, match="Inventory validation failed"):
            _flatten_inventory(data)

    def test_group_not_a_dict_raises(self):
        data = {"groups": {"site_lab": "not-a-dict"}}
        with pytest.raises(ValueError, match="Inventory validation failed"):
            _flatten_inventory(data)

    def test_multiple_errors_reported_together(self):
        data = {"devices": ["", {"name": "bad"}]}
        with pytest.raises(ValueError) as exc_info:
            _flatten_inventory(data)
        # Both errors should appear in the message
        assert "devices[0]" in str(exc_info.value)
        assert "devices[1]" in str(exc_info.value)
