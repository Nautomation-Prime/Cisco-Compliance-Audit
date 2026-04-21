"""
Unit tests for compliance_audit.remediation_workflow.get_remediation_settings.

Covers: None/empty input defaults, enabled propagation, explicit overrides,
nested approval/execution settings, and malformed node fallback.
"""

import pytest
from compliance_audit.remediation_workflow import get_remediation_settings


class TestGetRemediationSettingsDefaults:
    """None or empty input should produce safe defaults."""

    def test_none_input_returns_all_defaults(self):
        s = get_remediation_settings(None)
        assert s["enabled"] is True
        assert s["generate_script"] is True
        assert s["generate_review_pack"] is True
        assert s["approval_default_expires_hours"] == 24
        assert s["approval_require_ticket_id"] is True
        assert s["execution_enabled"] is False
        assert s["execution_linux_only"] is True
        assert s["execution_block_high_risk"] is True
        assert s["execution_enforce_checksum"] is True
        assert s["execution_preflight_drift_check"] is True
        assert s["execution_require_hostname_match"] is True
        assert s["execution_save_config"] is True
        assert s["execution_cmd_verify"] is False
        assert s["execution_generate_post_report"] is True
        assert s["execution_generate_consolidated_post_report"] is True

    def test_empty_dict_returns_defaults(self):
        s = get_remediation_settings({})
        assert s["enabled"] is True

    def test_default_post_report_formats(self):
        s = get_remediation_settings(None)
        assert "json" in s["execution_post_report_formats"]
        assert "html" in s["execution_post_report_formats"]


class TestGetRemediationSettingsEnabled:
    """enabled flag propagates into generate_script and generate_review_pack."""

    def test_enabled_false_propagates_to_generate_keys(self):
        s = get_remediation_settings({"remediation": {"enabled": False}})
        assert s["enabled"] is False
        assert s["generate_script"] is False
        assert s["generate_review_pack"] is False

    def test_explicit_generate_script_overrides_enabled(self):
        s = get_remediation_settings({
            "remediation": {"enabled": False, "generate_script": True}
        })
        assert s["enabled"] is False
        assert s["generate_script"] is True

    def test_explicit_generate_review_pack_overrides_enabled(self):
        s = get_remediation_settings({
            "remediation": {"enabled": False, "generate_review_pack": True}
        })
        assert s["generate_review_pack"] is True


class TestGetRemediationSettingsApproval:
    """Nested approval settings are resolved correctly."""

    def test_custom_expires_hours(self):
        s = get_remediation_settings({
            "remediation": {"approval": {"default_expires_hours": 48}}
        })
        assert s["approval_default_expires_hours"] == 48

    def test_require_ticket_id_false(self):
        s = get_remediation_settings({
            "remediation": {"approval": {"require_ticket_id": False}}
        })
        assert s["approval_require_ticket_id"] is False

    def test_non_dict_approval_node_uses_defaults(self):
        s = get_remediation_settings({
            "remediation": {"approval": "not-a-dict"}
        })
        assert s["approval_default_expires_hours"] == 24
        assert s["approval_require_ticket_id"] is True


class TestGetRemediationSettingsExecution:
    """Nested execution settings are resolved correctly."""

    def test_execution_can_be_enabled(self):
        s = get_remediation_settings({
            "remediation": {"execution": {"enabled": True}}
        })
        assert s["execution_enabled"] is True

    def test_execution_linux_only_false(self):
        s = get_remediation_settings({
            "remediation": {"execution": {"linux_only": False}}
        })
        assert s["execution_linux_only"] is False

    def test_execution_block_high_risk_false(self):
        s = get_remediation_settings({
            "remediation": {"execution": {"block_high_risk_by_default": False}}
        })
        assert s["execution_block_high_risk"] is False

    def test_custom_post_report_formats(self):
        s = get_remediation_settings({
            "remediation": {"execution": {"post_report_formats": ["json"]}}
        })
        assert s["execution_post_report_formats"] == ["json"]

    def test_non_dict_execution_node_uses_defaults(self):
        s = get_remediation_settings({
            "remediation": {"execution": "not-a-dict"}
        })
        assert s["execution_enabled"] is False
        assert s["execution_linux_only"] is True


class TestGetRemediationSettingsMalformedNode:
    """Non-dict remediation node falls back gracefully."""

    def test_string_remediation_node_uses_all_defaults(self):
        s = get_remediation_settings({"remediation": "invalid"})
        assert s["enabled"] is True
        assert s["execution_enabled"] is False

    def test_integer_remediation_node_uses_all_defaults(self):
        s = get_remediation_settings({"remediation": 42})
        assert s["enabled"] is True
