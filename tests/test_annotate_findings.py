"""
Unit tests for compliance_audit.compliance_engine._annotate_findings.

Covers all six filter stages:
  - severity and tags always set
  - applies_to_roles
  - exclude_hostnames
  - include_hostnames
  - exclude_groups
  - include_groups
  - exclude_interfaces

Also covers: already-SKIP'd findings are not re-evaluated, unknown check
names in check_map fall back to defaults.
"""

import pytest
from compliance_audit.compliance_engine import _annotate_findings, Finding, Status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(check_name="test_check", status=Status.PASS, interface=""):
    return Finding(
        check_name=check_name,
        status=status,
        detail="test detail",
        interface=interface,
    )


def _check_map(check_name="test_check", **kwargs):
    """Build a minimal check_map with *kwargs* as the check node."""
    return {check_name: kwargs}


def _annotate(findings, check_map=None, role="access_switch",
              hostname="ZZ-LAB1-005ASW001", group=""):
    """Call _annotate_findings with convenient defaults."""
    _annotate_findings(findings, check_map or {}, role, hostname, group)


# ---------------------------------------------------------------------------
# Severity and tags — always applied
# ---------------------------------------------------------------------------

class TestSeverityAndTags:
    def test_severity_set_from_check_map(self):
        f = _finding()
        _annotate([f], _check_map(severity="critical"))
        assert f.severity == "critical"

    def test_default_severity_when_absent(self):
        f = _finding()
        _annotate([f], _check_map())
        assert f.severity == "medium"

    def test_tags_set_from_check_map(self):
        f = _finding()
        _annotate([f], _check_map(tags=["cis", "pci"]))
        assert f.tags == ["cis", "pci"]

    def test_tags_empty_when_absent(self):
        f = _finding()
        _annotate([f], _check_map())
        assert f.tags == []

    def test_severity_applied_even_when_already_skipped(self):
        f = _finding(status=Status.SKIP)
        _annotate([f], _check_map(severity="high"))
        assert f.severity == "high"
        assert f.status == Status.SKIP  # not re-evaluated

    def test_tags_applied_even_when_already_skipped(self):
        f = _finding(status=Status.SKIP)
        _annotate([f], _check_map(tags=["nist"]))
        assert f.tags == ["nist"]
        assert f.status == Status.SKIP

    def test_unknown_check_name_uses_defaults(self):
        f = _finding(check_name="unknown_check")
        _annotate([f], _check_map(check_name="some_other_check", severity="high"))
        assert f.severity == "medium"  # no matching node → defaults
        assert f.status == Status.PASS

    def test_multiple_findings_all_annotated(self):
        findings = [_finding(), _finding(), _finding()]
        _annotate(findings, _check_map(severity="low"))
        assert all(f.severity == "low" for f in findings)


# ---------------------------------------------------------------------------
# applies_to_roles
# ---------------------------------------------------------------------------

class TestAppliesToRoles:
    def test_matching_role_stays_pass(self):
        f = _finding()
        _annotate([f], _check_map(applies_to_roles=["access_switch"]))
        assert f.status == Status.PASS

    def test_non_matching_role_becomes_skip(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(applies_to_roles=["access_switch"]),
            role="core_switch",
            hostname="ZZ-LAB1-005CSW001",
        )
        assert f.status == Status.SKIP

    def test_multiple_roles_matching(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(applies_to_roles=["access_switch", "core_switch"]),
            role="core_switch",
        )
        assert f.status == Status.PASS

    def test_empty_applies_to_roles_runs_for_all(self):
        f = _finding()
        _annotate([f], _check_map(applies_to_roles=[]), role="core_switch")
        assert f.status == Status.PASS

    def test_applies_to_roles_absent_runs_for_all(self):
        f = _finding()
        _annotate([f], _check_map(), role="core_switch")
        assert f.status == Status.PASS


# ---------------------------------------------------------------------------
# exclude_hostnames
# ---------------------------------------------------------------------------

class TestExcludeHostnames:
    def test_matching_hostname_becomes_skip(self):
        f = _finding()
        _annotate([f], _check_map(exclude_hostnames=["ZZ-LAB.*"]))
        assert f.status == Status.SKIP

    def test_non_matching_hostname_stays_pass(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(exclude_hostnames=["ZZ-BRN.*"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.PASS

    def test_exact_hostname_match(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(exclude_hostnames=["ZZ-LAB1-005ASW001"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.SKIP

    def test_invalid_regex_silently_ignored(self):
        f = _finding()
        _annotate([f], _check_map(exclude_hostnames=["[invalid"]))
        assert f.status == Status.PASS

    def test_case_insensitive_match(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(exclude_hostnames=["zz-lab.*"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.SKIP


# ---------------------------------------------------------------------------
# include_hostnames
# ---------------------------------------------------------------------------

class TestIncludeHostnames:
    def test_matching_hostname_stays_pass(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(include_hostnames=["ZZ-LAB.*"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.PASS

    def test_non_matching_hostname_becomes_skip(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(include_hostnames=["ZZ-BRN.*"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.SKIP

    def test_multiple_patterns_any_match_passes(self):
        f = _finding()
        _annotate(
            [f],
            _check_map(include_hostnames=["ZZ-BRN.*", "ZZ-LAB.*"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.PASS

    def test_invalid_regex_silently_ignored(self):
        f = _finding()
        # Invalid pattern is skipped; no valid pattern matches → SKIP
        _annotate(
            [f],
            _check_map(include_hostnames=["[invalid"]),
            hostname="ZZ-LAB1-005ASW001",
        )
        assert f.status == Status.SKIP


# ---------------------------------------------------------------------------
# exclude_groups
# ---------------------------------------------------------------------------

class TestExcludeGroups:
    def test_matching_group_becomes_skip(self):
        f = _finding()
        _annotate([f], _check_map(exclude_groups=["site_lab"]), group="site_lab")
        assert f.status == Status.SKIP

    def test_non_matching_group_stays_pass(self):
        f = _finding()
        _annotate([f], _check_map(exclude_groups=["site_lab"]), group="site_brn")
        assert f.status == Status.PASS

    def test_ungrouped_device_not_excluded(self):
        # exclude_groups has no effect when group is empty
        f = _finding()
        _annotate([f], _check_map(exclude_groups=["site_lab"]), group="")
        assert f.status == Status.PASS

    def test_case_insensitive_group_match(self):
        f = _finding()
        _annotate([f], _check_map(exclude_groups=["Site_Lab"]), group="site_lab")
        assert f.status == Status.SKIP


# ---------------------------------------------------------------------------
# include_groups
# ---------------------------------------------------------------------------

class TestIncludeGroups:
    def test_matching_group_stays_pass(self):
        f = _finding()
        _annotate([f], _check_map(include_groups=["site_lab"]), group="site_lab")
        assert f.status == Status.PASS

    def test_non_matching_group_becomes_skip(self):
        f = _finding()
        _annotate([f], _check_map(include_groups=["site_lab"]), group="site_brn")
        assert f.status == Status.SKIP

    def test_ungrouped_device_becomes_skip(self):
        f = _finding()
        _annotate([f], _check_map(include_groups=["site_lab"]), group="")
        assert f.status == Status.SKIP

    def test_case_insensitive_group_match(self):
        f = _finding()
        _annotate([f], _check_map(include_groups=["Site_Lab"]), group="site_lab")
        assert f.status == Status.PASS


# ---------------------------------------------------------------------------
# exclude_interfaces
# ---------------------------------------------------------------------------

class TestExcludeInterfaces:
    def test_matching_interface_becomes_skip(self):
        f = _finding(interface="GigabitEthernet0/1")
        _annotate([f], _check_map(exclude_interfaces=["GigabitEthernet0/1"]))
        assert f.status == Status.SKIP

    def test_non_matching_interface_stays_pass(self):
        f = _finding(interface="GigabitEthernet0/2")
        _annotate([f], _check_map(exclude_interfaces=["GigabitEthernet0/1"]))
        assert f.status == Status.PASS

    def test_regex_pattern_matches_interface(self):
        f = _finding(interface="GigabitEthernet0/10")
        _annotate([f], _check_map(exclude_interfaces=["GigabitEthernet.*"]))
        assert f.status == Status.SKIP

    def test_finding_without_interface_not_affected(self):
        # No interface → exclude_interfaces has no effect
        f = _finding(interface="")
        _annotate([f], _check_map(exclude_interfaces=["GigabitEthernet.*"]))
        assert f.status == Status.PASS

    def test_case_insensitive_interface_match(self):
        f = _finding(interface="gigabitethernet0/1")
        _annotate([f], _check_map(exclude_interfaces=["GigabitEthernet0/1"]))
        assert f.status == Status.SKIP

    def test_invalid_regex_silently_ignored(self):
        f = _finding(interface="GigabitEthernet0/1")
        _annotate([f], _check_map(exclude_interfaces=["[invalid"]))
        assert f.status == Status.PASS
