"""
Unit tests for the shared DHCP snooping / DAI port-trust check.

Cisco's guidance is to trust only the interfaces that lead to the DHCP server
and to leave every host-facing port untrusted, so the check has to enforce both
"trust must be here" and "trust must NOT be here".
"""

import pytest

from compliance_audit.compliance_engine import (
    ComplianceEngine,
    Status,
    pi_has_command,
)
from compliance_audit.port_classifier import PortInfo, PortRole


TRUST_CMD = "ip dhcp snooping trust"
DAI_CMD = "ip arp inspection trust"


def make_port(role: PortRole, *config_lines: str, name: str = "GigabitEthernet1/0/1"):
    return PortInfo(name=name, role=role, config_lines=list(config_lines))


def dp_policy(**overrides) -> dict:
    """data_plane policy with dhcp_snooping_trust on and DAI trust off.

    The unrelated check is listed as disabled to keep the policy explicit.
    """
    node = {"enabled": True}
    node.update(overrides)
    return {
        "dhcp_snooping_trust": node,
        "arp_inspection_trust": {"enabled": False},
    }


def run(dp: dict, pi: PortInfo):
    return ComplianceEngine({"data_plane": dp})._check_port_trust(dp, pi)


def only(findings, check_name: str):
    matches = [f for f in findings if f.check_name == check_name]
    assert len(matches) == 1, f"expected one {check_name} finding, got {matches}"
    return matches[0]


# ---------------------------------------------------------------------------
# pi_has_command
# ---------------------------------------------------------------------------

class TestPiHasCommand:
    def test_exact_line_matches(self):
        assert pi_has_command(make_port(PortRole.ACCESS, TRUST_CMD), TRUST_CMD)

    def test_indented_line_matches(self):
        assert pi_has_command(make_port(PortRole.ACCESS, f" {TRUST_CMD} "), TRUST_CMD)

    def test_negated_form_is_not_present(self):
        assert not pi_has_command(
            make_port(PortRole.ACCESS, f"no {TRUST_CMD}"), TRUST_CMD
        )

    def test_longer_command_does_not_match(self):
        assert not pi_has_command(
            make_port(PortRole.ACCESS, "ip dhcp snooping limit rate 15"), TRUST_CMD
        )


# ---------------------------------------------------------------------------
# Trust must NOT be present (the new half)
# ---------------------------------------------------------------------------

class TestTrustForbidden:
    def test_access_port_with_trust_fails_by_default(self):
        finding = only(run(dp_policy(), make_port(PortRole.ACCESS, TRUST_CMD)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL
        assert finding.remediation == f"no {TRUST_CMD}"
        assert "must NOT" in finding.detail

    def test_access_port_without_trust_passes(self):
        finding = only(run(dp_policy(), make_port(PortRole.ACCESS)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.PASS
        assert finding.remediation == ""

    @pytest.mark.parametrize(
        "role", [PortRole.TRUNK_ENDPOINT, PortRole.UNUSED]
    )
    def test_other_host_facing_kinds_forbidden_by_default(self, role):
        finding = only(run(dp_policy(), make_port(role, TRUST_CMD)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL

    def test_untrusted_can_be_disabled_per_kind(self):
        dp = dp_policy(untrusted={"access_ports": False})
        assert run(dp, make_port(PortRole.ACCESS, TRUST_CMD)) == []

    def test_untrusted_can_be_enabled_for_downlinks(self):
        dp = dp_policy(on_downlinks=False, untrusted={"downlinks": True})
        finding = only(run(dp, make_port(PortRole.TRUNK_DOWNLINK, TRUST_CMD)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL

    def test_required_wins_when_both_are_set(self):
        dp = dp_policy(on_access_ports=True, untrusted={"access_ports": True})
        finding = only(run(dp, make_port(PortRole.ACCESS, TRUST_CMD)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.PASS

    def test_negated_trust_line_is_treated_as_untrusted(self):
        finding = only(run(dp_policy(), make_port(PortRole.ACCESS, f"no {TRUST_CMD}")),
                       "dhcp_snooping_trust")
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# Trust must be present (pre-existing behaviour, now shared)
# ---------------------------------------------------------------------------

class TestTrustRequired:
    def test_uplink_missing_trust_fails(self):
        finding = only(run(dp_policy(), make_port(PortRole.TRUNK_UPLINK)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL
        assert finding.remediation == TRUST_CMD

    def test_uplink_with_trust_passes(self):
        finding = only(run(dp_policy(), make_port(PortRole.TRUNK_UPLINK, TRUST_CMD)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.PASS

    def test_downlink_default_still_requires_trust(self):
        finding = only(run(dp_policy(), make_port(PortRole.TRUNK_DOWNLINK)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL

    def test_endpoint_trunk_can_be_required(self):
        dp = dp_policy(on_endpoint_trunks=True)
        finding = only(run(dp, make_port(PortRole.TRUNK_ENDPOINT)),
                       "dhcp_snooping_trust")
        assert finding.status == Status.FAIL
        assert finding.remediation == TRUST_CMD

    def test_unknown_trunk_is_silent_by_default(self):
        assert run(dp_policy(), make_port(PortRole.TRUNK_UNKNOWN, TRUST_CMD)) == []


# ---------------------------------------------------------------------------
# Gating and scope
# ---------------------------------------------------------------------------

class TestScope:
    def test_disabled_check_emits_nothing(self):
        dp = dp_policy(enabled=False)
        assert run(dp, make_port(PortRole.ACCESS, TRUST_CMD)) == []

    @pytest.mark.parametrize(
        "role", [PortRole.ROUTED, PortRole.SVI, PortRole.LOOPBACK, PortRole.MGMT,
                 PortRole.PORT_CHANNEL, PortRole.OTHER]
    )
    def test_non_switchport_roles_are_skipped(self, role):
        assert run(dp_policy(), make_port(role, TRUST_CMD)) == []

    def test_arp_inspection_trust_uses_the_same_rules(self):
        dp = {
            "dhcp_snooping_trust": {"enabled": False},
            "arp_inspection_trust": {"enabled": True},
        }
        finding = only(run(dp, make_port(PortRole.ACCESS, DAI_CMD)),
                       "arp_inspection_trust")
        assert finding.status == Status.FAIL
        assert finding.remediation == f"no {DAI_CMD}"

    def test_both_checks_run_independently(self):
        dp = {
            "dhcp_snooping_trust": {"enabled": True},
            "arp_inspection_trust": {"enabled": True},
        }
        findings = run(dp, make_port(PortRole.ACCESS, TRUST_CMD))
        assert only(findings, "dhcp_snooping_trust").status == Status.FAIL
        assert only(findings, "arp_inspection_trust").status == Status.PASS


# ---------------------------------------------------------------------------
# DHCP snooping rate limit — the configured rate is a ceiling
# ---------------------------------------------------------------------------

class TestDhcpSnoopingLimitRate:
    @staticmethod
    def _run(rate: int, *config_lines: str):
        dp = {"dhcp_snooping_limit_rate": {"enabled": True, "rate": rate}}
        pi = make_port(PortRole.ACCESS, *config_lines)
        findings = ComplianceEngine({"data_plane": dp})._check_access_port(None, dp, pi)
        return only(findings, "dhcp_snooping_limit_rate")

    def test_missing_rate_limit_fails(self):
        finding = self._run(15)
        assert finding.status == Status.FAIL
        assert finding.remediation == "ip dhcp snooping limit rate 15"

    def test_matching_rate_passes(self):
        assert self._run(15, "ip dhcp snooping limit rate 15").status == Status.PASS

    def test_stricter_rate_passes(self):
        assert self._run(15, "ip dhcp snooping limit rate 10").status == Status.PASS

    def test_looser_rate_fails(self):
        finding = self._run(15, "ip dhcp snooping limit rate 100")
        assert finding.status == Status.FAIL
        assert "exceeds" in finding.detail
        assert finding.remediation == "ip dhcp snooping limit rate 15"
