"""
Unit tests for the highest-severity management-plane checks: SNMP, AAA, SSH,
VTY and console.

These are the checks an auditor acts on, so the cases that matter most are the
ones where a non-compliant config could be reported as PASS.
"""

import pytest

from compliance_audit.collector import DeviceData, parse_running_config
from compliance_audit.compliance_engine import (
    ComplianceEngine,
    Status,
    _snmp_community_has_acl,
)
from compliance_audit.hostname_parser import parse_hostname


def run_check(method_name: str, config_text: str, **checks):
    """Run one engine check method against a running-config snippet.

    *checks* maps check key to node overrides; each is enabled unless the
    override says otherwise.
    """
    policy = {"management_plane": {}}
    for key, node in checks.items():
        policy["management_plane"][key] = {"enabled": True, **(node or {})}
    engine = ComplianceEngine(policy)
    cfg = parse_running_config(config_text)
    data = DeviceData(
        hostname="SW1",
        ip="192.0.2.1",
        running_config=config_text,
        parsed_config=cfg,
    )
    return getattr(engine, method_name)(cfg, data, parse_hostname("SW1"), {})


def one(findings, check_name: str):
    matches = [f for f in findings if f.check_name == check_name]
    assert len(matches) == 1, f"expected one {check_name}, got {matches}"
    return matches[0]


def statuses(findings, check_name: str):
    return [f.status for f in findings if f.check_name == check_name]


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------

class TestSnmpCommunityAcl:
    """A community with an access mode but no ACL used to be reported PASS."""

    @pytest.mark.parametrize(
        "line, has_acl",
        [
            ("snmp-server community public RO", False),
            ("snmp-server community secret", False),
            ("snmp-server community s view V RO", False),
            ("snmp-server community secret RO 99", True),
            ("snmp-server community secret RW MGMT-ACL", True),
            ("snmp-server community s view V RO 10", True),
            ("snmp-server community s RO ipv6 V6ACL", True),
        ],
    )
    def test_acl_detection(self, line, has_acl):
        assert _snmp_community_has_acl(line) is has_acl

    def test_community_without_acl_fails(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community mysecret RO\n",
            snmp_community_acl={},
        )
        finding = one(findings, "snmp_community_acl")
        assert finding.status == Status.FAIL
        assert finding.remediation

    def test_community_with_acl_passes(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community mysecret RO SNMP-ACL\n",
            snmp_community_acl={},
        )
        assert one(findings, "snmp_community_acl").status == Status.PASS

    def test_one_bad_community_fails_the_check(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community good RO SNMP-ACL\nsnmp-server community bad RO\n",
            snmp_community_acl={},
        )
        assert one(findings, "snmp_community_acl").status == Status.FAIL

    def test_no_communities_passes(self):
        findings = run_check("_check_snmp", "hostname SW1\n", snmp_community_acl={})
        assert one(findings, "snmp_community_acl").status == Status.PASS


class TestSnmpDefaults:
    def test_public_community_fails(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community public RO\n",
            snmp_no_community_public={},
        )
        assert one(findings, "snmp_no_community_public").status == Status.FAIL

    def test_private_community_fails(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community private RW\n",
            snmp_no_community_private={},
        )
        assert one(findings, "snmp_no_community_private").status == Status.FAIL

    def test_no_default_communities_passes(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server community s3cret RO ACL\n",
            snmp_no_community_public={},
            snmp_no_community_private={},
        )
        assert one(findings, "snmp_no_community_public").status == Status.PASS
        assert one(findings, "snmp_no_community_private").status == Status.PASS


class TestSnmpV3Only:
    def test_v3_priv_group_passes(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server group ADMINS v3 priv\n",
            snmp_v3_only={},
        )
        assert one(findings, "snmp_v3_only").status == Status.PASS

    def test_v3_auth_only_group_fails(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server group ADMINS v3 auth\n",
            snmp_v3_only={},
        )
        assert one(findings, "snmp_v3_only").status == Status.FAIL

    def test_no_group_fails(self):
        findings = run_check("_check_snmp", "hostname SW1\n", snmp_v3_only={})
        assert one(findings, "snmp_v3_only").status == Status.FAIL


class TestSnmpHost:
    def test_expected_host_present(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server host 10.0.0.5 version 3 priv NMS\n",
            snmp_server_host={"expected_hosts": ["10.0.0.5"]},
        )
        assert one(findings, "snmp_server_host").status == Status.PASS

    def test_expected_host_missing(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server host 10.0.0.9 version 3 priv NMS\n",
            snmp_server_host={"expected_hosts": ["10.0.0.5"]},
        )
        assert one(findings, "snmp_server_host").status == Status.FAIL

    def test_each_expected_host_gets_its_own_finding(self):
        findings = run_check(
            "_check_snmp",
            "snmp-server host 10.0.0.5 version 3 priv NMS\n",
            snmp_server_host={"expected_hosts": ["10.0.0.5", "10.0.0.6"]},
        )
        assert sorted(s.value for s in statuses(findings, "snmp_server_host")) == [
            "FAIL",
            "PASS",
        ]


class TestExpectedHostMatching:
    """Expected servers/hosts are compared as whole addresses.

    The old regex prefix match let an expected ``192.0.2.7`` PASS against a
    device configured with ``192.0.2.70``.
    """

    @pytest.mark.parametrize(
        "method, config, node",
        [
            ("_check_ntp", "ntp server 192.0.2.70\n", {"ntp_servers": "expected_servers"}),
            ("_check_logging", "logging host 192.0.2.70\n", {"logging_host": "expected_hosts"}),
            ("_check_logging", "logging 192.0.2.70\n", {"logging_host": "expected_hosts"}),
            ("_check_snmp", "snmp-server host 192.0.2.70 version 3 priv NMS\n", {"snmp_server_host": "expected_hosts"}),
        ],
    )
    def test_address_prefix_does_not_pass(self, method, config, node):
        (check, key), = node.items()
        findings = run_check(method, config, **{check: {key: ["192.0.2.7"]}})
        finding_name = "ntp_server" if check == "ntp_servers" else check
        assert one(findings, finding_name).status == Status.FAIL

    @pytest.mark.parametrize(
        "config",
        [
            "ntp server 192.0.2.70\n",
            "ntp server 192.0.2.70 prefer\n",
            "ntp server vrf MGMT 192.0.2.70\n",
            "ntp server ip 192.0.2.70\n",
        ],
    )
    def test_ntp_server_forms(self, config):
        findings = run_check(
            "_check_ntp", config, ntp_servers={"expected_servers": ["192.0.2.70"]}
        )
        assert one(findings, "ntp_server").status == Status.PASS

    def test_ipv6_compared_canonically(self):
        findings = run_check(
            "_check_logging",
            "logging host ipv6 2001:db8::1\n",
            logging_host={"expected_hosts": ["2001:DB8:0:0::1"]},
        )
        assert one(findings, "logging_host").status == Status.PASS

    def test_hostname_compared_case_insensitively(self):
        findings = run_check(
            "_check_ntp",
            "ntp server NTP1.corp.example\n",
            ntp_servers={"expected_servers": ["ntp1.corp.example"]},
        )
        assert one(findings, "ntp_server").status == Status.PASS

    def test_logging_vrf_form(self):
        findings = run_check(
            "_check_logging",
            "logging host 192.0.2.70 vrf MGMT\n",
            logging_host={"expected_hosts": ["192.0.2.70"]},
        )
        assert one(findings, "logging_host").status == Status.PASS


# ---------------------------------------------------------------------------
# AAA
# ---------------------------------------------------------------------------

class TestAaa:
    def test_new_model_present(self):
        findings = run_check("_check_aaa", "aaa new-model\n", aaa_new_model={})
        assert one(findings, "aaa_new_model").status == Status.PASS

    def test_new_model_missing(self):
        findings = run_check("_check_aaa", "hostname SW1\n", aaa_new_model={})
        finding = one(findings, "aaa_new_model")
        assert finding.status == Status.FAIL
        assert finding.remediation == "aaa new-model"

    def test_authentication_login_matches_expected_line(self):
        expected = "aaa authentication login default group tacacs+ local"
        findings = run_check(
            "_check_aaa",
            expected + "\n",
            aaa_authentication_login={"expected": expected},
        )
        assert one(findings, "aaa_authentication_login").status == Status.PASS

    def test_authentication_login_wrong_method_fails(self):
        findings = run_check(
            "_check_aaa",
            "aaa authentication login default local\n",
            aaa_authentication_login={
                "expected": "aaa authentication login default group tacacs+ local"
            },
        )
        assert one(findings, "aaa_authentication_login").status == Status.FAIL

    def test_authorization_commands_one_finding_per_level(self):
        findings = run_check(
            "_check_aaa",
            "aaa authorization commands 15 default group tacacs+ local\n",
            aaa_authorization_commands={"levels": [1, 15]},
        )
        assert one(findings, "aaa_authorization_commands_15").status == Status.PASS
        assert one(findings, "aaa_authorization_commands_1").status == Status.FAIL

    def test_tacacs_server_minimum_enforced(self):
        cfg = "tacacs server TAC1\n address ipv4 10.0.0.1\n"
        assert (
            one(
                run_check("_check_aaa", cfg, tacacs_server={"min_servers": 1}),
                "tacacs_server",
            ).status
            == Status.PASS
        )
        assert (
            one(
                run_check("_check_aaa", cfg, tacacs_server={"min_servers": 2}),
                "tacacs_server",
            ).status
            == Status.FAIL
        )

    def test_radius_server_minimum_enforced(self):
        findings = run_check(
            "_check_aaa", "hostname SW1\n", radius_server={"min_servers": 1}
        )
        assert one(findings, "radius_server").status == Status.FAIL


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

class TestSsh:
    def test_version_2_passes(self):
        findings = run_check("_check_ssh", "ip ssh version 2\n", ssh_version={})
        assert one(findings, "ssh_version").status == Status.PASS

    def test_version_1_fails_when_2_required(self):
        findings = run_check("_check_ssh", "ip ssh version 1\n", ssh_version={})
        assert one(findings, "ssh_version").status == Status.FAIL

    def test_missing_version_fails(self):
        findings = run_check("_check_ssh", "hostname SW1\n", ssh_version={})
        assert one(findings, "ssh_version").status == Status.FAIL

    def test_timeout_within_maximum_passes(self):
        findings = run_check(
            "_check_ssh", "ip ssh time-out 30\n", ssh_timeout={"max_seconds": 60}
        )
        assert one(findings, "ssh_timeout").status == Status.PASS

    def test_timeout_above_maximum_fails(self):
        findings = run_check(
            "_check_ssh", "ip ssh time-out 120\n", ssh_timeout={"max_seconds": 60}
        )
        finding = one(findings, "ssh_timeout")
        assert finding.status == Status.FAIL
        assert finding.remediation == "ip ssh time-out 60"

    def test_missing_timeout_fails(self):
        findings = run_check(
            "_check_ssh", "hostname SW1\n", ssh_timeout={"max_seconds": 60}
        )
        assert one(findings, "ssh_timeout").status == Status.FAIL

    def test_auth_retries_above_maximum_fails(self):
        findings = run_check(
            "_check_ssh",
            "ip ssh authentication-retries 5\n",
            ssh_authentication_retries={"max_retries": 3},
        )
        assert one(findings, "ssh_auth_retries").status == Status.FAIL

    def test_auth_retries_unset_warns(self):
        findings = run_check(
            "_check_ssh",
            "hostname SW1\n",
            ssh_authentication_retries={"max_retries": 3},
        )
        assert one(findings, "ssh_auth_retries").status == Status.WARN


# ---------------------------------------------------------------------------
# VTY lines
# ---------------------------------------------------------------------------

VTY = "line vty 0 4\n{}\n"


class TestVtyTransport:
    def test_ssh_only_passes(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" transport input ssh"),
            vty_transport_input_ssh={},
        )
        assert one(findings, "vty_transport_ssh").status == Status.PASS

    def test_ssh_plus_telnet_fails(self):
        """transport input ssh telnet still permits telnet."""
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" transport input ssh telnet"),
            vty_transport_input_ssh={},
        )
        assert one(findings, "vty_transport_ssh").status == Status.FAIL

    def test_transport_all_fails(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" transport input all"),
            vty_transport_input_ssh={},
        )
        assert one(findings, "vty_transport_ssh").status == Status.FAIL


class TestVtyExecTimeout:
    def test_within_maximum_passes(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" exec-timeout 5 0"),
            vty_exec_timeout={"minutes": 10, "seconds": 0},
        )
        assert one(findings, "vty_exec_timeout").status == Status.PASS

    def test_too_long_fails(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" exec-timeout 30 0"),
            vty_exec_timeout={"minutes": 10, "seconds": 0},
        )
        assert one(findings, "vty_exec_timeout").status == Status.FAIL

    def test_zero_zero_disables_the_timeout_and_fails(self):
        """exec-timeout 0 0 never expires - it is not a stricter timeout."""
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" exec-timeout 0 0"),
            vty_exec_timeout={"minutes": 10, "seconds": 0},
        )
        finding = one(findings, "vty_exec_timeout")
        assert finding.status == Status.FAIL
        assert finding.remediation == "exec-timeout 10 0"

    def test_unset_fails(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" transport input ssh"),
            vty_exec_timeout={"minutes": 10, "seconds": 0},
        )
        assert one(findings, "vty_exec_timeout").status == Status.FAIL


class TestVtyAccessClass:
    def test_access_class_present_passes(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" access-class MGMT-IN in"),
            vty_access_class={"acl_name": "MGMT-IN"},
        )
        assert one(findings, "vty_access_class").status == Status.PASS

    def test_missing_access_class_fails(self):
        findings = run_check(
            "_check_vty_lines",
            VTY.format(" transport input ssh"),
            vty_access_class={"acl_name": "MGMT-IN"},
        )
        finding = one(findings, "vty_access_class")
        assert finding.status == Status.FAIL
        assert finding.remediation == "access-class MGMT-IN in"


class TestVtyMissingSection:
    def test_no_vty_config_warns(self):
        findings = run_check(
            "_check_vty_lines", "hostname SW1\n", vty_transport_input_ssh={}
        )
        assert one(findings, "vty_lines").status == Status.WARN


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

class TestConsoleExecTimeout:
    def test_within_maximum_passes(self):
        findings = run_check(
            "_check_console",
            "line con 0\n exec-timeout 5 0\n",
            console_exec_timeout={"minutes": 10, "seconds": 0},
        )
        assert one(findings, "console_exec_timeout").status == Status.PASS

    def test_zero_zero_disables_the_timeout_and_fails(self):
        findings = run_check(
            "_check_console",
            "line con 0\n exec-timeout 0 0\n",
            console_exec_timeout={"minutes": 10, "seconds": 0},
        )
        assert one(findings, "console_exec_timeout").status == Status.FAIL
