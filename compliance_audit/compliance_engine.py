"""
Compliance-check engine for Cisco IOS-XE.

Every check is a method on ``ComplianceEngine``.  The engine iterates
through all registered checks, skips disabled ones (per the YAML policy)
and collects Findings into an ``AuditResult``.
"""

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .collector import DeviceData, ParsedConfig
from .hostname_parser import HostnameInfo
from .port_classifier import PortInfo, PortRole

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class Finding:
    check_name: str
    status: Status
    detail: str
    category: str = ""
    interface: str = ""
    remediation: str = ""


@dataclass
class AuditResult:
    hostname: str
    ip: str
    role: str
    role_display: str
    findings: list[Finding] = field(default_factory=list)
    ios_version: str = ""
    tool_version: str = ""
    duration_secs: float = 0.0
    audit_ts: str = ""

    @property
    def total(self) -> int:
        return len([f for f in self.findings if f.status != Status.SKIP])

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.WARN)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.ERROR)

    @property
    def score_pct(self) -> float:
        t = self.total
        if t == 0:
            return 100.0
        return round(self.pass_count / t * 100, 1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _pol(policy: dict, *path, default=None):
    """Navigate nested policy dict and return the value (or *default*)."""
    cur = policy
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key, default)
    return cur


def _enabled(policy: dict, *path) -> bool:
    """Return True when the check at *path* has ``enabled: true``."""
    node = _pol(policy, *path)
    if isinstance(node, dict):
        return node.get("enabled", True)
    return True


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class ComplianceEngine:
    """Run all compliance checks against collected device data."""

    def __init__(self, policy: dict):
        self.policy = policy  # compliance section of YAML

    # ── public entry point ──────────────────────────────────────
    def audit(
        self,
        data: DeviceData,
        host_info: HostnameInfo,
        ports: dict[str, PortInfo],
    ) -> AuditResult:
        result = AuditResult(
            hostname=data.hostname or host_info.raw,
            ip=data.ip,
            role=host_info.role or "unknown",
            role_display=host_info.role_display or "Unknown",
        )
        cfg = data.parsed_config
        if cfg is None:
            result.findings.append(
                Finding("config_read", Status.ERROR, "No running-config collected", "system")
            )
            return result

        check_groups = [
            ("management_plane", self._check_services),
            ("management_plane", self._check_ip_settings),
            ("management_plane", self._check_ssh),
            ("management_plane", self._check_aaa),
            ("management_plane", self._check_ntp),
            ("management_plane", self._check_logging),
            ("management_plane", self._check_snmp),
            ("management_plane", self._check_banners),
            ("management_plane", self._check_users),
            ("management_plane", self._check_vty_lines),
            ("management_plane", self._check_console),
            ("management_plane", self._check_archive),
            ("management_plane", self._check_login_security),
            ("management_plane", self._check_cdp_lldp),
            ("control_plane",    self._check_stp),
            ("control_plane",    self._check_vtp),
            ("control_plane",    self._check_dhcp_snooping),
            ("control_plane",    self._check_arp_inspection),
            ("control_plane",    self._check_errdisable),
            ("control_plane",    self._check_udld),
            ("control_plane",    self._check_copp),
            ("data_plane",       self._check_interfaces),
            ("role_specific",    self._check_role_specific),
        ]

        for category, func in check_groups:
            try:
                findings = func(cfg, data, host_info, ports)
                for f in findings:
                    f.category = f.category or category
                result.findings.extend(findings)
            except Exception as exc:
                result.findings.append(
                    Finding(func.__name__, Status.ERROR, str(exc), category)
                )
                log.exception("Check %s raised an exception", func.__name__)

        return result

    # ===================================================================
    #                    MANAGEMENT  PLANE  CHECKS
    # ===================================================================

    # ── SERVICES ──────────────────────────────────────────────
    def _check_services(self, cfg: ParsedConfig, data: DeviceData,
                        host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        # service password-encryption
        if _enabled(mp, "service_password_encryption"):
            f.append(self._present(cfg, r"^service password-encryption",
                     "service_password_encryption", "service password-encryption",
                     "service password-encryption"))

        # service timestamps debug
        if _enabled(mp, "service_timestamps_debug"):
            exp = mp.get("service_timestamps_debug", {}).get(
                "expected",  "service timestamps debug datetime msec localtime show-timezone year")
            f.append(self._present(cfg, re.escape(exp),
                     "service_timestamps_debug", exp, exp))

        # service timestamps log
        if _enabled(mp, "service_timestamps_log"):
            exp = mp.get("service_timestamps_log", {}).get(
                "expected", "service timestamps log datetime msec localtime show-timezone year")
            f.append(self._present(cfg, re.escape(exp),
                     "service_timestamps_log", exp, exp))

        # tcp-keepalives
        if _enabled(mp, "service_tcp_keepalives_in"):
            f.append(self._present(cfg, r"^service tcp-keepalives-in",
                     "service_tcp_keepalives_in", "service tcp-keepalives-in",
                     "service tcp-keepalives-in"))
        if _enabled(mp, "service_tcp_keepalives_out"):
            f.append(self._present(cfg, r"^service tcp-keepalives-out",
                     "service_tcp_keepalives_out", "service tcp-keepalives-out",
                     "service tcp-keepalives-out"))

        # no service pad
        if _enabled(mp, "no_service_pad"):
            f.append(self._absent(cfg, r"^service pad$", "no_service_pad",
                     "service pad", "no service pad"))

        # no service config
        if _enabled(mp, "no_service_config"):
            f.append(self._absent(cfg, r"^service config$", "no_service_config",
                     "service config", "no service config"))

        return f

    # ── IP SETTINGS ───────────────────────────────────────────
    def _check_ip_settings(self, cfg: ParsedConfig, data: DeviceData,
                           host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        simple_present = [
            ("ip_cef", r"^ip cef", "ip cef", "ip cef"),
        ]
        simple_absent = [
            ("no_ip_source_route", r"^ip source-route", "ip source-route", "no ip source-route"),
            ("no_ip_bootp_server", r"^ip bootp server", "ip bootp server", "no ip bootp server"),
            ("no_ip_http_server", r"^ip http server$", "ip http server", "no ip http server"),
            ("no_ip_http_secure_server", r"^ip http secure-server", "ip http secure-server",
             "no ip http secure-server"),
            ("no_ip_gratuitous_arps", r"^ip gratuitous-arps", "ip gratuitous-arps",
             "no ip gratuitous-arps"),
            ("no_ip_domain_lookup", r"^ip domain.lookup", "ip domain lookup",
             "no ip domain lookup"),
        ]
        for name, pattern, desc, remed in simple_present:
            if _enabled(mp, name):
                f.append(self._present(cfg, pattern, name, desc, remed))
        for name, pattern, desc, remed in simple_absent:
            if _enabled(mp, name):
                f.append(self._absent(cfg, pattern, name, desc, remed))

        # ip http secure-server (when HTTPS management IS desired)
        if _enabled(mp, "ip_http_secure_server"):
            f.append(self._present(cfg, r"^ip http secure-server",
                     "ip_http_secure_server", "ip http secure-server",
                     "ip http secure-server"))

        # ip http authentication
        if _enabled(mp, "ip_http_authentication"):
            method = mp.get("ip_http_authentication", {}).get("method", "local")
            f.append(self._present(cfg, rf"^ip http authentication\s+{re.escape(method)}",
                     "ip_http_authentication",
                     f"ip http authentication {method}",
                     f"ip http authentication {method}"))

        # ip http access-class
        if _enabled(mp, "ip_http_access_class"):
            acl = mp.get("ip_http_access_class", {}).get("acl_name", "")
            if acl:
                f.append(self._present(cfg, rf"^ip http access-class\s+{re.escape(acl)}",
                         "ip_http_access_class",
                         f"ip http access-class {acl}",
                         f"ip http access-class {acl}"))
            else:
                f.append(self._present(cfg, r"^ip http access-class\s+\S+",
                         "ip_http_access_class",
                         "ip http access-class set",
                         "ip http access-class <acl>"))

        # clock timezone
        if _enabled(mp, "clock_timezone"):
            tz_node = mp.get("clock_timezone", {})
            tz = tz_node.get("timezone", "")
            if tz:
                f.append(self._present(cfg, rf"^clock timezone\s+{re.escape(tz)}",
                         "clock_timezone",
                         f"clock timezone {tz}",
                         f"clock timezone {tz} {tz_node.get('offset', 0)}"))
            else:
                f.append(self._present(cfg, r"^clock timezone\s+\S+",
                         "clock_timezone",
                         "clock timezone configured",
                         "clock timezone <tz> <offset>"))

        # ip domain-name
        if _enabled(mp, "ip_domain_name"):
            expected = mp.get("ip_domain_name", {}).get("expected", "")
            if expected:
                pattern = rf"^ip domain.name\s+{re.escape(expected)}"
                f.append(self._present(cfg, pattern, "ip_domain_name",
                         f"ip domain-name {expected}", f"ip domain-name {expected}"))
            else:
                f.append(self._present(cfg, r"^ip domain.name\s+\S+",
                         "ip_domain_name", "ip domain-name set",
                         "ip domain-name <your-domain>"))

        return f

    # ── SSH ───────────────────────────────────────────────────
    def _check_ssh(self, cfg: ParsedConfig, data: DeviceData,
                   host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        # SSH version
        if _enabled(mp, "ssh_version"):
            ver = mp.get("ssh_version", {}).get("version", 2)
            f.append(self._present(cfg, rf"^ip ssh version\s+{ver}",
                     "ssh_version", f"ip ssh version {ver}", f"ip ssh version {ver}"))

        # SSH timeout
        if _enabled(mp, "ssh_timeout"):
            max_s = mp.get("ssh_timeout", {}).get("max_seconds", 60)
            lines = cfg.find_lines(r"^ip ssh time-out\s+\d+")
            if lines:
                m = re.search(r"(\d+)", lines[0])
                actual = int(m.group(1)) if m else 999
                if actual <= max_s:
                    f.append(Finding("ssh_timeout", Status.PASS,
                             f"SSH timeout {actual}s <= {max_s}s"))
                else:
                    f.append(Finding("ssh_timeout", Status.FAIL,
                             f"SSH timeout {actual}s > {max_s}s",
                             remediation=f"ip ssh time-out {max_s}"))
            else:
                f.append(Finding("ssh_timeout", Status.FAIL,
                         "SSH timeout not configured",
                         remediation=f"ip ssh time-out {max_s}"))

        # SSH auth retries
        if _enabled(mp, "ssh_authentication_retries"):
            max_r = mp.get("ssh_authentication_retries", {}).get("max_retries", 3)
            lines = cfg.find_lines(r"^ip ssh authentication-retries\s+\d+")
            if lines:
                m = re.search(r"(\d+)", lines[0])
                actual = int(m.group(1)) if m else 999
                if actual <= max_r:
                    f.append(Finding("ssh_auth_retries", Status.PASS,
                             f"SSH retries {actual} <= {max_r}"))
                else:
                    f.append(Finding("ssh_auth_retries", Status.FAIL,
                             f"SSH retries {actual} > {max_r}",
                             remediation=f"ip ssh authentication-retries {max_r}"))
            else:
                f.append(Finding("ssh_auth_retries", Status.WARN,
                         "SSH authentication-retries not explicitly set"))

        # SSH source-interface
        if _enabled(mp, "ssh_source_interface"):
            intf = mp.get("ssh_source_interface", {}).get("interface", "")
            if intf:
                f.append(self._present(cfg, rf"^ip ssh source-interface\s+{re.escape(intf)}",
                         "ssh_source_interface",
                         f"ip ssh source-interface {intf}",
                         f"ip ssh source-interface {intf}"))

        # SSH RSA minimum modulus size
        if _enabled(mp, "ssh_rsa_min_modulus"):
            min_bits = mp.get("ssh_rsa_min_modulus", {}).get("min_bits", 2048)
            modulus_found = False

            # First, try to get modulus size from "show ip ssh" command output
            if data and data.raw_commands.get("show ip ssh"):
                ssh_output = data.raw_commands["show ip ssh"]
                # Look for "Modulus Size : 2048 bits" pattern
                for line in ssh_output.splitlines():
                    m = re.search(r"Modulus Size\s*:\s*(\d+)\s*bits?", line, re.IGNORECASE)
                    if m:
                        bits = int(m.group(1))
                        modulus_found = True
                        if bits >= min_bits:
                            f.append(Finding("ssh_rsa_min_modulus", Status.PASS,
                                     f"RSA key size {bits} >= {min_bits} bits"))
                        else:
                            f.append(Finding("ssh_rsa_min_modulus", Status.FAIL,
                                     f"RSA key size {bits} < {min_bits} bits",
                                     remediation=f"crypto key generate rsa modulus {min_bits}"))
                        break

            # Fallback: check running-config for RSA key modulus
            if not modulus_found:
                for gl in cfg.global_lines:
                    m = re.search(r"(\d+)\s*bit", gl)
                    if m and "rsa" in gl.lower():
                        bits = int(m.group(1))
                        modulus_found = True
                        if bits >= min_bits:
                            f.append(Finding("ssh_rsa_min_modulus", Status.PASS,
                                     f"RSA key size {bits} >= {min_bits} bits"))
                        else:
                            f.append(Finding("ssh_rsa_min_modulus", Status.FAIL,
                                     f"RSA key size {bits} < {min_bits} bits",
                                     remediation=f"crypto key generate rsa modulus {min_bits}"))
                        break

            if not modulus_found:
                f.append(Finding("ssh_rsa_min_modulus", Status.WARN,
                         f"RSA modulus could not be determined (expected >= {min_bits})",
                         remediation=f"crypto key generate rsa modulus {min_bits}"))

        return f

    # ── AAA ───────────────────────────────────────────────────
    def _check_aaa(self, cfg: ParsedConfig, data: DeviceData,
                   host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "aaa_new_model"):
            f.append(self._present(cfg, r"^aaa new-model",
                     "aaa_new_model", "aaa new-model", "aaa new-model"))

        # AAA line checks — expected exact line
        for check_name in ("aaa_authentication_login", "aaa_authentication_enable",
                           "aaa_authorization_console", "aaa_authorization_exec",
                           "aaa_accounting_exec", "aaa_accounting_connection",
                           "aaa_session_id"):
            node = mp.get(check_name, {})
            if not node.get("enabled", False):
                continue
            expected = node.get("expected", "")
            if expected:
                f.append(self._present(cfg, re.escape(expected), check_name,
                         expected, expected))

        # AAA authorization commands (per level)
        if _enabled(mp, "aaa_authorization_commands"):
            node = mp["aaa_authorization_commands"]
            for level in node.get("levels", [15]):
                prefix = node.get("expected_prefix",
                                  "aaa authorization commands {level} default group tacacs+ local")
                expected = prefix.format(level=level)
                name = f"aaa_authorization_commands_{level}"
                f.append(self._present(cfg, re.escape(expected), name,
                         expected, expected))

        # AAA accounting commands (per level)
        if _enabled(mp, "aaa_accounting_commands"):
            node = mp["aaa_accounting_commands"]
            for level in node.get("levels", [15]):
                prefix = node.get("expected_prefix",
                                  "aaa accounting commands {level} default start-stop group tacacs+")
                expected = prefix.format(level=level)
                name = f"aaa_accounting_commands_{level}"
                f.append(self._present(cfg, re.escape(expected), name,
                         expected, expected))

        # TACACS server
        if _enabled(mp, "tacacs_server"):
            min_svr = mp.get("tacacs_server", {}).get("min_servers", 1)
            servers = cfg.find_lines(r"^tacacs server\s+")
            if len(servers) >= min_svr:
                f.append(Finding("tacacs_server", Status.PASS,
                         f"{len(servers)} TACACS server(s) configured"))
            else:
                f.append(Finding("tacacs_server", Status.FAIL,
                         f"Expected >= {min_svr} TACACS server(s), found {len(servers)}",
                         remediation="tacacs server <name>"))

        # RADIUS server
        if _enabled(mp, "radius_server"):
            min_svr = mp.get("radius_server", {}).get("min_servers", 1)
            servers = cfg.find_lines(r"^radius server\s+")
            if len(servers) >= min_svr:
                f.append(Finding("radius_server", Status.PASS,
                         f"{len(servers)} RADIUS server(s) configured"))
            else:
                f.append(Finding("radius_server", Status.FAIL,
                         f"Expected >= {min_svr} RADIUS server(s), found {len(servers)}",
                         remediation="radius server <name>"))

        return f

    # ── NTP ───────────────────────────────────────────────────
    def _check_ntp(self, cfg: ParsedConfig, data: DeviceData,
                   host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "ntp_servers"):
            node = mp.get("ntp_servers", {})
            min_svr = node.get("min_servers", 1)
            expected = node.get("expected_servers", [])
            actual = cfg.find_lines(r"^ntp server\s+")

            if expected:
                for srv in expected:
                    if cfg.has_line(rf"^ntp server\s+{re.escape(srv)}"):
                        f.append(Finding("ntp_server", Status.PASS,
                                 f"NTP server {srv} configured"))
                    else:
                        f.append(Finding("ntp_server", Status.FAIL,
                                 f"NTP server {srv} missing",
                                 remediation=f"ntp server {srv}"))
            elif len(actual) >= min_svr:
                f.append(Finding("ntp_servers", Status.PASS,
                         f"{len(actual)} NTP server(s) configured"))
            else:
                f.append(Finding("ntp_servers", Status.FAIL,
                         f"Expected >= {min_svr} NTP server(s), found {len(actual)}",
                         remediation="ntp server <ip>"))

        if _enabled(mp, "ntp_authenticate"):
            f.append(self._present(cfg, r"^ntp authenticate",
                     "ntp_authenticate", "ntp authenticate", "ntp authenticate"))

        if _enabled(mp, "ntp_source_interface"):
            intf = mp.get("ntp_source_interface", {}).get("interface", "")
            if intf:
                f.append(self._present(cfg, rf"^ntp source\s+{re.escape(intf)}",
                         "ntp_source_interface",
                         f"ntp source {intf}", f"ntp source {intf}"))

        return f

    # ── LOGGING ───────────────────────────────────────────────
    def _check_logging(self, cfg: ParsedConfig, data: DeviceData,
                       host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "logging_buffered"):
            f.append(self._present(cfg, r"^logging buffered",
                     "logging_buffered", "logging buffered",
                     "logging buffered 64000 informational"))

        if _enabled(mp, "logging_console"):
            lvl = mp.get("logging_console", {}).get("level", "critical")
            f.append(self._present(cfg, r"^logging console",
                     "logging_console", f"logging console {lvl}",
                     f"logging console {lvl}"))

        if _enabled(mp, "no_logging_console"):
            f.append(self._absent(cfg, r"^logging console",
                     "no_logging_console", "logging console", "no logging console"))

        if _enabled(mp, "logging_trap"):
            f.append(self._present(cfg, r"^logging trap",
                     "logging_trap", "logging trap",
                     "logging trap informational"))

        if _enabled(mp, "logging_host"):
            node = mp.get("logging_host", {})
            expected = node.get("expected_hosts", [])
            min_h = node.get("min_hosts", 1)
            actual = cfg.find_lines(r"^logging host\s+\S+|^logging\s+\d+\.\d+\.\d+\.\d+")
            if expected:
                for h in expected:
                    if cfg.has_line(rf"^logging (host\s+)?{re.escape(h)}"):
                        f.append(Finding("logging_host", Status.PASS,
                                 f"Logging host {h} configured"))
                    else:
                        f.append(Finding("logging_host", Status.FAIL,
                                 f"Logging host {h} missing",
                                 remediation=f"logging host {h}"))
            elif len(actual) >= min_h:
                f.append(Finding("logging_host", Status.PASS,
                         f"{len(actual)} logging host(s) configured"))
            else:
                f.append(Finding("logging_host", Status.FAIL,
                         f"Expected >= {min_h} logging host(s), found {len(actual)}",
                         remediation="logging host <ip>"))

        if _enabled(mp, "logging_source_interface"):
            intf = mp.get("logging_source_interface", {}).get("interface", "")
            if intf:
                f.append(self._present(cfg, rf"^logging source-interface\s+{re.escape(intf)}",
                         "logging_source_interface",
                         f"logging source-interface {intf}",
                         f"logging source-interface {intf}"))

        # logging monitor
        if _enabled(mp, "logging_monitor"):
            lvl = mp.get("logging_monitor", {}).get("level", "warnings")
            f.append(self._present(cfg, r"^logging monitor",
                     "logging_monitor", f"logging monitor {lvl}",
                     f"logging monitor {lvl}"))

        # logging origin-id
        if _enabled(mp, "logging_origin_id"):
            id_type = mp.get("logging_origin_id", {}).get("type", "hostname")
            f.append(self._present(cfg, r"^logging origin-id",
                     "logging_origin_id", f"logging origin-id {id_type}",
                     f"logging origin-id {id_type}"))

        return f

    # ── SNMP ──────────────────────────────────────────────────
    def _check_snmp(self, cfg: ParsedConfig, data: DeviceData,
                    host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "snmp_no_community_public"):
            f.append(self._absent(cfg, r"^snmp-server community public",
                     "snmp_no_community_public",
                     "snmp-server community public",
                     "no snmp-server community public"))

        if _enabled(mp, "snmp_no_community_private"):
            f.append(self._absent(cfg, r"^snmp-server community private",
                     "snmp_no_community_private",
                     "snmp-server community private",
                     "no snmp-server community private"))

        if _enabled(mp, "snmp_v3_only"):
            groups = cfg.find_lines(r"^snmp-server group\s+\S+\s+v3\s+priv")
            if groups:
                f.append(Finding("snmp_v3_only", Status.PASS,
                         f"SNMPv3 group(s) configured: {len(groups)}"))
            else:
                f.append(Finding("snmp_v3_only", Status.FAIL,
                         "No SNMPv3 priv group found",
                         remediation="snmp-server group <name> v3 priv"))

        if _enabled(mp, "snmp_ifindex_persist"):
            f.append(self._present(cfg, r"^snmp-server ifindex persist",
                     "snmp_ifindex_persist", "snmp-server ifindex persist",
                     "snmp-server ifindex persist"))

        # SNMP community ACL
        if _enabled(mp, "snmp_community_acl"):
            communities = cfg.find_lines(r"^snmp-server community\s+")
            if communities:
                all_have_acl = True
                for comm_line in communities:
                    # community string + RO/RW + optional ACL
                    parts = comm_line.split()
                    # Format: snmp-server community <name> [RO|RW] [ACL]
                    if len(parts) < 4:
                        all_have_acl = False
                        break
                if all_have_acl:
                    f.append(Finding("snmp_community_acl", Status.PASS,
                             f"All {len(communities)} SNMP communities have ACL restrictions"))
                else:
                    f.append(Finding("snmp_community_acl", Status.FAIL,
                             "SNMP community without ACL restriction found",
                             remediation="snmp-server community <name> RO <acl>"))
            else:
                f.append(Finding("snmp_community_acl", Status.PASS,
                         "No SNMP v1/v2c communities configured"))

        # SNMP server host
        if _enabled(mp, "snmp_server_host"):
            node = mp.get("snmp_server_host", {})
            expected = node.get("expected_hosts", [])
            if expected:
                for h in expected:
                    if cfg.has_line(rf"^snmp-server host\s+{re.escape(h)}"):
                        f.append(Finding("snmp_server_host", Status.PASS,
                                 f"SNMP server host {h} configured"))
                    else:
                        f.append(Finding("snmp_server_host", Status.FAIL,
                                 f"SNMP server host {h} missing",
                                 remediation=f"snmp-server host {h}"))
            else:
                actual = cfg.find_lines(r"^snmp-server host\s+")
                if actual:
                    f.append(Finding("snmp_server_host", Status.PASS,
                             f"{len(actual)} SNMP server host(s) configured"))
                else:
                    f.append(Finding("snmp_server_host", Status.FAIL,
                             "No SNMP server host configured",
                             remediation="snmp-server host <ip>"))

        # SNMP contact
        if _enabled(mp, "snmp_contact"):
            expected = mp.get("snmp_contact", {}).get("expected", "")
            if expected:
                f.append(self._present(cfg, rf"^snmp-server contact\s+.*{re.escape(expected)}",
                         "snmp_contact", f"snmp-server contact {expected}",
                         f"snmp-server contact {expected}"))
            else:
                f.append(self._present(cfg, r"^snmp-server contact\s+\S+",
                         "snmp_contact", "snmp-server contact set",
                         "snmp-server contact <text>"))

        # SNMP location
        if _enabled(mp, "snmp_location"):
            expected = mp.get("snmp_location", {}).get("expected", "")
            if expected:
                f.append(self._present(cfg, rf"^snmp-server location\s+.*{re.escape(expected)}",
                         "snmp_location", f"snmp-server location {expected}",
                         f"snmp-server location {expected}"))
            else:
                f.append(self._present(cfg, r"^snmp-server location\s+\S+",
                         "snmp_location", "snmp-server location set",
                         "snmp-server location <text>"))

        return f

    # ── BANNERS ───────────────────────────────────────────────
    def _check_banners(self, cfg: ParsedConfig, data: DeviceData,
                       host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        for banner_type in ("login", "motd", "exec"):
            key = f"banner_{banner_type}"
            if not _enabled(mp, key):
                continue
            if cfg.has_line(rf"^banner {banner_type}\s+"):
                # Check for required text in banner if specified
                req_text = mp.get(key, {}).get("required_text", "")
                if req_text:
                    # Search the raw config for the banner content
                    banner_found = False
                    if data.running_config:
                        banner_rx = re.compile(
                            rf"banner {banner_type}.*?{re.escape(req_text)}",
                            re.IGNORECASE | re.DOTALL)
                        if banner_rx.search(data.running_config):
                            banner_found = True
                    if banner_found:
                        f.append(Finding(key, Status.PASS,
                                 f"banner {banner_type} present with required text"))
                    else:
                        f.append(Finding(key, Status.FAIL,
                                 f"banner {banner_type} present but missing required text: '{req_text}'",
                                 remediation=f"banner {banner_type} — must include '{req_text}'"))
                else:
                    f.append(Finding(key, Status.PASS, f"banner {banner_type} present"))
            else:
                f.append(Finding(key, Status.FAIL, f"banner {banner_type} missing",
                         remediation=f"banner {banner_type} ^<text>^"))

        return f

    # ── LOCAL USERS ───────────────────────────────────────────
    def _check_users(self, cfg: ParsedConfig, data: DeviceData,
                     host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "enable_secret"):
            f.append(self._present(cfg, r"^enable secret",
                     "enable_secret", "enable secret", "enable secret 0 <secret>"))

        if _enabled(mp, "no_enable_password"):
            f.append(self._absent(cfg, r"^enable password",
                     "no_enable_password", "enable password",
                     "no enable password / use enable secret"))

        if _enabled(mp, "username_secret"):
            pw_users = cfg.find_lines(r"^username\s+\S+.*\bpassword\b")
            if pw_users:
                for u in pw_users:
                    m = re.match(r"username\s+(\S+)", u)
                    name = m.group(1) if m else "?"
                    f.append(Finding("username_secret", Status.FAIL,
                             f"User '{name}' uses 'password' instead of 'secret'",
                             remediation=f"username {name} secret 0 <secret>"))
            else:
                f.append(Finding("username_secret", Status.PASS,
                         "All local users use 'secret'"))

        return f

    # ── VTY LINES ─────────────────────────────────────────────
    def _check_vty_lines(self, cfg: ParsedConfig, data: DeviceData,
                         host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})
        vty_sections = cfg.get_line_config_sections(r"^vty\s+")

        if not vty_sections:
            f.append(Finding("vty_lines", Status.WARN, "No VTY line config found"))
            return f

        for sec_name, lines in vty_sections.items():
            label = f"line {sec_name}"

            if _enabled(mp, "vty_transport_input_ssh"):
                has_ssh_only = any(re.match(r"transport input ssh", l, re.I) for l in lines)
                if has_ssh_only:
                    f.append(Finding("vty_transport_ssh", Status.PASS,
                             f"{label}: transport input ssh", interface=label))
                else:
                    f.append(Finding("vty_transport_ssh", Status.FAIL,
                             f"{label}: transport input is not 'ssh' only",
                             interface=label,
                             remediation="transport input ssh"))

            if _enabled(mp, "vty_exec_timeout"):
                exp_min = mp.get("vty_exec_timeout", {}).get("minutes", 5)
                exp_sec = mp.get("vty_exec_timeout", {}).get("seconds", 0)
                timeout_lines = [l for l in lines if l.startswith("exec-timeout")]
                if timeout_lines:
                    m = re.match(r"exec-timeout\s+(\d+)\s+(\d+)", timeout_lines[0])
                    if m:
                        actual_total = int(m.group(1)) * 60 + int(m.group(2))
                        exp_total = exp_min * 60 + exp_sec
                        if actual_total <= exp_total:
                            f.append(Finding("vty_exec_timeout", Status.PASS,
                                     f"{label}: exec-timeout {m.group(1)} {m.group(2)}",
                                     interface=label))
                        else:
                            f.append(Finding("vty_exec_timeout", Status.FAIL,
                                     f"{label}: exec-timeout too long ({m.group(1)} {m.group(2)})",
                                     interface=label,
                                     remediation=f"exec-timeout {exp_min} {exp_sec}"))
                else:
                    f.append(Finding("vty_exec_timeout", Status.FAIL,
                             f"{label}: exec-timeout not set",
                             interface=label,
                             remediation=f"exec-timeout {exp_min} {exp_sec}"))

            if _enabled(mp, "vty_access_class"):
                acl = mp.get("vty_access_class", {}).get("acl_name", "")
                has_acl = any("access-class" in l for l in lines)
                if has_acl:
                    f.append(Finding("vty_access_class", Status.PASS,
                             f"{label}: access-class applied", interface=label))
                else:
                    remed = f"access-class {acl} in" if acl else "access-class <acl> in"
                    f.append(Finding("vty_access_class", Status.FAIL,
                             f"{label}: no access-class", interface=label,
                             remediation=remed))

            if _enabled(mp, "vty_logging_synchronous"):
                if any("logging synchronous" in l for l in lines):
                    f.append(Finding("vty_logging_sync", Status.PASS,
                             f"{label}: logging synchronous", interface=label))
                else:
                    f.append(Finding("vty_logging_sync", Status.FAIL,
                             f"{label}: logging synchronous missing", interface=label,
                             remediation="logging synchronous"))

            # VTY login authentication method list
            if _enabled(mp, "vty_login_authentication"):
                method = mp.get("vty_login_authentication", {}).get("method_list", "default")
                has_auth = any(re.match(r"login authentication", l, re.I) for l in lines)
                if has_auth:
                    f.append(Finding("vty_login_authentication", Status.PASS,
                             f"{label}: login authentication configured", interface=label))
                else:
                    f.append(Finding("vty_login_authentication", Status.FAIL,
                             f"{label}: login authentication not set",
                             interface=label,
                             remediation=f"login authentication {method}"))

        return f

    # ── CONSOLE ───────────────────────────────────────────────
    def _check_console(self, cfg: ParsedConfig, data: DeviceData,
                       host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})
        con_sections = cfg.get_line_config_sections(r"^con\s+")

        if not con_sections:
            return f

        for sec_name, lines in con_sections.items():
            label = f"line {sec_name}"

            if _enabled(mp, "console_exec_timeout"):
                exp_min = mp.get("console_exec_timeout", {}).get("minutes", 5)
                exp_sec = mp.get("console_exec_timeout", {}).get("seconds", 0)
                timeout_lines = [l for l in lines if l.startswith("exec-timeout")]
                if timeout_lines:
                    m = re.match(r"exec-timeout\s+(\d+)\s+(\d+)", timeout_lines[0])
                    if m:
                        actual_total = int(m.group(1)) * 60 + int(m.group(2))
                        exp_total = exp_min * 60 + exp_sec
                        if actual_total <= exp_total:
                            f.append(Finding("console_exec_timeout", Status.PASS,
                                     f"{label}: exec-timeout {m.group(1)} {m.group(2)}",
                                     interface=label))
                        else:
                            f.append(Finding("console_exec_timeout", Status.FAIL,
                                     f"{label}: exec-timeout too long",
                                     interface=label,
                                     remediation=f"exec-timeout {exp_min} {exp_sec}"))
                else:
                    f.append(Finding("console_exec_timeout", Status.FAIL,
                             f"{label}: exec-timeout not set", interface=label,
                             remediation=f"exec-timeout {exp_min} {exp_sec}"))

            if _enabled(mp, "console_logging_synchronous"):
                if any("logging synchronous" in l for l in lines):
                    f.append(Finding("console_logging_sync", Status.PASS,
                             f"{label}: logging synchronous", interface=label))
                else:
                    f.append(Finding("console_logging_sync", Status.FAIL,
                             f"{label}: logging synchronous missing",
                             interface=label, remediation="logging synchronous"))

            # Console login authentication method list
            if _enabled(mp, "console_login_authentication"):
                method = mp.get("console_login_authentication", {}).get("method_list", "default")
                has_auth = any(re.match(r"login authentication", l, re.I) for l in lines)
                if has_auth:
                    f.append(Finding("console_login_authentication", Status.PASS,
                             f"{label}: login authentication configured", interface=label))
                else:
                    f.append(Finding("console_login_authentication", Status.FAIL,
                             f"{label}: login authentication not set",
                             interface=label,
                             remediation=f"login authentication {method}"))

        return f

    # ── ARCHIVE ───────────────────────────────────────────────
    def _check_archive(self, cfg: ParsedConfig, data: DeviceData,
                       host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})
        if not _enabled(mp, "archive_logging"):
            return f
        if cfg.has_line(r"^archive") and cfg.has_line(r"logging enable"):
            f.append(Finding("archive_logging", Status.PASS, "Archive config logging enabled"))
        else:
            f.append(Finding("archive_logging", Status.FAIL,
                     "Archive config logging not enabled",
                     remediation="archive / log config / logging enable"))
        return f

    # ── LOGIN SECURITY ────────────────────────────────────────
    def _check_login_security(self, cfg: ParsedConfig, data: DeviceData,
                              host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "login_block_for"):
            node = mp.get("login_block_for", {})
            secs = node.get("seconds", 120)
            att = node.get("attempts", 3)
            within = node.get("within", 60)
            f.append(self._present(cfg, r"^login block-for",
                     "login_block_for",
                     f"login block-for {secs} attempts {att} within {within}",
                     f"login block-for {secs} attempts {att} within {within}"))

        if _enabled(mp, "login_on_failure_log"):
            f.append(self._present(cfg, r"^login on-failure log",
                     "login_on_failure_log", "login on-failure log",
                     "login on-failure log"))

        if _enabled(mp, "login_on_success_log"):
            f.append(self._present(cfg, r"^login on-success log",
                     "login_on_success_log", "login on-success log",
                     "login on-success log"))

        if _enabled(mp, "login_delay"):
            f.append(self._present(cfg, r"^login delay\s+\d+",
                     "login_delay", "login delay",
                     f"login delay {mp.get('login_delay', {}).get('seconds', 2)}"))

        return f

    # ── CDP / LLDP ────────────────────────────────────────────
    def _check_cdp_lldp(self, cfg: ParsedConfig, data: DeviceData,
                        host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "cdp_global"):
            want = mp.get("cdp_global", {}).get("state", "enabled")
            if want == "disabled":
                f.append(self._present(cfg, r"^no cdp run",
                         "cdp_global", "no cdp run", "no cdp run"))
            else:
                # CDP is enabled by default; ensure 'no cdp run' is absent
                f.append(self._absent(cfg, r"^no cdp run",
                         "cdp_global", "no cdp run", "cdp run"))

        if _enabled(mp, "lldp_global"):
            want = mp.get("lldp_global", {}).get("state", "enabled")
            if want == "enabled":
                f.append(self._present(cfg, r"^lldp run",
                         "lldp_global", "lldp run", "lldp run"))
            else:
                f.append(self._absent(cfg, r"^lldp run",
                         "lldp_global", "lldp run", "no lldp run"))

        return f

    # ===================================================================
    #                     CONTROL  PLANE  CHECKS
    # ===================================================================

    # ── STP ───────────────────────────────────────────────────
    def _check_stp(self, cfg: ParsedConfig, data: DeviceData,
                   host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "stp_mode"):
            mode = cp.get("stp_mode", {}).get("mode", "rapid-pvst")
            f.append(self._present(cfg, rf"^spanning-tree mode\s+{re.escape(mode)}",
                     "stp_mode", f"spanning-tree mode {mode}",
                     f"spanning-tree mode {mode}"))

        if _enabled(cp, "stp_extend_system_id"):
            f.append(self._present(cfg, r"^spanning-tree extend system-id",
                     "stp_extend_system_id", "spanning-tree extend system-id",
                     "spanning-tree extend system-id"))

        if _enabled(cp, "stp_pathcost_method"):
            method = cp.get("stp_pathcost_method", {}).get("method", "long")
            f.append(self._present(cfg, rf"^spanning-tree pathcost method\s+{re.escape(method)}",
                     "stp_pathcost_method",
                     f"spanning-tree pathcost method {method}",
                     f"spanning-tree pathcost method {method}"))

        if _enabled(cp, "stp_loopguard_default"):
            f.append(self._present(cfg, r"^spanning-tree loopguard default",
                     "stp_loopguard_default", "spanning-tree loopguard default",
                     "spanning-tree loopguard default"))

        # STP priority (role-dependent)
        if _enabled(cp, "stp_priority") and host.parsed:
            node = cp.get("stp_priority", {})
            if host.is_core:
                exp = node.get("core_priority", 4096)
                if exp:
                    self._check_stp_priority(cfg, data, exp, "core", f)
            elif host.is_access or host.is_industrial:
                exp = node.get("access_priority", 32768)
                if exp:
                    self._check_stp_priority(cfg, data, exp, "access", f)

        return f

    def _check_stp_priority(self, cfg: ParsedConfig, data: DeviceData,
                            expected: int, label: str,
                            f: list[Finding]) -> None:
        # Try Genie parsed data first
        checked_vlans = False
        if data.stp:
            for mode_data in data.stp.values():
                if not isinstance(mode_data, dict):
                    continue
                for vid, vinfo in mode_data.get("vlans", {}).items():
                    bridge = vinfo.get("bridge", {})
                    prio = bridge.get("priority", None)
                    if prio is not None:
                        checked_vlans = True
                        if prio <= expected:
                            f.append(Finding("stp_priority", Status.PASS,
                                     f"VLAN {vid} bridge priority {prio} <= {expected} ({label})"))
                        else:
                            f.append(Finding("stp_priority", Status.FAIL,
                                     f"VLAN {vid} bridge priority {prio} > expected {expected} ({label})",
                                     remediation=f"spanning-tree vlan {vid} priority {expected}"))
            if checked_vlans:
                return  # Successfully checked all VLANs from parsed data

        # Fallback: regex on running-config
        lines = cfg.find_lines(r"^spanning-tree vlan\s+\S+\s+priority\s+\d+")
        if lines:
            for line in lines:
                m = re.search(r"vlan\s+(\S+)\s+priority\s+(\d+)", line)
                if m:
                    vlan_spec = m.group(1)
                    actual = int(m.group(2))
                    checked_vlans = True
                    if actual <= expected:
                        f.append(Finding("stp_priority", Status.PASS,
                                 f"VLAN {vlan_spec} STP priority {actual} <= {expected} ({label})"))
                    else:
                        f.append(Finding("stp_priority", Status.FAIL,
                                 f"VLAN {vlan_spec} STP priority {actual} > expected {expected} ({label})",
                                 remediation=f"spanning-tree vlan {vlan_spec} priority {expected}"))
            if checked_vlans:
                return

        f.append(Finding("stp_priority", Status.WARN,
                 f"STP priority not explicitly configured ({label})"))

    # ── VTP ───────────────────────────────────────────────────
    def _check_vtp(self, cfg: ParsedConfig, data: DeviceData,
                   host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})

        if not _enabled(cp, "vtp_mode"):
            return f

        expected = cp.get("vtp_mode", {}).get("expected", "transparent")

        # Try Genie parsed VTP data
        if data.vtp:
            actual = (data.vtp.get("vtp", {}).get("operating_mode", "")
                      or data.vtp.get("operating_mode", "")).lower()
            if actual == expected.lower():
                f.append(Finding("vtp_mode", Status.PASS,
                         f"VTP mode: {actual}"))
            else:
                f.append(Finding("vtp_mode", Status.FAIL,
                         f"VTP mode: {actual or 'unknown'}, expected: {expected}",
                         remediation=f"vtp mode {expected}"))
        else:
            # Fallback to config
            if cfg.has_line(rf"^vtp mode\s+{re.escape(expected)}"):
                f.append(Finding("vtp_mode", Status.PASS,
                         f"VTP mode {expected} in config"))
            else:
                f.append(Finding("vtp_mode", Status.WARN,
                         f"VTP mode not verified (expected: {expected})",
                         remediation=f"vtp mode {expected}"))

        return f

    # ── DHCP SNOOPING ─────────────────────────────────────────
    def _check_dhcp_snooping(self, cfg: ParsedConfig, data: DeviceData,
                             host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "dhcp_snooping_global"):
            f.append(self._present(cfg, r"^ip dhcp snooping$",
                     "dhcp_snooping_global", "ip dhcp snooping",
                     "ip dhcp snooping"))

        if _enabled(cp, "dhcp_snooping_vlans"):
            if cfg.has_line(r"^ip dhcp snooping vlan"):
                f.append(Finding("dhcp_snooping_vlans", Status.PASS,
                         "DHCP snooping VLAN(s) configured"))
            else:
                f.append(Finding("dhcp_snooping_vlans", Status.FAIL,
                         "No DHCP snooping VLANs configured",
                         remediation="ip dhcp snooping vlan <vlan-list>"))

        if _enabled(cp, "no_dhcp_snooping_information_option"):
            f.append(self._absent(cfg,
                     r"^ip dhcp snooping information option$",
                     "no_dhcp_snooping_info_option",
                     "ip dhcp snooping information option",
                     "no ip dhcp snooping information option"))

        return f

    # ── ARP INSPECTION ────────────────────────────────────────
    def _check_arp_inspection(self, cfg: ParsedConfig, data: DeviceData,
                              host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "arp_inspection_vlans"):
            if cfg.has_line(r"^ip arp inspection vlan"):
                f.append(Finding("arp_inspection_vlans", Status.PASS,
                         "Dynamic ARP Inspection VLAN(s) configured"))
            else:
                f.append(Finding("arp_inspection_vlans", Status.FAIL,
                         "No DAI VLANs configured",
                         remediation="ip arp inspection vlan <vlan-list>"))

        if _enabled(cp, "arp_inspection_validate"):
            checks = cp.get("arp_inspection_validate", {}).get("checks", [])
            if checks:
                pattern = r"^ip arp inspection validate\s+" + r"\s+".join(
                    re.escape(c) for c in checks
                )
                f.append(self._present(cfg, pattern,
                         "arp_inspection_validate",
                         "ip arp inspection validate " + " ".join(checks),
                         "ip arp inspection validate " + " ".join(checks)))

        return f

    # ── ERRDISABLE ────────────────────────────────────────────
    def _check_errdisable(self, cfg: ParsedConfig, data: DeviceData,
                          host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "errdisable_recovery"):
            return f

        node = cp["errdisable_recovery"]
        for cause in node.get("causes", []):
            name = f"errdisable_recovery_{cause}"
            pattern = rf"^errdisable recovery cause\s+{re.escape(cause)}"
            f.append(self._present(cfg, pattern, name,
                     f"errdisable recovery cause {cause}",
                     f"errdisable recovery cause {cause}"))

        interval = node.get("interval")
        if interval:
            f.append(self._present(cfg, rf"^errdisable recovery interval\s+{interval}",
                     "errdisable_recovery_interval",
                     f"errdisable recovery interval {interval}",
                     f"errdisable recovery interval {interval}"))

        return f

    # ── UDLD ──────────────────────────────────────────────────
    def _check_udld(self, cfg: ParsedConfig, data: DeviceData,
                    host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "udld_global"):
            return f
        mode = cp.get("udld_global", {}).get("mode", "enable")
        f.append(self._present(cfg, rf"^udld\s+{re.escape(mode)}",
                 "udld_global", f"udld {mode}", f"udld {mode}"))
        return f

    # ── CONTROL-PLANE POLICING ──────────────────────────────
    def _check_copp(self, cfg: ParsedConfig, data: DeviceData,
                    host: HostnameInfo, ports: dict) -> list[Finding]:
        f: list[Finding] = []
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "control_plane_policing"):
            return f
        # Check for service-policy under control-plane
        if cfg.has_line(r"^control-plane") and cfg.has_line(r"service-policy"):
            f.append(Finding("control_plane_policing", Status.PASS,
                     "Control-plane policing (CoPP) configured"))
        else:
            f.append(Finding("control_plane_policing", Status.FAIL,
                     "Control-plane policing (CoPP) not configured",
                     remediation="control-plane / service-policy input <policy-map>"))
        return f

    # ===================================================================
    #                       DATA  PLANE  CHECKS
    #       (per-interface, role-aware: access / trunk / unused)
    # ===================================================================

    def _check_interfaces(self, cfg: ParsedConfig, data: DeviceData,
                          host: HostnameInfo, ports: dict[str, PortInfo]) -> list[Finding]:
        f: list[Finding] = []
        dp = self.policy.get("data_plane", {})
        self._current_data = data   # stash for trunk_native_vlan lookups

        for intf_name, pi in ports.items():
            role = pi.role

            if role == PortRole.ACCESS:
                f.extend(self._check_access_port(cfg, dp, pi))
            elif role == PortRole.TRUNK_ENDPOINT:
                f.extend(self._check_endpoint_trunk_port(cfg, dp, pi))
            elif role in (PortRole.TRUNK_UPLINK, PortRole.TRUNK_DOWNLINK, PortRole.TRUNK_UNKNOWN):
                f.extend(self._check_trunk_port(cfg, dp, pi))
            elif role == PortRole.UNUSED:
                f.extend(self._check_unused_port(cfg, dp, pi))
            elif role in (PortRole.ROUTED, PortRole.SVI):
                f.extend(self._check_routed_port(cfg, dp, pi))
            # Loopback / MGMT are generally not subject to
            # switchport-level data-plane checks.

        return f

    # ── ACCESS PORT CHECKS ────────────────────────────────────
    def _check_access_port(self, cfg: ParsedConfig, dp: dict,
                           pi: PortInfo) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # BPDU guard
        if _enabled(dp, "bpdu_guard"):
            if pi_has(pi, r"spanning-tree bpduguard enable"):
                f.append(Finding("bpdu_guard", Status.PASS,
                         f"{intf}: BPDU guard enabled", interface=intf))
            else:
                f.append(Finding("bpdu_guard", Status.FAIL,
                         f"{intf}: BPDU guard missing (access port)",
                         interface=intf,
                         remediation="spanning-tree bpduguard enable"))

        # Portfast
        if _enabled(dp, "portfast"):
            if pi_has(pi, r"spanning-tree portfast$"):
                f.append(Finding("portfast", Status.PASS,
                         f"{intf}: portfast enabled", interface=intf))
            else:
                f.append(Finding("portfast", Status.FAIL,
                         f"{intf}: portfast missing (access port)",
                         interface=intf,
                         remediation="spanning-tree portfast"))

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(Finding("switchport_nonegotiate", Status.PASS,
                         f"{intf}: nonegotiate set", interface=intf))
            else:
                f.append(Finding("switchport_nonegotiate", Status.FAIL,
                         f"{intf}: switchport nonegotiate missing",
                         interface=intf,
                         remediation="switchport nonegotiate"))

        # Explicit switchport mode
        if _enabled(dp, "switchport_mode_explicit"):
            if pi.switchport_mode == "access":
                f.append(Finding("switchport_mode_explicit", Status.PASS,
                         f"{intf}: mode access explicitly set", interface=intf))
            else:
                f.append(Finding("switchport_mode_explicit", Status.FAIL,
                         f"{intf}: switchport mode not explicitly 'access'",
                         interface=intf,
                         remediation="switchport mode access"))

        # Access VLAN not in disallowed list
        if _enabled(dp, "access_vlan_set"):
            bad_vlans = dp.get("access_vlan_set", {}).get("disallowed_vlans", [1])
            if pi.access_vlan and pi.access_vlan not in bad_vlans:
                f.append(Finding("access_vlan_set", Status.PASS,
                         f"{intf}: access VLAN {pi.access_vlan}", interface=intf))
            elif pi.access_vlan in bad_vlans:
                f.append(Finding("access_vlan_set", Status.FAIL,
                         f"{intf}: access VLAN {pi.access_vlan} is disallowed",
                         interface=intf,
                         remediation="switchport access vlan <vlan>"))
            else:
                f.append(Finding("access_vlan_set", Status.FAIL,
                         f"{intf}: no access VLAN configured",
                         interface=intf,
                         remediation="switchport access vlan <vlan>"))

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(Finding("interface_description", Status.PASS,
                         f"{intf}: description present", interface=intf))
            else:
                f.append(Finding("interface_description", Status.FAIL,
                         f"{intf}: no description", interface=intf,
                         remediation="description <text>"))

        # Port Security
        if _enabled(dp, "port_security"):
            ps_node = dp.get("port_security", {})
            if pi_has(pi, r"switchport port-security"):
                f.append(Finding("port_security", Status.PASS,
                         f"{intf}: port-security enabled", interface=intf))
                # Check max MAC
                max_mac = ps_node.get("max_mac")
                if max_mac:
                    mac_line = [l for l in pi.config_lines
                                if re.search(r"port-security maximum", l, re.I)]
                    if mac_line:
                        m = re.search(r"maximum\s+(\d+)", mac_line[0])
                        if m and int(m.group(1)) <= max_mac:
                            f.append(Finding("port_security_max", Status.PASS,
                                     f"{intf}: max MAC {m.group(1)} <= {max_mac}",
                                     interface=intf))
                        elif m:
                            f.append(Finding("port_security_max", Status.FAIL,
                                     f"{intf}: max MAC {m.group(1)} > {max_mac}",
                                     interface=intf,
                                     remediation=f"switchport port-security maximum {max_mac}"))
                # Check violation action
                violation = ps_node.get("violation")
                if violation:
                    if pi_has(pi, rf"port-security violation\s+{re.escape(violation)}"):
                        f.append(Finding("port_security_violation", Status.PASS,
                                 f"{intf}: violation mode {violation}", interface=intf))
                    else:
                        f.append(Finding("port_security_violation", Status.FAIL,
                                 f"{intf}: violation mode not '{violation}'",
                                 interface=intf,
                                 remediation=f"switchport port-security violation {violation}"))
            else:
                f.append(Finding("port_security", Status.FAIL,
                         f"{intf}: port-security not enabled", interface=intf,
                         remediation="switchport port-security"))

        # No CDP on access ports
        if _enabled(dp, "no_cdp_on_access_ports"):
            if pi_has(pi, r"no cdp enable"):
                f.append(Finding("no_cdp_on_access", Status.PASS,
                         f"{intf}: CDP disabled on access port", interface=intf))
            else:
                f.append(Finding("no_cdp_on_access", Status.FAIL,
                         f"{intf}: CDP still enabled on access port",
                         interface=intf, remediation="no cdp enable"))

        # DHCP snooping limit rate on access ports
        if _enabled(dp, "dhcp_snooping_limit_rate"):
            rate = dp.get("dhcp_snooping_limit_rate", {}).get("rate", 15)
            if pi_has(pi, r"ip dhcp snooping limit rate"):
                f.append(Finding("dhcp_snooping_limit_rate", Status.PASS,
                         f"{intf}: DHCP snooping rate limit set", interface=intf))
            else:
                f.append(Finding("dhcp_snooping_limit_rate", Status.FAIL,
                         f"{intf}: DHCP snooping rate limit missing",
                         interface=intf,
                         remediation=f"ip dhcp snooping limit rate {rate}"))

        # IP Source Guard on access ports
        if _enabled(dp, "ip_source_guard"):
            # Match "ip verify source" but not "no ip verify source"
            if pi_has(pi, r"^\s*ip verify source") and not pi_has(pi, r"^\s*no ip verify source"):
                f.append(Finding("ip_source_guard", Status.PASS,
                         f"{intf}: IP source guard enabled", interface=intf))
            else:
                f.append(Finding("ip_source_guard", Status.FAIL,
                         f"{intf}: IP source guard not enabled",
                         interface=intf,
                         remediation="ip verify source"))

        return f

    # ── ENDPOINT TRUNK PORT CHECKS (APs etc.) ─────────────────
    def _check_endpoint_trunk_port(self, cfg: ParsedConfig, dp: dict,
                                   pi: PortInfo) -> list[Finding]:
        """
        Checks for trunk ports connected to endpoints (wireless APs, etc.).

        These are trunks that terminate at a non-switch device.  They should
        be treated more like access ports for STP purposes:
        - BPDU guard: YES  (endpoint should never send BPDUs)
        - Root guard: NO   (not a switch, cannot become root)
        - Portfast:   YES  (endpoint, fast convergence desired)
        - Storm control, description, VLAN pruning: same as trunks
        """
        f: list[Finding] = []
        intf = pi.name
        neighbor_desc = f"endpoint trunk to {pi.cdp_neighbor}" if pi.cdp_neighbor else "endpoint trunk"

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # BPDU guard — recommended on endpoint trunks (like access ports)
        if _enabled(dp, "bpdu_guard"):
            bpdu_node = dp.get("bpdu_guard", {})
            if bpdu_node.get("on_endpoint_trunks", True):
                if pi_has(pi, r"spanning-tree bpduguard enable"):
                    f.append(Finding("bpdu_guard", Status.PASS,
                             f"{intf}: BPDU guard enabled ({neighbor_desc})",
                             interface=intf))
                else:
                    f.append(Finding("bpdu_guard", Status.FAIL,
                             f"{intf}: BPDU guard missing ({neighbor_desc})",
                             interface=intf,
                             remediation="spanning-tree bpduguard enable"))

        # Root guard — should NOT be on endpoint trunks
        if _enabled(dp, "root_guard"):
            if pi_has(pi, r"spanning-tree guard root"):
                f.append(Finding("root_guard", Status.FAIL,
                         f"{intf}: root guard on endpoint trunk — not needed",
                         interface=intf,
                         remediation="no spanning-tree guard root"))
            else:
                f.append(Finding("root_guard", Status.PASS,
                         f"{intf}: no root guard on endpoint trunk (correct)",
                         interface=intf))

        # Portfast trunk — recommended for endpoint trunks
        if _enabled(dp, "portfast"):
            if pi_has(pi, r"spanning-tree portfast trunk"):
                f.append(Finding("portfast", Status.PASS,
                         f"{intf}: portfast trunk enabled ({neighbor_desc})",
                         interface=intf))
            else:
                f.append(Finding("portfast", Status.FAIL,
                         f"{intf}: portfast trunk missing ({neighbor_desc})",
                         interface=intf,
                         remediation="spanning-tree portfast trunk"))

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(Finding("switchport_nonegotiate", Status.PASS,
                         f"{intf}: nonegotiate ({neighbor_desc})", interface=intf))
            else:
                f.append(Finding("switchport_nonegotiate", Status.FAIL,
                         f"{intf}: nonegotiate missing ({neighbor_desc})",
                         interface=intf,
                         remediation="switchport nonegotiate"))

        # Trunk allowed VLANs
        if _enabled(dp, "trunk_allowed_vlans"):
            if pi.trunk_allowed_vlans and pi.trunk_allowed_vlans.lower() != "all":
                f.append(Finding("trunk_allowed_vlans", Status.PASS,
                         f"{intf}: trunk VLANs pruned ({neighbor_desc})",
                         interface=intf))
            else:
                f.append(Finding("trunk_allowed_vlans", Status.FAIL,
                         f"{intf}: trunk allows ALL VLANs ({neighbor_desc})",
                         interface=intf,
                         remediation="switchport trunk allowed vlan <list>"))

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(Finding("interface_description", Status.PASS,
                         f"{intf}: description present ({neighbor_desc})",
                         interface=intf))
            else:
                f.append(Finding("interface_description", Status.FAIL,
                         f"{intf}: no description ({neighbor_desc})",
                         interface=intf, remediation="description <text>"))

        # DHCP snooping trust — configurable for endpoint trunks
        if _enabled(dp, "dhcp_snooping_trust"):
            trust_node = dp.get("dhcp_snooping_trust", {})
            if trust_node.get("on_endpoint_trunks", False):
                has_trust = pi_has(pi, r"ip dhcp snooping trust")
                if has_trust:
                    f.append(Finding("dhcp_snooping_trust", Status.PASS,
                             f"{intf}: DHCP snooping trust ({neighbor_desc})",
                             interface=intf))
                else:
                    f.append(Finding("dhcp_snooping_trust", Status.FAIL,
                             f"{intf}: DHCP snooping trust missing ({neighbor_desc})",
                             interface=intf,
                             remediation="ip dhcp snooping trust"))

        # ARP inspection trust — configurable for endpoint trunks
        if _enabled(dp, "arp_inspection_trust"):
            trust_node = dp.get("arp_inspection_trust", {})
            if trust_node.get("on_endpoint_trunks", False):
                has_trust = pi_has(pi, r"ip arp inspection trust")
                if has_trust:
                    f.append(Finding("arp_inspection_trust", Status.PASS,
                             f"{intf}: DAI trust ({neighbor_desc})",
                             interface=intf))
                else:
                    f.append(Finding("arp_inspection_trust", Status.FAIL,
                             f"{intf}: DAI trust missing ({neighbor_desc})",
                             interface=intf,
                             remediation="ip arp inspection trust"))

        return f

    # ── TRUNK PORT CHECKS ─────────────────────────────────────
    def _check_trunk_port(self, cfg: ParsedConfig, dp: dict,
                          pi: PortInfo) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name
        is_uplink = pi.role == PortRole.TRUNK_UPLINK
        is_downlink = pi.role == PortRole.TRUNK_DOWNLINK
        direction = ("uplink" if is_uplink
                     else "downlink" if is_downlink
                     else "unknown-direction trunk")

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # Root guard — only on downlinks, never on uplinks
        if _enabled(dp, "root_guard"):
            if is_downlink:
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(Finding("root_guard", Status.PASS,
                             f"{intf}: root guard on downlink",
                             interface=intf))
                else:
                    f.append(Finding("root_guard", Status.FAIL,
                             f"{intf}: root guard missing (downlink)",
                             interface=intf,
                             remediation="spanning-tree guard root"))
            elif is_uplink:
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(Finding("root_guard", Status.FAIL,
                             f"{intf}: root guard on UPLINK — must be removed!",
                             interface=intf,
                             remediation="no spanning-tree guard root"))
                else:
                    f.append(Finding("root_guard", Status.PASS,
                             f"{intf}: no root guard on uplink (correct)",
                             interface=intf))
            else:
                # TRUNK_UNKNOWN
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(Finding("root_guard", Status.WARN,
                             f"{intf}: root guard present but direction unknown — verify manually",
                             interface=intf))
                else:
                    f.append(Finding("root_guard", Status.WARN,
                             f"{intf}: no root guard — direction unknown, verify manually",
                             interface=intf))

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(Finding("switchport_nonegotiate", Status.PASS,
                         f"{intf}: nonegotiate ({direction})", interface=intf))
            else:
                f.append(Finding("switchport_nonegotiate", Status.FAIL,
                         f"{intf}: nonegotiate missing ({direction})",
                         interface=intf,
                         remediation="switchport nonegotiate"))

        # Trunk allowed VLANs — should not be "all"
        if _enabled(dp, "trunk_allowed_vlans"):
            if pi.trunk_allowed_vlans and pi.trunk_allowed_vlans.lower() != "all":
                f.append(Finding("trunk_allowed_vlans", Status.PASS,
                         f"{intf}: trunk allowed vlans pruned ({direction})",
                         interface=intf))
            else:
                f.append(Finding("trunk_allowed_vlans", Status.FAIL,
                         f"{intf}: trunk allows ALL VLANs ({direction})",
                         interface=intf,
                         remediation="switchport trunk allowed vlan <list>"))

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(Finding("interface_description", Status.PASS,
                         f"{intf}: description present ({direction})",
                         interface=intf))
            else:
                f.append(Finding("interface_description", Status.FAIL,
                         f"{intf}: no description ({direction})",
                         interface=intf, remediation="description <text>"))

        # DHCP snooping trust
        if _enabled(dp, "dhcp_snooping_trust"):
            trust_node = dp.get("dhcp_snooping_trust", {})
            want_trust = (
                (is_uplink and trust_node.get("on_uplinks", True)) or
                (is_downlink and trust_node.get("on_downlinks", True))
            )
            has_trust = pi_has(pi, r"ip dhcp snooping trust")
            if want_trust:
                if has_trust:
                    f.append(Finding("dhcp_snooping_trust", Status.PASS,
                             f"{intf}: DHCP snooping trust ({direction})",
                             interface=intf))
                else:
                    f.append(Finding("dhcp_snooping_trust", Status.FAIL,
                             f"{intf}: DHCP snooping trust missing ({direction})",
                             interface=intf,
                             remediation="ip dhcp snooping trust"))

        # ARP inspection trust
        if _enabled(dp, "arp_inspection_trust"):
            trust_node = dp.get("arp_inspection_trust", {})
            want_trust = (
                (is_uplink and trust_node.get("on_uplinks", True)) or
                (is_downlink and trust_node.get("on_downlinks", True))
            )
            has_trust = pi_has(pi, r"ip arp inspection trust")
            if want_trust:
                if has_trust:
                    f.append(Finding("arp_inspection_trust", Status.PASS,
                             f"{intf}: DAI trust ({direction})",
                             interface=intf))
                else:
                    f.append(Finding("arp_inspection_trust", Status.FAIL,
                             f"{intf}: DAI trust missing ({direction})",
                             interface=intf,
                             remediation="ip arp inspection trust"))

        # Trunk native VLAN
        if _enabled(dp, "trunk_native_vlan"):
            expected_native = dp.get("trunk_native_vlan", {}).get("expected_vlan", 99)
            # Check from Genie switchport data
            native_vlan = None
            data = getattr(self, '_current_data', None)
            if data and data.switchports:
                sw_data = data.switchports.get(intf) or data.switchports.get(pi.name)
                if isinstance(sw_data, dict):
                    native_vlan = sw_data.get("native_vlan")
            # Fallback to running-config
            if native_vlan is None:
                for line in pi.config_lines:
                    m = re.search(r"switchport trunk native vlan\s+(\d+)", line, re.I)
                    if m:
                        native_vlan = int(m.group(1))
                        break
            if native_vlan is not None:
                if native_vlan == expected_native:
                    f.append(Finding("trunk_native_vlan", Status.PASS,
                             f"{intf}: native VLAN {native_vlan} ({direction})",
                             interface=intf))
                else:
                    f.append(Finding("trunk_native_vlan", Status.FAIL,
                             f"{intf}: native VLAN {native_vlan}, expected {expected_native} ({direction})",
                             interface=intf,
                             remediation=f"switchport trunk native vlan {expected_native}"))
            else:
                f.append(Finding("trunk_native_vlan", Status.WARN,
                         f"{intf}: native VLAN not determined ({direction})",
                         interface=intf,
                         remediation=f"switchport trunk native vlan {expected_native}"))

        return f

    # ── ROUTED PORT CHECKS ────────────────────────────────────
    def _check_routed_port(self, cfg: ParsedConfig, dp: dict,
                           pi: PortInfo) -> list[Finding]:
        """Checks for L3 (routed) interfaces and SVIs."""
        f: list[Finding] = []
        intf = pi.name

        # no ip proxy-arp
        if _enabled(dp, "no_ip_proxy_arp"):
            if pi_has(pi, r"no ip proxy-arp"):
                f.append(Finding("no_ip_proxy_arp", Status.PASS,
                         f"{intf}: ip proxy-arp disabled", interface=intf))
            else:
                f.append(Finding("no_ip_proxy_arp", Status.FAIL,
                         f"{intf}: ip proxy-arp not disabled",
                         interface=intf,
                         remediation="no ip proxy-arp"))

        return f

    # ── UNUSED PORT CHECKS ────────────────────────────────────
    def _check_unused_port(self, cfg: ParsedConfig, dp: dict,
                           pi: PortInfo) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name
        if not _enabled(dp, "unused_ports"):
            return f
        node = dp.get("unused_ports", {})

        if node.get("must_be_shutdown", True) and not pi.admin_down:
            f.append(Finding("unused_shutdown", Status.FAIL,
                     f"{intf}: unused port not shut down",
                     interface=intf, remediation="shutdown"))

        if node.get("must_be_access_mode", True):
            if pi.switchport_mode != "access":
                f.append(Finding("unused_access_mode", Status.FAIL,
                         f"{intf}: unused port not in access mode",
                         interface=intf, remediation="switchport mode access"))

        parking = self.policy.get("_audit_settings", {}).get("parking_vlan", 999)
        if node.get("must_be_in_parking_vlan", True):
            if pi.access_vlan != parking:
                f.append(Finding("unused_parking_vlan", Status.FAIL,
                         f"{intf}: unused port not in parking VLAN {parking} (is {pi.access_vlan})",
                         interface=intf,
                         remediation=f"switchport access vlan {parking}"))

        if node.get("must_have_nonegotiate", True):
            if not pi_has(pi, r"switchport nonegotiate"):
                f.append(Finding("unused_nonegotiate", Status.FAIL,
                         f"{intf}: unused port missing nonegotiate",
                         interface=intf, remediation="switchport nonegotiate"))

        if node.get("must_have_bpduguard", True):
            if not pi_has(pi, r"spanning-tree bpduguard enable"):
                f.append(Finding("unused_bpduguard", Status.FAIL,
                         f"{intf}: unused port missing BPDU guard",
                         interface=intf, remediation="spanning-tree bpduguard enable"))

        if node.get("must_have_no_cdp", True):
            if not pi_has(pi, r"no cdp enable"):
                f.append(Finding("unused_no_cdp", Status.FAIL,
                         f"{intf}: unused port has CDP enabled",
                         interface=intf, remediation="no cdp enable"))

        if node.get("must_have_no_lldp", True):
            has_no_tx = pi_has(pi, r"no lldp transmit")
            has_no_rx = pi_has(pi, r"no lldp receive")
            if not (has_no_tx and has_no_rx):
                f.append(Finding("unused_no_lldp", Status.FAIL,
                         f"{intf}: unused port has LLDP enabled",
                         interface=intf,
                         remediation="no lldp transmit / no lldp receive"))

        if node.get("must_have_description", True):
            exp_desc = node.get("expected_description", "UNUSED")
            if exp_desc.lower() in pi.description.lower():
                f.append(Finding("unused_description", Status.PASS,
                         f"{intf}: description contains '{exp_desc}'",
                         interface=intf))
            else:
                f.append(Finding("unused_description", Status.FAIL,
                         f"{intf}: description missing or wrong (expected '{exp_desc}')",
                         interface=intf,
                         remediation=f'description {exp_desc}'))

        return f

    # ── STORM CONTROL (speed-aware) ───────────────────────────
    def _check_storm_control(self, dp: dict, pi: PortInfo) -> list[Finding]:
        """Check storm-control levels against speed-based thresholds (rising and falling)."""
        f: list[Finding] = []
        if not _enabled(dp, "storm_control"):
            return f

        node = dp.get("storm_control", {})
        intf = pi.name
        speed = pi.speed_mbps or 1000  # default to 1G if unknown

        # Check if threshold validation is enabled (defaults to true for backward compatibility)
        check_thresholds = node.get("check_thresholds", True)

        # Pick threshold tier
        thresholds = node.get("thresholds_by_speed", {})
        tier = thresholds.get(speed) or thresholds.get(str(speed))
        if tier is None:
            # Find the nearest tier
            for spd in sorted(thresholds.keys(), key=lambda x: int(x), reverse=True):
                if speed >= int(spd):
                    tier = thresholds[spd]
                    break
        if tier is None:
            tier = node.get("default_thresholds", {})

        # Only check thresholds if enabled
        if check_thresholds:
            for sc_type in node.get("types", ["broadcast", "multicast"]):
                expected = tier.get(sc_type)
                if expected is None:
                    continue

                # Support both old format (single value) and new format (rising/falling)
                if isinstance(expected, dict):
                    expected_rising = expected.get("rising")
                    expected_falling = expected.get("falling")
                else:
                    # Backward compatibility: if it's a single number, use it for both
                    expected_rising = expected
                    expected_falling = None

                # Look in interface config for matching storm-control line
                # Pattern captures both rising and optional falling threshold
                pattern = rf"storm-control\s+{re.escape(sc_type)}\s+level\s+([\d.]+)(?:\s+([\d.]+))?"
                match = None
                for line in pi.config_lines:
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        match = m
                        break

                if match:
                    actual_rising = float(match.group(1))
                    actual_falling = float(match.group(2)) if match.group(2) else None

                    # Check rising threshold
                    rising_ok = actual_rising <= expected_rising
                    # Check falling threshold if both expected and actual are present
                    falling_ok = True
                    if expected_falling is not None and actual_falling is not None:
                        falling_ok = actual_falling <= expected_falling
                    elif expected_falling is not None and actual_falling is None:
                        # Expected falling but not configured
                        falling_ok = False

                    if rising_ok and falling_ok:
                        if actual_falling is not None and expected_falling is not None:
                            f.append(Finding("storm_control", Status.PASS,
                                     f"{intf}: {sc_type} storm-control {actual_rising}%/{actual_falling}% "
                                     f"<= {expected_rising}%/{expected_falling}% ({speed}Mbps tier)",
                                     interface=intf))
                        else:
                            f.append(Finding("storm_control", Status.PASS,
                                     f"{intf}: {sc_type} storm-control {actual_rising}% <= {expected_rising}% "
                                     f"({speed}Mbps tier)",
                                     interface=intf))
                    else:
                        # Build failure message based on what failed
                        if not rising_ok and not falling_ok:
                            fail_msg = (f"{intf}: {sc_type} storm-control {actual_rising}%/{actual_falling or 'N/A'}% "
                                       f"> {expected_rising}%/{expected_falling}% ({speed}Mbps tier)")
                        elif not rising_ok:
                            fail_msg = (f"{intf}: {sc_type} storm-control rising {actual_rising}% "
                                       f"> {expected_rising}% ({speed}Mbps tier)")
                        else:
                            if actual_falling is None:
                                fail_msg = (f"{intf}: {sc_type} storm-control falling threshold not configured "
                                           f"(expected {expected_falling}%, {speed}Mbps tier)")
                            else:
                                fail_msg = (f"{intf}: {sc_type} storm-control falling {actual_falling}% "
                                           f"> {expected_falling}% ({speed}Mbps tier)")

                        remediation_cmd = f"storm-control {sc_type} level {expected_rising}"
                        if expected_falling is not None:
                            remediation_cmd += f" {expected_falling}"

                        f.append(Finding("storm_control", Status.FAIL, fail_msg,
                                       interface=intf, remediation=remediation_cmd))
                else:
                    # Not configured at all
                    remediation_cmd = f"storm-control {sc_type} level {expected_rising}"
                    if expected_falling is not None:
                        remediation_cmd += f" {expected_falling}"

                    f.append(Finding("storm_control", Status.FAIL,
                             f"{intf}: {sc_type} storm-control not configured ({speed}Mbps tier)",
                             interface=intf,
                             remediation=remediation_cmd))

        # Storm-control action - only check if enabled (defaults to true for backward compatibility)
        check_action = node.get("check_action", True)
        if check_action:
            expected_action = node.get("action", "shutdown")
            if expected_action:
                if pi_has(pi, rf"storm-control action\s+{re.escape(expected_action)}"):
                    f.append(Finding("storm_control_action", Status.PASS,
                             f"{intf}: storm-control action {expected_action}",
                             interface=intf))
                else:
                    f.append(Finding("storm_control_action", Status.FAIL,
                             f"{intf}: storm-control action not '{expected_action}'",
                             interface=intf,
                             remediation=f"storm-control action {expected_action}"))

        return f

    # ===================================================================
    #                     ROLE-SPECIFIC  CHECKS
    # ===================================================================

    def _check_role_specific(self, cfg: ParsedConfig, data: DeviceData,
                             host: HostnameInfo,
                             ports: dict[str, PortInfo]) -> list[Finding]:
        f: list[Finding] = []
        rs = self.policy.get("role_specific", {})

        if host.is_core:
            f.extend(self._check_core_role(cfg, data, host, ports, rs))
        elif host.is_access:
            f.extend(self._check_access_role(cfg, data, host, ports, rs))

        return f

    def _check_core_role(self, cfg, data, host, ports, rs) -> list[Finding]:
        f: list[Finding] = []
        core_pol = rs.get("core_switch", {})

        if _enabled(core_pol, "stp_root_check") and data.stp:
            root_vlans = []
            non_root_vlans = []
            for mode_data in data.stp.values():
                if not isinstance(mode_data, dict):
                    continue
                for vid, vinfo in mode_data.get("vlans", {}).items():
                    root = vinfo.get("root", {})
                    bridge = vinfo.get("bridge", {})
                    if root.get("address") and bridge.get("address"):
                        if root["address"] == bridge["address"]:
                            root_vlans.append(vid)
                        else:
                            non_root_vlans.append(vid)

            # Report each VLAN where this core switch IS the root (PASS)
            for vid in root_vlans:
                f.append(Finding("core_stp_root", Status.PASS,
                         f"Core switch IS the STP root bridge for VLAN {vid}", "role_specific"))

            # Report each VLAN where this core switch is NOT the root (WARN)
            for vid in non_root_vlans:
                f.append(Finding("core_stp_root", Status.WARN,
                         f"Core switch is NOT the STP root bridge for VLAN {vid} — verify",
                         "role_specific"))

        return f

    def _check_access_role(self, cfg, data, host, ports, rs) -> list[Finding]:
        f: list[Finding] = []
        asw_pol = rs.get("access_switch", {})

        if _enabled(asw_pol, "stp_not_root") and data.stp:
            root_vlans = []
            for mode_data in data.stp.values():
                if not isinstance(mode_data, dict):
                    continue
                for vid, vinfo in mode_data.get("vlans", {}).items():
                    root = vinfo.get("root", {})
                    bridge = vinfo.get("bridge", {})
                    if (root.get("address") and bridge.get("address") and
                            root["address"] == bridge["address"]):
                        root_vlans.append(vid)

            if root_vlans:
                # Create a finding for each VLAN where this switch is root
                for vid in root_vlans:
                    f.append(Finding("asw_not_root", Status.FAIL,
                             f"Access switch IS the STP root for VLAN {vid} — this should be the core!",
                             "role_specific"))
            else:
                f.append(Finding("asw_not_root", Status.PASS,
                         "Access switch is not STP root (correct)", "role_specific"))

        if _enabled(asw_pol, "uplink_redundancy"):
            po_uplinks = [p for p in ports.values()
                          if p.role == PortRole.TRUNK_UPLINK
                          and p.name.startswith("Port-channel")]
            if po_uplinks:
                f.append(Finding("uplink_redundancy", Status.PASS,
                         "Uplink uses port-channel", "role_specific"))
            else:
                f.append(Finding("uplink_redundancy", Status.WARN,
                         "No port-channel uplink detected", "role_specific"))

        return f

    # ===================================================================
    #                         LOW-LEVEL HELPERS
    # ===================================================================

    def _present(self, cfg: ParsedConfig, pattern: str, name: str,
                 description: str, remediation: str) -> Finding:
        """PASS if *pattern* is found in global config; FAIL otherwise."""
        if cfg.has_line(pattern):
            return Finding(name, Status.PASS, description)
        return Finding(name, Status.FAIL, f"Missing: {description}",
                       remediation=remediation)

    def _absent(self, cfg: ParsedConfig, pattern: str, name: str,
                bad_description: str, remediation: str) -> Finding:
        """PASS if *pattern* is NOT found in global config; FAIL otherwise."""
        if cfg.has_line(pattern):
            return Finding(name, Status.FAIL, f"Found: {bad_description}",
                           remediation=remediation)
        return Finding(name, Status.PASS, f"Absent: {bad_description} (good)")


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def pi_has(pi: PortInfo, pattern: str) -> bool:
    """Check if any of *pi*'s config lines match *pattern*."""
    rx = re.compile(pattern, re.IGNORECASE)
    return any(rx.search(line) for line in pi.config_lines)
