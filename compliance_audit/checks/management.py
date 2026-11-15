"""
Management-plane checks: services, IP settings, SSH, AAA, NTP, logging,
SNMP, banners, users, VTY and console lines, login security, CDP/LLDP.
"""

import re
import logging

from ..collector import DeviceData, ParsedConfig
from ..hostname_parser import HostnameInfo
from .base import (
    SYSLOG_LEVELS,
    Finding,
    Status,
    _command_args,
    _configured_hosts,
    _enabled,
    _host_key,
    _same_interface,
    _setting,
    _snmp_community_has_acl,
    _syslog_level,
)

log = logging.getLogger(__name__)

#: Severity IOS uses when the running-config shows the command without a level.
_DEFAULT_LOG_LEVEL = {
    "logging console": 7,
    "logging monitor": 7,
    "logging trap": 6,
}


def _expand_level(prefix: str, level: int) -> str:
    """Expected AAA ``commands`` line for one privilege *level*.

    ``{level}`` in *prefix* is substituted; a prefix written for one level
    (``... commands 15 default ...``) has that number replaced instead, so a
    ``levels: [1, 15]`` list really checks both levels.
    """
    if "{level}" in prefix:
        return prefix.replace("{level}", str(level))
    return re.sub(r"(\bcommands\s+)\d+", rf"\g<1>{level}", prefix, count=1)


class ManagementPlaneChecks:
    """Checks for the management_plane policy section."""

    # ── shared finding builders ──────────────────────────────
    def _source_interface_finding(
        self, cfg: ParsedConfig, command: str, name: str, intf: str
    ) -> Finding:
        """PASS when *command* names *intf* (any interface if *intf* is blank).

        Interface names are compared whole, with abbreviations expanded, so
        ``Vlan1`` does not match ``Vlan10``.
        """
        configured = [args[0] for args in _command_args(cfg, command) if args]
        if intf:
            if any(_same_interface(c, intf) for c in configured):
                return Finding(name, Status.PASS, f"{command} {intf}")
            found = f" (found: {command} {configured[0]})" if configured else ""
            return Finding(
                name, Status.FAIL, f"Missing: {command} {intf}{found}",
                remediation=f"{command} {intf}",
            )
        if configured:
            return Finding(name, Status.PASS, f"{command} {configured[0]}")
        return Finding(
            name, Status.FAIL, f"Missing: {command}",
            remediation=f"{command} <interface>",
        )

    def _logging_level_finding(
        self, cfg: ParsedConfig, command: str, name: str, want, *, most_verbose: bool
    ) -> Finding:
        """Compare the severity level configured by *command* with *want*.

        ``most_verbose=True`` treats *want* as a ceiling (console/monitor:
        nothing chattier is allowed); otherwise it is a floor (trap: at least
        this much must reach the syslog servers).
        """
        want_n = _syslog_level(want)
        want_kw = SYSLOG_LEVELS[want_n]
        if most_verbose and cfg.has_line(rf"^no {re.escape(command)}$"):
            return Finding(name, Status.PASS, f"{command} disabled")
        lines = _command_args(cfg, command)
        if not lines:
            return Finding(
                name, Status.FAIL, f"Missing: {command} {want_kw}",
                remediation=f"{command} {want_kw}",
            )
        levels = [_syslog_level(a) for a in lines[-1]]
        levels = [lvl for lvl in levels if lvl is not None]
        # IOS omits the level from the running-config when it is the default.
        actual = levels[0] if levels else _DEFAULT_LOG_LEVEL[command]
        ok = actual <= want_n if most_verbose else actual >= want_n
        bound = "or less verbose" if most_verbose else "or more verbose"
        detail = f"{command} {SYSLOG_LEVELS[actual]} (policy: {want_kw} {bound})"
        if ok:
            return Finding(name, Status.PASS, detail)
        return Finding(name, Status.FAIL, detail, remediation=f"{command} {want_kw}")

    def _logging_buffered_finding(self, cfg: ParsedConfig, mp: dict) -> Finding:
        want = _syslog_level(_setting(mp, "logging_buffered", "level"))
        min_size = _setting(mp, "logging_buffered", "min_size")
        remediation = f"logging buffered {max(min_size, 4096)} {SYSLOG_LEVELS[want]}"
        lines = _command_args(cfg, "logging buffered")
        if not lines:
            return Finding(
                "logging_buffered", Status.FAIL, "Missing: logging buffered",
                remediation=remediation,
            )
        args = lines[-1]
        sizes = [int(a) for a in args if a.isdigit() and int(a) > 7]
        levels = [lvl for lvl in (_syslog_level(a) for a in args if not (a.isdigit() and int(a) > 7)) if lvl is not None]
        # Defaults when the running-config omits them: 4096 bytes, debugging.
        size = sizes[0] if sizes else 4096
        level = levels[0] if levels else 7
        problems = []
        if size < min_size:
            problems.append(f"size {size} < {min_size} bytes")
        if level < want:
            problems.append(
                f"level {SYSLOG_LEVELS[level]} drops messages below {SYSLOG_LEVELS[want]}"
            )
        detail = f"logging buffered {size} {SYSLOG_LEVELS[level]}"
        if problems:
            return Finding(
                "logging_buffered", Status.FAIL, f"{detail}: " + "; ".join(problems),
                remediation=remediation,
            )
        return Finding("logging_buffered", Status.PASS, detail)

    def _logging_origin_id_finding(self, cfg: ParsedConfig, mp: dict) -> Finding:
        want_type = _setting(mp, "logging_origin_id", "type")
        want_text = _setting(mp, "logging_origin_id", "string").strip()
        want = f"logging origin-id {want_type}" + (
            f" {want_text}" if want_type == "string" else ""
        )
        lines = _command_args(cfg, "logging origin-id")
        if not lines or not lines[-1]:
            return Finding(
                "logging_origin_id", Status.FAIL, f"Missing: {want}", remediation=want
            )
        args = lines[-1]
        ok = args[0].lower() == want_type
        if ok and want_type == "string":
            ok = " ".join(args[1:]).strip('"') == want_text
        actual = "logging origin-id " + " ".join(args)
        if ok:
            return Finding("logging_origin_id", Status.PASS, actual)
        return Finding(
            "logging_origin_id", Status.FAIL, f"{actual} (expected: {want})",
            remediation=want,
        )

    def _clock_timezone_finding(self, cfg: ParsedConfig, mp: dict, tz: str) -> Finding:
        offset = _setting(mp, "clock_timezone", "offset")
        offset_min = _setting(mp, "clock_timezone", "offset_minutes")
        want = f"clock timezone {tz} {offset if offset is not None else 0}" + (
            f" {offset_min}" if offset_min else ""
        )
        found = ""
        for args in _command_args(cfg, "clock timezone"):
            if not args:
                continue
            found = "clock timezone " + " ".join(args)
            if args[0].lower() != tz.lower():
                continue
            if offset is not None:
                hours = int(args[1]) if len(args) > 1 and args[1].lstrip("-").isdigit() else 0
                minutes = int(args[2]) if len(args) > 2 and args[2].isdigit() else 0
                if (hours, minutes) != (offset, offset_min):
                    continue
            return Finding("clock_timezone", Status.PASS, found)
        detail = f"Missing: {want}" + (f" (found: {found})" if found else "")
        return Finding("clock_timezone", Status.FAIL, detail, remediation=want)

    def _login_authentication_finding(
        self, cfg: ParsedConfig, lines: list[str], label: str, name: str, method: str
    ) -> Finding:
        """The line must use *method*.  ``default`` also matches no explicit list,
        because the default method list applies implicitly under AAA."""
        lists = [
            m.group(1)
            for line in lines
            if (m := re.match(r"login authentication\s+(\S+)", line, re.I))
        ]
        if method in lists:
            return Finding(name, Status.PASS, f"{label}: login authentication {method}", interface=label)
        if (
            method == "default"
            and not lists
            and cfg.has_line(r"^aaa new-model")
            and cfg.has_line(r"^aaa authentication login default\s")
        ):
            return Finding(
                name, Status.PASS,
                f"{label}: uses the default login method list",
                interface=label,
            )
        detail = (
            f"{label}: login authentication {lists[0]} (expected: {method})"
            if lists else f"{label}: login authentication {method} not in effect"
        )
        return Finding(
            name, Status.FAIL, detail, interface=label,
            remediation=f"login authentication {method}",
        )

    def _login_block_for_finding(self, cfg: ParsedConfig, mp: dict) -> Finding:
        secs = _setting(mp, "login_block_for", "seconds")
        att = _setting(mp, "login_block_for", "attempts")
        within = _setting(mp, "login_block_for", "within")
        want = f"login block-for {secs} attempts {att} within {within}"
        line = next(iter(cfg.find_lines(r"^login block-for\s+\d+")), "")
        m = re.match(r"login block-for\s+(\d+)\s+attempts\s+(\d+)\s+within\s+(\d+)", line)
        if not m:
            return Finding("login_block_for", Status.FAIL, f"Missing: {want}", remediation=want)
        a_secs, a_att, a_within = (int(g) for g in m.groups())
        problems = []
        if a_secs < secs:
            problems.append(f"blocks for {a_secs}s < {secs}s")
        if a_att > att:
            problems.append(f"allows {a_att} attempts > {att}")
        if a_within < within:
            problems.append(f"window {a_within}s < {within}s")
        if problems:
            return Finding(
                "login_block_for", Status.FAIL, f"{line}: " + "; ".join(problems),
                remediation=want,
            )
        return Finding("login_block_for", Status.PASS, line)

    # ===================================================================
    #                    MANAGEMENT  PLANE  CHECKS
    # ===================================================================

    # ── SERVICES ──────────────────────────────────────────────
    def _check_services(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        # service password-encryption
        if _enabled(mp, "service_password_encryption"):
            f.append(
                self._present(
                    cfg,
                    r"^service password-encryption",
                    "service_password_encryption",
                    "service password-encryption",
                    "service password-encryption",
                )
            )

        # service timestamps debug
        if _enabled(mp, "service_timestamps_debug"):
            exp = _setting(mp, "service_timestamps_debug", "expected")
            f.append(
                self._present(cfg, re.escape(exp), "service_timestamps_debug", exp, exp)
            )

        # service timestamps log
        if _enabled(mp, "service_timestamps_log"):
            exp = _setting(mp, "service_timestamps_log", "expected")
            f.append(
                self._present(cfg, re.escape(exp), "service_timestamps_log", exp, exp)
            )

        # tcp-keepalives
        if _enabled(mp, "service_tcp_keepalives_in"):
            f.append(
                self._present(
                    cfg,
                    r"^service tcp-keepalives-in",
                    "service_tcp_keepalives_in",
                    "service tcp-keepalives-in",
                    "service tcp-keepalives-in",
                )
            )
        if _enabled(mp, "service_tcp_keepalives_out"):
            f.append(
                self._present(
                    cfg,
                    r"^service tcp-keepalives-out",
                    "service_tcp_keepalives_out",
                    "service tcp-keepalives-out",
                    "service tcp-keepalives-out",
                )
            )

        # no service pad
        if _enabled(mp, "no_service_pad"):
            f.append(
                self._absent(
                    cfg,
                    r"^service pad$",
                    "no_service_pad",
                    "service pad",
                    "no service pad",
                )
            )

        # no service config
        if _enabled(mp, "no_service_config"):
            f.append(
                self._absent(
                    cfg,
                    r"^service config$",
                    "no_service_config",
                    "service config",
                    "no service config",
                )
            )

        # Legacy diagnostic services (echo/discard/chargen/daytime, finger).
        # Off by default on IOS-XE, so they only appear in the running-config
        # when someone has turned them on.
        for name, command in (
            ("no_service_finger", "service finger"),
            ("no_service_tcp_small_servers", "service tcp-small-servers"),
            ("no_service_udp_small_servers", "service udp-small-servers"),
        ):
            if _enabled(mp, name):
                f.append(
                    self._absent(
                        cfg, rf"^{re.escape(command)}(?:\s|$)", name, command, f"no {command}"
                    )
                )

        return f

    # ── IP SETTINGS ───────────────────────────────────────────
    def _check_ip_settings(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        simple_present = [
            ("ip_cef", r"^ip cef", "ip cef", "ip cef"),
        ]
        simple_absent = [
            (
                "no_ip_finger",
                r"^ip finger(?:\s|$)",
                "ip finger",
                "no ip finger",
            ),
            (
                "no_ip_source_route",
                r"^ip source-route",
                "ip source-route",
                "no ip source-route",
            ),
            (
                "no_ip_bootp_server",
                r"^ip bootp server",
                "ip bootp server",
                "no ip bootp server",
            ),
            (
                "no_ip_http_server",
                r"^ip http server$",
                "ip http server",
                "no ip http server",
            ),
            (
                "no_ip_http_secure_server",
                r"^ip http secure-server",
                "ip http secure-server",
                "no ip http secure-server",
            ),
            (
                "no_ip_gratuitous_arps",
                r"^ip gratuitous-arps",
                "ip gratuitous-arps",
                "no ip gratuitous-arps",
            ),
            (
                "no_ip_domain_lookup",
                r"^ip domain-lookup",
                "ip domain-lookup",
                "no ip domain-lookup",
            ),
        ]
        for name, pattern, desc, remed in simple_present:
            if _enabled(mp, name):
                f.append(self._present(cfg, pattern, name, desc, remed))
        for name, pattern, desc, remed in simple_absent:
            if _enabled(mp, name):
                f.append(self._absent(cfg, pattern, name, desc, remed))

        # ip http secure-server (when HTTPS management IS desired)
        if _enabled(mp, "ip_http_secure_server"):
            f.append(
                self._present(
                    cfg,
                    r"^ip http secure-server",
                    "ip_http_secure_server",
                    "ip http secure-server",
                    "ip http secure-server",
                )
            )

        # ip http authentication
        if _enabled(mp, "ip_http_authentication"):
            method = _setting(mp, "ip_http_authentication", "method")
            f.append(
                self._present(
                    cfg,
                    rf"^ip http authentication\s+{re.escape(method)}(?:\s|$)",
                    "ip_http_authentication",
                    f"ip http authentication {method}",
                    f"ip http authentication {method}",
                )
            )

        # ip http access-class
        if _enabled(mp, "ip_http_access_class"):
            acl = _setting(mp, "ip_http_access_class", "acl_name")
            if acl:
                f.append(
                    self._present(
                        cfg,
                        rf"^ip http access-class\s+(?:ipv4\s+)?{re.escape(acl)}\s*$",
                        "ip_http_access_class",
                        f"ip http access-class {acl}",
                        f"ip http access-class {acl}",
                    )
                )
            else:
                f.append(
                    self._present(
                        cfg,
                        r"^ip http access-class\s+\S+",
                        "ip_http_access_class",
                        "ip http access-class set",
                        "ip http access-class <acl>",
                    )
                )

        # clock timezone
        if _enabled(mp, "clock_timezone"):
            tz = _setting(mp, "clock_timezone", "timezone")
            if tz:
                f.append(self._clock_timezone_finding(cfg, mp, tz))
            else:
                f.append(
                    self._present(
                        cfg,
                        r"^clock timezone\s+\S+",
                        "clock_timezone",
                        "clock timezone configured",
                        "clock timezone <tz> <offset>",
                    )
                )

        # ip domain name
        if _enabled(mp, "ip_domain_name"):
            expected = _setting(mp, "ip_domain_name", "expected")
            if expected:
                pattern = rf"^ip domain[ -]name\s+{re.escape(expected)}\.?\s*$"
                f.append(
                    self._present(
                        cfg,
                        pattern,
                        "ip_domain_name",
                        f"ip domain name {expected}",
                        f"ip domain name {expected}",
                    )
                )
            else:
                f.append(
                    self._present(
                        cfg,
                        r"^ip domain[ -]name\s+\S+",
                        "ip_domain_name",
                        "ip domain name set",
                        "ip domain name <your-domain>",
                    )
                )

        return f

    # ── SSH ───────────────────────────────────────────────────
    def _check_ssh(
        self, cfg: ParsedConfig, data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        # SSH version
        if _enabled(mp, "ssh_version"):
            ver = _setting(mp, "ssh_version", "version")
            if cfg.has_line(rf"^ip ssh version\s+{ver}"):
                f.append(Finding("ssh_version", Status.PASS, f"ip ssh version {ver}"))
            else:
                # Fallback: check "show ip ssh" structured or raw output
                ssh_struct = getattr(data, "ssh", None) or {}
                ssh_info = ssh_struct.get("ssh", {})
                if ssh_info.get("version"):
                    active_ver = ssh_info["version"].split(".")[0]
                    if int(active_ver) == int(ver):
                        f.append(
                            Finding(
                                "ssh_version",
                                Status.PASS,
                                f"ip ssh version {ver} (confirmed via show ip ssh)",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "ssh_version",
                                Status.FAIL,
                                f"Missing: ip ssh version {ver}",
                                remediation=f"ip ssh version {ver}",
                            )
                        )
                else:
                    ssh_out = data.raw_commands.get("show ip ssh", "")
                    m = re.search(
                        r"SSH\s+Enabled\s*-\s*version\s+(\d+)", ssh_out
                    )
                    if m and int(m.group(1)) == int(ver):
                        f.append(
                            Finding(
                                "ssh_version",
                                Status.PASS,
                                f"ip ssh version {ver} (confirmed via show ip ssh)",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "ssh_version",
                                Status.FAIL,
                                f"Missing: ip ssh version {ver}",
                                remediation=f"ip ssh version {ver}",
                            )
                        )

        # SSH timeout
        if _enabled(mp, "ssh_timeout"):
            max_s = _setting(mp, "ssh_timeout", "max_seconds")
            lines = cfg.find_lines(r"^ip ssh time-out\s+\d+")
            if lines:
                m = re.search(r"(\d+)", lines[0])
                actual = int(m.group(1)) if m else 999
                if actual <= max_s:
                    f.append(
                        Finding(
                            "ssh_timeout",
                            Status.PASS,
                            f"SSH timeout {actual}s <= {max_s}s",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "ssh_timeout",
                            Status.FAIL,
                            f"SSH timeout {actual}s > {max_s}s",
                            remediation=f"ip ssh time-out {max_s}",
                        )
                    )
            else:
                f.append(
                    Finding(
                        "ssh_timeout",
                        Status.FAIL,
                        "SSH timeout not configured",
                        remediation=f"ip ssh time-out {max_s}",
                    )
                )

        # SSH auth retries
        if _enabled(mp, "ssh_authentication_retries"):
            max_r = _setting(mp, "ssh_authentication_retries", "max_retries")
            lines = cfg.find_lines(r"^ip ssh authentication-retries\s+\d+")
            if lines:
                m = re.search(r"(\d+)", lines[0])
                actual = int(m.group(1)) if m else 999
                if actual <= max_r:
                    f.append(
                        Finding(
                            "ssh_auth_retries",
                            Status.PASS,
                            f"SSH retries {actual} <= {max_r}",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "ssh_auth_retries",
                            Status.FAIL,
                            f"SSH retries {actual} > {max_r}",
                            remediation=f"ip ssh authentication-retries {max_r}",
                        )
                    )
            else:
                f.append(
                    Finding(
                        "ssh_auth_retries",
                        Status.WARN,
                        "SSH authentication-retries not explicitly set",
                    )
                )

        # SSH source-interface
        if _enabled(mp, "ssh_source_interface"):
            intf = _setting(mp, "ssh_source_interface", "interface")
            f.append(
                self._source_interface_finding(
                    cfg, "ip ssh source-interface", "ssh_source_interface", intf
                )
            )

        # SSH RSA minimum modulus size
        if _enabled(mp, "ssh_rsa_min_modulus"):
            min_bits = _setting(mp, "ssh_rsa_min_modulus", "min_bits")
            modulus_found = False

            # First, try structured "show ip ssh" data
            ssh_struct = getattr(data, "ssh", None) or {}
            ssh_info = ssh_struct.get("ssh", {})
            rsa_key = ssh_info.get("rsa_key", {})
            if rsa_key.get("modulus_size"):
                bits = rsa_key["modulus_size"]
                modulus_found = True
                if bits >= min_bits:
                    f.append(
                        Finding(
                            "ssh_rsa_min_modulus",
                            Status.PASS,
                            f"RSA key size {bits} >= {min_bits} bits",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "ssh_rsa_min_modulus",
                            Status.FAIL,
                            f"RSA key size {bits} < {min_bits} bits",
                            remediation=f"crypto key generate rsa modulus {min_bits}",
                        )
                    )

            # Fallback: try raw "show ip ssh" output
            if not modulus_found and data and data.raw_commands.get("show ip ssh"):
                ssh_output = data.raw_commands["show ip ssh"]
                for line in ssh_output.splitlines():
                    m = re.search(
                        r"Modulus Size\s*:\s*(\d+)\s*bits?", line, re.IGNORECASE
                    )
                    if m:
                        bits = int(m.group(1))
                        modulus_found = True
                        if bits >= min_bits:
                            f.append(
                                Finding(
                                    "ssh_rsa_min_modulus",
                                    Status.PASS,
                                    f"RSA key size {bits} >= {min_bits} bits",
                                )
                            )
                        else:
                            f.append(
                                Finding(
                                    "ssh_rsa_min_modulus",
                                    Status.FAIL,
                                    f"RSA key size {bits} < {min_bits} bits",
                                    remediation=f"crypto key generate rsa modulus {min_bits}",
                                )
                            )
                        break

            # Fallback: check running-config for RSA key modulus
            if not modulus_found:
                for gl in cfg.global_lines:
                    m = re.search(r"(\d+)\s*bit", gl)
                    if m and "rsa" in gl.lower():
                        bits = int(m.group(1))
                        modulus_found = True
                        if bits >= min_bits:
                            f.append(
                                Finding(
                                    "ssh_rsa_min_modulus",
                                    Status.PASS,
                                    f"RSA key size {bits} >= {min_bits} bits",
                                )
                            )
                        else:
                            f.append(
                                Finding(
                                    "ssh_rsa_min_modulus",
                                    Status.FAIL,
                                    f"RSA key size {bits} < {min_bits} bits",
                                    remediation=f"crypto key generate rsa modulus {min_bits}",
                                )
                            )
                        break

            if not modulus_found:
                f.append(
                    Finding(
                        "ssh_rsa_min_modulus",
                        Status.WARN,
                        f"RSA modulus could not be determined (expected >= {min_bits})",
                        remediation=f"crypto key generate rsa modulus {min_bits}",
                    )
                )

        return f

    # ── AAA ───────────────────────────────────────────────────
    def _check_aaa(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "aaa_new_model"):
            f.append(
                self._present(
                    cfg,
                    r"^aaa new-model",
                    "aaa_new_model",
                    "aaa new-model",
                    "aaa new-model",
                )
            )

        # AAA line checks — expected exact line
        for check_name in (
            "aaa_authentication_login",
            "aaa_authentication_enable",
            "aaa_authorization_console",
            "aaa_authorization_exec",
            "aaa_accounting_exec",
            "aaa_accounting_connection",
            "aaa_session_id",
        ):
            if not _enabled(mp, check_name):
                continue
            expected = _setting(mp, check_name, "expected").strip()
            if expected:
                f.append(
                    self._present(
                        cfg, rf"^{re.escape(expected)}\s*$", check_name, expected, expected
                    )
                )

        # AAA authorization / accounting commands (one line per privilege level)
        for check_name in ("aaa_authorization_commands", "aaa_accounting_commands"):
            if not _enabled(mp, check_name):
                continue
            prefix = _setting(mp, check_name, "expected_prefix")
            for level in _setting(mp, check_name, "levels"):
                expected = _expand_level(prefix, level)
                f.append(
                    self._present(
                        cfg,
                        rf"^{re.escape(expected)}(?:\s|$)",
                        f"{check_name}_{level}",
                        expected,
                        expected,
                    )
                )

        # TACACS server
        if _enabled(mp, "tacacs_server"):
            min_svr = _setting(mp, "tacacs_server", "min_servers")
            servers = cfg.find_lines(r"^tacacs server\s+")
            if len(servers) >= min_svr:
                f.append(
                    Finding(
                        "tacacs_server",
                        Status.PASS,
                        f"{len(servers)} TACACS server(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "tacacs_server",
                        Status.FAIL,
                        f"Expected >= {min_svr} TACACS server(s), found {len(servers)}",
                        remediation="tacacs server <name>",
                    )
                )

        # TACACS source interface — global, or inside an ``aaa group server``
        # block (whose indented lines are parsed as global lines).
        if _enabled(mp, "tacacs_source_interface"):
            intf = _setting(mp, "tacacs_source_interface", "interface")
            f.append(
                self._source_interface_finding(
                    cfg, "ip tacacs source-interface", "tacacs_source_interface", intf
                )
            )

        # RADIUS server
        if _enabled(mp, "radius_server"):
            min_svr = _setting(mp, "radius_server", "min_servers")
            servers = cfg.find_lines(r"^radius server\s+")
            if len(servers) >= min_svr:
                f.append(
                    Finding(
                        "radius_server",
                        Status.PASS,
                        f"{len(servers)} RADIUS server(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "radius_server",
                        Status.FAIL,
                        f"Expected >= {min_svr} RADIUS server(s), found {len(servers)}",
                        remediation="radius server <name>",
                    )
                )

        return f

    # ── NTP ───────────────────────────────────────────────────
    def _check_ntp(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "ntp_servers"):
            min_svr = _setting(mp, "ntp_servers", "min_servers")
            expected = _setting(mp, "ntp_servers", "expected_servers")
            actual = cfg.find_lines(r"^ntp server\s+")

            if expected:
                configured = _configured_hosts(cfg, "ntp server")
                for srv in expected:
                    if _host_key(srv) in configured:
                        f.append(
                            Finding(
                                "ntp_server",
                                Status.PASS,
                                f"NTP server {srv} configured",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "ntp_server",
                                Status.FAIL,
                                f"NTP server {srv} missing",
                                remediation=f"ntp server {srv}",
                            )
                        )
            elif len(actual) >= min_svr:
                f.append(
                    Finding(
                        "ntp_servers",
                        Status.PASS,
                        f"{len(actual)} NTP server(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "ntp_servers",
                        Status.FAIL,
                        f"Expected >= {min_svr} NTP server(s), found {len(actual)}",
                        remediation="ntp server <ip>",
                    )
                )

        if _enabled(mp, "ntp_authenticate"):
            f.append(
                self._present(
                    cfg,
                    r"^ntp authenticate",
                    "ntp_authenticate",
                    "ntp authenticate",
                    "ntp authenticate",
                )
            )

        if _enabled(mp, "ntp_source_interface"):
            intf = _setting(mp, "ntp_source_interface", "interface")
            f.append(
                self._source_interface_finding(
                    cfg, "ntp source", "ntp_source_interface", intf
                )
            )

        return f

    # ── LOGGING ───────────────────────────────────────────────
    def _check_logging(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "logging_buffered"):
            f.append(self._logging_buffered_finding(cfg, mp))

        if _enabled(mp, "logging_console"):
            f.append(
                self._logging_level_finding(
                    cfg, "logging console", "logging_console",
                    _setting(mp, "logging_console", "level"), most_verbose=True,
                )
            )

        if _enabled(mp, "no_logging_console"):
            f.append(
                self._absent(
                    cfg,
                    r"^logging console",
                    "no_logging_console",
                    "logging console",
                    "no logging console",
                )
            )

        if _enabled(mp, "logging_trap"):
            f.append(
                self._logging_level_finding(
                    cfg, "logging trap", "logging_trap",
                    _setting(mp, "logging_trap", "level"), most_verbose=False,
                )
            )

        if _enabled(mp, "logging_host"):
            expected = _setting(mp, "logging_host", "expected_hosts")
            min_h = _setting(mp, "logging_host", "min_hosts")
            actual = cfg.find_lines(
                r"^logging host\s+\S+|^logging\s+\d+\.\d+\.\d+\.\d+"
            )
            if expected:
                # ``logging host <addr>`` plus the legacy ``logging <ipv4>`` form.
                configured = _configured_hosts(cfg, "logging host") | {
                    _host_key(line.split()[1])
                    for line in cfg.find_lines(r"^logging\s+\d+\.\d+\.\d+\.\d+")
                }
                for h in expected:
                    if _host_key(h) in configured:
                        f.append(
                            Finding(
                                "logging_host",
                                Status.PASS,
                                f"Logging host {h} configured",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "logging_host",
                                Status.FAIL,
                                f"Logging host {h} missing",
                                remediation=f"logging host {h}",
                            )
                        )
            elif len(actual) >= min_h:
                f.append(
                    Finding(
                        "logging_host",
                        Status.PASS,
                        f"{len(actual)} logging host(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "logging_host",
                        Status.FAIL,
                        f"Expected >= {min_h} logging host(s), found {len(actual)}",
                        remediation="logging host <ip>",
                    )
                )

        if _enabled(mp, "logging_source_interface"):
            intf = _setting(mp, "logging_source_interface", "interface")
            f.append(
                self._source_interface_finding(
                    cfg, "logging source-interface", "logging_source_interface", intf
                )
            )

        # logging monitor
        if _enabled(mp, "logging_monitor"):
            f.append(
                self._logging_level_finding(
                    cfg, "logging monitor", "logging_monitor",
                    _setting(mp, "logging_monitor", "level"), most_verbose=True,
                )
            )

        # logging origin-id
        if _enabled(mp, "logging_origin_id"):
            f.append(self._logging_origin_id_finding(cfg, mp))

        return f

    # ── SNMP ──────────────────────────────────────────────────
    def _check_snmp(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "snmp_no_community_public"):
            f.append(
                self._absent(
                    cfg,
                    r"^snmp-server community public",
                    "snmp_no_community_public",
                    "snmp-server community public",
                    "no snmp-server community public",
                )
            )

        if _enabled(mp, "snmp_no_community_private"):
            f.append(
                self._absent(
                    cfg,
                    r"^snmp-server community private",
                    "snmp_no_community_private",
                    "snmp-server community private",
                    "no snmp-server community private",
                )
            )

        if _enabled(mp, "snmp_v3_only"):
            groups = cfg.find_lines(r"^snmp-server group\s+\S+\s+v3\s+priv")
            if groups:
                f.append(
                    Finding(
                        "snmp_v3_only",
                        Status.PASS,
                        f"SNMPv3 group(s) configured: {len(groups)}",
                    )
                )
            else:
                f.append(
                    Finding(
                        "snmp_v3_only",
                        Status.FAIL,
                        "No SNMPv3 priv group found",
                        remediation="snmp-server group <name> v3 priv",
                    )
                )

        if _enabled(mp, "snmp_ifindex_persist"):
            f.append(
                self._present(
                    cfg,
                    r"^snmp-server ifindex persist",
                    "snmp_ifindex_persist",
                    "snmp-server ifindex persist",
                    "snmp-server ifindex persist",
                )
            )

        # SNMP community ACL
        if _enabled(mp, "snmp_community_acl"):
            communities = cfg.find_lines(r"^snmp-server community\s+")
            if communities:
                all_have_acl = all(
                    _snmp_community_has_acl(line) for line in communities
                )
                if all_have_acl:
                    f.append(
                        Finding(
                            "snmp_community_acl",
                            Status.PASS,
                            f"All {len(communities)} SNMP communities have ACL restrictions",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "snmp_community_acl",
                            Status.FAIL,
                            "SNMP community without ACL restriction found",
                            remediation="snmp-server community <name> RO <acl>",
                        )
                    )
            else:
                f.append(
                    Finding(
                        "snmp_community_acl",
                        Status.PASS,
                        "No SNMP v1/v2c communities configured",
                    )
                )

        # SNMP server host
        if _enabled(mp, "snmp_server_host"):
            expected = _setting(mp, "snmp_server_host", "expected_hosts")
            if expected:
                configured = _configured_hosts(cfg, "snmp-server host")
                for h in expected:
                    if _host_key(h) in configured:
                        f.append(
                            Finding(
                                "snmp_server_host",
                                Status.PASS,
                                f"SNMP server host {h} configured",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "snmp_server_host",
                                Status.FAIL,
                                f"SNMP server host {h} missing",
                                remediation=f"snmp-server host {h}",
                            )
                        )
            else:
                actual = cfg.find_lines(r"^snmp-server host\s+")
                if actual:
                    f.append(
                        Finding(
                            "snmp_server_host",
                            Status.PASS,
                            f"{len(actual)} SNMP server host(s) configured",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "snmp_server_host",
                            Status.FAIL,
                            "No SNMP server host configured",
                            remediation="snmp-server host <ip>",
                        )
                    )

        # SNMP contact
        if _enabled(mp, "snmp_contact"):
            expected = _setting(mp, "snmp_contact", "expected")
            if expected:
                f.append(
                    self._present(
                        cfg,
                        rf"^snmp-server contact\s+.*{re.escape(expected)}",
                        "snmp_contact",
                        f"snmp-server contact {expected}",
                        f"snmp-server contact {expected}",
                    )
                )
            else:
                f.append(
                    self._present(
                        cfg,
                        r"^snmp-server contact\s+\S+",
                        "snmp_contact",
                        "snmp-server contact set",
                        "snmp-server contact <text>",
                    )
                )

        # SNMP location
        if _enabled(mp, "snmp_location"):
            expected = _setting(mp, "snmp_location", "expected")
            if expected:
                f.append(
                    self._present(
                        cfg,
                        rf"^snmp-server location\s+.*{re.escape(expected)}",
                        "snmp_location",
                        f"snmp-server location {expected}",
                        f"snmp-server location {expected}",
                    )
                )
            else:
                f.append(
                    self._present(
                        cfg,
                        r"^snmp-server location\s+\S+",
                        "snmp_location",
                        "snmp-server location set",
                        "snmp-server location <text>",
                    )
                )

        return f

    # ── BANNERS ───────────────────────────────────────────────
    def _check_banners(
        self, cfg: ParsedConfig, data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        for banner_type in ("login", "motd", "exec"):
            key = f"banner_{banner_type}"
            if not _enabled(mp, key):
                continue
            if cfg.has_line(rf"^banner {banner_type}\s+"):
                # Check for required text in banner if specified
                req_text = _setting(mp, key, "required_text")
                if req_text:
                    # Search the raw config for the banner content
                    banner_found = False
                    if data.running_config:
                        banner_rx = re.compile(
                            rf"banner {banner_type}.*?{re.escape(req_text)}",
                            re.IGNORECASE | re.DOTALL,
                        )
                        if banner_rx.search(data.running_config):
                            banner_found = True
                    if banner_found:
                        f.append(
                            Finding(
                                key,
                                Status.PASS,
                                f"banner {banner_type} present with required text",
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                key,
                                Status.FAIL,
                                f"banner {banner_type} present but missing required text: '{req_text}'",
                                remediation=f"banner {banner_type} — must include '{req_text}'",
                            )
                        )
                else:
                    f.append(Finding(key, Status.PASS, f"banner {banner_type} present"))
            else:
                f.append(
                    Finding(
                        key,
                        Status.FAIL,
                        f"banner {banner_type} missing",
                        remediation=f"banner {banner_type} ^<text>^",
                    )
                )

        return f

    # ── LOCAL USERS ───────────────────────────────────────────
    def _check_users(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "enable_secret"):
            f.append(
                self._present(
                    cfg,
                    r"^enable secret",
                    "enable_secret",
                    "enable secret",
                    "enable secret 0 <secret>",
                )
            )

        if _enabled(mp, "no_enable_password"):
            f.append(
                self._absent(
                    cfg,
                    r"^enable password",
                    "no_enable_password",
                    "enable password",
                    "no enable password / use enable secret",
                )
            )

        if _enabled(mp, "username_secret"):
            pw_users = cfg.find_lines(r"^username\s+\S+.*\bpassword\b")
            if pw_users:
                for u in pw_users:
                    m = re.match(r"username\s+(\S+)", u)
                    name = m.group(1) if m else "?"
                    f.append(
                        Finding(
                            "username_secret",
                            Status.FAIL,
                            f"User '{name}' uses 'password' instead of 'secret'",
                            remediation=f"username {name} secret 0 <secret>",
                        )
                    )
            else:
                f.append(
                    Finding(
                        "username_secret", Status.PASS, "All local users use 'secret'"
                    )
                )

        return f

    # ── VTY LINES ─────────────────────────────────────────────
    def _check_vty_lines(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})
        vty_sections = cfg.get_line_config_sections(r"^vty\s+")

        if not vty_sections:
            f.append(Finding("vty_lines", Status.WARN, "No VTY line config found"))
            return f

        for sec_name, lines in vty_sections.items():
            label = f"line {sec_name}"

            if _enabled(mp, "vty_transport_input_ssh"):
                # Must be exactly "transport input ssh": re.match is only
                # anchored at the start, so "transport input ssh telnet" used
                # to pass while still permitting telnet.
                has_ssh_only = any(
                    re.fullmatch(r"transport input ssh", line.strip(), re.I)
                    for line in lines
                )
                if has_ssh_only:
                    f.append(
                        Finding(
                            "vty_transport_ssh",
                            Status.PASS,
                            f"{label}: transport input ssh",
                            interface=label,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "vty_transport_ssh",
                            Status.FAIL,
                            f"{label}: transport input is not 'ssh' only",
                            interface=label,
                            remediation="transport input ssh",
                        )
                    )

            if _enabled(mp, "vty_exec_timeout"):
                exp_min = _setting(mp, "vty_exec_timeout", "minutes")
                exp_sec = _setting(mp, "vty_exec_timeout", "seconds")
                timeout_lines = [
                    line for line in lines if line.startswith("exec-timeout")
                ]
                if timeout_lines:
                    m = re.match(r"exec-timeout\s+(\d+)\s+(\d+)", timeout_lines[0])
                    if m:
                        actual_total = int(m.group(1)) * 60 + int(m.group(2))
                        exp_total = exp_min * 60 + exp_sec
                        if actual_total == 0:
                            # "exec-timeout 0 0" disables the idle timeout
                            # entirely — the session never expires, so it can
                            # never satisfy a maximum.
                            f.append(
                                Finding(
                                    "vty_exec_timeout",
                                    Status.FAIL,
                                    f"{label}: exec-timeout 0 0 disables the "
                                    f"idle timeout",
                                    interface=label,
                                    remediation=f"exec-timeout {exp_min} {exp_sec}",
                                )
                            )
                        elif actual_total <= exp_total:
                            f.append(
                                Finding(
                                    "vty_exec_timeout",
                                    Status.PASS,
                                    f"{label}: exec-timeout {m.group(1)} {m.group(2)}",
                                    interface=label,
                                )
                            )
                        else:
                            f.append(
                                Finding(
                                    "vty_exec_timeout",
                                    Status.FAIL,
                                    f"{label}: exec-timeout too long ({m.group(1)} {m.group(2)})",
                                    interface=label,
                                    remediation=f"exec-timeout {exp_min} {exp_sec}",
                                )
                            )
                else:
                    f.append(
                        Finding(
                            "vty_exec_timeout",
                            Status.FAIL,
                            f"{label}: exec-timeout not set",
                            interface=label,
                            remediation=f"exec-timeout {exp_min} {exp_sec}",
                        )
                    )

            if _enabled(mp, "vty_access_class"):
                acl = _setting(mp, "vty_access_class", "acl_name")
                # Only an inbound class restricts who can log in; "out"
                # filters onward connections from the line.
                acl_rx = re.escape(acl) if acl else r"\S+"
                applied = [
                    line for line in lines
                    if re.match(rf"access-class\s+{acl_rx}\s+in(?:\s|$)", line, re.I)
                ]
                if applied:
                    f.append(
                        Finding(
                            "vty_access_class",
                            Status.PASS,
                            f"{label}: {applied[0]}",
                            interface=label,
                        )
                    )
                else:
                    current = [ln for ln in lines if ln.startswith("access-class")]
                    detail = (
                        f"{label}: inbound access-class {acl} not applied"
                        if acl else f"{label}: no inbound access-class"
                    )
                    if current:
                        detail += f" (found: {current[0]})"
                    f.append(
                        Finding(
                            "vty_access_class",
                            Status.FAIL,
                            detail,
                            interface=label,
                            remediation=f"access-class {acl or '<acl>'} in",
                        )
                    )

            if _enabled(mp, "vty_logging_synchronous"):
                if any("logging synchronous" in line for line in lines):
                    f.append(
                        Finding(
                            "vty_logging_sync",
                            Status.PASS,
                            f"{label}: logging synchronous",
                            interface=label,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "vty_logging_sync",
                            Status.FAIL,
                            f"{label}: logging synchronous missing",
                            interface=label,
                            remediation="logging synchronous",
                        )
                    )

            # VTY login authentication method list
            if _enabled(mp, "vty_login_authentication"):
                method = _setting(mp, "vty_login_authentication", "method_list")
                f.append(
                    self._login_authentication_finding(
                        cfg, lines, label, "vty_login_authentication", method
                    )
                )

        return f

    # ── CONSOLE ───────────────────────────────────────────────
    def _check_console(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})
        con_sections = cfg.get_line_config_sections(r"^con\s+")

        if not con_sections:
            return f

        for sec_name, lines in con_sections.items():
            label = f"line {sec_name}"

            if _enabled(mp, "console_exec_timeout"):
                exp_min = _setting(mp, "console_exec_timeout", "minutes")
                exp_sec = _setting(mp, "console_exec_timeout", "seconds")
                timeout_lines = [
                    line for line in lines if line.startswith("exec-timeout")
                ]
                if timeout_lines:
                    m = re.match(r"exec-timeout\s+(\d+)\s+(\d+)", timeout_lines[0])
                    if m:
                        actual_total = int(m.group(1)) * 60 + int(m.group(2))
                        exp_total = exp_min * 60 + exp_sec
                        if actual_total == 0:
                            # "exec-timeout 0 0" disables the idle timeout
                            # entirely — the session never expires, so it can
                            # never satisfy a maximum.
                            f.append(
                                Finding(
                                    "console_exec_timeout",
                                    Status.FAIL,
                                    f"{label}: exec-timeout 0 0 disables the "
                                    f"idle timeout",
                                    interface=label,
                                    remediation=f"exec-timeout {exp_min} {exp_sec}",
                                )
                            )
                        elif actual_total <= exp_total:
                            f.append(
                                Finding(
                                    "console_exec_timeout",
                                    Status.PASS,
                                    f"{label}: exec-timeout {m.group(1)} {m.group(2)}",
                                    interface=label,
                                )
                            )
                        else:
                            f.append(
                                Finding(
                                    "console_exec_timeout",
                                    Status.FAIL,
                                    f"{label}: exec-timeout too long",
                                    interface=label,
                                    remediation=f"exec-timeout {exp_min} {exp_sec}",
                                )
                            )
                else:
                    f.append(
                        Finding(
                            "console_exec_timeout",
                            Status.FAIL,
                            f"{label}: exec-timeout not set",
                            interface=label,
                            remediation=f"exec-timeout {exp_min} {exp_sec}",
                        )
                    )

            if _enabled(mp, "console_logging_synchronous"):
                if any("logging synchronous" in line for line in lines):
                    f.append(
                        Finding(
                            "console_logging_sync",
                            Status.PASS,
                            f"{label}: logging synchronous",
                            interface=label,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "console_logging_sync",
                            Status.FAIL,
                            f"{label}: logging synchronous missing",
                            interface=label,
                            remediation="logging synchronous",
                        )
                    )

            # Console login authentication method list
            if _enabled(mp, "console_login_authentication"):
                method = _setting(mp, "console_login_authentication", "method_list")
                f.append(
                    self._login_authentication_finding(
                        cfg, lines, label, "console_login_authentication", method
                    )
                )

        return f

    # ── ARCHIVE ───────────────────────────────────────────────
    # Archive compliance check temporarily removed as requested.

    # ── LOGIN SECURITY ────────────────────────────────────────
    def _check_login_security(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "login_block_for"):
            f.append(self._login_block_for_finding(cfg, mp))

        if _enabled(mp, "login_on_failure_log"):
            f.append(
                self._present(
                    cfg,
                    r"^login on-failure log",
                    "login_on_failure_log",
                    "login on-failure log",
                    "login on-failure log",
                )
            )

        if _enabled(mp, "login_on_success_log"):
            f.append(
                self._present(
                    cfg,
                    r"^login on-success log",
                    "login_on_success_log",
                    "login on-success log",
                    "login on-success log",
                )
            )

        if _enabled(mp, "login_delay"):
            want = _setting(mp, "login_delay", "seconds")
            args = _command_args(cfg, "login delay")
            actual = int(args[-1][0]) if args and args[-1] and args[-1][0].isdigit() else None
            if actual is not None and actual >= want:
                f.append(Finding("login_delay", Status.PASS, f"login delay {actual}s >= {want}s"))
            else:
                f.append(
                    Finding(
                        "login_delay",
                        Status.FAIL,
                        f"login delay {actual}s < {want}s" if actual is not None
                        else "Missing: login delay",
                        remediation=f"login delay {want}",
                    )
                )

        return f

    # ── CDP / LLDP ────────────────────────────────────────────
    def _check_cdp_lldp(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "management_plane" not in self.policy:
            return f
        mp = self.policy.get("management_plane", {})

        if _enabled(mp, "cdp_global"):
            want = _setting(mp, "cdp_global", "state")
            if want == "disabled":
                f.append(
                    self._present(
                        cfg, r"^no cdp run", "cdp_global", "no cdp run", "no cdp run"
                    )
                )
            else:
                # CDP is enabled by default; ensure 'no cdp run' is absent
                f.append(
                    self._absent(
                        cfg, r"^no cdp run", "cdp_global", "no cdp run", "cdp run"
                    )
                )

        if _enabled(mp, "lldp_global"):
            want = _setting(mp, "lldp_global", "state")
            if want == "enabled":
                f.append(
                    self._present(
                        cfg, r"^lldp run", "lldp_global", "lldp run", "lldp run"
                    )
                )
            else:
                f.append(
                    self._absent(
                        cfg, r"^lldp run", "lldp_global", "lldp run", "no lldp run"
                    )
                )

        return f

