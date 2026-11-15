"""
Shared primitives for the compliance checks: result models, policy lookup
helpers, and the small predicates the per-plane check mixins are built from.

Split out of ``compliance_engine`` so the check modules can import these
without importing the engine that assembles them.
"""

import copy
import ipaddress
import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Optional

from ..collector import ParsedConfig, normalize_intf
from ..port_classifier import PortInfo, PortRole

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..policy_exceptions import AppliedException

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
    #: A FAIL or WARN covered by an approved policy exception (see
    #: ``policy_exceptions``).  Never remediated — whether the exception is
    #: active or expired — and left out of the score unless
    #: ``exception_settings.expired_counts_against_score`` says otherwise.
    EXCEPTION = "EXCEPTION"


#: Numeric priority for severity levels — higher value = more severe.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass
class Finding:
    check_name: str
    status: Status
    detail: str
    category: str = ""
    interface: str = ""
    remediation: str = ""
    severity: str = "medium"          # critical | high | medium | low | info
    tags: list[str] = field(default_factory=list)  # arbitrary labels (e.g. cis, pci)
    framework_controls: dict[str, str] = field(default_factory=dict)  # e.g. {"cis_ios_xe_v4": "2.2.1"}
    #: Set when a policy exception covers this finding (status EXCEPTION).
    exception: "Optional[AppliedException]" = None

    @property
    def exception_state(self) -> str:
        """``active`` / ``expiring`` / ``expired`` / ``permanent``, or ``""``."""
        return self.exception.state if self.exception is not None else ""


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
    structured_parse_engine: dict[str, str] = field(default_factory=dict)
    group: str = ""  # site group from the inventory ("" when ungrouped)
    #: ``exception_settings`` in force when the exceptions were applied.
    expired_exceptions_count_in_score: bool = False
    expired_exceptions_fail_run: bool = False
    #: Exceptions scoped to this device that covered none of its findings —
    #: usually because the configuration is now compliant and the exception
    #: can be retired.  One dict per exception (see ``ExceptionRule.describe``).
    unused_exceptions: list[dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Findings that count towards the score.

        SKIPs never count.  Findings covered by an exception do not count
        either, except expired ones when ``expired_counts_against_score`` is
        on — they then count as not passing.
        """
        return sum(
            1
            for f in self.findings
            if f.status not in (Status.SKIP, Status.EXCEPTION)
            or (
                f.status == Status.EXCEPTION
                and self.expired_exceptions_count_in_score
                and f.exception_state == "expired"
            )
        )

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
    def exception_count(self) -> int:
        """Findings covered by a policy exception (any state)."""
        return sum(1 for f in self.findings if f.status == Status.EXCEPTION)

    @property
    def expired_exception_count(self) -> int:
        """Findings covered by an exception that has passed its expiry date."""
        return sum(
            1
            for f in self.findings
            if f.status == Status.EXCEPTION and f.exception_state == "expired"
        )

    @property
    def expiring_exception_count(self) -> int:
        """Findings covered by an exception inside the expiring-soon window."""
        return sum(
            1
            for f in self.findings
            if f.status == Status.EXCEPTION and f.exception_state == "expiring"
        )

    @property
    def has_failures(self) -> bool:
        """True when this result should make the run exit non-zero.

        A FAIL always does; an expired exception does only when
        ``exception_settings.fail_on_expired`` is on.
        """
        return self.fail_count > 0 or (
            self.expired_exceptions_fail_run and self.expired_exception_count > 0
        )

    @property
    def score_pct(self) -> float:
        t = self.total
        if t == 0:
            return 100.0
        return round(self.pass_count / t * 100, 1)

    @property
    def structured_parse_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for engine in self.structured_parse_engine.values():
            counts[engine] = counts.get(engine, 0) + 1
        return counts

    @property
    def structured_parse_summary(self) -> str:
        if not self.structured_parse_engine:
            return ""

        counts = self.structured_parse_counts
        total = len(self.structured_parse_engine)
        parts: list[str] = []

        if counts.get("genie"):
            parts.append(f"Genie {counts['genie']}/{total}")
        if counts.get("raw-only"):
            parts.append(f"raw fallback {counts['raw-only']}")
        if counts.get("missing-output"):
            parts.append(f"missing output {counts['missing-output']}")

        for engine, count in sorted(counts.items()):
            if engine not in {"genie", "raw-only", "missing-output"}:
                parts.append(f"{engine} {count}")

        return ", ".join(parts)


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
    """Return True only when the check at *path* has ``enabled: true``.

    An absent node, or a node without an ``enabled`` key, is disabled.  The
    schema requires ``enabled`` on every check node, so a typo is reported
    at load time; failing closed here means it can never switch a check on.
    """
    node = _pol(policy, *path)
    return isinstance(node, dict) and node.get("enabled") is True


@lru_cache(maxsize=None)
def _setting_default(check_key: str, name: str):
    from ..config_schema import CHECK_SCHEMAS, ROLE_CHECK_SCHEMAS

    for schemas in (*CHECK_SCHEMAS.values(), *ROLE_CHECK_SCHEMAS.values()):
        model = schemas.get(check_key)
        if model is not None and name in model.model_fields:
            return model.model_fields[name].get_default(call_default_factory=True)
    raise KeyError(f"{check_key}.{name} is not a declared check setting")


def _setting(section: dict, check_key: str, name: str):
    """Return a check setting, falling back to the schema's documented default.

    Defaults live in one place (``config_schema``) so the value the engine
    uses when a key is omitted is the value the schema documents.
    """
    node = section.get(check_key) if isinstance(section, dict) else None
    if isinstance(node, dict) and node.get(name) is not None:
        return node[name]
    default = _setting_default(check_key, name)
    if hasattr(default, "model_dump"):  # nested settings model → plain dict
        return default.model_dump(exclude_none=True)
    return copy.copy(default)


def _expand_vlan_ranges(spec) -> set[int]:
    """Expand a Cisco VLAN list/range spec into a set of VLAN IDs.

    Accepts values such as ``"1-4094"``, ``"10,20,30-40"``, ``"10 20 30"`` or a
    single integer.  Whitespace and empty segments are ignored.  Invalid tokens
    are skipped rather than raising, so a malformed policy value never crashes
    an audit.
    """
    if spec is None:
        return set()
    text = str(spec).strip()
    if not text:
        return set()

    vlans: set[int] = set()
    # Segments may be separated by commas or whitespace.
    for token in re.split(r"[,\s]+", text):
        if not token:
            continue
        if "-" in token:
            lo, _, hi = token.partition("-")
            try:
                start, end = int(lo), int(hi)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            vlans.update(range(start, end + 1))
        else:
            try:
                vlans.add(int(token))
            except ValueError:
                continue
    return vlans


def _host_key(value) -> str:
    """Comparison key for a host: canonical form for an IP, lower-case for a name.

    ``2001:DB8:0::1`` and ``2001:db8::1`` compare equal, as do ``NTP1.corp``
    and ``ntp1.corp.``.
    """
    text = str(value).strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower().rstrip(".")


#: Tokens between a command and its host argument that are not the host.
#: ``vrf`` consumes the VRF name that follows it.
_HOST_ARG_KEYWORDS = {"ip", "ipv6"}


def _configured_hosts(cfg: "ParsedConfig", command: str) -> set[str]:
    """Host keys configured by every global line starting with *command*.

    Parses the host argument out of lines such as ``ntp server vrf MGMT
    192.0.2.70 prefer`` or ``logging host ipv6 2001:db8::1``, so the
    comparison is on the whole address.  A regex prefix match would let an
    expected ``192.0.2.7`` PASS against a configured ``192.0.2.70``.
    """
    words = command.split()
    hosts: set[str] = set()
    for line in cfg.find_lines(rf"^{re.escape(command)}\s+"):
        tokens = line.split()[len(words):]
        i = 0
        while i < len(tokens):
            token = tokens[i].lower()
            if token == "vrf":
                i += 2
            elif token in _HOST_ARG_KEYWORDS:
                i += 1
            else:
                hosts.add(_host_key(tokens[i]))
                break
    return hosts


def _command_args(cfg: "ParsedConfig", command: str) -> list[list[str]]:
    """Argument tokens of every global line that is exactly *command* + args.

    ``_command_args(cfg, "logging console")`` returns ``[["critical"]]`` for
    ``logging console critical``.  The command must end on a word boundary,
    so ``logging console`` does not match ``logging console-foo``.
    """
    words = command.split()
    rx = r"^" + r"\s+".join(re.escape(w) for w in words) + r"(?:\s|$)"
    return [line.split()[len(words):] for line in cfg.find_lines(rx)]


def _same_interface(a: str, b: str) -> bool:
    """Compare interface names, expanding abbreviations (``Lo0`` = ``Loopback0``)."""
    return normalize_intf(a.strip()).lower() == normalize_intf(b.strip()).lower()


#: IOS syslog severities, most to least severe.
SYSLOG_LEVELS = (
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debugging",
)


def _syslog_level(value) -> "int | None":
    """Numeric severity (0-7) for a level keyword or number, else ``None``."""
    text = str(value).strip().lower()
    if text.isdigit() and 0 <= int(text) <= 7:
        return int(text)
    return SYSLOG_LEVELS.index(text) if text in SYSLOG_LEVELS else None


def _configured_vlans(cfg: "ParsedConfig", command_prefix: str) -> set[int]:
    """Union of every VLAN configured across all lines matching *command_prefix*.

    e.g. for ``ip dhcp snooping vlan`` this collects the VLANs from every
    ``ip dhcp snooping vlan <spec>`` line (they may be split across lines).
    """
    pattern = rf"^{command_prefix}\s+(.+)$"
    rx = re.compile(pattern, re.IGNORECASE)
    configured: set[int] = set()
    for line in cfg.find_lines(pattern):
        match = rx.search(line.strip())
        if match:
            configured |= _expand_vlan_ranges(match.group(1))
    return configured


def _format_vlan_set(vlans: set[int]) -> str:
    """Render a set of VLAN IDs back into a compact Cisco range string."""
    if not vlans:
        return ""
    ordered = sorted(vlans)
    parts: list[str] = []
    start = prev = ordered[0]
    for vlan in ordered[1:]:
        if vlan == prev + 1:
            prev = vlan
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = vlan
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


def _build_check_map(policy: dict) -> dict[str, dict]:
    """Build a flat ``{check_key → policy_node}`` lookup from the compliance policy."""
    m: dict[str, dict] = {}
    for section_key in ("management_plane", "control_plane", "data_plane"):
        for check_key, node in (policy.get(section_key) or {}).items():
            if isinstance(node, dict):
                m[check_key] = node
    # role_specific has one extra nesting level: role → {check_key: node}
    for role_checks in (policy.get("role_specific") or {}).values():
        if isinstance(role_checks, dict):
            for check_key, node in role_checks.items():
                if isinstance(node, dict):
                    m[check_key] = node
    return m


#: Finding names that differ from the YAML key of the check that emits them.
#: Without this, ``_find_check_node`` cannot find their policy node, so the
#: check's severity, tags and include/exclude filters would never reach them.
FINDING_NAME_ALIASES: dict[str, str] = {
    "asw_not_root": "stp_not_root",
    "console_logging_sync": "console_logging_synchronous",
    "no_cdp_on_access": "no_cdp_on_access_ports",
    "no_dhcp_snooping_info_option": "no_dhcp_snooping_information_option",
    "ntp_server": "ntp_servers",
    "ssh_auth_retries": "ssh_authentication_retries",
    "unused_access_mode": "unused_ports",
    "unused_bpduguard": "unused_ports",
    "unused_description": "unused_ports",
    "unused_no_cdp": "unused_ports",
    "unused_no_lldp": "unused_ports",
    "unused_nonegotiate": "unused_ports",
    "unused_parking_vlan": "unused_ports",
    "unused_shutdown": "unused_ports",
    "vty_logging_sync": "vty_logging_synchronous",
    "vty_transport_ssh": "vty_transport_input_ssh",
}

#: Finding names emitted outside any single check node (e.g. the VTY section
#: warning when no ``line vty`` config exists at all).
UNOWNED_FINDING_NAMES: frozenset[str] = frozenset({"vty_lines"})


def _find_check_key(check_name: str, check_map: dict[str, dict]) -> str:
    """Return the YAML key of the check that owns *check_name*, or ``""``.

    Exact keys win, then the alias table, then the longest key that is a
    ``<key>_`` prefix of the name — so dynamic names such as
    ``errdisable_recovery_bpduguard`` resolve to ``errdisable_recovery``.
    """
    if check_name in check_map:
        return check_name
    alias = FINDING_NAME_ALIASES.get(check_name)
    if alias and alias in check_map:
        return alias
    candidates = [k for k in check_map if check_name.startswith(k + "_")]
    return max(candidates, key=len) if candidates else ""


def _find_check_node(check_name: str, check_map: dict[str, dict]) -> dict:
    """Return the policy node for a finding; prefix-matches dynamic names.

    Dynamic check names like ``errdisable_recovery_bpduguard`` are matched
    against the ``errdisable_recovery`` YAML key by longest prefix.
    """
    key = _find_check_key(check_name, check_map)
    return check_map[key] if key else {}


def _annotate_findings(
    findings: list["Finding"],
    check_map: dict[str, dict],
    role: str,
    hostname: str,
    group: str = "",
) -> None:
    """Annotate findings with ``severity``/``tags`` and apply YAML-level filters in-place.

    YAML-level filters supported per check node:

    * ``severity``           – one of critical / high / medium / low / info
    * ``tags``               – list of arbitrary label strings
    * ``applies_to_roles``   – list of role identifiers; findings for other roles
                               are converted to SKIP
    * ``exclude_hostnames``  – list of hostname regex patterns; matching devices
                               have the check converted to SKIP
    * ``include_hostnames``  – list of hostname regex patterns; only matching
                               devices run this check (others become SKIP)
    * ``exclude_groups``     – list of site group names; matching devices skip
                               this check
    * ``include_groups``     – list of site group names; only devices in these
                               groups run this check (ungrouped devices also SKIP)
    * ``exclude_interfaces`` – list of interface regex patterns; per-interface
                               findings for matching interfaces are SKIP'd
    """
    for f in findings:
        node = _find_check_node(f.check_name, check_map)

        # Always set severity + tags + framework_controls (even on already-SKIP'd findings)
        f.severity = node.get("severity", "medium")
        raw_tags = node.get("tags")
        f.tags = list(raw_tags) if isinstance(raw_tags, list) else []
        raw_controls = node.get("framework_controls")
        f.framework_controls = dict(raw_controls) if isinstance(raw_controls, dict) else {}

        if f.status == Status.SKIP:
            continue

        # applies_to_roles
        applies_to = node.get("applies_to_roles")
        if applies_to and isinstance(applies_to, list) and role not in applies_to:
            f.status = Status.SKIP
            f.detail = f"Not applicable to role '{role}'"
            continue

        # exclude_hostnames
        excludes = node.get("exclude_hostnames")
        if excludes and isinstance(excludes, list):
            for pattern in excludes:
                try:
                    if re.match(pattern, hostname, re.IGNORECASE):
                        f.status = Status.SKIP
                        f.detail = "Excluded by hostname policy"
                        break
                except re.error:
                    pass
            if f.status == Status.SKIP:
                continue

        # include_hostnames
        includes_h = node.get("include_hostnames")
        if includes_h and isinstance(includes_h, list):
            matched = False
            for pattern in includes_h:
                try:
                    if re.match(pattern, hostname, re.IGNORECASE):
                        matched = True
                        break
                except re.error:
                    pass
            if not matched:
                f.status = Status.SKIP
                f.detail = "Not in hostname include list"
                continue

        # exclude_groups
        excl_groups = node.get("exclude_groups")
        if excl_groups and isinstance(excl_groups, list) and group:
            if group.lower() in [g.lower() for g in excl_groups]:
                f.status = Status.SKIP
                f.detail = f"Excluded by group policy (group: '{group}')"
                continue

        # include_groups
        incl_groups = node.get("include_groups")
        if incl_groups and isinstance(incl_groups, list):
            if not group or group.lower() not in [g.lower() for g in incl_groups]:
                f.status = Status.SKIP
                f.detail = f"Not in group include list (group: '{group or 'ungrouped'}')"
                continue

        # exclude_interfaces (only for per-interface findings)
        if f.interface:
            excl_intfs = node.get("exclude_interfaces")
            if excl_intfs and isinstance(excl_intfs, list):
                for pattern in excl_intfs:
                    try:
                        if re.match(pattern, f.interface, re.IGNORECASE):
                            f.status = Status.SKIP
                            f.detail = "Interface excluded by policy"
                            break
                    except re.error:
                        pass


# ---------------------------------------------------------------------------
# Port-trust policy tables (DHCP snooping / Dynamic ARP Inspection)
# ---------------------------------------------------------------------------

#: PortRole → the policy key used to describe that kind of port in YAML.
#: Roles absent from this map (loopback, SVI, management, port-channel
#: members) are not switchports and never carry a trust command.
_PORT_KIND_BY_ROLE: dict[PortRole, str] = {
    PortRole.ACCESS: "access_ports",
    PortRole.TRUNK_UPLINK: "uplinks",
    PortRole.TRUNK_DOWNLINK: "downlinks",
    PortRole.TRUNK_UNKNOWN: "unknown_trunks",
    PortRole.TRUNK_ENDPOINT: "endpoint_trunks",
    PortRole.UNUSED: "unused_ports",
}

#: PortRole → wording used in per-port finding details.
_PORT_CONTEXT_BY_ROLE: dict[PortRole, str] = {
    PortRole.ACCESS: "access port",
    PortRole.TRUNK_UPLINK: "uplink",
    PortRole.TRUNK_DOWNLINK: "downlink",
    PortRole.TRUNK_UNKNOWN: "unknown-direction trunk",
    PortRole.UNUSED: "unused port",
}

#: port kind → (YAML key saying trust is *required* there, default if absent).
#: The uplink/downlink defaults preserve the behaviour these checks had before
#: the untrusted half was added.
_TRUST_REQUIRED_KEYS: dict[str, tuple[str, bool]] = {
    "access_ports": ("on_access_ports", False),
    "uplinks": ("on_uplinks", True),
    "downlinks": ("on_downlinks", True),
    "unknown_trunks": ("on_unknown_trunks", False),
    "endpoint_trunks": ("on_endpoint_trunks", False),
    "unused_ports": ("on_unused_ports", False),
}

#: port kind → default for ``untrusted: {<kind>: ...}`` when the key is absent.
#: Cisco's guidance is to trust only the interfaces that lead to the DHCP
#: server and to leave every host-facing port untrusted, so the host-facing
#: kinds default to "must not be trusted".
_TRUST_FORBIDDEN_DEFAULTS: dict[str, bool] = {
    "access_ports": True,
    "uplinks": False,
    "downlinks": False,
    "unknown_trunks": False,
    "endpoint_trunks": True,
    "unused_ports": True,
}

#: (YAML check key, IOS-XE interface command, label used in finding details).
_TRUST_CHECKS: tuple[tuple[str, str, str], ...] = (
    ("dhcp_snooping_trust", "ip dhcp snooping trust", "DHCP snooping trust"),
    ("arp_inspection_trust", "ip arp inspection trust", "DAI trust"),
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared check primitives
# ---------------------------------------------------------------------------
class CheckPrimitives:
    """The present/absent predicates every plane's checks are built on."""

    def _present(
        self,
        cfg: ParsedConfig,
        pattern: str,
        name: str,
        description: str,
        remediation: str,
    ) -> Finding:
        """PASS if *pattern* is found in global config; FAIL otherwise."""
        if cfg.has_line(pattern):
            return Finding(name, Status.PASS, description)
        return Finding(
            name, Status.FAIL, f"Missing: {description}", remediation=remediation
        )

    def _absent(
        self,
        cfg: ParsedConfig,
        pattern: str,
        name: str,
        bad_description: str,
        remediation: str,
    ) -> Finding:
        """PASS if *pattern* is NOT found in global config; FAIL otherwise."""
        if cfg.has_line(pattern):
            return Finding(
                name, Status.FAIL, f"Found: {bad_description}", remediation=remediation
            )
        return Finding(name, Status.PASS, f"Absent: {bad_description} (good)")


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _snmp_community_has_acl(line: str) -> bool:
    """True if an ``snmp-server community`` line restricts access with an ACL.

    IOS-XE syntax is::

        snmp-server community <string> [view <name>] [RO|RW] [ipv6 <nacl>] [<acl>]

    so the ACL is whatever remains after the optional ``view`` pair and the
    access mode.  A bare ``snmp-server community public RO`` has none.
    """
    rest = line.split()[3:]  # drop "snmp-server community <string>"
    if rest[:1] == ["view"]:
        rest = rest[2:]
    if rest[:1] and rest[0].upper() in ("RO", "RW"):
        rest = rest[1:]
    if rest[:1] == ["ipv6"]:
        # "ipv6 <nacl>" is itself an access restriction
        return len(rest) >= 2
    return bool(rest)


def pi_has(pi: PortInfo, pattern: str) -> bool:
    """Check if any of *pi*'s config lines match *pattern*."""
    rx = re.compile(pattern, re.IGNORECASE)
    return any(rx.search(line) for line in pi.config_lines)


def pi_int_arg(pi: PortInfo, pattern: str) -> int | None:
    """Return the first capture group of *pattern* as an int, or None.

    Used by checks that need the configured *value* of an interface command
    rather than just its presence.
    """
    rx = re.compile(pattern, re.IGNORECASE)
    for line in pi.config_lines:
        m = rx.search(line)
        if m:
            try:
                return int(m.group(1))
            except (IndexError, ValueError):
                return None
    return None


def pi_has_command(pi: PortInfo, command: str) -> bool:
    """Check if *command* is configured on *pi* as a whole line.

    Unlike :func:`pi_has` this anchors both ends of the line, so a negated
    (``no <command>``) form is never mistaken for the command being present.
    """
    rx = re.compile(rf"^\s*{re.escape(command)}\s*$", re.IGNORECASE)
    return any(rx.match(line) for line in pi.config_lines)


def port_kind(role: PortRole) -> str:
    """Return the policy key naming *role*, or ``""`` for non-switchport roles."""
    return _PORT_KIND_BY_ROLE.get(role, "")


def port_context(pi: PortInfo) -> str:
    """Human-readable description of a port's role, used in finding details."""
    if pi.role == PortRole.TRUNK_ENDPOINT:
        return (
            f"endpoint trunk to {pi.cdp_neighbor}"
            if pi.cdp_neighbor
            else "endpoint trunk"
        )
    return _PORT_CONTEXT_BY_ROLE.get(pi.role, pi.role.value)
