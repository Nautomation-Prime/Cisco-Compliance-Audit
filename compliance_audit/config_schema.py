"""
Pydantic v2 schemas for the split compliance YAML configuration.

Call ``validate_compliance_config(cfg)`` with the merged dict returned by
``load_compliance_config()`` to get a list of human-readable error messages
(an empty list means the config is valid), or ``ensure_valid_config(cfg)`` to
raise :class:`ConfigValidationError` instead.

The schemas validate; they do not rewrite the config.  The check engine
reads every check setting through ``checks.base._setting``, which falls back
to the defaults declared here, so a check's documented default and the value
the engine uses when a key is omitted are the same thing.

Most models use ``extra="forbid"``.  A YAML linter cannot tell that
``max_worker:`` or ``expected_server:`` is a typo, and the engine ignores keys
it does not read, so an unknown key here almost always means a setting the
operator believes is in force is being silently ignored.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from datetime import date
from typing import Annotated, Any, Literal, Optional, Type, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainValidator,
    ValidationError,
    field_validator,
    model_validator,
)

from .schema_types import (
    HostOrIP,
    Regex,
    Severity,
    SyslogLevel,
    VlanId,
    VlanSpec,
)


class ConfigValidationError(ValueError):
    """Raised by :func:`ensure_valid_config`; ``errors`` holds one line per problem."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(
            f"Config validation failed ({len(errors)} error(s)):\n" + "\n".join(errors)
        )


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ─────────────────────────────────────────────────────────────────────────────
#  audit_settings
# ─────────────────────────────────────────────────────────────────────────────

class _ROIProfileSchema(_Strict):
    """Per-context overrides; an omitted value inherits the base ``roi`` value."""

    manual_minutes_per_device: Optional[float] = Field(default=None, ge=0)
    manual_minutes_per_check: Optional[float] = Field(default=None, ge=0)
    automation_overhead_minutes_per_device: Optional[float] = Field(default=None, ge=0)
    validation_minutes_per_device: Optional[float] = Field(default=None, ge=0)


class _ROIProfilesSchema(_Strict):
    audit: _ROIProfileSchema = Field(default_factory=_ROIProfileSchema)
    post_remediation: _ROIProfileSchema = Field(default_factory=_ROIProfileSchema)


class _ROISchema(_Strict):
    enabled: bool = True
    manual_minutes_per_device: float = Field(default=20.0, ge=0)
    manual_minutes_per_check: float = Field(default=0.25, ge=0)
    automation_overhead_minutes_per_device: float = Field(default=2.0, ge=0)
    validation_minutes_per_device: float = Field(default=0.0, ge=0)
    min_runtime_seconds: float = Field(default=0.0, ge=0)
    check_scaling_inflection: float = Field(default=20.0, ge=0)
    max_manual_minutes_per_device: float = Field(default=120.0, ge=0)
    hourly_rate: float = Field(default=0.0, ge=0)
    currency: str = "GBP"
    profiles: _ROIProfilesSchema = Field(default_factory=_ROIProfilesSchema)


# The remediation defaults are deliberately fail-safe: if a key is removed,
# execution is off and approvals need a ticket.  The shipped YAML opts in
# explicitly, so a missing key can never widen what the tool may do.
class _RemediationApprovalSchema(_Strict):
    default_expires_hours: int = Field(default=24, ge=1, le=8760)
    require_ticket_id: bool = True


class _RemediationExecutionSchema(_Strict):
    enabled: bool = False
    linux_only: bool = True
    block_high_risk_by_default: bool = True
    enforce_checksum: bool = True
    preflight_drift_check: bool = True
    require_hostname_match: bool = True
    save_config: bool = True
    command_verify: bool = False
    allow_bulk_apply: bool = True
    generate_post_report: bool = True
    generate_consolidated_post_report: bool = True
    post_report_formats: list[Literal["json", "html"]] = Field(
        default_factory=lambda: ["json", "html"]
    )


class _RemediationSchema(_Strict):
    enabled: bool = True
    generate_script: bool = True
    generate_review_pack: bool = True
    approval: _RemediationApprovalSchema = Field(
        default_factory=_RemediationApprovalSchema
    )
    execution: _RemediationExecutionSchema = Field(
        default_factory=_RemediationExecutionSchema
    )


class AuditSettingsSchema(_Strict):
    max_workers: int = Field(default=5, ge=1, le=100)
    collect_timeout: int = Field(default=30, ge=1, le=600)
    retries: Optional[int] = Field(default=None, ge=0, le=20)
    output_dir: str = "./reports"
    html_report: bool = True
    json_report: bool = True
    csv_report: bool = False
    delta_report: bool = True
    report_title: str = ""
    report_subtitle: str = ""
    default_min_severity: Literal["critical", "high", "medium", "low", "info", ""] = ""
    default_tags: list[str] = Field(default_factory=list)
    parking_vlan: VlanId = 99
    native_vlan: VlanId = 99
    roi: _ROISchema = Field(default_factory=_ROISchema)
    remediation: _RemediationSchema = Field(default_factory=_RemediationSchema)


# ─────────────────────────────────────────────────────────────────────────────
#  connection
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionSchema(_Strict):
    device_type: str = "cisco_xe"
    timeout: int = Field(default=30, ge=1, le=300)
    retries: int = Field(default=3, ge=0, le=20)
    jump_host: Optional[HostOrIP] = None
    use_jump_host: bool = False
    credential_store: Literal["none", "keyring"] = "none"
    keyring_service: str = "cisco-compliance-audit"
    host_key_checking: bool = False

    @field_validator("jump_host", mode="before")
    @classmethod
    def _blank_is_unset(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("device_type")
    @classmethod
    def _check_device_type(cls, v: str) -> str:
        try:
            from netmiko.ssh_dispatcher import CLASS_MAPPER
        except ImportError:  # pragma: no cover - netmiko is a core dependency
            return v
        if v not in CLASS_MAPPER:
            hint = difflib.get_close_matches(v, CLASS_MAPPER, n=3)
            raise ValueError(
                f"'{v}' is not a Netmiko device_type"
                + (f" (did you mean: {', '.join(hint)}?)" if hint else "")
            )
        return v

    @model_validator(mode="after")
    def _jump_host_when_used(self) -> "ConnectionSchema":
        if self.use_jump_host and self.jump_host is None:
            raise ValueError("use_jump_host is true but jump_host is empty")
        return self


# ─────────────────────────────────────────────────────────────────────────────
#  classification (top-level keys in the merged config)
# ─────────────────────────────────────────────────────────────────────────────

class _HostnameRoleSchema(_Strict):
    code: str = Field(pattern=r"^[A-Za-z]+$")
    role: str = Field(min_length=1)
    display: str = ""
    trunk_signal: Literal["uplink", "downlink", "none"] = "none"


class _EndpointNeighborsSchema(_Strict):
    enabled: bool = True
    hostname_patterns: list[Regex] = Field(default_factory=list)
    platform_patterns: list[Regex] = Field(default_factory=list)
    capabilities: list[Regex] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  Compliance check nodes
# ─────────────────────────────────────────────────────────────────────────────

#: Compliance sections whose values are ``{check_key: check_node}``.
CHECK_SECTIONS = ("management_plane", "control_plane", "data_plane")

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


class CheckNodeSchema(_Strict):
    """Fields common to every compliance check node.

    The shared fields are required rather than defaulted.  ``_enabled()``
    runs a check only on ``enabled: true``, so a typo such as ``enabld: true``
    would silently leave it off; requiring the key makes that an error.

    Checks with their own settings subclass this and declare them, so each
    check accepts exactly the keys the engine reads for it.
    """

    enabled: bool
    severity: Severity
    tags: list[str]
    framework_controls: dict[str, str] = Field(default_factory=dict)
    applies_to_roles: Optional[list[str]] = None
    # ``_annotate_findings`` swallows ``re.error`` when applying these, so an
    # invalid pattern would silently stop filtering instead of failing loudly.
    include_hostnames: Optional[list[Regex]] = None
    exclude_hostnames: Optional[list[Regex]] = None
    include_groups: Optional[list[str]] = None
    exclude_groups: Optional[list[str]] = None
    exclude_interfaces: Optional[list[Regex]] = None


class _ExpectedText(CheckNodeSchema):
    expected: str = ""


class _SourceInterface(CheckNodeSchema):
    interface: str = ""


class _AclName(CheckNodeSchema):
    acl_name: str = ""


class _MethodList(CheckNodeSchema):
    method_list: str = "default"


class _Banner(CheckNodeSchema):
    required_text: str = ""


class _LoggingConsole(CheckNodeSchema):
    """``level`` is the most verbose level allowed on the console."""

    level: SyslogLevel = "critical"


class _LoggingMonitor(CheckNodeSchema):
    """``level`` is the most verbose level allowed on terminal monitors."""

    level: SyslogLevel = "warnings"


class _LoggingTrap(CheckNodeSchema):
    """``level`` is the least verbose level allowed for syslog servers."""

    level: SyslogLevel = "informational"


class _ExecTimeout(CheckNodeSchema):
    minutes: int = Field(default=5, ge=0, le=35791)
    seconds: int = Field(default=0, ge=0, le=2147483)


class _CommandLevels(CheckNodeSchema):
    """``expected_prefix`` may contain ``{level}``; each level gets its own line."""

    levels: list[int] = Field(default_factory=lambda: [15])
    expected_prefix: str = ""

    @field_validator("levels")
    @classmethod
    def _privilege_levels(cls, v: list[int]) -> list[int]:
        bad = [lvl for lvl in v if not 0 <= lvl <= 15]
        if bad:
            raise ValueError(f"privilege levels must be 0-15 (got {bad})")
        return v


class _AuthorizationCommands(_CommandLevels):
    expected_prefix: str = "aaa authorization commands {level} default group tacacs+ local"


class _AccountingCommands(_CommandLevels):
    expected_prefix: str = "aaa accounting commands {level} default start-stop group tacacs+"


class _ServerCount(CheckNodeSchema):
    min_servers: int = Field(default=1, ge=0)


class _GlobalState(CheckNodeSchema):
    state: Literal["enabled", "disabled"] = "enabled"


class _IpHttpAuthentication(CheckNodeSchema):
    method: Literal["local", "aaa", "enable"] = "local"


class _ClockTimezone(CheckNodeSchema):
    """An empty ``timezone`` accepts any; ``offset`` is checked only when set."""

    timezone: str = ""
    offset: Optional[int] = Field(default=None, ge=-23, le=23)
    offset_minutes: int = Field(default=0, ge=0, le=59)


class _SshVersion(CheckNodeSchema):
    version: Literal[1, 2] = 2


class _SshTimeout(CheckNodeSchema):
    max_seconds: int = Field(default=60, ge=1, le=120)


class _SshRetries(CheckNodeSchema):
    max_retries: int = Field(default=3, ge=0, le=5)


class _SshRsaModulus(CheckNodeSchema):
    min_bits: int = Field(default=2048, ge=360, le=4096)


class _NtpServers(CheckNodeSchema):
    expected_servers: list[HostOrIP] = Field(default_factory=list)
    min_servers: int = Field(default=1, ge=0)


class _LoggingBuffered(CheckNodeSchema):
    """``level`` is the least verbose level allowed; ``min_size`` 0 skips the size check."""

    min_size: int = Field(default=0, ge=0)
    level: SyslogLevel = "informational"


class _LoggingHost(CheckNodeSchema):
    expected_hosts: list[HostOrIP] = Field(default_factory=list)
    min_hosts: int = Field(default=1, ge=0)


class _LoggingOriginId(CheckNodeSchema):
    type: Literal["hostname", "ip", "ipv6", "string"] = "hostname"
    string: str = ""

    @model_validator(mode="after")
    def _string_needs_text(self) -> "_LoggingOriginId":
        if self.type == "string" and not self.string.strip():
            raise ValueError("type 'string' needs the origin text in 'string'")
        return self


class _SnmpServerHost(CheckNodeSchema):
    expected_hosts: list[HostOrIP] = Field(default_factory=list)


class _LoginBlockFor(CheckNodeSchema):
    """Minimums for ``seconds``/``within``, maximum for ``attempts``."""

    seconds: int = Field(default=120, ge=1, le=65535)
    attempts: int = Field(default=3, ge=1, le=65535)
    within: int = Field(default=60, ge=1, le=65535)


class _LoginDelay(CheckNodeSchema):
    """Minimum delay between login attempts."""

    seconds: int = Field(default=2, ge=1, le=10)


class _StpMode(CheckNodeSchema):
    mode: Literal["pvst", "rapid-pvst", "mst"] = "rapid-pvst"


class _StpPathcost(CheckNodeSchema):
    method: Literal["short", "long"] = "long"


def _bridge_priority(v: int) -> int:
    if not 0 <= v <= 61440 or v % 4096:
        raise ValueError(f"must be a multiple of 4096 between 0 and 61440 (got {v})")
    return v


class _StpPriority(CheckNodeSchema):
    """Base bridge priority (without the VLAN system-ID extension).

    Access switches must not be *more* preferred than ``access_priority``, so
    they can never win the root election; switches whose role is in
    ``core_roles`` must be at least as preferred as ``core_priority``.
    """

    core_priority: int = 4096
    access_priority: int = 32768
    core_roles: list[str] = Field(default_factory=lambda: ["core_switch"])

    @field_validator("core_priority", "access_priority")
    @classmethod
    def _check_priorities(cls, v: int) -> int:
        return _bridge_priority(v)


class _VtpMode(CheckNodeSchema):
    expected: Literal["off", "transparent", "server", "client"] = "off"


class _VlanList(CheckNodeSchema):
    vlans: VlanSpec = ""


class _ArpInspectionValidate(CheckNodeSchema):
    checks: list[Literal["src-mac", "dst-mac", "ip"]] = Field(default_factory=list)


class _ErrdisableRecovery(CheckNodeSchema):
    causes: list[str] = Field(default_factory=list)
    interval: Optional[int] = Field(default=None, ge=30, le=86400)


class _UdldGlobal(CheckNodeSchema):
    mode: Literal["enable", "aggressive"] = "enable"


StormType = Literal["broadcast", "multicast", "unicast"]


class _StormThreshold(_Strict):
    rising: float = Field(ge=0, le=100)
    falling: Optional[float] = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def _falling_below_rising(self) -> "_StormThreshold":
        if self.falling is not None and self.falling > self.rising:
            raise ValueError(
                f"falling ({self.falling}) must not exceed rising ({self.rising})"
            )
        return self


class _StormTier(_Strict):
    broadcast: Optional[_StormThreshold] = None
    multicast: Optional[_StormThreshold] = None
    unicast: Optional[_StormThreshold] = None

    @field_validator("broadcast", "multicast", "unicast", mode="before")
    @classmethod
    def _bare_number_is_rising(cls, v: Any) -> Any:
        # A bare number is the legacy single-threshold format the engine still reads.
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return {"rising": v}
        return v


class _StormControl(CheckNodeSchema):
    check_thresholds: bool = True
    check_action: bool = False
    action: Literal["shutdown", "trap"] = "shutdown"
    types: list[StormType] = Field(default_factory=lambda: ["broadcast", "multicast"])
    thresholds_by_speed: dict[int, _StormTier] = Field(default_factory=dict)
    default_thresholds: _StormTier = Field(default_factory=_StormTier)

    @field_validator("thresholds_by_speed")
    @classmethod
    def _positive_speeds(cls, v: dict[int, _StormTier]) -> dict[int, _StormTier]:
        bad = [speed for speed in v if speed <= 0]
        if bad:
            raise ValueError(f"speed tiers must be positive Mbps values (got {bad})")
        return v


class _BpduGuard(CheckNodeSchema):
    on_endpoint_trunks: bool = False


class _PortSecurity(CheckNodeSchema):
    """Unset values are not checked.  ``aging_type`` is checked only with ``aging_time``."""

    max_mac: Optional[int] = Field(default=None, ge=1)
    violation: Optional[Literal["protect", "restrict", "shutdown"]] = None
    aging_type: Literal["absolute", "inactivity"] = "absolute"
    aging_time: int = Field(default=0, ge=0, le=1440)


class _AccessVlanSet(CheckNodeSchema):
    disallowed_vlans: list[VlanId] = Field(default_factory=lambda: [1])


class _DhcpSnoopingLimitRate(CheckNodeSchema):
    rate: int = Field(default=15, ge=1, le=2048)


class _UntrustedPortKindsSchema(_Strict):
    """Ports where a trust command must NOT be present.

    Forbidding unknown keys matters most here: a mistyped port kind would
    otherwise be ignored and the check would quietly stop enforcing.
    """

    access_ports: bool = True
    uplinks: bool = False
    downlinks: bool = False
    unknown_trunks: bool = False
    endpoint_trunks: bool = True
    unused_ports: bool = True


class PortTrustCheckSchema(CheckNodeSchema):
    on_access_ports: bool = False
    on_uplinks: bool = True
    on_downlinks: bool = True
    on_unknown_trunks: bool = False
    on_endpoint_trunks: bool = False
    on_unused_ports: bool = False
    untrusted: _UntrustedPortKindsSchema = Field(
        default_factory=_UntrustedPortKindsSchema
    )


#: data_plane check keys validated by :class:`PortTrustCheckSchema`.
PORT_TRUST_CHECKS = ("dhcp_snooping_trust", "arp_inspection_trust")


class _UnusedPorts(CheckNodeSchema):
    must_be_shutdown: bool = True
    must_be_access_mode: bool = False
    must_be_in_parking_vlan: bool = False
    must_have_nonegotiate: bool = False
    must_have_bpduguard: bool = False
    must_have_no_cdp: bool = False
    must_have_no_lldp: bool = False
    must_have_description: bool = True
    expected_description: str = "* unused *"


class _TrunkNativeVlan(CheckNodeSchema):
    on_uplinks: bool = True
    on_downlinks: bool = True
    on_endpoint_trunks: bool = True
    expected_vlan: VlanId = 99
    expected_vlan_endpoint: Optional[VlanId] = None


_Plain = CheckNodeSchema

#: Every check the engine knows, per section, mapped to the schema for its
#: node.  ``tests/test_config_schema.py`` cross-checks this against the check
#: modules and the shipped YAML so it cannot drift silently.
CHECK_SCHEMAS: dict[str, dict[str, Type[CheckNodeSchema]]] = {
    "management_plane": {
        "service_password_encryption": _Plain,
        "service_timestamps_debug": _ExpectedText,
        "service_timestamps_log": _ExpectedText,
        "service_tcp_keepalives_in": _Plain,
        "service_tcp_keepalives_out": _Plain,
        "no_service_pad": _Plain,
        "no_service_finger": _Plain,
        "no_service_config": _Plain,
        "no_service_tcp_small_servers": _Plain,
        "no_service_udp_small_servers": _Plain,
        "no_ip_source_route": _Plain,
        "no_ip_finger": _Plain,
        "no_ip_bootp_server": _Plain,
        "no_ip_http_server": _Plain,
        "ip_http_secure_server": _Plain,
        "no_ip_http_secure_server": _Plain,
        "ip_http_authentication": _IpHttpAuthentication,
        "ip_http_access_class": _AclName,
        "no_ip_gratuitous_arps": _Plain,
        "ip_cef": _Plain,
        "no_ip_domain_lookup": _Plain,
        "ip_domain_name": _ExpectedText,
        "clock_timezone": _ClockTimezone,
        "ssh_version": _SshVersion,
        "ssh_timeout": _SshTimeout,
        "ssh_authentication_retries": _SshRetries,
        "ssh_source_interface": _SourceInterface,
        "ssh_rsa_min_modulus": _SshRsaModulus,
        "aaa_new_model": _Plain,
        "aaa_authentication_login": _ExpectedText,
        "aaa_authentication_enable": _ExpectedText,
        "aaa_authorization_console": _ExpectedText,
        "aaa_authorization_exec": _ExpectedText,
        "aaa_authorization_commands": _AuthorizationCommands,
        "aaa_accounting_exec": _ExpectedText,
        "aaa_accounting_commands": _AccountingCommands,
        "aaa_accounting_connection": _ExpectedText,
        "aaa_session_id": _ExpectedText,
        "tacacs_server": _ServerCount,
        "tacacs_source_interface": _SourceInterface,
        "radius_server": _ServerCount,
        "ntp_servers": _NtpServers,
        "ntp_authenticate": _Plain,
        "ntp_source_interface": _SourceInterface,
        "logging_buffered": _LoggingBuffered,
        "logging_console": _LoggingConsole,
        "logging_monitor": _LoggingMonitor,
        "logging_trap": _LoggingTrap,
        "logging_host": _LoggingHost,
        "logging_source_interface": _SourceInterface,
        "logging_origin_id": _LoggingOriginId,
        "no_logging_console": _Plain,
        "snmp_v3_only": _Plain,
        "snmp_no_community_public": _Plain,
        "snmp_no_community_private": _Plain,
        "snmp_community_acl": _Plain,
        "snmp_server_host": _SnmpServerHost,
        "snmp_contact": _ExpectedText,
        "snmp_location": _ExpectedText,
        "snmp_ifindex_persist": _Plain,
        "banner_login": _Banner,
        "banner_motd": _Banner,
        "banner_exec": _Banner,
        "enable_secret": _Plain,
        "no_enable_password": _Plain,
        "username_secret": _Plain,
        "vty_transport_input_ssh": _Plain,
        "vty_exec_timeout": _ExecTimeout,
        "vty_access_class": _AclName,
        "vty_logging_synchronous": _Plain,
        "vty_login_authentication": _MethodList,
        "console_exec_timeout": _ExecTimeout,
        "console_logging_synchronous": _Plain,
        "console_login_authentication": _MethodList,
        "login_block_for": _LoginBlockFor,
        "login_on_failure_log": _Plain,
        "login_on_success_log": _Plain,
        "login_delay": _LoginDelay,
        "cdp_global": _GlobalState,
        "lldp_global": _GlobalState,
    },
    "control_plane": {
        "stp_mode": _StpMode,
        "stp_extend_system_id": _Plain,
        "stp_pathcost_method": _StpPathcost,
        "stp_loopguard_default": _Plain,
        "stp_priority": _StpPriority,
        "stp_backbonefast": _Plain,
        "stp_uplinkfast": _Plain,
        "vtp_mode": _VtpMode,
        "vtp_domain": _ExpectedText,
        "dhcp_snooping_global": _Plain,
        "dhcp_snooping_vlans": _VlanList,
        "no_dhcp_snooping_information_option": _Plain,
        "arp_inspection_vlans": _VlanList,
        "arp_inspection_validate": _ArpInspectionValidate,
        "errdisable_recovery": _ErrdisableRecovery,
        "udld_global": _UdldGlobal,
        "control_plane_policing": _Plain,
    },
    "data_plane": {
        "storm_control": _StormControl,
        "bpdu_guard": _BpduGuard,
        "root_guard": _Plain,
        "portfast": _Plain,
        "switchport_nonegotiate": _Plain,
        "port_security": _PortSecurity,
        "trunk_allowed_vlans": _Plain,
        "switchport_mode_explicit": _Plain,
        "access_vlan_set": _AccessVlanSet,
        "interface_description": _Plain,
        "dhcp_snooping_trust": PortTrustCheckSchema,
        "dhcp_snooping_limit_rate": _DhcpSnoopingLimitRate,
        "ip_source_guard": _Plain,
        "arp_inspection_trust": PortTrustCheckSchema,
        "unused_ports": _UnusedPorts,
        "no_cdp_on_access_ports": _Plain,
        "no_ip_proxy_arp": _Plain,
        "trunk_native_vlan": _TrunkNativeVlan,
    },
}

#: ``compliance.role_specific.<role>`` → the checks the engine runs for it.
ROLE_CHECK_SCHEMAS: dict[str, dict[str, Type[CheckNodeSchema]]] = {
    "access_switch": {
        "stp_not_root": _Plain,
        "uplink_redundancy": _Plain,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  Policy exceptions  (exceptions.yaml — see compliance_audit.policy_exceptions)
# ─────────────────────────────────────────────────────────────────────────────

#: Singular spellings accepted for the list-valued exception selectors, so
#: ``check: bpdu_guard`` and ``checks: [bpdu_guard]`` mean the same thing.
EXCEPTION_SINGULAR_KEYS = {
    "hostname": "hostnames",
    "ip": "ips",
    "group": "groups",
    "role": "roles",
    "check": "checks",
    "interface": "interfaces",
}

#: A check selector that is a bare name rather than a regex.
_PLAIN_CHECK_NAME = re.compile(r"^[A-Za-z0-9_]+$")


def _ip_network(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"must be an IP address or CIDR network, got {type(value).__name__}")
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError as exc:
        raise ValueError(f"'{value}' is not an IP address or CIDR network") from exc


#: An IP address or network; host bits are allowed (``10.1.2.3/24``).
IpNetwork = Annotated[str, PlainValidator(_ip_network)]


class ExceptionSettingsSchema(_Strict):
    expiring_soon_days: int = Field(default=30, ge=0, le=3650)
    expired_counts_against_score: bool = False
    fail_on_expired: bool = False
    allow_permanent: bool = False


class ExceptionEntrySchema(_Strict):
    """One approved deviation.  Every selector given must match."""

    id: str
    reason: str
    expires: Union[date, Literal["never"]]
    approved_by: str = ""
    approved_on: Optional[date] = None
    ticket: str = ""
    owner: str = ""
    notes: str = ""
    # Device selectors — at least one is required.
    hostnames: list[Regex] = Field(default_factory=list)
    ips: list[IpNetwork] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    # Finding selectors — ``checks`` is required.
    checks: list[Regex] = Field(min_length=1)
    interfaces: list[Regex] = Field(default_factory=list)
    detail: Optional[Regex] = None

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        data.pop("_source", None)  # added by the loader, not by the operator
        for single, plural in EXCEPTION_SINGULAR_KEYS.items():
            if single in data:
                if plural in data:
                    raise ValueError(f"use either '{single}' or '{plural}', not both")
                data[plural] = data.pop(single)
        for plural in EXCEPTION_SINGULAR_KEYS.values():
            value = data.get(plural)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                data[plural] = [value]
        for key in ("id", "ticket"):  # ``id: 42`` / ``ticket: 12345`` are fine
            value = data.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                data[key] = str(value)
        return data

    @field_validator("id", "reason")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v

    @field_validator("id")
    @classmethod
    def _id_shape(cls, v: str) -> str:
        if any(ch.isspace() for ch in v):
            raise ValueError("must not contain whitespace")
        return v

    @model_validator(mode="after")
    def _needs_a_device_and_sane_dates(self) -> "ExceptionEntrySchema":
        if not (self.hostnames or self.ips or self.groups or self.roles):
            raise ValueError(
                "needs at least one device selector — hostnames, ips, groups or "
                "roles (use hostnames: ['.*'] to cover every device on purpose)"
            )
        if (
            self.approved_on is not None
            and isinstance(self.expires, date)
            and self.approved_on > self.expires
        ):
            raise ValueError(
                f"approved_on ({self.approved_on}) is after expires ({self.expires})"
            )
        return self


# ─────────────────────────────────────────────────────────────────────────────
#  Notifications  (notifications.yaml — see compliance_audit.notifications)
# ─────────────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")


def _email_address(value: object) -> str:
    if not isinstance(value, str) or not _EMAIL_RE.match(value.strip()):
        raise ValueError(f"{value!r} is not an email address")
    return value.strip()


EmailAddress = Annotated[str, PlainValidator(_email_address)]


class EmailNotificationSchema(_Strict):
    """SMTP settings for run, apply and failure emails."""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=25, ge=1, le=65535)
    #: ``starttls`` upgrades a plain connection (relays on 25/587);
    #: ``ssl`` connects with TLS from the start (465); ``none`` sends in clear.
    security: Literal["none", "starttls", "ssl"] = "starttls"
    #: Optional SMTP AUTH user; the password comes from SMTP_PASSWORD.
    username: str = ""
    from_address: Optional[EmailAddress] = None
    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    subject_prefix: str = "[Compliance Audit]"
    #: When a scheduled audit sends its run email:
    #: ``always``; ``issues`` (anything not fully compliant, unreachable devices,
    #: expired exceptions); ``action_required`` (packs awaiting approval,
    #: unreachable devices, ERROR findings, expired exceptions).
    send_when: Literal["always", "issues", "action_required"] = "always"
    notify_on_apply: bool = True
    notify_on_failure: bool = True
    attach_report: bool = True
    attach_scripts: bool = True
    max_attachment_mb: float = Field(default=10.0, ge=0, le=100)
    #: Findings listed per device in the email body (0 = all of them).
    max_findings_per_device: int = Field(default=100, ge=0)
    #: How an approver runs the tool on the audit host, shown in the
    #: approve/reject commands.  Blank = the Python that ran the audit.
    command: str = ""
    timeout: int = Field(default=30, ge=1, le=300)

    @field_validator("from_address", mode="before")
    @classmethod
    def _blank_is_unset(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @model_validator(mode="after")
    def _complete_when_enabled(self) -> "EmailNotificationSchema":
        if self.enabled:
            missing = [
                name for name, value in (
                    ("smtp_host", self.smtp_host.strip()),
                    ("from_address", self.from_address),
                    ("to", self.to),
                ) if not value
            ]
            if missing:
                raise ValueError(
                    "email is enabled but these are not set: " + ", ".join(missing)
                )
        return self


class NotificationsSchema(_Strict):
    email: EmailNotificationSchema = Field(default_factory=EmailNotificationSchema)


#: Top-level keys of the merged config, and the compliance sub-sections.
TOP_LEVEL_KEYS = (
    "audit_settings",
    "connection",
    "compliance",
    "inventory_file",
    "hostname_roles",
    "endpoint_neighbors",
    "exceptions",
    "exception_settings",
    "exceptions_file",
    "notifications",
)
COMPLIANCE_SECTIONS = CHECK_SECTIONS + ("role_specific",)

#: Check pairs that demand opposite things; enabling both guarantees a FAIL.
MUTUALLY_EXCLUSIVE = (
    ("management_plane", "ip_http_secure_server", "no_ip_http_secure_server"),
    ("management_plane", "logging_console", "no_logging_console"),
)


# ─────────────────────────────────────────────────────────────────────────────
#  Error formatting
# ─────────────────────────────────────────────────────────────────────────────

def _join_path(prefix: str, loc: tuple) -> str:
    path = prefix
    for part in loc:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{part}" if path else str(part)
    return path


def _model_at(model: Type[BaseModel], loc: tuple) -> Optional[Type[BaseModel]]:
    """Walk *loc* through nested model fields; return the model it lands on."""
    current: Any = model
    for part in loc:
        if not (isinstance(current, type) and issubclass(current, BaseModel)):
            return None
        field = current.model_fields.get(part) if isinstance(part, str) else None
        if field is None:
            return None
        current = field.annotation
    return current if isinstance(current, type) and issubclass(current, BaseModel) else None


def _suggest(name: str, choices) -> str:
    hint = difflib.get_close_matches(str(name), list(choices), n=1)
    return f" — did you mean '{hint[0]}'?" if hint else ""


def _fmt_errors(
    exc: ValidationError, prefix: str, model: Optional[Type[BaseModel]] = None
) -> list[str]:
    """Format a Pydantic ``ValidationError`` into readable one-line messages."""
    out: list[str] = []
    for e in exc.errors():
        loc = tuple(e["loc"])
        path = _join_path(prefix, loc)
        if e["type"] == "extra_forbidden":
            parent = _model_at(model, loc[:-1]) if model else None
            hint = _suggest(loc[-1], parent.model_fields) if parent else ""
            out.append(f"  {path}: unknown key{hint}")
            continue
        msg = e["msg"].removeprefix("Value error, ")
        given = e.get("input")
        if e["type"] != "missing" and isinstance(given, (str, int, float, bool)):
            if repr(given) not in msg and str(given) not in msg:
                msg += f" (got {given!r})"
        out.append(f"  {path}: {msg}")
    return out


def _validate(model: Type[BaseModel], data: Any, prefix: str) -> list[str]:
    try:
        model.model_validate(data)
    except ValidationError as exc:
        return _fmt_errors(exc, prefix, model)
    return []


# ─────────────────────────────────────────────────────────────────────────────
#  Section validators
# ─────────────────────────────────────────────────────────────────────────────

def _check_owner(check_key: str) -> Optional[str]:
    for section, checks in CHECK_SCHEMAS.items():
        if check_key in checks:
            return section
    return None


def _validate_checks(
    prefix: str,
    checks: dict,
    schemas: dict[str, Type[CheckNodeSchema]],
    known_roles: set[str],
) -> list[str]:
    errors: list[str] = []
    for check_key, node in checks.items():
        path = f"{prefix}.{check_key}"
        schema = schemas.get(check_key)
        if schema is None:
            owner = _check_owner(check_key)
            if owner and not prefix.endswith(owner):
                errors.append(
                    f"  {path}: '{check_key}' is a {owner} check — move it under "
                    f"compliance.{owner} (it is ignored here)"
                )
            else:
                errors.append(
                    f"  {path}: unknown check — it would never run"
                    + _suggest(check_key, schemas)
                )
            continue
        if not isinstance(node, dict):
            errors.append(f"  {path}: must be a mapping, got {type(node).__name__}")
            continue
        errors.extend(_validate(schema, node, path))

        roles = node.get("applies_to_roles")
        if isinstance(roles, list) and known_roles:
            for role in roles:
                if role not in known_roles:
                    errors.append(
                        f"  {path}.applies_to_roles: unknown role '{role}' — the "
                        "check would be skipped on every device (known roles: "
                        + ", ".join(sorted(known_roles)) + ")"
                    )
    return errors


def _known_roles(cfg: dict) -> set[str]:
    """Role identifiers a device can be assigned (``unknown`` = unparsed hostname)."""
    roles = cfg.get("hostname_roles")
    if not isinstance(roles, list):
        from .hostname_parser import DEFAULT_ROLES

        roles = DEFAULT_ROLES
    return {
        str(entry["role"]) for entry in roles if isinstance(entry, dict) and entry.get("role")
    } | {"unknown"}


def _validate_compliance(cfg: dict) -> list[str]:
    """Validate the section layout and every check node under ``compliance:``."""
    compliance = cfg.get("compliance")
    if compliance is None:
        return []
    if not isinstance(compliance, dict):
        return [f"  compliance: must be a mapping, got {type(compliance).__name__}"]

    errors: list[str] = []
    known_roles = _known_roles(cfg)
    for section, first, second in MUTUALLY_EXCLUSIVE:
        checks = compliance.get(section)
        if isinstance(checks, dict) and all(
            isinstance(checks.get(k), dict) and checks[k].get("enabled") is True
            for k in (first, second)
        ):
            errors.append(
                f"  compliance.{section}: '{first}' and '{second}' are both enabled — "
                "they require opposite configuration, so one always fails; disable one"
            )
    for section, checks in compliance.items():
        prefix = f"compliance.{section}"
        if section not in COMPLIANCE_SECTIONS:
            errors.append(
                f"  {prefix}: unknown section" + _suggest(section, COMPLIANCE_SECTIONS)
            )
            continue
        if checks is None:
            continue
        if not isinstance(checks, dict):
            errors.append(f"  {prefix}: must be a mapping, got {type(checks).__name__}")
            continue
        if section != "role_specific":
            errors.extend(
                _validate_checks(prefix, checks, CHECK_SCHEMAS[section], known_roles)
            )
            continue
        for role, role_checks in checks.items():
            role_prefix = f"{prefix}.{role}"
            if role not in ROLE_CHECK_SCHEMAS:
                errors.append(
                    f"  {role_prefix}: no role-specific checks exist for this role "
                    f"(supported: {', '.join(ROLE_CHECK_SCHEMAS)})"
                )
                continue
            if not isinstance(role_checks, dict):
                errors.append(
                    f"  {role_prefix}: must be a mapping, got {type(role_checks).__name__}"
                )
                continue
            errors.extend(
                _validate_checks(
                    role_prefix, role_checks, ROLE_CHECK_SCHEMAS[role], known_roles
                )
            )
    return errors


def _validate_hostname_roles(roles: Any) -> list[str]:
    if roles is None:
        return []
    if not isinstance(roles, list):
        return [f"  hostname_roles: must be a list, got {type(roles).__name__}"]
    errors: list[str] = []
    seen: dict[str, int] = {}
    for i, entry in enumerate(roles):
        path = f"hostname_roles[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"  {path}: must be a mapping, got {type(entry).__name__}")
            continue
        errors.extend(_validate(_HostnameRoleSchema, entry, path))
        code = str(entry.get("code", "")).upper()
        if code in seen:
            errors.append(
                f"  {path}.code: duplicate role code '{code}' "
                f"(already defined at hostname_roles[{seen[code]}])"
            )
        elif code:
            seen[code] = i
    return errors


def _known_finding_name(name: str) -> bool:
    """True if *name* is a check key or a finding name the engine can emit."""
    from .checks.base import FINDING_NAME_ALIASES, UNOWNED_FINDING_NAMES

    keys = {k for schemas in CHECK_SCHEMAS.values() for k in schemas}
    keys |= {k for schemas in ROLE_CHECK_SCHEMAS.values() for k in schemas}
    name = name.lower()
    if name in keys or name in FINDING_NAME_ALIASES or name in UNOWNED_FINDING_NAMES:
        return True
    return any(name.startswith(k + "_") for k in keys)


def _all_finding_names() -> list[str]:
    from .checks.base import FINDING_NAME_ALIASES, UNOWNED_FINDING_NAMES

    keys = {k for schemas in CHECK_SCHEMAS.values() for k in schemas}
    keys |= {k for schemas in ROLE_CHECK_SCHEMAS.values() for k in schemas}
    return sorted(keys | set(FINDING_NAME_ALIASES) | set(UNOWNED_FINDING_NAMES))


def _exception_label(index: int, entry: Any) -> str:
    eid = entry.get("id") if isinstance(entry, dict) else None
    return f"exceptions[{index}:{eid}]" if eid not in (None, "") else f"exceptions[{index}]"


def _validate_exceptions(cfg: dict) -> list[str]:
    """Validate ``exception_settings``, ``exceptions_file`` and ``exceptions``."""
    errors: list[str] = []

    settings = cfg.get("exception_settings")
    if settings is not None:
        errors.extend(_validate(ExceptionSettingsSchema, settings, "exception_settings"))
    allow_permanent = isinstance(settings, dict) and settings.get("allow_permanent") is True

    files = cfg.get("exceptions_file")
    if files is not None:
        listed = files if isinstance(files, list) else [files]
        if not all(isinstance(f, str) and f.strip() for f in listed):
            errors.append(
                "  exceptions_file: must be a path string or a list of path strings"
            )

    entries = cfg.get("exceptions")
    if entries is None:
        return errors
    if not isinstance(entries, list):
        return errors + [
            f"  exceptions: must be a list of exceptions, got {type(entries).__name__}"
        ]

    known_roles = _known_roles(cfg)
    seen: dict[str, str] = {}
    for i, entry in enumerate(entries):
        label = _exception_label(i, entry)
        source = entry.get("_source", "") if isinstance(entry, dict) else ""
        where = f" (in {source})" if source else ""
        if not isinstance(entry, dict):
            errors.append(f"  {label}: must be a mapping, got {type(entry).__name__}")
            continue

        entry_errors = _validate(ExceptionEntrySchema, entry, label)
        errors.extend(e + where for e in entry_errors)

        eid = str(entry.get("id", "")).strip()
        if eid:
            if eid in seen:
                errors.append(
                    f"  {label}.id: duplicate exception id '{eid}' "
                    f"(already used by {seen[eid]}){where}"
                )
            else:
                seen[eid] = label + where
        if entry_errors:
            continue

        model = ExceptionEntrySchema.model_validate(entry)
        if model.expires == "never" and not allow_permanent:
            errors.append(
                f"  {label}.expires: 'never' needs exception_settings.allow_permanent: "
                f"true — otherwise give the exception an expiry date{where}"
            )
        for role in model.roles:
            if role not in known_roles:
                errors.append(
                    f"  {label}.roles: unknown role '{role}' — the exception would "
                    "never match (known roles: "
                    + ", ".join(sorted(known_roles)) + f"){where}"
                )
        for pattern in model.checks:
            if _PLAIN_CHECK_NAME.match(pattern) and not _known_finding_name(pattern):
                errors.append(
                    f"  {label}.checks: unknown check '{pattern}' — the exception "
                    "would never match"
                    + _suggest(pattern.lower(), _all_finding_names())
                    + where
                )
    return errors


# ─────────────────────────────────────────────────────────────────────────────
#  Public validation entry-points
# ─────────────────────────────────────────────────────────────────────────────

def validate_compliance_config(cfg: dict) -> list[str]:
    """Validate the merged compliance config dict.

    Returns a list of human-readable error strings.
    An empty list means the whole config is valid.
    """
    errors: list[str] = []

    for key in cfg:
        if key not in TOP_LEVEL_KEYS:
            errors.append(
                f"  {key}: unknown top-level key" + _suggest(key, TOP_LEVEL_KEYS)
            )

    if cfg.get("audit_settings") is not None:
        errors.extend(_validate(AuditSettingsSchema, cfg["audit_settings"], "audit_settings"))
    if cfg.get("connection") is not None:
        errors.extend(_validate(ConnectionSchema, cfg["connection"], "connection"))
    if cfg.get("endpoint_neighbors") is not None:
        errors.extend(
            _validate(_EndpointNeighborsSchema, cfg["endpoint_neighbors"], "endpoint_neighbors")
        )
    inventory_file = cfg.get("inventory_file")
    if inventory_file is not None and not (
        isinstance(inventory_file, str) and inventory_file.strip()
    ):
        errors.append("  inventory_file: must be a non-empty path string")

    errors.extend(_validate_hostname_roles(cfg.get("hostname_roles")))
    errors.extend(_validate_compliance(cfg))
    errors.extend(_validate_exceptions(cfg))
    if cfg.get("notifications") is not None:
        errors.extend(_validate(NotificationsSchema, cfg["notifications"], "notifications"))
    return errors


def ensure_valid_config(cfg: dict) -> dict:
    """Return *cfg* unchanged, or raise :class:`ConfigValidationError`."""
    errors = validate_compliance_config(cfg)
    if errors:
        raise ConfigValidationError(errors)
    return cfg
