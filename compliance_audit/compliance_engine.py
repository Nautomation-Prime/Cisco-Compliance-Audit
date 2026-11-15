"""
Compliance-check engine for Cisco IOS-XE.

The checks themselves live in :mod:`compliance_audit.checks`, one module per
policy section.  This module assembles them into a single ``ComplianceEngine``
and drives the run.

Every name callers have historically imported from here is re-exported below,
so ``from .compliance_engine import Finding, Status`` keeps working.
"""

import re
import logging
from typing import TYPE_CHECKING, Optional

from .collector import DeviceData, ParsedConfig
from .hostname_parser import HostnameInfo
from .port_classifier import PortInfo, PortRole
from .checks.base import (
    AuditResult,
    CheckPrimitives,
    Finding,
    SEVERITY_ORDER,
    Status,
    _PORT_CONTEXT_BY_ROLE,
    _PORT_KIND_BY_ROLE,
    _TRUST_CHECKS,
    _TRUST_FORBIDDEN_DEFAULTS,
    _TRUST_REQUIRED_KEYS,
    _annotate_findings,
    _build_check_map,
    _configured_vlans,
    _enabled,
    _expand_vlan_ranges,
    _find_check_node,
    _format_vlan_set,
    _pol,
    _snmp_community_has_acl,
    pi_has,
    pi_has_command,
    pi_int_arg,
    port_context,
    port_kind,
)
from .checks.control import ControlPlaneChecks
from .checks.data import DataPlaneChecks
from .checks.management import ManagementPlaneChecks
from .checks.role import RoleSpecificChecks

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .policy_exceptions import ExceptionRegister

log = logging.getLogger(__name__)

#: Public surface, plus every private helper that callers and tests have
#: historically imported from this module.  The imports above look unused to a
#: linter precisely because they exist to keep those import paths working.
__all__ = [
    "AuditResult",
    "ComplianceEngine",
    "Finding",
    "SEVERITY_ORDER",
    "Status",
    "pi_has",
    "pi_has_command",
    "pi_int_arg",
    "port_context",
    "port_kind",
    "_annotate_findings",
    "_build_check_map",
    "_configured_vlans",
    "_enabled",
    "_expand_vlan_ranges",
    "_find_check_node",
    "_format_vlan_set",
    "_pol",
    "_snmp_community_has_acl",
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class ComplianceEngine(
    ManagementPlaneChecks,
    ControlPlaneChecks,
    DataPlaneChecks,
    RoleSpecificChecks,
    CheckPrimitives,
):
    """Run all compliance checks against collected device data."""

    def __init__(self, policy: dict, exceptions: "Optional[ExceptionRegister]" = None):
        self.policy = policy  # compliance section of YAML
        #: Approved policy exceptions; covered FAIL/WARN findings become EXCEPTION.
        self.exceptions = exceptions
        self._current_data: DeviceData | None = None

    # ── public entry point ──────────────────────────────────────
    def audit(
        self,
        data: DeviceData,
        host_info: HostnameInfo,
        ports: dict[str, PortInfo],
        group: str = "",
    ) -> AuditResult:
        result = AuditResult(
            hostname=data.hostname or host_info.raw,
            ip=data.ip,
            role=host_info.role or "unknown",
            role_display=host_info.role_display or "Unknown",
            structured_parse_engine=dict(data.structured_parse_engine),
            group=group or "",
        )
        cfg = data.parsed_config
        if cfg is None:
            result.findings.append(
                Finding(
                    "config_read", Status.ERROR, "No running-config collected", "system"
                )
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
            ("management_plane", self._check_login_security),
            ("management_plane", self._check_cdp_lldp),
            ("control_plane", self._check_stp),
            ("control_plane", self._check_vtp),
            ("control_plane", self._check_dhcp_snooping),
            ("control_plane", self._check_arp_inspection),
            ("control_plane", self._check_errdisable),
            ("control_plane", self._check_udld),
            ("control_plane", self._check_copp),
            ("data_plane", self._check_interfaces),
            ("role_specific", self._check_role_specific),
        ]

        for category, func in check_groups:
            try:
                findings = func(cfg, data, host_info, ports)
                for f in findings:
                    f.category = f.category or category
                result.findings.extend(findings)
            except (
                AttributeError,
                LookupError,
                TypeError,
                ValueError,
                re.error,
            ) as exc:
                result.findings.append(
                    Finding(func.__name__, Status.ERROR, str(exc), category)
                )
                log.exception("Check %s raised an exception", func.__name__)

        # Annotate findings with severity/tags and apply YAML-level filters
        check_map = _build_check_map(self.policy)
        _annotate_findings(
            result.findings,
            check_map,
            role=host_info.role or "unknown",
            hostname=result.hostname,
            group=group,
        )

        # Policy exceptions come last, so they see each finding's final status
        # (a check already SKIP'd by a YAML filter is left alone).
        if self.exceptions is not None and len(self.exceptions):
            self.exceptions.apply_to_result(result, check_map)

        return result

