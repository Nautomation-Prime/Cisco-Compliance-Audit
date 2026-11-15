"""
Data-plane checks: per-interface policy applied by port role, including
the shared DHCP snooping / DAI trust placement rules.
"""

import re
import logging

from ..collector import DeviceData, ParsedConfig
from ..hostname_parser import HostnameInfo
from ..port_classifier import PortInfo, PortRole
from .base import (
    Finding,
    Status,
    _TRUST_CHECKS,
    _TRUST_FORBIDDEN_DEFAULTS,
    _TRUST_REQUIRED_KEYS,
    _enabled,
    _setting,
    pi_has,
    pi_has_command,
    pi_int_arg,
    port_context,
    port_kind,
)

log = logging.getLogger(__name__)


class DataPlaneChecks:
    """Checks for the data_plane policy section."""

    # ===================================================================
    #                       DATA  PLANE  CHECKS
    #       (per-interface, role-aware: access / trunk / unused)
    # ===================================================================

    def _check_interfaces(
        self,
        cfg: ParsedConfig,
        data: DeviceData,
        _host: HostnameInfo,
        ports: dict[str, PortInfo],
    ) -> list[Finding]:
        f: list[Finding] = []
        # Skip all data plane checks if data_plane not in policy (e.g. category filtering)
        if "data_plane" not in self.policy:
            return f
        dp = self.policy.get("data_plane", {})
        self._current_data = data  # stash for trunk_native_vlan lookups

        for pi in ports.values():
            role = pi.role

            # Port-channel members are classified as OTHER and skipped;
            # checks run against the Port-channel interface instead.
            if role == PortRole.ACCESS:
                f.extend(self._check_access_port(cfg, dp, pi))
            elif role == PortRole.TRUNK_ENDPOINT:
                f.extend(self._check_endpoint_trunk_port(cfg, dp, pi))
            elif role in (
                PortRole.TRUNK_UPLINK,
                PortRole.TRUNK_DOWNLINK,
                PortRole.TRUNK_UNKNOWN,
            ):
                f.extend(self._check_trunk_port(cfg, dp, pi))
            elif role == PortRole.UNUSED:
                f.extend(self._check_unused_port(cfg, dp, pi))
            elif role in (PortRole.ROUTED, PortRole.SVI):
                f.extend(self._check_routed_port(cfg, dp, pi))
            # Loopback / MGMT / port-channel members (OTHER) are not
            # subject to switchport-level data-plane checks.

            # DHCP snooping / DAI trust placement is policy-driven per port
            # kind for every switchport role, so it runs from one place.
            f.extend(self._check_port_trust(dp, pi))

        return f

    # ── PORT TRUST CHECKS (DHCP snooping / DAI) ───────────────
    def _check_port_trust(self, dp: dict, pi: PortInfo) -> list[Finding]:
        """Verify trust commands are present *and absent* where policy says.

        Cisco's guidance for both DHCP snooping and Dynamic ARP Inspection is
        to trust only the interfaces that lead to the DHCP server (uplinks and
        inter-switch links) and to leave every host-facing port untrusted — a
        trusted access port is exempt from snooping and DAI validation, which
        is exactly the port a rogue DHCP server or ARP spoofer sits on.

        Both halves are policy driven per port kind: ``on_<kind>`` says where
        the trust command is required, ``untrusted: {<kind>: true}`` says where
        it must not appear.  When a kind is listed in both, "required" wins.
        """
        f: list[Finding] = []
        kind = port_kind(pi.role)
        if not kind:
            return f

        intf = pi.name
        context = port_context(pi)

        for check_key, command, label in _TRUST_CHECKS:
            if not _enabled(dp, check_key):
                continue
            node = dp.get(check_key) or {}
            if not isinstance(node, dict):
                continue

            required_key, required_default = _TRUST_REQUIRED_KEYS[kind]
            required = bool(node.get(required_key, required_default))

            untrusted = node.get("untrusted")
            if not isinstance(untrusted, dict):
                untrusted = {}
            forbidden = bool(untrusted.get(kind, _TRUST_FORBIDDEN_DEFAULTS[kind]))

            has_trust = pi_has_command(pi, command)

            if required:
                if has_trust:
                    f.append(
                        Finding(
                            check_key,
                            Status.PASS,
                            f"{intf}: {label} ({context})",
                            interface=intf,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            check_key,
                            Status.FAIL,
                            f"{intf}: {label} missing ({context})",
                            interface=intf,
                            remediation=command,
                        )
                    )
            elif forbidden:
                if has_trust:
                    f.append(
                        Finding(
                            check_key,
                            Status.FAIL,
                            f"{intf}: {label} must NOT be set on this port "
                            f"({context}) — it bypasses validation here",
                            interface=intf,
                            remediation=f"no {command}",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            check_key,
                            Status.PASS,
                            f"{intf}: untrusted for {label} ({context})",
                            interface=intf,
                        )
                    )

        return f

    # ── ACCESS PORT CHECKS ────────────────────────────────────
    def _check_access_port(
        self, _cfg: ParsedConfig, dp: dict, pi: PortInfo
    ) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # BPDU guard
        if _enabled(dp, "bpdu_guard"):
            if pi_has(pi, r"spanning-tree bpduguard enable"):
                f.append(
                    Finding(
                        "bpdu_guard",
                        Status.PASS,
                        f"{intf}: BPDU guard enabled",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "bpdu_guard",
                        Status.FAIL,
                        f"{intf}: BPDU guard missing (access port)",
                        interface=intf,
                        remediation="spanning-tree bpduguard enable",
                    )
                )

        # Portfast
        if _enabled(dp, "portfast"):
            if pi_has(pi, r"spanning-tree portfast$"):
                f.append(
                    Finding(
                        "portfast",
                        Status.PASS,
                        f"{intf}: portfast enabled",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "portfast",
                        Status.FAIL,
                        f"{intf}: portfast missing (access port)",
                        interface=intf,
                        remediation="spanning-tree portfast",
                    )
                )

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.PASS,
                        f"{intf}: nonegotiate set",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.FAIL,
                        f"{intf}: switchport nonegotiate missing",
                        interface=intf,
                        remediation="switchport nonegotiate",
                    )
                )

        # Explicit switchport mode
        if _enabled(dp, "switchport_mode_explicit"):
            if pi.switchport_mode == "access":
                f.append(
                    Finding(
                        "switchport_mode_explicit",
                        Status.PASS,
                        f"{intf}: mode access explicitly set",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "switchport_mode_explicit",
                        Status.FAIL,
                        f"{intf}: switchport mode not explicitly 'access'",
                        interface=intf,
                        remediation="switchport mode access",
                    )
                )

        # Access VLAN not in disallowed list
        if _enabled(dp, "access_vlan_set"):
            bad_vlans = _setting(dp, "access_vlan_set", "disallowed_vlans")
            if pi.access_vlan and pi.access_vlan not in bad_vlans:
                f.append(
                    Finding(
                        "access_vlan_set",
                        Status.PASS,
                        f"{intf}: access VLAN {pi.access_vlan}",
                        interface=intf,
                    )
                )
            elif pi.access_vlan in bad_vlans:
                f.append(
                    Finding(
                        "access_vlan_set",
                        Status.FAIL,
                        f"{intf}: access VLAN {pi.access_vlan} is disallowed",
                        interface=intf,
                        remediation="switchport access vlan <vlan>",
                    )
                )
            else:
                f.append(
                    Finding(
                        "access_vlan_set",
                        Status.FAIL,
                        f"{intf}: no access VLAN configured",
                        interface=intf,
                        remediation="switchport access vlan <vlan>",
                    )
                )

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(
                    Finding(
                        "interface_description",
                        Status.PASS,
                        f"{intf}: description present",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "interface_description",
                        Status.FAIL,
                        f"{intf}: no description",
                        interface=intf,
                        remediation="description <text>",
                    )
                )

        # Port Security
        if _enabled(dp, "port_security"):
            if pi_has(pi, r"switchport port-security\s*$"):
                f.append(
                    Finding(
                        "port_security",
                        Status.PASS,
                        f"{intf}: port-security enabled",
                        interface=intf,
                    )
                )
                f.extend(self._port_security_settings(dp, pi))
            else:
                f.append(
                    Finding(
                        "port_security",
                        Status.FAIL,
                        f"{intf}: port-security not enabled",
                        interface=intf,
                        remediation="switchport port-security",
                    )
                )

        # No CDP on access ports
        if _enabled(dp, "no_cdp_on_access_ports"):
            if pi_has(pi, r"no cdp enable"):
                f.append(
                    Finding(
                        "no_cdp_on_access",
                        Status.PASS,
                        f"{intf}: CDP disabled on access port",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "no_cdp_on_access",
                        Status.FAIL,
                        f"{intf}: CDP still enabled on access port",
                        interface=intf,
                        remediation="no cdp enable",
                    )
                )

        # DHCP snooping limit rate on access ports.  The configured value is
        # a ceiling: a stricter (lower) limit on the port still passes.
        if _enabled(dp, "dhcp_snooping_limit_rate"):
            rate = _setting(dp, "dhcp_snooping_limit_rate", "rate")
            configured = pi_int_arg(pi, r"ip dhcp snooping limit rate\s+(\d+)")
            if configured is None:
                f.append(
                    Finding(
                        "dhcp_snooping_limit_rate",
                        Status.FAIL,
                        f"{intf}: DHCP snooping rate limit missing",
                        interface=intf,
                        remediation=f"ip dhcp snooping limit rate {rate}",
                    )
                )
            elif configured > rate:
                f.append(
                    Finding(
                        "dhcp_snooping_limit_rate",
                        Status.FAIL,
                        f"{intf}: DHCP snooping rate limit {configured} pps "
                        f"exceeds the maximum of {rate} pps",
                        interface=intf,
                        remediation=f"ip dhcp snooping limit rate {rate}",
                    )
                )
            else:
                f.append(
                    Finding(
                        "dhcp_snooping_limit_rate",
                        Status.PASS,
                        f"{intf}: DHCP snooping rate limit {configured} pps "
                        f"(max {rate})",
                        interface=intf,
                    )
                )

        # IP Source Guard on access ports
        if _enabled(dp, "ip_source_guard"):
            # Match "ip verify source" but not "no ip verify source"
            if pi_has(pi, r"^\s*ip verify source") and not pi_has(
                pi, r"^\s*no ip verify source"
            ):
                f.append(
                    Finding(
                        "ip_source_guard",
                        Status.PASS,
                        f"{intf}: IP source guard enabled",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "ip_source_guard",
                        Status.FAIL,
                        f"{intf}: IP source guard not enabled",
                        interface=intf,
                        remediation="ip verify source",
                    )
                )

        return f

    # ── ENDPOINT TRUNK PORT CHECKS (APs etc.) ─────────────────
    def _check_endpoint_trunk_port(
        self, _cfg: ParsedConfig, dp: dict, pi: PortInfo
    ) -> list[Finding]:
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
        neighbor_desc = (
            f"endpoint trunk to {pi.cdp_neighbor}"
            if pi.cdp_neighbor
            else "endpoint trunk"
        )

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # BPDU guard — recommended on endpoint trunks (like access ports)
        if _enabled(dp, "bpdu_guard"):
            if _setting(dp, "bpdu_guard", "on_endpoint_trunks"):
                if pi_has(pi, r"spanning-tree bpduguard enable"):
                    f.append(
                        Finding(
                            "bpdu_guard",
                            Status.PASS,
                            f"{intf}: BPDU guard enabled ({neighbor_desc})",
                            interface=intf,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "bpdu_guard",
                            Status.FAIL,
                            f"{intf}: BPDU guard missing ({neighbor_desc})",
                            interface=intf,
                            remediation="spanning-tree bpduguard enable",
                        )
                    )

        # Root guard — should NOT be on endpoint trunks
        if _enabled(dp, "root_guard"):
            if pi_has(pi, r"spanning-tree guard root"):
                f.append(
                    Finding(
                        "root_guard",
                        Status.FAIL,
                        f"{intf}: root guard on endpoint trunk — not needed",
                        interface=intf,
                        remediation="no spanning-tree guard root",
                    )
                )
            else:
                f.append(
                    Finding(
                        "root_guard",
                        Status.PASS,
                        f"{intf}: no root guard on endpoint trunk (correct)",
                        interface=intf,
                    )
                )

        # Portfast trunk — recommended for endpoint trunks
        if _enabled(dp, "portfast"):
            if pi_has(pi, r"spanning-tree portfast trunk"):
                f.append(
                    Finding(
                        "portfast",
                        Status.PASS,
                        f"{intf}: portfast trunk enabled ({neighbor_desc})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "portfast",
                        Status.FAIL,
                        f"{intf}: portfast trunk missing ({neighbor_desc})",
                        interface=intf,
                        remediation="spanning-tree portfast trunk",
                    )
                )

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.PASS,
                        f"{intf}: nonegotiate ({neighbor_desc})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.FAIL,
                        f"{intf}: nonegotiate missing ({neighbor_desc})",
                        interface=intf,
                        remediation="switchport nonegotiate",
                    )
                )

        # Trunk allowed VLANs
        if _enabled(dp, "trunk_allowed_vlans"):
            if pi.trunk_allowed_vlans and pi.trunk_allowed_vlans.lower() != "all":
                f.append(
                    Finding(
                        "trunk_allowed_vlans",
                        Status.PASS,
                        f"{intf}: trunk VLANs pruned ({neighbor_desc})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "trunk_allowed_vlans",
                        Status.FAIL,
                        f"{intf}: trunk allows ALL VLANs ({neighbor_desc})",
                        interface=intf,
                        remediation="switchport trunk allowed vlan <list>",
                    )
                )

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(
                    Finding(
                        "interface_description",
                        Status.PASS,
                        f"{intf}: description present ({neighbor_desc})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "interface_description",
                        Status.FAIL,
                        f"{intf}: no description ({neighbor_desc})",
                        interface=intf,
                        remediation="description <text>",
                    )
                )

        # Trunk native VLAN
        if _enabled(dp, "trunk_native_vlan"):
            # Check if endpoint trunks should be checked
            if _setting(dp, "trunk_native_vlan", "on_endpoint_trunks"):
                # Use endpoint-specific expected VLAN if configured, otherwise fall back to default
                expected_native = _setting(
                    dp, "trunk_native_vlan", "expected_vlan_endpoint"
                ) or _setting(dp, "trunk_native_vlan", "expected_vlan")
                # Check from Genie switchport data
                native_vlan = None
                data = getattr(self, "_current_data", None)
                if data and data.switchports:
                    sw_data = data.switchports.get(intf) or data.switchports.get(
                        pi.name
                    )
                    if isinstance(sw_data, dict):
                        native_vlan = sw_data.get("native_vlan")
                # Fallback to running-config
                if native_vlan is None:
                    for line in pi.config_lines:
                        m = re.search(
                            r"switchport trunk native vlan\s+(\d+)", line, re.I
                        )
                        if m:
                            native_vlan = int(m.group(1))
                            break
                if native_vlan is not None:
                    if native_vlan == expected_native:
                        f.append(
                            Finding(
                                "trunk_native_vlan",
                                Status.PASS,
                                f"{intf}: native VLAN {native_vlan} ({neighbor_desc})",
                                interface=intf,
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "trunk_native_vlan",
                                Status.FAIL,
                                f"{intf}: native VLAN {native_vlan}, expected {expected_native} ({neighbor_desc})",
                                interface=intf,
                                remediation=f"switchport trunk native vlan {expected_native}",
                            )
                        )
                else:
                    f.append(
                        Finding(
                            "trunk_native_vlan",
                            Status.WARN,
                            f"{intf}: native VLAN not determined ({neighbor_desc})",
                            interface=intf,
                            remediation=f"switchport trunk native vlan {expected_native}",
                        )
                    )

        return f

    # ── TRUNK PORT CHECKS ─────────────────────────────────────
    def _check_trunk_port(
        self, _cfg: ParsedConfig, dp: dict, pi: PortInfo
    ) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name
        is_uplink = pi.role == PortRole.TRUNK_UPLINK
        is_downlink = pi.role == PortRole.TRUNK_DOWNLINK
        direction = (
            "uplink"
            if is_uplink
            else "downlink"
            if is_downlink
            else "unknown-direction trunk"
        )

        # Storm control
        f.extend(self._check_storm_control(dp, pi))

        # Root guard — only on downlinks, never on uplinks
        if _enabled(dp, "root_guard"):
            if is_downlink:
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(
                        Finding(
                            "root_guard",
                            Status.PASS,
                            f"{intf}: root guard on downlink",
                            interface=intf,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "root_guard",
                            Status.FAIL,
                            f"{intf}: root guard missing (downlink)",
                            interface=intf,
                            remediation="spanning-tree guard root",
                        )
                    )
            elif is_uplink:
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(
                        Finding(
                            "root_guard",
                            Status.FAIL,
                            f"{intf}: root guard on UPLINK — must be removed!",
                            interface=intf,
                            remediation="no spanning-tree guard root",
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "root_guard",
                            Status.PASS,
                            f"{intf}: no root guard on uplink (correct)",
                            interface=intf,
                        )
                    )
            else:
                # TRUNK_UNKNOWN
                if pi_has(pi, r"spanning-tree guard root"):
                    f.append(
                        Finding(
                            "root_guard",
                            Status.WARN,
                            f"{intf}: root guard present but direction unknown — verify manually",
                            interface=intf,
                        )
                    )
                # If root guard is not present and direction is unknown, no finding needed

        # Switchport nonegotiate
        if _enabled(dp, "switchport_nonegotiate"):
            if pi_has(pi, r"switchport nonegotiate"):
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.PASS,
                        f"{intf}: nonegotiate ({direction})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "switchport_nonegotiate",
                        Status.FAIL,
                        f"{intf}: nonegotiate missing ({direction})",
                        interface=intf,
                        remediation="switchport nonegotiate",
                    )
                )

        # Trunk allowed VLANs — should not be "all"
        if _enabled(dp, "trunk_allowed_vlans"):
            if pi.trunk_allowed_vlans and pi.trunk_allowed_vlans.lower() != "all":
                f.append(
                    Finding(
                        "trunk_allowed_vlans",
                        Status.PASS,
                        f"{intf}: trunk allowed vlans pruned ({direction})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "trunk_allowed_vlans",
                        Status.FAIL,
                        f"{intf}: trunk allows ALL VLANs ({direction})",
                        interface=intf,
                        remediation="switchport trunk allowed vlan <list>",
                    )
                )

        # Description
        if _enabled(dp, "interface_description"):
            if pi.description:
                f.append(
                    Finding(
                        "interface_description",
                        Status.PASS,
                        f"{intf}: description present ({direction})",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "interface_description",
                        Status.FAIL,
                        f"{intf}: no description ({direction})",
                        interface=intf,
                        remediation="description <text>",
                    )
                )

        # Trunk native VLAN
        if _enabled(dp, "trunk_native_vlan"):
            # Determine if this port type should be checked
            want_check = (is_uplink and _setting(dp, "trunk_native_vlan", "on_uplinks")) or (
                is_downlink and _setting(dp, "trunk_native_vlan", "on_downlinks")
            )
            if want_check:
                # Use standard expected VLAN for uplinks/downlinks
                expected_native = _setting(dp, "trunk_native_vlan", "expected_vlan")
                # Check from Genie switchport data
                native_vlan = None
                data = getattr(self, "_current_data", None)
                if data and data.switchports:
                    sw_data = data.switchports.get(intf) or data.switchports.get(
                        pi.name
                    )
                    if isinstance(sw_data, dict):
                        native_vlan = sw_data.get("native_vlan")
                # Fallback to running-config
                if native_vlan is None:
                    for line in pi.config_lines:
                        m = re.search(
                            r"switchport trunk native vlan\s+(\d+)", line, re.I
                        )
                        if m:
                            native_vlan = int(m.group(1))
                            break
                if native_vlan is not None:
                    if native_vlan == expected_native:
                        f.append(
                            Finding(
                                "trunk_native_vlan",
                                Status.PASS,
                                f"{intf}: native VLAN {native_vlan} ({direction})",
                                interface=intf,
                            )
                        )
                    else:
                        f.append(
                            Finding(
                                "trunk_native_vlan",
                                Status.FAIL,
                                f"{intf}: native VLAN {native_vlan}, expected {expected_native} ({direction})",
                                interface=intf,
                                remediation=f"switchport trunk native vlan {expected_native}",
                            )
                        )
                else:
                    f.append(
                        Finding(
                            "trunk_native_vlan",
                            Status.WARN,
                            f"{intf}: native VLAN not determined ({direction})",
                            interface=intf,
                            remediation=f"switchport trunk native vlan {expected_native}",
                        )
                    )

        return f

    # ── ROUTED PORT CHECKS ────────────────────────────────────
    def _check_routed_port(
        self, _cfg: ParsedConfig, dp: dict, pi: PortInfo
    ) -> list[Finding]:
        """Checks for L3 (routed) interfaces and SVIs."""
        f: list[Finding] = []
        intf = pi.name

        # no ip proxy-arp
        if _enabled(dp, "no_ip_proxy_arp"):
            if pi_has(pi, r"no ip proxy-arp"):
                f.append(
                    Finding(
                        "no_ip_proxy_arp",
                        Status.PASS,
                        f"{intf}: ip proxy-arp disabled",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "no_ip_proxy_arp",
                        Status.FAIL,
                        f"{intf}: ip proxy-arp not disabled",
                        interface=intf,
                        remediation="no ip proxy-arp",
                    )
                )

        return f

    # ── PORT SECURITY SETTINGS ────────────────────────────────
    def _port_security_settings(self, dp: dict, pi: PortInfo) -> list[Finding]:
        """Max MAC, violation mode and aging, using IOS defaults for omitted lines.

        IOS leaves defaults out of the running-config: maximum 1, violation
        shutdown, aging time 0 (off), aging type absolute.
        """
        f: list[Finding] = []
        intf = pi.name

        max_mac = _setting(dp, "port_security", "max_mac")
        if max_mac:
            actual = pi_int_arg(pi, r"^switchport port-security maximum\s+(\d+)")
            actual = 1 if actual is None else actual
            if actual <= max_mac:
                f.append(Finding(
                    "port_security_max", Status.PASS,
                    f"{intf}: max MAC {actual} <= {max_mac}", interface=intf,
                ))
            else:
                f.append(Finding(
                    "port_security_max", Status.FAIL,
                    f"{intf}: max MAC {actual} > {max_mac}", interface=intf,
                    remediation=f"switchport port-security maximum {max_mac}",
                ))

        violation = _setting(dp, "port_security", "violation")
        if violation:
            m = next(
                (re.match(r"switchport port-security violation\s+(\S+)", ln, re.I)
                 for ln in pi.config_lines
                 if re.match(r"switchport port-security violation\s", ln, re.I)),
                None,
            )
            actual = m.group(1).lower() if m else "shutdown"
            if actual == violation:
                f.append(Finding(
                    "port_security_violation", Status.PASS,
                    f"{intf}: violation mode {actual}", interface=intf,
                ))
            else:
                f.append(Finding(
                    "port_security_violation", Status.FAIL,
                    f"{intf}: violation mode {actual}, expected {violation}",
                    interface=intf,
                    remediation=f"switchport port-security violation {violation}",
                ))

        aging_time = _setting(dp, "port_security", "aging_time")
        if aging_time:
            aging_type = _setting(dp, "port_security", "aging_type")
            actual_time = pi_int_arg(pi, r"switchport port-security aging time\s+(\d+)") or 0
            m = next(
                (re.match(r"switchport port-security aging type\s+(\S+)", ln, re.I)
                 for ln in pi.config_lines
                 if re.match(r"switchport port-security aging type\s", ln, re.I)),
                None,
            )
            actual_type = m.group(1).lower() if m else "absolute"
            problems = []
            if actual_time != aging_time:
                problems.append(f"aging time {actual_time} (expected {aging_time})")
            if actual_type != aging_type:
                problems.append(f"aging type {actual_type} (expected {aging_type})")
            if problems:
                f.append(Finding(
                    "port_security_aging", Status.FAIL,
                    f"{intf}: " + ", ".join(problems), interface=intf,
                    remediation=(
                        f"switchport port-security aging time {aging_time} / "
                        f"switchport port-security aging type {aging_type}"
                    ),
                ))
            else:
                f.append(Finding(
                    "port_security_aging", Status.PASS,
                    f"{intf}: aging {aging_type} {aging_time} min", interface=intf,
                ))

        return f

    # ── UNUSED PORT CHECKS ────────────────────────────────────
    def _check_unused_port(
        self, _cfg: ParsedConfig, dp: dict, pi: PortInfo
    ) -> list[Finding]:
        f: list[Finding] = []
        intf = pi.name
        if not _enabled(dp, "unused_ports"):
            return f

        if _setting(dp, "unused_ports", "must_be_shutdown") and not pi.admin_down:
            f.append(
                Finding(
                    "unused_shutdown",
                    Status.FAIL,
                    f"{intf}: unused port not shut down",
                    interface=intf,
                    remediation="shutdown",
                )
            )

        if _setting(dp, "unused_ports", "must_be_access_mode"):
            if pi.switchport_mode != "access":
                f.append(
                    Finding(
                        "unused_access_mode",
                        Status.FAIL,
                        f"{intf}: unused port not in access mode",
                        interface=intf,
                        remediation="switchport mode access",
                    )
                )

        parking = self.policy.get("_audit_settings", {}).get("parking_vlan", 99)
        if _setting(dp, "unused_ports", "must_be_in_parking_vlan"):
            if pi.access_vlan != parking:
                f.append(
                    Finding(
                        "unused_parking_vlan",
                        Status.FAIL,
                        f"{intf}: unused port not in parking VLAN {parking} (is {pi.access_vlan})",
                        interface=intf,
                        remediation=f"switchport access vlan {parking}",
                    )
                )

        if _setting(dp, "unused_ports", "must_have_nonegotiate"):
            if not pi_has(pi, r"switchport nonegotiate"):
                f.append(
                    Finding(
                        "unused_nonegotiate",
                        Status.FAIL,
                        f"{intf}: unused port missing nonegotiate",
                        interface=intf,
                        remediation="switchport nonegotiate",
                    )
                )

        if _setting(dp, "unused_ports", "must_have_bpduguard"):
            if not pi_has(pi, r"spanning-tree bpduguard enable"):
                f.append(
                    Finding(
                        "unused_bpduguard",
                        Status.FAIL,
                        f"{intf}: unused port missing BPDU guard",
                        interface=intf,
                        remediation="spanning-tree bpduguard enable",
                    )
                )

        if _setting(dp, "unused_ports", "must_have_no_cdp"):
            if not pi_has(pi, r"no cdp enable"):
                f.append(
                    Finding(
                        "unused_no_cdp",
                        Status.FAIL,
                        f"{intf}: unused port has CDP enabled",
                        interface=intf,
                        remediation="no cdp enable",
                    )
                )

        if _setting(dp, "unused_ports", "must_have_no_lldp"):
            has_no_tx = pi_has(pi, r"no lldp transmit")
            has_no_rx = pi_has(pi, r"no lldp receive")
            if not (has_no_tx and has_no_rx):
                f.append(
                    Finding(
                        "unused_no_lldp",
                        Status.FAIL,
                        f"{intf}: unused port has LLDP enabled",
                        interface=intf,
                        remediation="no lldp transmit / no lldp receive",
                    )
                )

        if _setting(dp, "unused_ports", "must_have_description"):
            exp_desc = _setting(dp, "unused_ports", "expected_description")
            if exp_desc.lower() in pi.description.lower():
                f.append(
                    Finding(
                        "unused_description",
                        Status.PASS,
                        f"{intf}: description contains '{exp_desc}'",
                        interface=intf,
                    )
                )
            else:
                f.append(
                    Finding(
                        "unused_description",
                        Status.FAIL,
                        f"{intf}: description missing or wrong (expected '{exp_desc}')",
                        interface=intf,
                        remediation=f"description {exp_desc}",
                    )
                )

        return f

    # ── STORM CONTROL (speed-aware) ───────────────────────────
    def _check_storm_control(self, dp: dict, pi: PortInfo) -> list[Finding]:
        """Check storm-control levels against speed-based thresholds (rising and falling)."""
        f: list[Finding] = []
        if not _enabled(dp, "storm_control"):
            return f

        intf = pi.name
        speed = pi.speed_mbps or 1000  # default to 1G if unknown

        # Check if threshold validation is enabled (defaults to true for backward compatibility)
        check_thresholds = _setting(dp, "storm_control", "check_thresholds")

        # Pick threshold tier
        thresholds = _setting(dp, "storm_control", "thresholds_by_speed")
        tier = thresholds.get(speed) or thresholds.get(str(speed))
        if tier is None:
            # Find the nearest tier
            for spd in sorted(thresholds.keys(), key=int, reverse=True):
                if speed >= int(spd):
                    tier = thresholds[spd]
                    break
        if tier is None:
            tier = _setting(dp, "storm_control", "default_thresholds")

        # Only check thresholds if enabled
        if check_thresholds:
            for sc_type in _setting(dp, "storm_control", "types"):
                expected = tier.get(sc_type)
                if expected is None:
                    continue

                # Support both old format (single value) and new format (rising/falling)
                if isinstance(expected, dict):
                    expected_rising_raw = expected.get("rising")
                    expected_falling_raw = expected.get("falling")
                else:
                    # Backward compatibility: if it's a single number, use it for both
                    expected_rising_raw = expected
                    expected_falling_raw = None

                if expected_rising_raw is None:
                    continue

                expected_rising = float(expected_rising_raw)
                expected_falling = (
                    float(expected_falling_raw)
                    if expected_falling_raw is not None
                    else None
                )
                expected_rising_text = str(expected_rising_raw)
                expected_falling_text = (
                    str(expected_falling_raw)
                    if expected_falling_raw is not None
                    else None
                )

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
                            f.append(
                                Finding(
                                    "storm_control",
                                    Status.PASS,
                                    f"{intf}: {sc_type} storm-control {actual_rising}%/{actual_falling}% "
                                    f"<= {expected_rising_text}%/{expected_falling_text}% ({speed}Mbps tier)",
                                    interface=intf,
                                )
                            )
                        else:
                            f.append(
                                Finding(
                                    "storm_control",
                                    Status.PASS,
                                    f"{intf}: {sc_type} storm-control {actual_rising}% <= {expected_rising_text}% "
                                    f"({speed}Mbps tier)",
                                    interface=intf,
                                )
                            )
                    else:
                        # Build failure message based on what failed
                        if not rising_ok and not falling_ok:
                            fail_msg = (
                                f"{intf}: {sc_type} storm-control {actual_rising}%/{actual_falling or 'N/A'}% "
                                f"> {expected_rising_text}%/{expected_falling_text}% ({speed}Mbps tier)"
                            )
                        elif not rising_ok:
                            fail_msg = (
                                f"{intf}: {sc_type} storm-control rising {actual_rising}% "
                                f"> {expected_rising_text}% ({speed}Mbps tier)"
                            )
                        else:
                            if actual_falling is None:
                                fail_msg = (
                                    f"{intf}: {sc_type} storm-control falling threshold not configured "
                                    f"(expected {expected_falling_text}%, {speed}Mbps tier)"
                                )
                            else:
                                fail_msg = (
                                    f"{intf}: {sc_type} storm-control falling {actual_falling}% "
                                    f"> {expected_falling_text}% ({speed}Mbps tier)"
                                )

                        remediation_cmd = (
                            f"storm-control {sc_type} level {expected_rising_text}"
                        )
                        if expected_falling_text is not None:
                            remediation_cmd += f" {expected_falling_text}"

                        f.append(
                            Finding(
                                "storm_control",
                                Status.FAIL,
                                fail_msg,
                                interface=intf,
                                remediation=remediation_cmd,
                            )
                        )
                else:
                    # Not configured at all
                    remediation_cmd = (
                        f"storm-control {sc_type} level {expected_rising_text}"
                    )
                    if expected_falling_text is not None:
                        remediation_cmd += f" {expected_falling_text}"

                    f.append(
                        Finding(
                            "storm_control",
                            Status.FAIL,
                            f"{intf}: {sc_type} storm-control not configured ({speed}Mbps tier)",
                            interface=intf,
                            remediation=remediation_cmd,
                        )
                    )

        # Storm-control action - only check if enabled (defaults to true for backward compatibility)
        check_action = _setting(dp, "storm_control", "check_action")
        if check_action:
            expected_action = _setting(dp, "storm_control", "action")
            if expected_action:
                if pi_has(pi, rf"storm-control action\s+{re.escape(expected_action)}"):
                    f.append(
                        Finding(
                            "storm_control_action",
                            Status.PASS,
                            f"{intf}: storm-control action {expected_action}",
                            interface=intf,
                        )
                    )
                else:
                    f.append(
                        Finding(
                            "storm_control_action",
                            Status.FAIL,
                            f"{intf}: storm-control action not '{expected_action}'",
                            interface=intf,
                            remediation=f"storm-control action {expected_action}",
                        )
                    )

        return f

