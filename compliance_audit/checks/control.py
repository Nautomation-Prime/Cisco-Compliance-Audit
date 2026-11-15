"""
Control-plane checks: spanning tree, VTP, DHCP snooping, dynamic ARP
inspection, errdisable recovery, UDLD and CoPP.
"""

import re
import logging

from ..collector import DeviceData, ParsedConfig
from ..hostname_parser import HostnameInfo
from .base import (
    Finding,
    Status,
    _configured_vlans,
    _enabled,
    _expand_vlan_ranges,
    _format_vlan_set,
    _command_args,
    _setting,
)

log = logging.getLogger(__name__)



def _stp_mode(cfg: ParsedConfig, data: DeviceData) -> str:
    """Running STP mode (``pvst``/``rapid-pvst``/``mst``), or ``""`` if unknown."""
    args = _command_args(cfg, "spanning-tree mode")
    if args and args[-1]:
        return args[-1][0].lower()
    keys = set(data.stp or {})
    if "rapid_pvst" in keys:
        return "rapid-pvst"
    if keys & {"mstp", "mst"}:
        return "mst"
    if "pvst" in keys:
        return "pvst"
    return ""


def _vtp_domain_finding(cfg: ParsedConfig, data: DeviceData, expected: str) -> Finding:
    """The VTP domain lives in vlan.dat, so ``show vtp status`` is the primary source."""
    actual = None
    if data.vtp:
        vtp = data.vtp.get("vtp", data.vtp)
        if isinstance(vtp, dict) and "domain_name" in vtp:
            actual = str(vtp.get("domain_name") or "").strip()
    if actual is None:
        args = _command_args(cfg, "vtp domain")
        if args and args[-1]:
            actual = args[-1][0]
    want = f"vtp domain {expected or '<domain>'}"
    if actual is None:
        return Finding(
            "vtp_domain", Status.WARN,
            f"VTP domain not verified (no show vtp status data; expected: {expected or 'any'})",
            remediation=want,
        )
    if (expected and actual == expected) or (not expected and actual):
        return Finding("vtp_domain", Status.PASS, f"VTP domain: {actual}")
    detail = (
        f"VTP domain: {actual or 'not set'}, expected: {expected}"
        if expected else "VTP domain not set"
    )
    return Finding("vtp_domain", Status.FAIL, detail, remediation=want)


class ControlPlaneChecks:
    """Checks for the control_plane policy section."""

    # ===================================================================
    #                     CONTROL  PLANE  CHECKS
    # ===================================================================

    # ── STP ───────────────────────────────────────────────────
    def _check_stp(
        self, cfg: ParsedConfig, data: DeviceData, host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "stp_mode"):
            mode = _setting(cp, "stp_mode", "mode")
            f.append(
                self._present(
                    cfg,
                    rf"^spanning-tree mode\s+{re.escape(mode)}\s*$",
                    "stp_mode",
                    f"spanning-tree mode {mode}",
                    f"spanning-tree mode {mode}",
                )
            )

        if _enabled(cp, "stp_extend_system_id"):
            f.append(
                self._present(
                    cfg,
                    r"^spanning-tree extend system-id",
                    "stp_extend_system_id",
                    "spanning-tree extend system-id",
                    "spanning-tree extend system-id",
                )
            )

        if _enabled(cp, "stp_pathcost_method"):
            method = _setting(cp, "stp_pathcost_method", "method")
            f.append(
                self._present(
                    cfg,
                    rf"^spanning-tree pathcost method\s+{re.escape(method)}\s*$",
                    "stp_pathcost_method",
                    f"spanning-tree pathcost method {method}",
                    f"spanning-tree pathcost method {method}",
                )
            )

        if _enabled(cp, "stp_loopguard_default"):
            f.append(
                self._present(
                    cfg,
                    r"^spanning-tree loopguard default",
                    "stp_loopguard_default",
                    "spanning-tree loopguard default",
                    "spanning-tree loopguard default",
                )
            )

        # STP priority by role: access switches must never be preferred as
        # root; core switches must be.
        if _enabled(cp, "stp_priority"):
            if host.is_access:
                self._check_stp_priority(
                    cfg, data, _setting(cp, "stp_priority", "access_priority"), "access", f
                )
            elif host.role in _setting(cp, "stp_priority", "core_roles"):
                self._check_stp_priority(
                    cfg, data, _setting(cp, "stp_priority", "core_priority"), "core", f
                )

        # BackboneFast / UplinkFast are PVST+ features; RSTP and MST converge
        # quickly by design and ignore them.
        mode = _stp_mode(cfg, data)
        for name, command in (
            ("stp_backbonefast", "spanning-tree backbonefast"),
            ("stp_uplinkfast", "spanning-tree uplinkfast"),
        ):
            if not _enabled(cp, name):
                continue
            if mode in ("rapid-pvst", "mst"):
                f.append(
                    Finding(
                        name,
                        Status.SKIP,
                        f"Not applicable: spanning-tree mode {mode} has fast "
                        f"convergence built in ({command} has no effect)",
                    )
                )
            else:
                f.append(
                    self._present(cfg, rf"^{re.escape(command)}(?:\s|$)", name, command, command)
                )

        return f

    def _check_stp_priority(
        self,
        cfg: ParsedConfig,
        data: DeviceData,
        expected: int,
        label: str,
        f: list[Finding],
    ) -> None:
        """Compare each VLAN's base bridge priority with *expected*.

        Reported priorities include the VLAN system-ID extension (32768 + VLAN
        ID), so the base is the value rounded down to a multiple of 4096.
        ``access``: base must be >= *expected* (never preferred as root).
        ``core``: base must be <= *expected* (preferred as root).
        """

        def judge(vlan: str, base: int, source: str) -> None:
            ok = base >= expected if label == "access" else base <= expected
            op = (">=" if ok else "<") if label == "access" else ("<=" if ok else ">")
            detail = f"VLAN {vlan} priority {base} {op} {expected} ({label}{source})"
            if ok:
                f.append(Finding("stp_priority", Status.PASS, detail))
            else:
                f.append(
                    Finding(
                        "stp_priority",
                        Status.FAIL,
                        detail,
                        remediation=f"spanning-tree vlan {vlan} priority {expected}",
                    )
                )

        # Structured data first: covers every VLAN, configured or not.
        checked = False
        for mode_data in (data.stp or {}).values():
            if not isinstance(mode_data, dict):
                continue
            for vid, vinfo in (mode_data.get("vlans") or {}).items():
                bridge = vinfo.get("bridge", {}) if isinstance(vinfo, dict) else {}
                prio = bridge.get("configured_bridge_priority", bridge.get("priority"))
                if isinstance(prio, int):
                    checked = True
                    judge(str(vid), prio - prio % 4096, "")
        if checked:
            return

        # Fallback: explicit priorities in the running-config.
        for line in cfg.find_lines(r"^spanning-tree vlan\s+\S+\s+priority\s+\d+"):
            m = re.search(r"vlan\s+(\S+)\s+priority\s+(\d+)", line)
            if m:
                checked = True
                judge(m.group(1), int(m.group(2)), ", from config")
        if checked:
            return

        # Nothing configured: every VLAN runs at the IOS default of 32768.
        judge("all", 32768, ", default priority")

    # ── VTP ───────────────────────────────────────────────────
    def _check_vtp(
        self, cfg: ParsedConfig, data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "vtp_domain"):
            f.append(_vtp_domain_finding(cfg, data, _setting(cp, "vtp_domain", "expected")))

        if not _enabled(cp, "vtp_mode"):
            return f

        expected = _setting(cp, "vtp_mode", "expected")

        # Try Genie parsed VTP data
        if data.vtp:
            actual = (
                data.vtp.get("vtp", {}).get("operating_mode", "")
                or data.vtp.get("operating_mode", "")
            ).lower()
            if actual == expected.lower():
                f.append(Finding("vtp_mode", Status.PASS, f"VTP mode: {actual}"))
            else:
                f.append(
                    Finding(
                        "vtp_mode",
                        Status.FAIL,
                        f"VTP mode: {actual or 'unknown'}, expected: {expected}",
                        remediation=f"vtp mode {expected}",
                    )
                )
        else:
            # Fallback to config
            if cfg.has_line(rf"^vtp mode\s+{re.escape(expected)}"):
                f.append(
                    Finding("vtp_mode", Status.PASS, f"VTP mode {expected} in config")
                )
            else:
                f.append(
                    Finding(
                        "vtp_mode",
                        Status.WARN,
                        f"VTP mode not verified (expected: {expected})",
                        remediation=f"vtp mode {expected}",
                    )
                )

        return f

    # ── DHCP SNOOPING ─────────────────────────────────────────
    def _check_dhcp_snooping(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "dhcp_snooping_global"):
            f.append(
                self._present(
                    cfg,
                    r"^ip dhcp snooping$",
                    "dhcp_snooping_global",
                    "ip dhcp snooping",
                    "ip dhcp snooping",
                )
            )

        if _enabled(cp, "dhcp_snooping_vlans"):
            required_spec = str(_setting(cp, "dhcp_snooping_vlans", "vlans") or "").strip()
            has_any = cfg.has_line(r"^ip dhcp snooping vlan")

            if required_spec:
                # A specific VLAN list is mandated by policy — verify every
                # required VLAN is actually covered by the device config.
                required = _expand_vlan_ranges(required_spec)
                configured = _configured_vlans(cfg, r"ip dhcp snooping vlan")
                missing = required - configured
                if not missing:
                    f.append(
                        Finding(
                            "dhcp_snooping_vlans",
                            Status.PASS,
                            f"DHCP snooping enabled on required VLAN(s) {required_spec}",
                        )
                    )
                else:
                    missing_spec = _format_vlan_set(missing)
                    f.append(
                        Finding(
                            "dhcp_snooping_vlans",
                            Status.FAIL,
                            (
                                f"DHCP snooping missing on VLAN(s) {missing_spec} "
                                f"(required: {required_spec})"
                            ),
                            remediation=f"ip dhcp snooping vlan {required_spec}",
                        )
                    )
            elif has_any:
                f.append(
                    Finding(
                        "dhcp_snooping_vlans",
                        Status.PASS,
                        "DHCP snooping VLAN(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "dhcp_snooping_vlans",
                        Status.FAIL,
                        "No DHCP snooping VLANs configured",
                        remediation="ip dhcp snooping vlan <vlan-list>",
                    )
                )

        if _enabled(cp, "no_dhcp_snooping_information_option"):
            f.append(
                self._absent(
                    cfg,
                    r"^ip dhcp snooping information option$",
                    "no_dhcp_snooping_info_option",
                    "ip dhcp snooping information option",
                    "no ip dhcp snooping information option",
                )
            )

        return f

    # ── ARP INSPECTION ────────────────────────────────────────
    def _check_arp_inspection(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})

        if _enabled(cp, "arp_inspection_vlans"):
            required_spec = str(_setting(cp, "arp_inspection_vlans", "vlans") or "").strip()
            has_any = cfg.has_line(r"^ip arp inspection vlan")

            if required_spec:
                required = _expand_vlan_ranges(required_spec)
                configured = _configured_vlans(cfg, r"ip arp inspection vlan")
                missing = required - configured
                if not missing:
                    f.append(
                        Finding(
                            "arp_inspection_vlans",
                            Status.PASS,
                            f"Dynamic ARP Inspection enabled on required VLAN(s) {required_spec}",
                        )
                    )
                else:
                    missing_spec = _format_vlan_set(missing)
                    f.append(
                        Finding(
                            "arp_inspection_vlans",
                            Status.FAIL,
                            (
                                f"DAI missing on VLAN(s) {missing_spec} "
                                f"(required: {required_spec})"
                            ),
                            remediation=f"ip arp inspection vlan {required_spec}",
                        )
                    )
            elif has_any:
                f.append(
                    Finding(
                        "arp_inspection_vlans",
                        Status.PASS,
                        "Dynamic ARP Inspection VLAN(s) configured",
                    )
                )
            else:
                f.append(
                    Finding(
                        "arp_inspection_vlans",
                        Status.FAIL,
                        "No DAI VLANs configured",
                        remediation="ip arp inspection vlan <vlan-list>",
                    )
                )

        if _enabled(cp, "arp_inspection_validate"):
            wanted = [c.lower() for c in _setting(cp, "arp_inspection_validate", "checks")]
            if wanted:
                configured = {
                    a.lower()
                    for args in _command_args(cfg, "ip arp inspection validate")
                    for a in args
                }
                command = "ip arp inspection validate " + " ".join(wanted)
                missing = [c for c in wanted if c not in configured]
                if missing:
                    f.append(
                        Finding(
                            "arp_inspection_validate",
                            Status.FAIL,
                            f"Missing: {command} (not validated: {', '.join(missing)})",
                            remediation=command,
                        )
                    )
                else:
                    f.append(Finding("arp_inspection_validate", Status.PASS, command))

        return f

    # ── ERRDISABLE ────────────────────────────────────────────
    def _check_errdisable(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "errdisable_recovery"):
            return f

        for cause in _setting(cp, "errdisable_recovery", "causes"):
            name = f"errdisable_recovery_{cause}"
            pattern = rf"^errdisable recovery cause\s+{re.escape(cause)}\s*$"
            f.append(
                self._present(
                    cfg,
                    pattern,
                    name,
                    f"errdisable recovery cause {cause}",
                    f"errdisable recovery cause {cause}",
                )
            )

        interval = _setting(cp, "errdisable_recovery", "interval")
        if interval:
            f.append(
                self._present(
                    cfg,
                    rf"^errdisable recovery interval\s+{int(interval)}\s*$",
                    "errdisable_recovery_interval",
                    f"errdisable recovery interval {interval}",
                    f"errdisable recovery interval {interval}",
                )
            )

        return f

    # ── UDLD ──────────────────────────────────────────────────
    def _check_udld(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "udld_global"):
            return f
        mode = _setting(cp, "udld_global", "mode")
        f.append(
            self._present(
                cfg,
                rf"^udld\s+{re.escape(mode)}\s*$",
                "udld_global",
                f"udld {mode}",
                f"udld {mode}",
            )
        )
        return f

    # ── CONTROL-PLANE POLICING ──────────────────────────────
    def _check_copp(
        self, cfg: ParsedConfig, _data: DeviceData, _host: HostnameInfo, _ports: dict
    ) -> list[Finding]:
        f: list[Finding] = []
        if "control_plane" not in self.policy:
            return f
        cp = self.policy.get("control_plane", {})
        if not _enabled(cp, "control_plane_policing"):
            return f
        # Check for service-policy under control-plane
        if cfg.has_line(r"^control-plane") and cfg.has_line(r"service-policy"):
            f.append(
                Finding(
                    "control_plane_policing",
                    Status.PASS,
                    "Control-plane policing (CoPP) configured",
                )
            )
        else:
            f.append(
                Finding(
                    "control_plane_policing",
                    Status.FAIL,
                    "Control-plane policing (CoPP) not configured",
                    remediation="control-plane / service-policy input <policy-map>",
                )
            )
        return f

