"""
Role-specific checks: policy that applies to a device because of the role
encoded in its hostname (e.g. access switches).
"""

import logging

from ..collector import DeviceData, ParsedConfig
from ..hostname_parser import HostnameInfo
from ..port_classifier import PortInfo, PortRole
from .base import (
    Finding,
    Status,
    _enabled,
)

log = logging.getLogger(__name__)


class RoleSpecificChecks:
    """Checks for the role_specific policy section."""

    # ===================================================================
    #                     ROLE-SPECIFIC  CHECKS
    # ===================================================================

    def _check_role_specific(
        self,
        cfg: ParsedConfig,
        data: DeviceData,
        host: HostnameInfo,
        ports: dict[str, PortInfo],
    ) -> list[Finding]:
        f: list[Finding] = []
        if "role_specific" not in self.policy:
            return f
        rs = self.policy.get("role_specific", {})

        if host.is_access:
            f.extend(self._check_access_role(cfg, data, host, ports, rs))

        return f

    def _stp_root_status(self, data: DeviceData) -> tuple[list[str], list[str]]:
        """Return VLAN IDs where the local switch is and is not the STP root."""
        root_vlans: list[str] = []
        non_root_vlans: list[str] = []
        if not data.stp:
            return root_vlans, non_root_vlans

        for mode_data in data.stp.values():
            if not isinstance(mode_data, dict):
                continue
            for vid, vinfo in mode_data.get("vlans", {}).items():
                root = vinfo.get("root", {})
                bridge = vinfo.get("bridge", {})
                if not (root.get("address") and bridge.get("address")):
                    continue
                vlan_id = str(vid)
                if root["address"] == bridge["address"]:
                    root_vlans.append(vlan_id)
                else:
                    non_root_vlans.append(vlan_id)

        return root_vlans, non_root_vlans

    def _check_access_role(
        self,
        _cfg: ParsedConfig,
        data: DeviceData,
        _host: HostnameInfo,
        ports: dict[str, PortInfo],
        rs: dict,
    ) -> list[Finding]:
        f: list[Finding] = []
        asw_pol = rs.get("access_switch", {})

        if _enabled(asw_pol, "stp_not_root") and data.stp:
            root_vlans, _non_root_vlans = self._stp_root_status(data)

            if root_vlans:
                # Create a finding for each VLAN where this switch is root
                for vid in root_vlans:
                    f.append(
                        Finding(
                            "asw_not_root",
                            Status.FAIL,
                            f"Access switch IS the STP root for VLAN {vid} — this should be the core!",
                            "role_specific",
                        )
                    )
            else:
                f.append(
                    Finding(
                        "asw_not_root",
                        Status.PASS,
                        "Access switch is not STP root (correct)",
                        "role_specific",
                    )
                )

        if _enabled(asw_pol, "uplink_redundancy"):
            po_uplinks = [
                p
                for p in ports.values()
                if p.role == PortRole.TRUNK_UPLINK and p.name.startswith("Port-channel")
            ]
            if po_uplinks:
                f.append(
                    Finding(
                        "uplink_redundancy",
                        Status.PASS,
                        "Uplink uses port-channel",
                        "role_specific",
                    )
                )
            else:
                f.append(
                    Finding(
                        "uplink_redundancy",
                        Status.WARN,
                        "No port-channel uplink detected",
                        "role_specific",
                    )
                )

        return f

