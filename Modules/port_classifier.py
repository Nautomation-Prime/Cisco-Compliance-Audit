"""
Classify switch ports into roles so that interface-level compliance checks
can apply the correct policy per port type.

Roles
-----
- ACCESS          : switchport mode access
- TRUNK_UPLINK    : trunk going toward the core / root bridge
- TRUNK_DOWNLINK  : trunk going to a downstream access / industrial switch
- TRUNK_UNKNOWN   : trunk whose direction could not be determined
- UNUSED          : admin-down with no operational link
- ROUTED          : L3 (no switchport) physical interface
- SVI             : Vlan interface
- LOOPBACK        : Loopback interface
- PORT_CHANNEL    : Port-channel logical interface (members inherit its role)
- MGMT            : AppGigabitEthernet / Management interface
- OTHER           : Anything not classified above (tunnels, etc.)

Detection strategy for uplink vs downlink
------------------------------------------
1. **STP root port** — the interface elected as Root Port *is* the uplink
   toward the root bridge (typically the core switch).
2. **CDP / LLDP neighbor hostname** — if the neighbor's hostname matches
   the CSW naming convention the local port is an uplink; if it matches
   ASW / ISW it is a downlink.
3. Combination: both signals are combined; STP is trusted first, then CDP.
"""

import re
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from .collector import DeviceData, normalize_intf
from .hostname_parser import parse_hostname

log = logging.getLogger(__name__)


class PortRole(str, Enum):
    ACCESS = "access"
    TRUNK_UPLINK = "trunk_uplink"
    TRUNK_DOWNLINK = "trunk_downlink"
    TRUNK_UNKNOWN = "trunk_unknown"
    UNUSED = "unused"
    ROUTED = "routed"
    SVI = "svi"
    LOOPBACK = "loopback"
    PORT_CHANNEL = "port-channel"
    MGMT = "management"
    OTHER = "other"


@dataclass
class PortInfo:
    name: str
    role: PortRole = PortRole.OTHER
    speed_mbps: int = 0
    admin_down: bool = False
    oper_down: bool = False
    description: str = ""
    is_stp_root_port: bool = False
    cdp_neighbor: str = ""
    cdp_neighbor_role: str = ""      # ASW / CSW / SDW / ISW / ""
    switchport_mode: str = ""        # access / trunk / dynamic / ""
    access_vlan: int = 0
    trunk_allowed_vlans: str = ""
    config_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_ports(data: DeviceData) -> dict[str, PortInfo]:
    """Return a dict of normalised interface name → PortInfo."""

    ports: dict[str, PortInfo] = {}
    parsed = data.parsed_config

    if parsed is None:
        return ports

    # 1) Seed every interface found in the running-config
    for intf_name, cfg_lines in parsed.interfaces.items():
        norm = normalize_intf(intf_name)
        pi = PortInfo(name=norm, config_lines=cfg_lines)
        pi.description = _extract_description(cfg_lines)
        pi.admin_down = any(l == "shutdown" for l in cfg_lines)
        pi.switchport_mode = _extract_switchport_mode(cfg_lines)
        pi.access_vlan = _extract_access_vlan(cfg_lines)
        pi.trunk_allowed_vlans = _extract_trunk_allowed_vlans(cfg_lines)
        ports[norm] = pi

    # 2) Enrich with Genie-parsed interface data (speed, oper status)
    _enrich_interface_data(ports, data.interfaces)

    # 3) Locate STP root ports
    root_ports = _find_root_ports(data.stp)
    for rp in root_ports:
        norm = normalize_intf(rp)
        if norm in ports:
            ports[norm].is_stp_root_port = True

    # 4) Map CDP neighbors to local interfaces
    _map_cdp_neighbors(ports, data.cdp)
    _map_lldp_neighbors(ports, data.lldp)

    # 5) Assign roles
    for pi in ports.values():
        pi.role = _determine_role(pi)

    return ports


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_description(cfg: list[str]) -> str:
    for line in cfg:
        if line.lower().startswith("description "):
            return line.split("description ", 1)[1].strip()
    return ""


def _extract_switchport_mode(cfg: list[str]) -> str:
    for line in cfg:
        m = re.match(r"switchport mode (\S+)", line, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return ""


def _extract_access_vlan(cfg: list[str]) -> int:
    for line in cfg:
        m = re.match(r"switchport access vlan (\d+)", line, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return 0


def _extract_trunk_allowed_vlans(cfg: list[str]) -> str:
    for line in cfg:
        m = re.match(r"switchport trunk allowed vlan (.+)", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _enrich_interface_data(
    ports: dict[str, PortInfo],
    genie_intf: Optional[dict],
) -> None:
    """Pull speed and oper-status from Genie 'show interfaces' output."""
    if not genie_intf:
        return
    for intf_name, info in genie_intf.items():
        norm = normalize_intf(intf_name)
        if norm not in ports:
            continue
        pi = ports[norm]

        # Bandwidth is in kbps in Genie output
        bw = info.get("bandwidth", 0)
        if bw:
            pi.speed_mbps = bw // 1000

        oper = info.get("oper_status", "up")
        pi.oper_down = oper.lower() != "up"

        enabled = info.get("enabled", True)
        if not enabled:
            pi.admin_down = True


def _find_root_ports(stp_data: Optional[dict]) -> set[str]:
    """Extract every interface that is an STP Root Port for any VLAN."""
    root_ports: set[str] = set()
    if not stp_data:
        return root_ports

    # Genie 'show spanning-tree' structure:
    #   { <stp-mode>: { 'vlans': { <vlan-id>: { 'interfaces': { <intf>: { 'role': 'root' } } } } } }
    for mode_data in stp_data.values():
        if not isinstance(mode_data, dict):
            continue
        vlans = mode_data.get("vlans", {})
        for vlan_info in vlans.values():
            if not isinstance(vlan_info, dict):
                continue
            for intf, intf_data in vlan_info.get("interfaces", {}).items():
                if isinstance(intf_data, dict) and intf_data.get("role", "").lower() == "root":
                    root_ports.add(normalize_intf(intf))

    if root_ports:
        log.info("STP root ports detected: %s", root_ports)
    return root_ports


def _map_cdp_neighbors(
    ports: dict[str, PortInfo],
    cdp_data: Optional[dict],
) -> None:
    """Populate cdp_neighbor/cdp_neighbor_role on each PortInfo."""
    if not cdp_data:
        return

    # Genie 'show cdp neighbors detail' structure:
    #   { 'index': { <n>: { 'device_id': '...', 'local_interface': '...', ... } } }
    index = cdp_data.get("index", {})
    for entry in index.values():
        if not isinstance(entry, dict):
            continue
        local_if = normalize_intf(entry.get("local_interface", ""))
        neighbor_id = entry.get("device_id", "")

        if local_if in ports:
            ports[local_if].cdp_neighbor = neighbor_id
            host_info = parse_hostname(neighbor_id.split(".")[0])  # strip domain
            if host_info.parsed and host_info.role_code:
                ports[local_if].cdp_neighbor_role = host_info.role_code


def _map_lldp_neighbors(
    ports: dict[str, PortInfo],
    lldp_data: Optional[dict],
) -> None:
    """Fallback: use LLDP when CDP has no entry for a port."""
    if not lldp_data:
        return

    interfaces = lldp_data.get("interfaces", {})
    for local_if_raw, if_data in interfaces.items():
        local_if = normalize_intf(local_if_raw)
        if local_if not in ports or ports[local_if].cdp_neighbor:
            continue  # CDP already populated
        neighbors = if_data.get("port_id", {})
        for neigh_data in (neighbors.values() if isinstance(neighbors, dict) else []):
            if not isinstance(neigh_data, dict):
                continue
            system_name = neigh_data.get("system_name", "")
            if system_name:
                ports[local_if].cdp_neighbor = system_name
                host_info = parse_hostname(system_name.split(".")[0])
                if host_info.parsed and host_info.role_code:
                    ports[local_if].cdp_neighbor_role = host_info.role_code
                break


_PHYSICAL_RE = re.compile(
    r"^(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
    r"FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet)",
    re.IGNORECASE,
)


def _is_physical(name: str) -> bool:
    return bool(_PHYSICAL_RE.match(name))


def _determine_role(pi: PortInfo) -> PortRole:
    """Assign a PortRole based on all collected signals."""
    name = pi.name

    # Non-switchport interfaces
    if name.startswith("Loopback"):
        return PortRole.LOOPBACK
    if name.startswith("Vlan"):
        return PortRole.SVI
    if name.startswith("Port-channel"):
        return PortRole.PORT_CHANNEL
    if name.startswith("Tunnel"):
        return PortRole.OTHER
    if name.startswith("AppGigabitEthernet") or name.lower().startswith("mgmt"):
        return PortRole.MGMT

    # Check if it's a routed (no switchport) interface
    if _is_physical(name) and any(
        l.startswith("no switchport") for l in pi.config_lines
    ):
        return PortRole.ROUTED

    # Unused detection: admin-down AND oper-down AND not a trunk/access explicitly
    if pi.admin_down and (pi.oper_down or not pi.switchport_mode):
        return PortRole.UNUSED

    # Switchport access
    if pi.switchport_mode == "access":
        return PortRole.ACCESS

    # Switchport trunk — determine direction
    if pi.switchport_mode == "trunk":
        # Signal 1: STP root port → uplink
        if pi.is_stp_root_port:
            return PortRole.TRUNK_UPLINK

        # Signal 2: CDP/LLDP neighbor role
        nr = pi.cdp_neighbor_role.upper()
        if nr == "CSW":
            return PortRole.TRUNK_UPLINK
        if nr in ("ASW", "ISW"):
            return PortRole.TRUNK_DOWNLINK

        # Could not determine
        return PortRole.TRUNK_UNKNOWN

    # Physical port with no explicit switchport mode — treat as access by default
    if _is_physical(name):
        if pi.admin_down:
            return PortRole.UNUSED
        return PortRole.ACCESS

    return PortRole.OTHER
