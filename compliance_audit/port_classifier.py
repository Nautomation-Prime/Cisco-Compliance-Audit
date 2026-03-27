"""
Classify switch ports into roles so that interface-level compliance checks
can apply the correct policy per port type.

Roles
-----
- ACCESS          : switchport mode access
- TRUNK_UPLINK    : trunk going toward the core / root bridge
- TRUNK_DOWNLINK  : trunk going to a downstream switch (ASW/ISW daisy-chain)
- TRUNK_ENDPOINT  : trunk to an endpoint device (wireless AP, etc.)
- TRUNK_UNKNOWN   : trunk whose direction could not be determined
- UNUSED          : admin-down with no operational link
- ROUTED          : L3 (no switchport) physical interface
- SVI             : Vlan interface
- LOOPBACK        : Loopback interface
- PORT_CHANNEL    : Port-channel logical interface (members inherit its role)
- MGMT            : AppGigabitEthernet / Management interface
- OTHER           : Anything not classified above (tunnels, etc.)

Detection strategy for uplink vs downlink vs endpoint
------------------------------------------------------
1. **Endpoint check** — CDP/LLDP neighbor is matched against configurable
   hostname patterns, platform strings, and capability keywords.  A match
   classifies the trunk as TRUNK_ENDPOINT (e.g. wireless APs).
2. **STP root port** — the interface elected as Root Port *is* the uplink
   toward the root bridge (typically the core switch).
3. **CDP / LLDP neighbor hostname** — the neighbour’s role code drives the
   trunk_signal from config (uplink / downlink / none).
4. Combination: endpoint is checked first, then STP, then CDP hostname.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .collector import DeviceData, normalize_intf
from .hostname_parser import get_trunk_signal_map, parse_hostname

log = logging.getLogger(__name__)


class PortRole(str, Enum):
    ACCESS = "access"
    TRUNK_UPLINK = "trunk_uplink"
    TRUNK_DOWNLINK = "trunk_downlink"
    TRUNK_ENDPOINT = "trunk_endpoint"
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
    is_stp_alternate_port: bool = (
        False  # True if port has STP alternate role (backup uplink)
    )
    cdp_neighbor: str = ""
    cdp_neighbor_role: str = ""  # ASW / CSW / SDW / ISW / ""
    cdp_neighbor_platform: str = ""  # CDP platform string
    cdp_neighbor_capabilities: str = ""  # CDP capabilities string
    is_endpoint_neighbor: bool = False  # True if CDP/LLDP says AP/endpoint
    switchport_mode: str = ""  # access / trunk / dynamic / ""
    access_vlan: int = 0
    trunk_allowed_vlans: str = ""
    port_channel_member_of: str = (
        ""  # e.g. "Port-channel1" if this is a member
    )
    config_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_ports(
    data: DeviceData,
    role_config: list[dict] | None = None,
    endpoint_config: dict | None = None,
) -> dict[str, PortInfo]:
    """Return a dict of normalised interface name → PortInfo."""

    ports: dict[str, PortInfo] = {}
    parsed = data.parsed_config

    if parsed is None:
        return ports

    # Build trunk-signal map from config (or defaults)
    signal_map = get_trunk_signal_map(role_config)

    # Pre-compile endpoint patterns
    ep_patterns = _compile_endpoint_patterns(endpoint_config)

    # 1) Seed every interface found in the running-config
    for intf_name, cfg_lines in parsed.interfaces.items():
        norm = normalize_intf(intf_name)
        pi = PortInfo(name=norm, config_lines=cfg_lines)
        pi.description = _extract_description(cfg_lines)
        pi.admin_down = any(line == "shutdown" for line in cfg_lines)
        pi.switchport_mode = _extract_switchport_mode(cfg_lines)
        pi.access_vlan = _extract_access_vlan(cfg_lines)
        pi.trunk_allowed_vlans = _extract_trunk_allowed_vlans(cfg_lines)
        ports[norm] = pi

    # 2) Enrich with Genie-parsed interface data (speed, oper status)
    _enrich_interface_data(ports, data.interfaces)

    # 3) Locate STP root ports and alternate ports
    root_ports = _find_root_ports(data.stp)
    for rp in root_ports:
        norm = normalize_intf(rp)
        if norm in ports:
            ports[norm].is_stp_root_port = True

    alternate_ports = _find_alternate_ports(data.stp)
    for ap in alternate_ports:
        norm = normalize_intf(ap)
        if norm in ports:
            ports[norm].is_stp_alternate_port = True

    # 4) Map CDP neighbors to local interfaces (including endpoint detection)
    _map_cdp_neighbors(ports, data.cdp, role_config, ep_patterns)
    _map_lldp_neighbors(ports, data.lldp, role_config, ep_patterns)

    # 5) Map port-channel membership (Genie etherchannel data + config fallback)
    _map_etherchannel_members(ports, data.etherchannel)

    # 6) Assign roles
    for pi in ports.values():
        pi.role = _determine_role(pi, signal_map)

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
        m = re.match(
            r"switchport trunk allowed vlan (.+)", line, re.IGNORECASE
        )
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
    #   { <stp-mode>: { 'vlans': { <vlan-id>: { 'interfaces':
    #   { <intf>: { 'role': 'root' } } } } } }
    for mode_data in stp_data.values():
        if not isinstance(mode_data, dict):
            continue
        vlans = mode_data.get("vlans", {})
        for vlan_info in vlans.values():
            if not isinstance(vlan_info, dict):
                continue
            for intf, intf_data in vlan_info.get("interfaces", {}).items():
                if (
                    isinstance(intf_data, dict)
                    and intf_data.get("role", "").lower() == "root"
                ):
                    root_ports.add(normalize_intf(intf))

    if root_ports:
        log.info("STP root ports detected: %s", root_ports)
    return root_ports


def _find_alternate_ports(stp_data: Optional[dict]) -> set[str]:
    """Extract every interface that is an STP Alternate Port for any VLAN.

    Alternate ports are backup uplinks that would become active if the root port fails.
    They are typically shown as 'Altn' role with 'BLK' (blocked) status in STP output.

    Note: We look across all VLANs and identify ports that are alternate in ANY VLAN,
    since the alternate port should be consistent across all VLANs on an access switch.
    """
    alternate_ports: set[str] = set()
    if not stp_data:
        return alternate_ports

    # Genie 'show spanning-tree' structure:
    #   { <stp-mode>: { 'vlans': { <vlan-id>: { 'interfaces':
    #   { <intf>: { 'role': 'alternate' } } } } } }
    for mode_data in stp_data.values():
        if not isinstance(mode_data, dict):
            continue
        vlans = mode_data.get("vlans", {})
        for vlan_info in vlans.values():
            if not isinstance(vlan_info, dict):
                continue
            for intf, intf_data in vlan_info.get("interfaces", {}).items():
                if isinstance(intf_data, dict):
                    role = intf_data.get("role", "").lower()
                    # Check for both 'alternate' and common abbreviations like 'altn'
                    if role in ("alternate", "altn", "alt"):
                        alternate_ports.add(normalize_intf(intf))

    if alternate_ports:
        log.info("STP alternate ports detected: %s", alternate_ports)
    return alternate_ports


def _map_etherchannel_members(
    ports: dict[str, PortInfo],
    etherchannel_data: Optional[dict],
) -> None:
    """Mark physical ports that are members of a port-channel.

    Uses Genie-parsed ``show etherchannel summary`` when available,
    with a running-config ``channel-group`` fallback.

    Genie structure::

        { 'interfaces': {
            'Port-channel1': {
                'members': {
                    'GigabitEthernet1/0/21': { 'flags': 'P', ... },
                    'GigabitEthernet1/0/22': { 'flags': 'P', ... },
                },
                ...
            }
        }}
    """
    mapped = False

    # ── Primary: Genie-parsed data ──────────────────────────────
    if etherchannel_data:
        po_interfaces = etherchannel_data.get("interfaces", {})
        for po_name, po_data in po_interfaces.items():
            po_norm = normalize_intf(po_name)
            members = po_data.get("members", {})
            for member_name in members:
                member_norm = normalize_intf(member_name)
                if member_norm in ports:
                    ports[member_norm].port_channel_member_of = po_norm
                    mapped = True
            if members:
                log.info(
                    "Port-channel %s members: %s",
                    po_norm,
                    [normalize_intf(m) for m in members],
                )

    # ── Fallback: parse 'channel-group' from running-config ─────
    if not mapped:
        for intf_name, pi in ports.items():
            for line in pi.config_lines:
                m = re.match(r"channel-group\s+(\d+)", line, re.IGNORECASE)
                if m:
                    po_num = m.group(1)
                    pi.port_channel_member_of = f"Port-channel{po_num}"


def _map_cdp_neighbors(
    ports: dict[str, PortInfo],
    cdp_data: Optional[dict],
    role_config: list[dict] | None = None,
    ep_patterns: Optional[dict] = None,
) -> None:
    """Populate cdp_neighbor/cdp_neighbor_role/endpoint flags on each PortInfo."""
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
        platform = entry.get("platform", "")
        capabilities = entry.get("capabilities", "")

        if local_if in ports:
            pi = ports[local_if]
            pi.cdp_neighbor = neighbor_id
            pi.cdp_neighbor_platform = platform
            pi.cdp_neighbor_capabilities = capabilities

            # Check endpoint patterns first (AP detection)
            if _is_endpoint(neighbor_id, platform, capabilities, ep_patterns):
                pi.is_endpoint_neighbor = True
            else:
                # Fall back to hostname role parsing
                host_info = parse_hostname(
                    neighbor_id.split(".")[0], role_config=role_config
                )
                if host_info.parsed and host_info.role_code:
                    pi.cdp_neighbor_role = host_info.role_code


def _map_lldp_neighbors(
    ports: dict[str, PortInfo],
    lldp_data: Optional[dict],
    role_config: list[dict] | None = None,
    ep_patterns: Optional[dict] = None,
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
        for neigh_data in (
            neighbors.values() if isinstance(neighbors, dict) else []
        ):
            if not isinstance(neigh_data, dict):
                continue
            system_name = neigh_data.get("system_name", "")
            system_desc = neigh_data.get("system_description", "")
            if system_name:
                pi = ports[local_if]
                pi.cdp_neighbor = system_name
                # LLDP has system_description but no platform/capabilities like CDP.
                # Match hostname patterns + use system_description as platform.
                if _is_endpoint(system_name, system_desc, "", ep_patterns):
                    pi.is_endpoint_neighbor = True
                else:
                    host_info = parse_hostname(
                        system_name.split(".")[0], role_config=role_config
                    )
                    if host_info.parsed and host_info.role_code:
                        pi.cdp_neighbor_role = host_info.role_code
                break


_ENDPOINT_DEFAULT_HOSTNAME = [re.compile(r"^AP[\d_-]+", re.IGNORECASE)]
_ENDPOINT_DEFAULT_PLATFORM = [
    re.compile(r"AIR-|C91[2-7]|CW91|MR\d", re.IGNORECASE)
]
_ENDPOINT_DEFAULT_CAPABILITIES = [re.compile(r"Trans-Bridge", re.IGNORECASE)]


def _compile_endpoint_patterns(ep_cfg: dict | None) -> dict:
    """
    Pre-compile the endpoint_neighbors regexes from config.

    Returns a dict with keys 'hostname', 'platform', 'capabilities',
    each a list of compiled re.Pattern objects.
    """
    if not ep_cfg or not ep_cfg.get("enabled", True):
        return {
            "hostname": _ENDPOINT_DEFAULT_HOSTNAME,
            "platform": _ENDPOINT_DEFAULT_PLATFORM,
            "capabilities": _ENDPOINT_DEFAULT_CAPABILITIES,
        }

    def _compile_list(patterns: list) -> list[re.Pattern]:
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error:
                log.warning("Invalid endpoint regex pattern: %s", p)
        return compiled

    return {
        "hostname": _compile_list(ep_cfg.get("hostname_patterns", []))
        or _ENDPOINT_DEFAULT_HOSTNAME,
        "platform": _compile_list(ep_cfg.get("platform_patterns", []))
        or _ENDPOINT_DEFAULT_PLATFORM,
        "capabilities": _compile_list(ep_cfg.get("capabilities", []))
        or _ENDPOINT_DEFAULT_CAPABILITIES,
    }


def _is_endpoint(
    device_id: str,
    platform: str,
    capabilities: str,
    ep_patterns: dict | None,
) -> bool:
    """Return True if the CDP/LLDP neighbor looks like an endpoint (AP etc.)."""
    if ep_patterns is None:
        return False

    # Check hostname patterns
    for pat in ep_patterns.get("hostname", []):
        if pat.search(device_id):
            return True

    # Check platform patterns
    if platform:
        for pat in ep_patterns.get("platform", []):
            if pat.search(platform):
                return True

    # Check capabilities
    if capabilities:
        for pat in ep_patterns.get("capabilities", []):
            if pat.search(capabilities):
                return True

    return False


_PHYSICAL_RE = re.compile(
    r"^(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
    r"FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet)",
    re.IGNORECASE,
)


def _is_physical(name: str) -> bool:
    return bool(_PHYSICAL_RE.match(name))


def _determine_role(
    pi: PortInfo,
    signal_map: dict[str, str] | None = None,
) -> PortRole:
    """Assign a PortRole based on all collected signals."""
    name = pi.name

    # Skip member ports — their port-channel will be checked instead
    if pi.port_channel_member_of:
        return PortRole.OTHER

    # Non-switchport interfaces
    if name.startswith("Loopback"):
        return PortRole.LOOPBACK
    if name.startswith("Vlan"):
        return PortRole.SVI
    if name.startswith("Tunnel"):
        return PortRole.OTHER
    if name.startswith("AppGigabitEthernet") or name.lower().startswith(
        "mgmt"
    ):
        return PortRole.MGMT

    is_po = name.startswith("Port-channel")

    # Check if it's a routed (no switchport) interface
    if (is_po or _is_physical(name)) and any(
        line.startswith("no switchport") for line in pi.config_lines
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
        # Signal 1: Endpoint neighbor (AP etc.) — takes priority
        if pi.is_endpoint_neighbor:
            return PortRole.TRUNK_ENDPOINT

        # Signal 2: STP root port → uplink
        if pi.is_stp_root_port:
            return PortRole.TRUNK_UPLINK

        # Signal 2b: STP alternate port → uplink (backup uplink)
        if pi.is_stp_alternate_port:
            return PortRole.TRUNK_UPLINK

        # Signal 3: CDP/LLDP neighbor role → use trunk_signal from config
        nr = pi.cdp_neighbor_role.upper()
        if nr and signal_map:
            sig = signal_map.get(nr, "none")
            if sig == "uplink":
                return PortRole.TRUNK_UPLINK
            if sig == "downlink":
                return PortRole.TRUNK_DOWNLINK

        # Could not determine
        return PortRole.TRUNK_UNKNOWN

    # Physical port or Port-channel with no explicit switchport mode
    if _is_physical(name) or is_po:
        if pi.admin_down:
            return PortRole.UNUSED
        return PortRole.ACCESS

    return PortRole.OTHER
