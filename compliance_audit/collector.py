"""
Data collection from IOS-XE devices via Netmiko, with structured parsing.

Connects using the existing DeviceConnector/JumpManager infrastructure,
collects CLI output, then parses it into structured data using Netmiko's
built-in Genie and TextFSM integration.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from netmiko.exceptions import NetmikoBaseException
from netmiko.utilities import get_structured_data, get_structured_data_genie

log = logging.getLogger(__name__)

COLLECTION_ERRORS = (
    AttributeError,
    NetmikoBaseException,
    OSError,
    RuntimeError,
    TimeoutError,
    TypeError,
    ValueError,
)

# ---------------------------------------------------------------------------
# Structured-parsing availability flags (Genie primary, TextFSM fallback)
# ---------------------------------------------------------------------------
try:
    import genie  # noqa: F401

    _GENIE_AVAILABLE = True
except ImportError:
    _GENIE_AVAILABLE = False

try:
    import ntc_templates  # noqa: F401

    _TEXTFSM_AVAILABLE = True
except ImportError:
    _TEXTFSM_AVAILABLE = False

if not _GENIE_AVAILABLE and not _TEXTFSM_AVAILABLE:
    log.warning(
        "Neither Genie nor TextFSM templates installed — structured parsing "
        "unavailable. Install with:  pip install pyats[library]  "
        "and/or  pip install ntc-templates"
    )
elif not _GENIE_AVAILABLE:
    log.info(
        "Genie not installed — TextFSM will be used for structured parsing. "
        "For best results install:  pip install pyats[library]"
    )


# ---------------------------------------------------------------------------
# Parsed running-config helper
# ---------------------------------------------------------------------------
@dataclass
class ParsedConfig:
    """Structured view of a running-configuration."""

    global_lines: list[str] = field(default_factory=list)
    interfaces: dict[str, list[str]] = field(default_factory=dict)
    line_configs: dict[str, list[str]] = field(default_factory=dict)
    raw: str = ""

    # --- query helpers ---------------------------------------------------
    def has_line(self, pattern: str) -> bool:
        """True if *any* global config line matches the regex *pattern*."""
        rx = re.compile(pattern, re.IGNORECASE)
        return any(rx.search(ln) for ln in self.global_lines)

    def find_lines(self, pattern: str) -> list[str]:
        """Return every global config line matching *pattern*."""
        rx = re.compile(pattern, re.IGNORECASE)
        return [ln for ln in self.global_lines if rx.search(ln)]

    def interface_has(self, intf: str, pattern: str) -> bool:
        rx = re.compile(pattern, re.IGNORECASE)
        for ln in self.interfaces.get(intf, []):
            if rx.search(ln):
                return True
        return False

    def interface_lines(self, intf: str, pattern: str) -> list[str]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [ln for ln in self.interfaces.get(intf, []) if rx.search(ln)]

    def line_config_has(self, line_name: str, pattern: str) -> bool:
        rx = re.compile(pattern, re.IGNORECASE)
        for ln in self.line_configs.get(line_name, []):
            if rx.search(ln):
                return True
        return False

    def get_line_config_sections(self, pattern: str) -> dict[str, list[str]]:
        """Return all line config sections whose name matches *pattern*."""
        rx = re.compile(pattern, re.IGNORECASE)
        return {k: v for k, v in self.line_configs.items() if rx.search(k)}


def parse_running_config(config_text: str) -> ParsedConfig:
    """Parse a running-config into structured sections."""
    pc = ParsedConfig(raw=config_text)
    current_section: Optional[str] = None  # "interface" | "line" | None
    current_name: Optional[str] = None

    for line in config_text.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped == "!"
            or stripped.startswith("Building configuration")
        ):
            current_section = None
            current_name = None
            continue

        if line.startswith("interface "):
            current_section = "interface"
            current_name = line.split("interface ", 1)[1].strip()
            pc.interfaces.setdefault(current_name, [])
        elif line.startswith("line "):
            current_section = "line"
            current_name = line.split("line ", 1)[1].strip()
            pc.line_configs.setdefault(current_name, [])
        elif current_section == "interface" and line.startswith(" ") and current_name:
            pc.interfaces[current_name].append(stripped)
        elif current_section == "line" and line.startswith(" ") and current_name:
            pc.line_configs[current_name].append(stripped)
        elif not line.startswith(" "):
            # Top-level config line (also resets section context)
            current_section = None
            current_name = None
            pc.global_lines.append(stripped)
        else:
            # Indented line under some other section (router, crypto, etc.)
            # Still treat as global for compliance matching
            pc.global_lines.append(stripped)

    return pc


# ---------------------------------------------------------------------------
# Interface-name helpers
# ---------------------------------------------------------------------------
_ABBREV_MAP = {
    "Gi": "GigabitEthernet",
    "Te": "TenGigabitEthernet",
    "Tw": "TwentyFiveGigE",
    "Fo": "FortyGigabitEthernet",
    "Hu": "HundredGigE",
    "Fa": "FastEthernet",
    "Et": "Ethernet",
    "Lo": "Loopback",
    "Vl": "Vlan",
    "Po": "Port-channel",
    "Tu": "Tunnel",
    "Ap": "AppGigabitEthernet",
}


def normalize_intf(name: str) -> str:
    """Expand abbreviated interface names to their full Cisco form."""
    for abbr, full in _ABBREV_MAP.items():
        if name.startswith(abbr) and not name.startswith(full):
            return full + name[len(abbr) :]
    return name


# ---------------------------------------------------------------------------
# Collected data container
# ---------------------------------------------------------------------------
@dataclass
class DeviceData:
    """All data collected from a single device."""

    hostname: str = ""
    ip: str = ""
    running_config: str = ""
    parsed_config: Optional[ParsedConfig] = None
    interfaces: Optional[dict] = None  # Genie: show interfaces
    switchports: Optional[dict] = None  # Genie: show interfaces switchport
    stp: Optional[dict] = None  # Genie: show spanning-tree
    cdp: Optional[dict] = None  # Genie: show cdp neighbors detail
    lldp: Optional[dict] = None  # Genie: show lldp neighbors detail
    version: Optional[dict] = None  # Genie: show version
    vtp: Optional[dict] = None  # Genie: show vtp status
    etherchannel: Optional[dict] = None  # Genie: show etherchannel summary
    ssh: Optional[dict] = None  # Genie: show ip ssh
    raw_commands: dict = field(default_factory=dict)
    structured_parse_engine: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
# Commands to collect — ordered so that expensive ones come later.
COMMANDS = [
    "show running-config",
    "show version",
    "show interfaces",
    "show interfaces switchport",
    "show spanning-tree",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show vtp status",
    "show ip ssh",
    "show etherchannel summary",
]

STRUCTURED_COMMAND_FIELDS: dict[str, str] = {
    "show version": "version",
    "show interfaces": "interfaces",
    "show interfaces switchport": "switchports",
    "show spanning-tree": "stp",
    "show cdp neighbors detail": "cdp",
    "show lldp neighbors detail": "lldp",
    "show vtp status": "vtp",
    "show etherchannel summary": "etherchannel",
    "show ip ssh": "ssh",
}


# ---------------------------------------------------------------------------
# TextFSM → Genie-compatible dict normalisers
# ---------------------------------------------------------------------------
# ntc-templates (TextFSM) returns a *list* of row dicts.  Every consumer in
# port_classifier, auditor, and compliance_engine expects the Genie *dict*
# shape.  These small functions convert the TextFSM list to the minimal
# Genie-compatible structure that all consumers understand.

def _norm_interfaces(rows: list) -> dict | None:
    """show interfaces → {intf_name: {bandwidth, oper_status, enabled}}"""
    result: dict = {}
    for row in rows:
        name = row.get("INTERFACE", "")
        if not name:
            continue
        link = (row.get("LINK_STATUS") or "").lower()
        try:
            bw = int(row.get("BANDWIDTH") or 0)
        except (TypeError, ValueError):
            bw = 0
        result[name] = {
            "bandwidth": bw,
            "oper_status": "up" if link == "up" else "down",
            "enabled": "administratively" not in link,
        }
    return result or None


def _norm_switchports(rows: list) -> dict | None:
    """show interfaces switchport → {intf_name: {native_vlan, ...}}"""
    result: dict = {}
    for row in rows:
        name = row.get("INTERFACE", "")
        if not name:
            continue
        try:
            native = int(row.get("NATIVE_VLAN") or 0) or None
        except (TypeError, ValueError):
            native = None
        result[name] = {"native_vlan": native}
    return result or None


def _norm_cdp(rows: list) -> dict | None:
    """show cdp neighbors detail → {index: {n: {device_id, local_interface, ...}}}"""
    index: dict = {}
    for i, row in enumerate(rows, start=1):
        index[str(i)] = {
            "device_id": row.get("DESTINATION_HOST", ""),
            "local_interface": row.get("LOCAL_PORT", ""),
            "platform": row.get("PLATFORM", ""),
            "capabilities": row.get("CAPABILITIES", ""),
        }
    return {"index": index} if index else None


def _norm_lldp(rows: list) -> dict | None:
    """show lldp neighbors detail → {interfaces: {local_if: {port_id: {...}}}}"""
    interfaces: dict = {}
    for row in rows:
        local_if = row.get("LOCAL_INTERFACE", "")
        if not local_if:
            continue
        port_id = row.get("PORT_ID", "")
        if local_if not in interfaces:
            interfaces[local_if] = {"port_id": {}}
        interfaces[local_if]["port_id"][port_id] = {
            "system_name": row.get("SYSTEM_NAME", ""),
            "system_description": row.get("SYSTEM_DESCRIPTION", ""),
        }
    return {"interfaces": interfaces} if interfaces else None


def _norm_stp(rows: list) -> dict | None:
    """show spanning-tree → {pvst: {vlans: {vlan_id: {bridge, interfaces}}}}"""
    vlans: dict = {}
    for row in rows:
        # NAME field is like "VLAN0001"; extract the numeric ID.
        name = row.get("NAME", "")
        m = re.search(r"\d+", name)
        vlan_id = str(int(m.group(0))) if m else name  # normalise "0001" → "1"

        intf = row.get("INTERFACE", "")
        role = (row.get("ROLE") or "").lower()

        if vlan_id not in vlans:
            try:
                bp = int(row.get("BRIDGE_PRIORITY") or 0) + int(
                    row.get("BRIDGE_SYSID") or 0
                )
            except (TypeError, ValueError):
                bp = None
            vlans[vlan_id] = {"bridge": {"priority": bp}, "interfaces": {}}

        if intf:
            vlans[vlan_id]["interfaces"][intf] = {"role": role}

    return {"pvst": {"vlans": vlans}} if vlans else None


def _norm_version(rows: list) -> dict | None:
    """show version → {version: {version: "..."}}"""
    if not rows:
        return None
    ver = rows[0].get("VERSION", "")
    return {"version": {"version": ver}} if ver else None


def _norm_vtp(rows: list) -> dict | None:
    """show vtp status → {vtp: {operating_mode: "..."}}"""
    if not rows:
        return None
    mode = rows[0].get("OPERATING_MODE", "")
    return {"vtp": {"operating_mode": mode.lower()}} if mode else None


# Map each command to its normaliser.  Commands not listed here return None
# (consumers fall back to running-config checks).
_TEXTFSM_NORMALIZERS: dict[str, Any] = {
    "show interfaces":           _norm_interfaces,
    "show interfaces switchport": _norm_switchports,
    "show cdp neighbors detail":  _norm_cdp,
    "show lldp neighbors detail": _norm_lldp,
    "show spanning-tree":         _norm_stp,
    "show version":               _norm_version,
    "show vtp status":            _norm_vtp,
    # show etherchannel summary — running-config 'channel-group' fallback handles it
    # show ip ssh              — raw-output regex fallback handles it
}


def _populate_structured_data(data: DeviceData, platform: str) -> None:
    """Populate structured fields: try Genie first, then TextFSM fallback.

    Genie returns nested dicts; TextFSM returns lists.  The per-command
    normalisers in ``_TEXTFSM_NORMALIZERS`` convert TextFSM lists to the
    minimal Genie-compatible dict shape expected by all consumers.
    """
    for command, attr_name in STRUCTURED_COMMAND_FIELDS.items():
        output = data.raw_commands.get(command, "")
        if not output.strip():
            data.structured_parse_engine[command] = "missing-output"
            continue

        # Try Genie (primary)
        if _GENIE_AVAILABLE:
            try:
                parsed = get_structured_data_genie(output, platform, command)
                if isinstance(parsed, dict) and parsed:
                    setattr(data, attr_name, parsed)
                    data.structured_parse_engine[command] = "genie"
                    continue
            except (LookupError, TypeError, ValueError, AttributeError, OSError):
                log.debug("Genie parse failed for '%s', trying TextFSM", command)

        # Try TextFSM (fallback)
        if _TEXTFSM_AVAILABLE:
            try:
                parsed = get_structured_data(output, platform=platform, command=command)
                if isinstance(parsed, list) and parsed:
                    normalizer = _TEXTFSM_NORMALIZERS.get(command)
                    if normalizer:
                        normalised = normalizer(parsed)
                        if normalised:
                            setattr(data, attr_name, normalised)
                            data.structured_parse_engine[command] = "textfsm"
                            continue
                    # No normaliser or normalisation returned None.
                    # Leave the attribute as None; consumers use running-config.
                    data.structured_parse_engine[command] = "raw-only"
                    continue
            except (LookupError, TypeError, ValueError, AttributeError, OSError):
                log.debug("TextFSM parse failed for '%s'", command)

        data.structured_parse_engine[command] = "raw-only"


class DataCollector:
    """Collect and parse data from a live Netmiko connection."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def collect(self, connection: Any, ip: str = "") -> DeviceData:
        """
        Run all show commands, parse output, and return a DeviceData bundle.
        *connection* is an active Netmiko BaseConnection.
        """
        data = DeviceData(ip=ip)

        # Discover hostname from prompt
        try:
            prompt = connection.find_prompt()
            data.hostname = prompt.strip().rstrip("#>")
        except COLLECTION_ERRORS:
            data.hostname = ip

        # Collect raw output for each command
        for cmd in COMMANDS:
            try:
                output = connection.send_command(
                    cmd,
                    read_timeout=self.timeout,
                    strip_command=True,
                    strip_prompt=True,
                )
                data.raw_commands[cmd] = output
                log.info("Collected: %s (%d bytes)", cmd, len(output))
            except COLLECTION_ERRORS as exc:
                log.warning("Failed to collect '%s': %s", cmd, exc)
                data.raw_commands[cmd] = ""

        # Parse running-config
        data.running_config = data.raw_commands.get("show running-config", "")
        data.parsed_config = parse_running_config(data.running_config)

        # Parse structured data using platform from connection
        platform = getattr(connection, "device_type", "cisco_xe")
        _populate_structured_data(data, platform=platform)

        return data
