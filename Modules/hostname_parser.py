"""
Parse the corporate hostname naming convention to extract device role,
site information, and cabinet/instance numbers.

Convention:  GB-MKD1-005ASW001
             ││  │││  │││││ │││
             ││  │││  │││││ └── device number (001)
             ││  │││  ││└──── role code (ASW/CSW/SDW/ISW)
             ││  │││  └────── comms room / cabinet (005)
             ││  ││└───────── site instance (1)
             ││  └─────────── site code (MKD)
             └──────────────── country code (GB)
"""

import re
from dataclasses import dataclass
from typing import Optional

ROLE_MAP = {
    "ASW": "access_switch",
    "CSW": "core_switch",
    "SDW": "sdwan_router",
    "ISW": "industrial_switch",
}

ROLE_DISPLAY = {
    "ASW": "Access Switch",
    "CSW": "Core Switch",
    "SDW": "SD-WAN Router",
    "ISW": "Industrial Switch",
}

# GB-MKD1-005ASW001
HOSTNAME_PATTERN = re.compile(
    r"^(?P<country>[A-Z]{2})"
    r"-(?P<site>[A-Z]{2,4})(?P<site_inst>\d)"
    r"-(?P<comms>\d{3})(?P<role>ASW|CSW|SDW|ISW)(?P<num>\d{3})$",
    re.IGNORECASE,
)


@dataclass
class HostnameInfo:
    raw: str
    country: Optional[str] = None
    site_code: Optional[str] = None
    site_instance: Optional[str] = None
    comms_room: Optional[str] = None
    role_code: Optional[str] = None
    role: Optional[str] = None
    role_display: Optional[str] = None
    device_number: Optional[str] = None
    parsed: bool = False

    @property
    def is_access(self) -> bool:
        return self.role_code == "ASW"

    @property
    def is_core(self) -> bool:
        return self.role_code == "CSW"

    @property
    def is_sdwan(self) -> bool:
        return self.role_code == "SDW"

    @property
    def is_industrial(self) -> bool:
        return self.role_code == "ISW"


def parse_hostname(hostname: str) -> HostnameInfo:
    """Parse a hostname and extract role/site metadata."""
    m = HOSTNAME_PATTERN.match(hostname.strip().upper())
    if not m:
        return HostnameInfo(raw=hostname, parsed=False)
    role_code = m.group("role").upper()
    return HostnameInfo(
        raw=hostname,
        country=m.group("country"),
        site_code=m.group("site"),
        site_instance=m.group("site_inst"),
        comms_room=m.group("comms"),
        role_code=role_code,
        role=ROLE_MAP.get(role_code, "unknown"),
        role_display=ROLE_DISPLAY.get(role_code, "Unknown"),
        device_number=m.group("num"),
        parsed=True,
    )


def extract_role_from_hostname(hostname: str) -> Optional[str]:
    """Quick helper: return role code (ASW/CSW/SDW/ISW) or None."""
    info = parse_hostname(hostname)
    return info.role_code if info.parsed else None
