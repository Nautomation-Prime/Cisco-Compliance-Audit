"""
Parse the configurable hostname naming convention to extract device role,
site information, and cabinet/instance numbers.

Convention:  ZZ-LAB1-005ASW001
             ││  │││  │││││ │││
             ││  │││  │││││ └── device number (001)
             ││  │││  ││└──── role code (ASW/CSW/SDW/ISW — configurable)
             ││  │││  └────── comms room / cabinet (005)
             ││  ││└───────── site instance (1)
             ││  └─────────── site code (LAB = sample site code)
             └──────────────── prefix / country code (ZZ placeholder)

Role codes are loaded from 'hostname_roles' in compliance_config.yaml
so they can be added/changed/removed without touching this file.
"""

import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Defaults — used when no config is supplied
# ---------------------------------------------------------------------------
DEFAULT_ROLES: list[dict] = [
    {
        "code": "ASW",
        "role": "access_switch",
        "display": "Access Switch",
        "trunk_signal": "downlink",
    },
]


# ---------------------------------------------------------------------------
# Build lookup maps from a roles list
# ---------------------------------------------------------------------------
def _build_role_maps(roles: list[dict]) -> tuple[dict, dict, dict]:
    """Return (code→role, code→display, code→trunk_signal) dicts."""
    role_map: dict[str, str] = {}
    display_map: dict[str, str] = {}
    signal_map: dict[str, str] = {}
    for entry in roles:
        code = entry["code"].upper()
        role_map[code] = entry.get("role", code.lower())
        display_map[code] = entry.get("display", code)
        signal_map[code] = entry.get("trunk_signal", "none").lower()
    return role_map, display_map, signal_map


def _build_pattern(codes: list[str]) -> re.Pattern:
    """Build the hostname regex dynamically from the configured codes."""
    codes_alt = "|".join(re.escape(c) for c in codes)
    return re.compile(
        r"^(?P<country>[A-Z]{2})"
        r"-(?P<site>[A-Z]{2,4})(?P<site_inst>\d)"
        rf"-(?P<comms>\d{{3}})(?P<role>{codes_alt})(?P<num>\d{{3}})$",
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
        return self.role == "access_switch"


# ---------------------------------------------------------------------------
# Compiled defaults (used when no config is passed)
# ---------------------------------------------------------------------------
_DEFAULT_ROLE_MAP, _DEFAULT_DISPLAY_MAP, _DEFAULT_SIGNAL_MAP = _build_role_maps(
    DEFAULT_ROLES
)
_DEFAULT_PATTERN = _build_pattern(list(_DEFAULT_ROLE_MAP.keys()))


def parse_hostname(
    hostname: str,
    role_config: Optional[list[dict]] = None,
    explicit_role: Optional[str] = None,
) -> HostnameInfo:
    """
    Parse a hostname and extract role/site metadata.

    Parameters
    ----------
    hostname : str
        The device hostname to parse.
    role_config : list[dict] | None
        The ``hostname_roles`` list from compliance_config.yaml.
        Each dict must have at least ``code``, ``role``, ``display``.
        If None, built-in defaults (ASW/CSW/SDW/ISW) are used.
    explicit_role : str | None
        If set, override the role derived from the hostname.
        Accepts a role code (e.g. ``ASW``) or a role name
        (e.g. ``access_switch``).
    """
    if role_config:
        role_map, display_map, _ = _build_role_maps(role_config)
        pattern = _build_pattern(list(role_map.keys()))
    else:
        role_map = _DEFAULT_ROLE_MAP
        display_map = _DEFAULT_DISPLAY_MAP
        pattern = _DEFAULT_PATTERN

    m = pattern.match(hostname.strip().upper())
    if not m:
        info = HostnameInfo(raw=hostname, parsed=False)
    else:
        role_code = m.group("role").upper()
        info = HostnameInfo(
            raw=hostname,
            country=m.group("country"),
            site_code=m.group("site"),
            site_instance=m.group("site_inst"),
            comms_room=m.group("comms"),
            role_code=role_code,
            role=role_map.get(role_code, "unknown"),
            role_display=display_map.get(role_code, "Unknown"),
            device_number=m.group("num"),
            parsed=True,
        )

    # Apply explicit role override
    if explicit_role:
        upper = explicit_role.upper()
        if upper in role_map:
            info.role_code = upper
            info.role = role_map[upper]
            info.role_display = display_map.get(upper, upper)
        else:
            # Treat as a role name; try to reverse-lookup the code
            reverse = {v: k for k, v in role_map.items()}
            code = reverse.get(explicit_role)
            if code:
                info.role_code = code
                info.role = explicit_role
                info.role_display = display_map.get(code, explicit_role)
            else:
                info.role = explicit_role
                info.role_display = explicit_role

    return info


def extract_role_from_hostname(
    hostname: str,
    role_config: Optional[list[dict]] = None,
) -> Optional[str]:
    """Quick helper: return role code (e.g. ASW/CSW) or None."""
    info = parse_hostname(hostname, role_config=role_config)
    return info.role_code if info.parsed else None


def get_trunk_signal_map(role_config: Optional[list[dict]] = None) -> dict[str, str]:
    """
    Return {code: trunk_signal} from the role config.
    trunk_signal is "uplink", "downlink", or "none".
    """
    if role_config:
        _, _, signal_map = _build_role_maps(role_config)
        return signal_map
    return _DEFAULT_SIGNAL_MAP
