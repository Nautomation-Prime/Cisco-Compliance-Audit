"""
Reusable Pydantic field types shared by the config and inventory schemas.

Each type validates a value the way an operator would expect when writing
YAML by hand, and reports one clear error rather than a pydantic union dump.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import (
    AfterValidator,
    Field,
    IPvAnyAddress,
    PlainValidator,
    TypeAdapter,
    ValidationError,
)

_IP_ADAPTER: TypeAdapter = TypeAdapter(IPvAnyAddress)

#: RFC 1123 hostname: dot-separated labels of letters, digits, ``-`` and
#: ``_`` (``_`` is not strictly legal but is common in lab naming), each label
#: 1-63 characters and not starting or ending with ``-``.  A trailing root
#: dot is tolerated.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$"
)

#: Looks like an IP address (digits and dots, or contains ``:``).  Such a
#: value is never treated as a hostname, so ``192.0.2.300`` is reported as a
#: bad address instead of being accepted as a DNS name.
_IP_LIKE_RE = re.compile(r"^[\d.]+$|:")


def parse_ip(value: object) -> "IPvAnyAddress | None":
    """Return *value* as an ``IPv4Address``/``IPv6Address``, or ``None``."""
    if not isinstance(value, str):
        return None
    try:
        return _IP_ADAPTER.validate_python(value.strip())
    except ValidationError:
        return None


def validate_hostname(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"must be a string, got {type(value).__name__}")
    value = value.strip()
    if not value:
        raise ValueError("must not be empty")
    if _IP_LIKE_RE.search(value):
        raise ValueError(f"'{value}' is not a valid IP address")
    if not _HOSTNAME_RE.match(value):
        raise ValueError(f"'{value}' is not a valid hostname")
    return value


def _validate_host_or_ip(value: object) -> "IPvAnyAddress | str":
    ip = parse_ip(value)
    if ip is not None:
        return ip
    return validate_hostname(value)


#: A DNS hostname (never an IP-shaped string).
Hostname = Annotated[str, PlainValidator(validate_hostname)]

#: An IPv4/IPv6 address (parsed with pydantic's ``IPvAnyAddress``) or a
#: hostname.  IP addresses come back as ``ipaddress`` objects.
HostOrIP = Annotated[Union[IPvAnyAddress, str], PlainValidator(_validate_host_or_ip)]


def _validate_regex(value: str) -> str:
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"invalid regex '{value}': {exc}") from exc
    return value


#: A string that must compile as a Python regular expression.
Regex = Annotated[str, AfterValidator(_validate_regex)]

#: An 802.1Q VLAN ID.
VlanId = Annotated[int, Field(ge=1, le=4094)]


def _validate_vlan_spec(value: object) -> str:
    """Validate a Cisco VLAN list such as ``"10,20,30-40"``.

    The engine's ``_expand_vlan_ranges`` skips tokens it cannot parse so a bad
    value never crashes an audit; that also means a typo silently narrows the
    VLAN set being checked, so it is rejected here instead.
    """
    if isinstance(value, bool):
        raise ValueError("must be a VLAN list string, not a boolean")
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        raise ValueError(f"must be a VLAN list string, got {type(value).__name__}")
    for token in re.split(r"[,\s]+", value.strip()):
        if not token:
            continue
        lo, sep, hi = token.partition("-")
        bounds = (lo, hi) if sep else (lo,)
        if not all(b.isdigit() and 1 <= int(b) <= 4094 for b in bounds):
            raise ValueError(
                f"invalid VLAN token '{token}' (expected an ID or range within 1-4094)"
            )
        if sep and int(lo) > int(hi):
            raise ValueError(f"VLAN range '{token}' runs backwards")
    return value


#: A Cisco VLAN list/range spec (``""`` means "none configured").
VlanSpec = Annotated[Union[str, int], PlainValidator(_validate_vlan_spec)]

Severity = Literal["critical", "high", "medium", "low", "info"]

SYSLOG_LEVELS = (
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debugging",
)


def _validate_syslog_level(value: object) -> "str | int":
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 7:
        return value
    if isinstance(value, str) and value in SYSLOG_LEVELS:
        return value
    raise ValueError(
        f"must be a syslog level 0-7 or one of: {', '.join(SYSLOG_LEVELS)}"
    )


#: IOS syslog severity keywords, or their numeric equivalents 0-7.
SyslogLevel = Annotated[Union[str, int], PlainValidator(_validate_syslog_level)]
