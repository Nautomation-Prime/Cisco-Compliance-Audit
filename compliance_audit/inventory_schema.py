"""
Pydantic models for the device inventory (``devices.yaml``) and for the
``--device`` CLI targets.

An inventory entry may name a device by hostname, by IP address, or both.
IP addresses are parsed with pydantic's ``IPvAnyAddress`` so IPv4 and IPv6
both work and a malformed address is reported here, with its location in the
file, rather than surfacing later as an unhelpful connection failure.
"""

from __future__ import annotations

from typing import Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    ValidationError,
    field_validator,
    model_validator,
)

from .schema_types import Hostname, parse_ip, validate_hostname


class InventoryError(ValueError):
    """The device list could not be built: bad inventory, ``--device`` or ``--ip-filter``."""


class DeviceEntry(BaseModel):
    """One device.  Extra keys (``platform``, ``notes`` …) are kept as-is."""

    model_config = ConfigDict(extra="allow")

    hostname: Optional[Hostname] = None
    ip: Optional[IPvAnyAddress] = None
    role: Optional[str] = Field(default=None, min_length=1)

    @field_validator("ip", mode="before")
    @classmethod
    def _dns_name_hint(cls, v: object) -> object:
        if isinstance(v, str) and parse_ip(v) is None:
            try:
                validate_hostname(v)
            except ValueError:
                return v  # let IPvAnyAddress report the bad address
            raise ValueError(
                f"'{v}' is a DNS name, not an IP address — put it under 'hostname'"
            )
        return v

    @model_validator(mode="after")
    def _needs_a_target(self) -> "DeviceEntry":
        if self.hostname is None and self.ip is None:
            raise ValueError("must contain at least 'hostname' or 'ip'")
        return self

    @property
    def target(self) -> str:
        """The connection target: the IP when known, otherwise the hostname."""
        return str(self.ip) if self.ip is not None else str(self.hostname)

    def to_dict(self) -> dict:
        """Return the normalised ``{hostname, ip, …}`` dict the auditor uses.

        Both keys are always present: a missing one is filled from the other,
        so ``ip`` is the connection target even when it is a DNS name.
        """
        out = self.model_dump(exclude_none=True)
        target = self.target
        out["ip"] = target
        out["hostname"] = self.hostname or target
        return out


class InventoryGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    devices: Optional[list] = None


class InventoryFile(BaseModel):
    """Top level of ``devices.yaml``.

    Unknown keys are rejected: a typo such as ``device:`` would otherwise
    load an empty inventory and the audit would quietly do nothing.
    """

    model_config = ConfigDict(extra="forbid")

    devices: Optional[list] = None
    groups: Optional[dict[str, InventoryGroup]] = None


def parse_device_entry(raw: object) -> DeviceEntry:
    """Build a :class:`DeviceEntry` from a bare string or a mapping.

    A bare string is an IP address if it parses as one, otherwise a hostname.
    Raises ``ValueError`` (``ValidationError`` included) for anything else.
    """
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            raise ValueError("empty string")
        ip = parse_ip(value)
        if ip is not None:
            return DeviceEntry(ip=ip)
        return DeviceEntry(hostname=validate_hostname(value))
    if isinstance(raw, dict):
        return DeviceEntry.model_validate(raw)
    raise ValueError(f"expected string or mapping, got {type(raw).__name__}")


def parse_device_target(spec: str) -> DeviceEntry:
    """Parse a ``--device`` value: ``HOST``, ``IP`` or ``HOST:IP``.

    A whole-string IP is checked first so IPv6 addresses, which contain
    colons, are not split.  In ``HOST:IP`` the split is on the first colon,
    since hostnames never contain one.
    """
    spec = spec.strip()
    if parse_ip(spec) is not None or ":" not in spec:
        return parse_device_entry(spec)
    hostname, _, ip = spec.partition(":")
    return DeviceEntry.model_validate({"hostname": hostname, "ip": ip})


def format_entry_error(exc: ValueError, location: str) -> str:
    """One readable line for a rejected entry at *location*."""
    if isinstance(exc, ValidationError):
        parts = []
        for e in exc.errors():
            field = ".".join(str(p) for p in e["loc"])
            msg = e["msg"].removeprefix("Value error, ")
            parts.append(f"{field}: {msg}" if field else msg)
        return f"{location}: " + "; ".join(parts)
    return f"{location}: {exc}"
