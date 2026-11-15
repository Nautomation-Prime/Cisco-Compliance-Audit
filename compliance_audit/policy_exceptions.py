"""
Policy exceptions — approved, time-boxed deviations from the compliance policy.

An exception says *"this finding is a known, accepted deviation on this
device: report it as an exception, not a failure, and never remediate it"*.
Every exception carries a reason and an expiry date, so the register cannot
quietly turn into a list of permanently ignored checks.  Once an exception
expires it is flagged in every report for review — but it is **still never
remediated**.  Fixing an expired deviation stays a deliberate human decision,
made by removing (or renewing) the exception.

Exceptions are declared under the top-level ``exceptions:`` key — normally
in ``assets/compliance_config/exceptions.yaml`` — and validated with the rest
of the config by :mod:`compliance_audit.config_schema`.  Matching works on
two levels, and every selector given must match (selectors left out match
everything):

* **device** — ``hostnames`` (regex, also tried against the management IP),
  ``ips`` (addresses or CIDR networks), ``groups`` (inventory site groups)
  and ``roles``.  At least one device selector is required.
* **finding** — ``checks`` (required; a finding name as shown in the report,
  the YAML key of the check that emits it, or a regex), ``interfaces``
  (interface names or regexes; ``Gi1/0/1`` matches ``GigabitEthernet1/0/1``)
  and ``detail`` (a regex searched for in the finding text).

Only FAIL and WARN findings can be covered.  An ERROR means the check could
not run, and an exception must never hide that.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import date
from enum import Enum
from typing import TYPE_CHECKING, Iterable, Optional

from .checks.base import Finding, Status, _find_check_key
from .collector import _ABBREV_MAP

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .checks.base import AuditResult

log = logging.getLogger(__name__)

#: Statuses an exception may cover.
EXCEPTABLE_STATUSES = frozenset({Status.FAIL, Status.WARN})


class ExceptionState(str, Enum):
    """Where an exception is in its lifecycle on the day of the audit."""

    ACTIVE = "active"
    EXPIRING = "expiring"    # active, but inside the expiring-soon window
    EXPIRED = "expired"      # past its expiry date — needs review
    PERMANENT = "permanent"  # ``expires: never`` (needs allow_permanent)


#: Report ordering: the states that need attention first.
STATE_ORDER = {
    ExceptionState.EXPIRED.value: 0,
    ExceptionState.EXPIRING.value: 1,
    ExceptionState.ACTIVE.value: 2,
    ExceptionState.PERMANENT.value: 3,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExceptionSettings:
    """``exception_settings:`` — how exceptions affect scoring and exit codes."""

    #: Flag an active exception as *expiring* this many days before it
    #: expires (0 turns the warning off).
    expiring_soon_days: int = 30
    #: Count findings under an expired exception as not passing in the score.
    expired_counts_against_score: bool = False
    #: Make the run exit 1 when any finding sits under an expired exception.
    fail_on_expired: bool = False
    #: Allow ``expires: never``.  Off by default so every exception is reviewed.
    allow_permanent: bool = False

    @classmethod
    def from_config(cls, raw: object) -> "ExceptionSettings":
        from .config_schema import ExceptionSettingsSchema

        model = ExceptionSettingsSchema.model_validate(raw or {})
        return cls(**model.model_dump())


# ─────────────────────────────────────────────────────────────────────────────
#  What a covered finding carries
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AppliedException:
    """The exception covering one finding, as recorded on ``Finding.exception``."""

    id: str
    state: str
    reason: str
    expires: str                     # ISO date, or "never"
    days_remaining: Optional[int]    # negative once expired; None if permanent
    original_status: str             # FAIL or WARN — what the check reported
    approved_by: str = ""
    approved_on: str = ""
    ticket: str = ""
    owner: str = ""
    notes: str = ""
    source: str = ""                 # file the exception was defined in

    @property
    def expired(self) -> bool:
        return self.state == ExceptionState.EXPIRED.value

    def to_dict(self) -> dict:
        return asdict(self)

    def status_text(self) -> str:
        """Short human description, e.g. ``expired 12 day(s) ago``."""
        return describe_state(self.state, self.days_remaining, self.expires)


def describe_state(state: str, days_remaining: Optional[int], expires: str) -> str:
    """Human wording for an exception's state, used by every report."""
    if state == ExceptionState.PERMANENT.value:
        return "permanent (no expiry)"
    if state == ExceptionState.EXPIRED.value:
        ago = -(days_remaining or 0)
        return f"EXPIRED {expires} ({ago} day(s) ago) — review required"
    if days_remaining == 0:
        return f"expires today ({expires})"
    return f"expires {expires} (in {days_remaining} day(s))"


# ─────────────────────────────────────────────────────────────────────────────
#  One compiled exception
# ─────────────────────────────────────────────────────────────────────────────

def _compile(pattern: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:  # the schema rejects these; never crash an audit on one
        log.warning("Ignoring invalid exception pattern %r", pattern)
        return None


def _expand_intf(name: str) -> str:
    """Case-insensitive ``normalize_intf``: ``gi1/0/1`` → ``GigabitEthernet1/0/1``."""
    lower = name.lower()
    for abbr, full in _ABBREV_MAP.items():
        if lower.startswith(abbr.lower()) and not lower.startswith(full.lower()):
            return full + name[len(abbr):]
    return name


@dataclass
class _InterfacePattern:
    raw: str
    patterns: tuple[re.Pattern, ...]

    @classmethod
    def build(cls, raw: str) -> "_InterfacePattern":
        # Compile the pattern as written and with its leading abbreviation
        # expanded, so "Gi1/0/(1|2)" matches "GigabitEthernet1/0/1".
        variants = {raw, _expand_intf(raw)}
        compiled = tuple(p for p in (_compile(v) for v in variants) if p is not None)
        return cls(raw, compiled)

    def matches(self, interface: str) -> bool:
        if not interface:
            return False
        if _expand_intf(self.raw).lower() == _expand_intf(interface).lower():
            return True
        names = {interface, _expand_intf(interface)}
        return any(p.fullmatch(n) for p in self.patterns for n in names)


@dataclass
class ExceptionRule:
    """One entry of the exception register, with its patterns compiled."""

    id: str
    reason: str
    expires: Optional[date]          # None = permanent
    checks: tuple[re.Pattern, ...]
    hostnames: tuple[re.Pattern, ...] = ()
    ips: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    groups: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    interfaces: tuple[_InterfacePattern, ...] = ()
    detail: Optional[re.Pattern] = None
    approved_by: str = ""
    approved_on: Optional[date] = None
    ticket: str = ""
    owner: str = ""
    notes: str = ""
    source: str = ""
    #: The selectors as written, for reports.
    spec: dict = field(default_factory=dict)

    # ── construction ────────────────────────────────────────
    @classmethod
    def from_entry(cls, entry: dict) -> "ExceptionRule":
        """Build a rule from one ``exceptions:`` entry (validated by the schema)."""
        from .config_schema import ExceptionEntrySchema

        source = str(entry.get("_source", "")) if isinstance(entry, dict) else ""
        m = ExceptionEntrySchema.model_validate(entry)
        return cls(
            id=m.id,
            reason=m.reason,
            expires=None if m.expires == "never" else m.expires,
            checks=tuple(p for p in map(_compile, m.checks) if p is not None),
            hostnames=tuple(p for p in map(_compile, m.hostnames) if p is not None),
            ips=tuple(ipaddress.ip_network(n, strict=False) for n in m.ips),
            groups=frozenset(g.lower() for g in m.groups),
            roles=frozenset(m.roles),
            interfaces=tuple(_InterfacePattern.build(i) for i in m.interfaces),
            detail=_compile(m.detail) if m.detail else None,
            approved_by=m.approved_by,
            approved_on=m.approved_on,
            ticket=m.ticket,
            owner=m.owner,
            notes=m.notes,
            source=source,
            spec={
                "hostnames": list(m.hostnames),
                "ips": list(m.ips),
                "groups": list(m.groups),
                "roles": list(m.roles),
                "checks": list(m.checks),
                "interfaces": list(m.interfaces),
                "detail": m.detail or "",
            },
        )

    # ── lifecycle ──────────────────────────────────────────
    @property
    def expires_text(self) -> str:
        return self.expires.isoformat() if self.expires else "never"

    def state_on(self, today: date, expiring_soon_days: int) -> tuple[str, Optional[int]]:
        """``(state, days_remaining)`` on *today*.

        An exception is valid through the whole of its expiry date and
        expired from the day after.
        """
        if self.expires is None:
            return ExceptionState.PERMANENT.value, None
        days = (self.expires - today).days
        if days < 0:
            return ExceptionState.EXPIRED.value, days
        if expiring_soon_days and days <= expiring_soon_days:
            return ExceptionState.EXPIRING.value, days
        return ExceptionState.ACTIVE.value, days

    # ── matching ───────────────────────────────────────────
    def matches_device(
        self,
        hostname: str,
        ip: str = "",
        role: str = "",
        group: Optional[str] = "",
    ) -> bool:
        """True when every device selector given matches this device.

        *group* ``None`` means "unknown" (a review pack written before packs
        recorded the group).  A group selector then counts as matching — when
        the question is whether a command may be pushed, unknown must err on
        the side of not pushing it.
        """
        if self.hostnames:
            names = {n for n in (hostname, hostname.split(".")[0], ip) if n}
            if not any(p.fullmatch(n) for p in self.hostnames for n in names):
                return False
        if self.ips:
            try:
                addr = ipaddress.ip_address(str(ip).strip())
            except ValueError:
                return False
            if not any(addr.version == net.version and addr in net for net in self.ips):
                return False
        if self.groups and group is not None:
            if not group or group.lower() not in self.groups:
                return False
        if self.roles and role not in self.roles:
            return False
        return True

    def matches_finding(
        self, check_name: str, check_key: str, interface: str, detail: str
    ) -> bool:
        """True when every finding selector given matches."""
        names = [n for n in (check_name, check_key) if n]
        if not any(p.fullmatch(n) for p in self.checks for n in names):
            return False
        if self.interfaces and not any(i.matches(interface) for i in self.interfaces):
            return False
        if self.detail is not None and not self.detail.search(detail or ""):
            return False
        return True

    # ── reporting ──────────────────────────────────────────
    def scope_text(self) -> str:
        """One-line summary of what the exception covers."""
        parts: list[str] = []
        labels = (
            ("hostnames", "hosts"),
            ("ips", "ips"),
            ("groups", "groups"),
            ("roles", "roles"),
            ("checks", "checks"),
            ("interfaces", "interfaces"),
        )
        for key, label in labels:
            if self.spec.get(key):
                parts.append(f"{label}: {', '.join(self.spec[key])}")
        if self.spec.get("detail"):
            parts.append(f"detail: /{self.spec['detail']}/")
        return "; ".join(parts)

    def describe(self, today: date, expiring_soon_days: int) -> dict:
        """Report-friendly dict of the exception and its state on *today*."""
        state, days = self.state_on(today, expiring_soon_days)
        return {
            "id": self.id,
            "state": state,
            "days_remaining": days,
            "expires": self.expires_text,
            "status_text": describe_state(state, days, self.expires_text),
            "reason": self.reason,
            "approved_by": self.approved_by,
            "approved_on": self.approved_on.isoformat() if self.approved_on else "",
            "ticket": self.ticket,
            "owner": self.owner,
            "notes": self.notes,
            "source": self.source,
            "scope": self.scope_text(),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  The register
# ─────────────────────────────────────────────────────────────────────────────

class ExceptionRegister:
    """Every exception in the config, plus the settings and the audit date."""

    def __init__(
        self,
        rules: Iterable[ExceptionRule] = (),
        settings: Optional[ExceptionSettings] = None,
        today: Optional[date] = None,
    ):
        self.rules: list[ExceptionRule] = list(rules)
        self.settings = settings or ExceptionSettings()
        self.today = today or date.today()

    @classmethod
    def from_config(cls, cfg: dict, today: Optional[date] = None) -> "ExceptionRegister":
        """Build the register from the merged (and validated) config dict.

        Raises ``pydantic.ValidationError`` for an entry the schema rejects;
        normal loading validates first, so this only fires for callers that
        skipped validation.
        """
        entries = cfg.get("exceptions") or []
        rules = [ExceptionRule.from_entry(e) for e in entries if isinstance(e, dict)]
        settings = ExceptionSettings.from_config(cfg.get("exception_settings"))
        return cls(rules, settings, today)

    @classmethod
    def empty(cls) -> "ExceptionRegister":
        return cls()

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    # ── state ──────────────────────────────────────────────
    def state_of(self, rule: ExceptionRule) -> tuple[str, Optional[int]]:
        return rule.state_on(self.today, self.settings.expiring_soon_days)

    def describe(self, rule: ExceptionRule) -> dict:
        return rule.describe(self.today, self.settings.expiring_soon_days)

    def state_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in ExceptionState}
        for rule in self.rules:
            counts[self.state_of(rule)[0]] += 1
        return counts

    # ── matching ───────────────────────────────────────────
    def rules_for_device(
        self, hostname: str, ip: str = "", role: str = "", group: Optional[str] = ""
    ) -> list[ExceptionRule]:
        return [r for r in self.rules if r.matches_device(hostname, ip, role, group)]

    @staticmethod
    def best_match(
        rules: Iterable[ExceptionRule],
        check_name: str,
        check_key: str,
        interface: str,
        detail: str,
    ) -> Optional[ExceptionRule]:
        """The matching rule with the latest expiry (permanent beats any date).

        When an exception has been renewed by adding a new entry, the renewal
        wins and the finding is not flagged as expired; ties go to the entry
        listed first.
        """
        best: Optional[ExceptionRule] = None
        for rule in rules:
            if not rule.matches_finding(check_name, check_key, interface, detail):
                continue
            if best is None or _expiry_key(rule) > _expiry_key(best):
                best = rule
        return best

    def applied(self, rule: ExceptionRule, original_status: str) -> AppliedException:
        state, days = self.state_of(rule)
        return AppliedException(
            id=rule.id,
            state=state,
            reason=rule.reason,
            expires=rule.expires_text,
            days_remaining=days,
            original_status=original_status,
            approved_by=rule.approved_by,
            approved_on=rule.approved_on.isoformat() if rule.approved_on else "",
            ticket=rule.ticket,
            owner=rule.owner,
            notes=rule.notes,
            source=rule.source,
        )

    def apply(
        self,
        findings: list[Finding],
        *,
        hostname: str,
        ip: str = "",
        role: str = "",
        group: str = "",
        check_map: Optional[dict[str, dict]] = None,
    ) -> list[ExceptionRule]:
        """Mark every FAIL/WARN an exception covers as EXCEPTION, in place.

        Returns the exceptions scoped to this device that covered nothing.
        """
        device_rules = self.rules_for_device(hostname, ip, role, group)
        if not device_rules:
            return []
        check_map = check_map or {}
        used: set[str] = set()
        for f in findings:
            if f.status not in EXCEPTABLE_STATUSES:
                continue
            key = _find_check_key(f.check_name, check_map)
            matching = [
                r for r in device_rules
                if r.matches_finding(f.check_name, key, f.interface, f.detail)
            ]
            if not matching:
                continue
            used.update(id(r) for r in matching)
            rule = self.best_match(matching, f.check_name, key, f.interface, f.detail)
            if rule is None:  # unreachable: *matching* is non-empty
                continue
            f.exception = self.applied(rule, f.status.value)
            f.status = Status.EXCEPTION
        return [r for r in device_rules if id(r) not in used]

    def apply_to_result(self, result: "AuditResult", check_map: dict[str, dict]) -> None:
        """Apply the register to *result* and record the settings it needs."""
        result.expired_exceptions_count_in_score = (
            self.settings.expired_counts_against_score
        )
        result.expired_exceptions_fail_run = self.settings.fail_on_expired
        unused = self.apply(
            result.findings,
            hostname=result.hostname,
            ip=result.ip,
            role=result.role,
            group=result.group,
            check_map=check_map,
        )
        result.unused_exceptions = [self.describe(r) for r in unused]

    def covering_rule(
        self,
        *,
        hostname: str,
        ip: str,
        role: str,
        group: Optional[str],
        check_name: str,
        interface: str,
        detail: str,
        check_map: Optional[dict[str, dict]] = None,
    ) -> Optional[ExceptionRule]:
        """The exception that covers one finding, if any (state is ignored).

        Used at remediation apply time: an item covered by *any* exception —
        active or expired — is never pushed to the device.
        """
        rules = self.rules_for_device(hostname, ip, role, group)
        key = _find_check_key(check_name, check_map or {})
        return self.best_match(rules, check_name, key, interface, detail)


def _expiry_key(rule: ExceptionRule) -> date:
    return rule.expires or date.max


# ─────────────────────────────────────────────────────────────────────────────
#  Run-level summaries for reports
# ─────────────────────────────────────────────────────────────────────────────

def register_rows(
    results: list["AuditResult"],
    register: Optional[ExceptionRegister] = None,
) -> list[dict]:
    """One row per exception with how it was used across *results*.

    With a *register*, every exception in the config is listed — including
    ones whose device selectors matched no audited device (``usage`` =
    ``out_of_scope``).  Without one (e.g. a report rebuilt from results
    alone), the rows come from the exceptions recorded on findings.

    Rows are sorted expired → expiring → active → permanent, then by ID.
    """
    covered: dict[str, dict] = {}
    for r in results:
        for f in r.findings:
            exc = f.exception
            if f.status != Status.EXCEPTION or exc is None:
                continue
            row = covered.setdefault(exc.id, {"findings": 0, "devices": []})
            row["findings"] += 1
            if r.hostname not in row["devices"]:
                row["devices"].append(r.hostname)

    rows: list[dict] = []
    if register is not None:
        for rule in register.rules:
            row = register.describe(rule)
            in_scope = [
                r.hostname for r in results
                if rule.matches_device(r.hostname, r.ip, r.role, r.group)
            ]
            use = covered.get(rule.id, {"findings": 0, "devices": []})
            row.update(
                devices_in_scope=len(in_scope),
                covered_findings=use["findings"],
                covered_devices=list(use["devices"]),
                usage=(
                    "in_use" if use["findings"]
                    else "unused" if in_scope
                    else "out_of_scope"
                ),
            )
            rows.append(row)
    else:
        seen: dict[str, AppliedException] = {}
        for r in results:
            for f in r.findings:
                if f.status == Status.EXCEPTION and f.exception is not None:
                    seen.setdefault(f.exception.id, f.exception)
        for exc_id, exc in seen.items():
            use = covered[exc_id]
            rows.append({
                "id": exc.id,
                "state": exc.state,
                "days_remaining": exc.days_remaining,
                "expires": exc.expires,
                "status_text": exc.status_text(),
                "reason": exc.reason,
                "approved_by": exc.approved_by,
                "approved_on": exc.approved_on,
                "ticket": exc.ticket,
                "owner": exc.owner,
                "notes": exc.notes,
                "source": exc.source,
                "scope": "",
                "devices_in_scope": len(use["devices"]),
                "covered_findings": use["findings"],
                "covered_devices": list(use["devices"]),
                "usage": "in_use",
            })
        # Exceptions recorded as unused on a device but covering nothing anywhere.
        for r in results:
            for desc in r.unused_exceptions:
                if desc["id"] in seen or any(row["id"] == desc["id"] for row in rows):
                    continue
                rows.append({
                    **desc,
                    "devices_in_scope": 1,
                    "covered_findings": 0,
                    "covered_devices": [],
                    "usage": "unused",
                })

    rows.sort(key=lambda row: (STATE_ORDER.get(row["state"], 9), row["id"]))
    return rows


def run_summary(results: list["AuditResult"], register: Optional[ExceptionRegister] = None) -> dict:
    """Counts for the console summary and report headers."""
    rows = register_rows(results, register)
    return {
        "rows": rows,
        "covered_findings": sum(r.exception_count for r in results),
        "expired_findings": sum(r.expired_exception_count for r in results),
        "expiring_findings": sum(r.expiring_exception_count for r in results),
        "expired": [row for row in rows if row["state"] == ExceptionState.EXPIRED.value],
        "expiring": [row for row in rows if row["state"] == ExceptionState.EXPIRING.value],
        "unused": [row for row in rows if row["usage"] == "unused"],
    }
