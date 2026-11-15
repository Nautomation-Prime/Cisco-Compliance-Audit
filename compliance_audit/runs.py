"""
Audit runs: the unit a scheduled audit reports on and an approver acts on.

Every audit already has a run ID (``audit-20261106T013000123456Z``).  This
module records a *run manifest* — ``<output_dir>/runs/<run_id>.json`` —
summarising the run (scores, unreachable devices, review packs, expired
exceptions, report paths), and provides the run-level operations:

* approve every pack a run produced, to apply now or at a scheduled time
  (``--run-approve RUN_ID [--apply-now | --apply-at TIME]``);
* reject every pack a run produced (``--run-reject RUN_ID``);
* list and show runs (``--run-list``, ``--run-show RUN_ID``).

It also provides a small exclusive lock so a scheduled audit or apply never
overlaps with another one writing to the same output directory.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from .remediation_workflow import (
    ReviewEntry,
    approve_review_pack,
    format_schedule,
    list_review_packs,
    reject_review_pack,
)

log = logging.getLogger(__name__)

MANIFEST_SCHEMA_VERSION = 1

#: Pack states a run-level approval acts on.  ``approved`` is included so a
#: run can be re-approved to change its schedule (or switch to --apply-now).
APPROVABLE_STATUSES = ("pending", "approved")

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


# ─────────────────────────────────────────────────────────────────────────────
#  Paths and manifests
# ─────────────────────────────────────────────────────────────────────────────

def runs_dir(output_dir: str | Path) -> Path:
    return Path(output_dir).expanduser() / "runs"


def _check_run_id(run_id: str) -> str:
    run_id = (run_id or "").strip()
    if not _RUN_ID_RE.match(run_id):
        raise RuntimeError(f"Invalid run ID: {run_id!r}")
    return run_id


def manifest_path(output_dir: str | Path, run_id: str) -> Path:
    return runs_dir(output_dir) / f"{_check_run_id(run_id)}.json"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_str(when: Optional[datetime] = None) -> str:
    return (when or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_manifest(output_dir: str | Path, manifest: dict) -> Path:
    """Write (or overwrite) a run manifest; returns its path."""
    path = manifest_path(output_dir, manifest["run_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_manifest(output_dir: str | Path, run_id: str) -> dict:
    path = manifest_path(output_dir, run_id)
    if not path.is_file():
        raise RuntimeError(
            f"Run not found: {run_id} (no manifest at {path}). "
            "Use --run-list to see the runs in this output directory."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def update_manifest(output_dir: str | Path, run_id: str, **fields) -> dict:
    """Merge *fields* into a manifest's top level and save it."""
    manifest = load_manifest(output_dir, run_id)
    manifest.update(fields)
    write_manifest(output_dir, manifest)
    return manifest


def list_manifests(output_dir: str | Path, limit: Optional[int] = None) -> list[dict]:
    """Run manifests, newest first."""
    directory = runs_dir(output_dir)
    if not directory.is_dir():
        return []
    manifests: list[dict] = []
    for path in directory.glob("*.json"):
        try:
            manifests.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Skipping unreadable run manifest %s: %s", path, exc)
    # finished_at has one-second resolution; run IDs carry microseconds, so
    # they order runs that finish within the same second.
    manifests.sort(key=lambda m: (m.get("finished_at", ""), m.get("run_id", "")), reverse=True)
    return manifests[:limit] if limit else manifests


# ─────────────────────────────────────────────────────────────────────────────
#  Building a manifest from an audit
# ─────────────────────────────────────────────────────────────────────────────

def _delta_summary(delta: Optional[dict]) -> Optional[dict]:
    if not delta:
        return None
    return {
        "baseline_score": delta.get("baseline_score"),
        "score_change": delta.get("score_change"),
        "new_failures": delta.get("new_failure_count", 0),
        "resolved": delta.get("resolved_count", 0),
        "unchanged": delta.get("unchanged_fail_count", 0),
        "excepted": delta.get("excepted_count", 0),
        "new_failure_items": [
            {
                "check": item.get("check", ""),
                "interface": item.get("interface", ""),
                "status": item.get("new_status", ""),
                "detail": item.get("detail", ""),
            }
            for item in (delta.get("new_failures") or [])[:50]
        ],
    }


def build_manifest(
    *,
    run_id: str,
    started_at: datetime,
    results: list,
    unreachable: list[dict],
    config_path: str,
    output_dir: str,
    tool_version: str,
    exception_summary: Optional[dict] = None,
    reports: Optional[dict] = None,
    scope: Optional[dict] = None,
) -> dict:
    """Summarise one audit run.  *results* are ``AuditResult`` objects."""
    devices: list[dict] = []
    for r in results:
        pack = getattr(r, "_pack", None) or {}
        report_paths = getattr(r, "_report_paths", None) or {}
        devices.append({
            "hostname": r.hostname,
            "ip": r.ip,
            "role": r.role,
            "role_display": r.role_display,
            "group": getattr(r, "group", ""),
            "ios_version": r.ios_version,
            "score_pct": r.score_pct,
            "pass": r.pass_count,
            "fail": r.fail_count,
            "warn": r.warn_count,
            "error": r.error_count,
            "exception": r.exception_count,
            "expired_exceptions": r.expired_exception_count,
            "expiring_exceptions": r.expiring_exception_count,
            "pack_id": pack.get("pack_id", ""),
            "pack_risk": pack.get("highest_risk", ""),
            "pack_findings": pack.get("findings_count", 0),
            "script_path": pack.get("script_path", ""),
            "pack_path": pack.get("pack_path", ""),
            "reports": report_paths,
            "delta": _delta_summary(getattr(r, "_delta", None)),
        })

    total_checks = sum(r.total for r in results)
    total_pass = sum(r.pass_count for r in results)
    exc = exception_summary or {}
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": _utc_str(started_at),
        "finished_at": _utc_str(),
        "host": socket.gethostname(),
        "tool_version": tool_version,
        "config_path": str(config_path),
        "output_dir": str(output_dir),
        "scope": scope or {},
        "totals": {
            "devices": len(results) + len(unreachable),
            "audited": len(results),
            "unreachable": len(unreachable),
            "score_pct": round(total_pass / total_checks * 100, 1) if total_checks else 100.0,
            "pass": total_pass,
            "fail": sum(r.fail_count for r in results),
            "warn": sum(r.warn_count for r in results),
            "error": sum(r.error_count for r in results),
            "exception": sum(r.exception_count for r in results),
            "expired_exceptions": sum(r.expired_exception_count for r in results),
            "packs": sum(1 for d in devices if d["pack_id"]),
        },
        "devices": devices,
        "unreachable": unreachable,
        "exceptions": {
            "expired": exc.get("expired", []),
            "expiring": exc.get("expiring", []),
            "unused": exc.get("unused", []),
        },
        "reports": reports or {},
        "notification": {},
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Run status (manifest + live pack states)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RunStatus:
    manifest: dict
    packs: list[ReviewEntry] = field(default_factory=list)

    @property
    def run_id(self) -> str:
        return self.manifest.get("run_id", "")

    def count(self, status: str) -> int:
        return sum(1 for p in self.packs if p.status == status)

    @property
    def scheduled(self) -> list[ReviewEntry]:
        return [p for p in self.packs if p.status == "approved" and p.scheduled_for]

    @property
    def state(self) -> str:
        """One-word summary of where the run's packs are."""
        if not self.packs:
            return "nothing to remediate"
        statuses = {p.status for p in self.packs}
        if statuses == {"superseded"}:
            return "superseded"
        if "pending" in statuses:
            return "awaiting approval"
        if self.scheduled:
            return "scheduled"
        if "approved" in statuses:
            return "approved"
        if statuses <= {"applied"}:
            return "applied"
        if "failed" in statuses:
            return "failed"
        return ", ".join(sorted(statuses))


def run_status(output_dir: str | Path, run_id: str) -> RunStatus:
    manifest = load_manifest(output_dir, run_id)
    packs = list_review_packs(str(output_dir), run_id=manifest["run_id"])
    return RunStatus(manifest, packs)


# ─────────────────────────────────────────────────────────────────────────────
#  Schedule parsing
# ─────────────────────────────────────────────────────────────────────────────

_LOCAL_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")


def parse_schedule_time(text: str, now: Optional[datetime] = None) -> datetime:
    """Parse an ``--apply-at`` value into an aware UTC datetime.

    Accepted forms:

    * ``2026-11-07 02:00`` — the audit host's local time;
    * ``02:00`` — the next occurrence of that local time;
    * ``2026-11-07T02:00:00Z`` / ``2026-11-07T02:00:00+01:00`` — explicit.

    The time must be in the future.
    """
    now = now or _utc_now()
    raw = (text or "").strip()
    if not raw:
        raise RuntimeError("--apply-at needs a time, e.g. '2026-11-07 02:00' or '02:00'.")

    when: Optional[datetime] = None
    if re.fullmatch(r"\d{1,2}:\d{2}", raw):
        hour, minute = (int(x) for x in raw.split(":"))
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise RuntimeError(f"Invalid time of day: {raw!r}")
        local_now = now.astimezone()
        candidate = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= local_now:
            candidate += timedelta(days=1)
        when = candidate
    else:
        iso = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError:
            parsed = None
            for fmt in _LOCAL_FORMATS:
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
        if parsed is None:
            raise RuntimeError(
                f"Could not read --apply-at {raw!r}. Use 'YYYY-MM-DD HH:MM' (local time), "
                "'HH:MM', or an ISO-8601 time with an offset."
            )
        when = parsed if parsed.tzinfo else parsed.astimezone()  # naive → local time

    when = when.astimezone(timezone.utc)
    if when <= now:
        raise RuntimeError(
            f"--apply-at {raw!r} is in the past ({format_schedule(when)}); "
            "use --apply-now to apply immediately."
        )
    return when


# ─────────────────────────────────────────────────────────────────────────────
#  Run-level approve / reject
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RunDecision:
    """Outcome of a run-level approve or reject."""

    run_id: str
    acted: list[dict] = field(default_factory=list)    # packs approved / rejected
    skipped: list[dict] = field(default_factory=list)  # packs left alone, with why

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "acted": self.acted, "skipped": self.skipped}


def approve_run(
    output_dir: str,
    run_id: str,
    *,
    approver: str,
    ticket_id: str,
    expires_hours: int,
    require_ticket_id: bool,
    scheduled_for: Optional[datetime] = None,
    allow_high_risk: bool = False,
    block_high_risk: bool = True,
) -> RunDecision:
    """Approve every pending pack a run produced (re-approving reschedules).

    High-risk packs are approved only with *allow_high_risk* when
    *block_high_risk* is on (the default policy); otherwise they are skipped
    with a reason, and the rest of the run is still approved.
    """
    status = run_status(output_dir, run_id)
    decision = RunDecision(status.run_id)
    if not status.packs:
        raise RuntimeError(f"Run {status.run_id} produced no remediation packs.")

    for entry in status.packs:
        item = {"pack_id": entry.pack_id, "hostname": entry.hostname, "risk": entry.highest_risk}
        if entry.status not in APPROVABLE_STATUSES:
            why = f"status is {entry.status}"
            if entry.status == "superseded":
                why += " — a newer audit replaced this pack; approve the newer run"
            decision.skipped.append({**item, "reason": why})
            continue
        if entry.highest_risk == "high" and block_high_risk and not allow_high_risk:
            decision.skipped.append({
                **item,
                "reason": "high-risk commands — add --allow-high-risk to approve them",
            })
            continue
        approve_review_pack(
            output_dir=output_dir,
            pack_id=entry.pack_id,
            approver=approver,
            ticket_id=ticket_id,
            expires_hours=expires_hours,
            require_ticket_id=require_ticket_id,
            scheduled_for=scheduled_for,
            allow_high_risk=allow_high_risk,
        )
        decision.acted.append({**item, "status": "approved",
                               "scheduled_for": _utc_str(scheduled_for) if scheduled_for else ""})

    if not decision.acted:
        reasons = "; ".join(f"{s['hostname']}: {s['reason']}" for s in decision.skipped)
        raise RuntimeError(f"Nothing in run {status.run_id} could be approved ({reasons}).")
    return decision


def reject_run(output_dir: str, run_id: str, *, approver: str, reason: str) -> RunDecision:
    """Reject every pack of a run that has not been applied or superseded."""
    status = run_status(output_dir, run_id)
    decision = RunDecision(status.run_id)
    if not status.packs:
        raise RuntimeError(f"Run {status.run_id} produced no remediation packs.")
    for entry in status.packs:
        item = {"pack_id": entry.pack_id, "hostname": entry.hostname, "risk": entry.highest_risk}
        if entry.status not in ("pending", "approved"):
            decision.skipped.append({**item, "reason": f"status is {entry.status}"})
            continue
        reject_review_pack(output_dir, entry.pack_id, approver, reason)
        decision.acted.append({**item, "status": "rejected"})
    if not decision.acted:
        raise RuntimeError(f"Nothing in run {status.run_id} is pending or approved.")
    return decision


# ─────────────────────────────────────────────────────────────────────────────
#  Exclusive lock
# ─────────────────────────────────────────────────────────────────────────────

class LockHeld(RuntimeError):
    """Another process holds the lock."""


@contextmanager
def exclusive_lock(output_dir: str | Path, name: str) -> Iterator[Path]:
    """Hold ``<output_dir>/.locks/<name>.lock`` for the duration, or raise ``LockHeld``.

    Non-blocking: a scheduled job that finds the previous one still running
    stops at once instead of queueing behind it.  The lock is released when
    the process exits, even on a crash.  Where ``fcntl`` is unavailable
    (Windows) this is a no-op.
    """
    lock_dir = Path(output_dir).expanduser() / ".locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    path = lock_dir / f"{name}.lock"
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        yield path
        return
    fh = open(path, "a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.seek(0)
            holder = fh.read().strip()
            raise LockHeld(
                f"Another {name} is already running for this output directory"
                + (f" ({holder})" if holder else "")
                + f" — lock file {path}"
            ) from exc
        fh.seek(0)
        fh.truncate()
        fh.write(f"pid {os.getpid()} on {socket.gethostname()} since {_utc_str()}")
        fh.flush()
        yield path
    finally:
        fh.close()
