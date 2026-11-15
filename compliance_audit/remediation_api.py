"""Programmatic integration wrappers for remediation lifecycle operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .remediation_cli import limit_review_entries, sort_review_entries
from .remediation_workflow import (
    apply_all_approved_packs,
    apply_approved_pack,
    approve_review_pack,
    get_review_pack,
    list_review_packs,
    reject_review_pack,
)


def _entry_as_dict(entry) -> dict:
    return {
        "pack_id": str(getattr(entry, "pack_id", "")),
        "status": str(getattr(entry, "status", "")),
        "hostname": str(getattr(entry, "hostname", "")),
        "ip": str(getattr(entry, "ip", "")),
        "highest_risk": str(getattr(entry, "highest_risk", "")),
        "findings_count": int(getattr(entry, "findings_count", 0)),
        "created_ts": str(getattr(entry, "created_ts", "")),
        "approved_by": str(getattr(entry, "approved_by", "")),
        "approved_at": str(getattr(entry, "approved_at", "")),
        "ticket_id": str(getattr(entry, "ticket_id", "")),
        "expires_at": str(getattr(entry, "expires_at", "")),
        "script_path": str(getattr(entry, "script_path", "")),
        "pack_path": str(getattr(entry, "pack_path", "")),
        "run_id": str(getattr(entry, "run_id", "")),
        "scheduled_for": str(getattr(entry, "scheduled_for", "")),
    }


def to_json(payload: dict | list[dict]) -> str:
    """Serialize remediation API response payloads for backend ingestion."""
    return json.dumps(payload, indent=2)


def list_review_packs_api(
    output_dir: str,
    status: Optional[str] = None,
    *,
    sort_by: str = "created",
    limit: Optional[int] = None,
) -> dict:
    """Return review-pack listing payload with deterministic ordering."""
    rows = list_review_packs(output_dir, status=status)
    rows = sort_review_entries(rows, sort_by=sort_by)
    rows = limit_review_entries(rows, limit)
    return {
        "operation": "list_review_packs",
        "status_filter": status or "all",
        "count": len(rows),
        "packs": [_entry_as_dict(row) for row in rows],
    }


def approve_review_pack_api(
    output_dir: str,
    pack_id: str,
    approver: str,
    ticket_id: str,
    *,
    expires_hours: int = 24,
    require_ticket_id: bool = True,
) -> dict:
    """Approve one review pack and return machine-readable metadata."""
    pack_path = approve_review_pack(
        output_dir=output_dir,
        pack_id=pack_id,
        approver=approver,
        ticket_id=ticket_id,
        expires_hours=expires_hours,
        require_ticket_id=require_ticket_id,
    )
    pack = get_review_pack(output_dir, pack_id)
    return {
        "operation": "approve_review_pack",
        "pack_id": pack_id,
        "status": str(pack["lifecycle"]["status"]),
        "pack_path": str(pack_path),
        "approved_by": str(pack["approval"].get("approved_by", "")),
        "approved_at": str(pack["approval"].get("approved_at", "")),
        "ticket_id": str(pack["approval"].get("ticket_id", "")),
        "expires_at": str(pack["approval"].get("expires_at", "")),
    }


def reject_review_pack_api(
    output_dir: str,
    pack_id: str,
    approver: str,
    reason: str,
) -> dict:
    """Reject one review pack and return machine-readable metadata."""
    pack_path = reject_review_pack(
        output_dir=output_dir,
        pack_id=pack_id,
        approver=approver,
        reason=reason,
    )
    pack = get_review_pack(output_dir, pack_id)
    return {
        "operation": "reject_review_pack",
        "pack_id": pack_id,
        "status": str(pack["lifecycle"]["status"]),
        "pack_path": str(pack_path),
        "rejected_by": str(pack["approval"].get("rejected_by", "")),
        "rejected_at": str(pack["approval"].get("rejected_at", "")),
        "reject_reason": str(pack["approval"].get("reject_reason", "")),
    }


def apply_approved_pack_api(
    config_path: str,
    output_dir: str,
    pack_id: str,
    *,
    skip_jump: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
) -> dict:
    """Apply one approved pack and return the execution summary payload."""
    summary = apply_approved_pack(
        config_path=config_path,
        output_dir=output_dir,
        pack_id=pack_id,
        skip_jump=skip_jump,
        allow_high_risk=allow_high_risk,
        remediation_settings=remediation_settings,
    )
    summary["operation"] = "apply_approved_pack"
    return summary


def apply_all_approved_packs_api(
    config_path: str,
    output_dir: str,
    *,
    skip_jump: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
) -> dict:
    """Apply every approved pack allowed by policy and return summaries."""
    summaries = apply_all_approved_packs(
        config_path=config_path,
        output_dir=output_dir,
        skip_jump=skip_jump,
        allow_high_risk=allow_high_risk,
        remediation_settings=remediation_settings,
    )
    succeeded = sum(1 for item in summaries if item.get("status") in {"success", "dry-run"})
    return {
        "operation": "apply_all_approved_packs",
        "count": len(summaries),
        "succeeded": succeeded,
        "failed": len(summaries) - succeeded,
        "results": summaries,
    }


def report_file_ref(path: str | Path, output_dir: str | Path) -> dict:
    """Return a backend-friendly absolute/relative report path descriptor."""
    full = Path(path).resolve()
    root = Path(output_dir).resolve()
    rel = full.relative_to(root)
    return {"absolute_path": str(full), "relative_path": str(rel)}


# ─────────────────────────────────────────────────────────────────────────────
#  Run-level operations (scheduled audits)
# ─────────────────────────────────────────────────────────────────────────────

def list_runs_api(output_dir: str, *, limit: Optional[int] = 20) -> dict:
    """Recent audit runs, newest first, with their remediation state."""
    from .run_cli import run_status_as_dict
    from .runs import RunStatus, list_manifests

    statuses = [
        RunStatus(m, list_review_packs(output_dir, run_id=m["run_id"]))
        for m in list_manifests(output_dir, limit=limit)
    ]
    return {
        "operation": "list_runs",
        "count": len(statuses),
        "runs": [run_status_as_dict(st) for st in statuses],
    }


def get_run_api(output_dir: str, run_id: str) -> dict:
    """One run's manifest and current pack states."""
    from .run_cli import run_status_as_dict
    from .runs import run_status

    return {"operation": "get_run", **run_status_as_dict(run_status(output_dir, run_id))}


def approve_run_api(
    output_dir: str,
    run_id: str,
    *,
    approver: str,
    ticket_id: str,
    expires_hours: int = 24,
    require_ticket_id: bool = True,
    apply_at: Optional[str] = None,
    allow_high_risk: bool = False,
    block_high_risk: bool = True,
) -> dict:
    """Approve a run's packs, optionally scheduled (``apply_at`` as for --apply-at).

    Applying immediately is left to the caller (``apply_approved_pack_api``),
    so a backend can show progress per device.
    """
    from .runs import approve_run, parse_schedule_time

    scheduled = parse_schedule_time(apply_at) if apply_at else None
    decision = approve_run(
        output_dir, run_id, approver=approver, ticket_id=ticket_id,
        expires_hours=expires_hours, require_ticket_id=require_ticket_id,
        scheduled_for=scheduled, allow_high_risk=allow_high_risk,
        block_high_risk=block_high_risk,
    )
    return {"operation": "approve_run", **decision.to_dict()}


def reject_run_api(output_dir: str, run_id: str, *, approver: str, reason: str) -> dict:
    """Reject every pending or approved pack of a run."""
    from .runs import reject_run

    decision = reject_run(output_dir, run_id, approver=approver, reason=reason)
    return {"operation": "reject_run", **decision.to_dict()}
