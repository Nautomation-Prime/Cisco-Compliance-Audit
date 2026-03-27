"""Shared CLI formatting helpers for remediation workflow output."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable, Optional

from rich.console import Console
from rich.table import Table

RISK_SORT_WEIGHT = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

STATUS_SORT_WEIGHT = {
    "pending": 0,
    "approved": 1,
    "applied": 2,
    "failed": 3,
    "expired": 4,
    "rejected": 5,
}

STATUS_STYLE = {
    "pending": "yellow",
    "approved": "green",
    "rejected": "red",
    "applied": "cyan",
    "failed": "bold red",
    "expired": "magenta",
}


def _as_dict(entry: Any) -> dict:
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
    }


def sort_review_entries(
    entries: list[Any], sort_by: str = "created"
) -> list[Any]:
    """Return entries sorted by a supported key."""
    if sort_by == "risk":
        return sorted(
            entries,
            key=lambda e: (
                RISK_SORT_WEIGHT.get(
                    str(getattr(e, "highest_risk", "")).lower(), 9
                ),
                str(getattr(e, "hostname", "")).lower(),
            ),
        )
    if sort_by == "status":
        return sorted(
            entries,
            key=lambda e: (
                STATUS_SORT_WEIGHT.get(
                    str(getattr(e, "status", "")).lower(), 99
                ),
                str(getattr(e, "hostname", "")).lower(),
            ),
        )
    if sort_by == "hostname":
        return sorted(
            entries, key=lambda e: str(getattr(e, "hostname", "")).lower()
        )
    if sort_by == "findings":
        return sorted(
            entries,
            key=lambda e: int(getattr(e, "findings_count", 0)),
            reverse=True,
        )

    return sorted(
        entries, key=lambda e: str(getattr(e, "created_ts", "")), reverse=True
    )


def limit_review_entries(
    entries: list[Any], limit: Optional[int]
) -> list[Any]:
    """Return at most *limit* entries, preserving existing order."""
    if limit is None:
        return entries
    if limit <= 0:
        return []
    return entries[:limit]


def review_entries_as_json(entries: Iterable[Any]) -> str:
    """Serialize remediation review entries as pretty-printed JSON."""
    rows = [_as_dict(entry) for entry in entries]
    return json.dumps(rows, indent=2)


def review_entries_as_csv(entries: Iterable[Any]) -> str:
    """Serialize remediation review entries as CSV text."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "pack_id",
            "status",
            "hostname",
            "ip",
            "highest_risk",
            "findings_count",
            "created_ts",
            "approved_by",
            "approved_at",
            "ticket_id",
            "expires_at",
            "script_path",
            "pack_path",
        ],
    )
    writer.writeheader()
    for entry in entries:
        writer.writerow(_as_dict(entry))
    return output.getvalue().strip()


def render_review_entries_table(
    entries: Iterable[Any],
    *,
    title: str,
    show_created: bool = True,
) -> Table:
    """Build a Rich table for remediation review entries."""
    table = Table(title=title, show_lines=False)
    table.add_column("Pack ID", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Hostname", overflow="fold")
    table.add_column("IP", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    if show_created:
        table.add_column("Created", no_wrap=True)

    for entry in entries:
        status = str(getattr(entry, "status", ""))
        status_style = STATUS_STYLE.get(status.lower(), "")
        status_text = (
            f"[{status_style}]{status}[/]" if status_style else status
        )

        row_values = [
            str(getattr(entry, "pack_id", "")),
            status_text,
            str(getattr(entry, "hostname", "")),
            str(getattr(entry, "ip", "")),
            str(getattr(entry, "highest_risk", "")),
            str(int(getattr(entry, "findings_count", 0))),
        ]
        if show_created:
            row_values.append(str(getattr(entry, "created_ts", "")))
        table.add_row(*row_values)

    return table


def print_review_entries_table(
    entries: Iterable[Any],
    *,
    title: str,
    show_created: bool = True,
    console: Optional[Console] = None,
) -> None:
    """Render and print remediation review entries in table form."""
    con = console or Console()
    con.print(
        render_review_entries_table(
            entries, title=title, show_created=show_created
        )
    )


def print_remediation_list_hints(
    *,
    status_filter: Optional[str],
    shown: int,
    total: int,
    output_format: str,
    console: Optional[Console] = None,
) -> None:
    """Print summary hints after remediation list output."""
    if output_format != "table":
        return

    con = console or Console()
    filter_label = status_filter or "all"
    con.print(f"Showing {shown} of {total} pack(s). Filter: {filter_label}.")
    con.print(
        "Status legend: pending -> approved -> applied (or failed/expired/rejected)."
    )
    con.print(
        "Next steps: --remediation-approve PACK_ID, "
        "--remediation-reject PACK_ID, --remediation-apply PACK_ID"
    )
