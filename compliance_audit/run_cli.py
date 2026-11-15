"""Console and JSON rendering for audit runs (``--run-list`` / ``--run-show``)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .remediation_workflow import format_schedule
from .runs import RunDecision, RunStatus

_STATE_STYLE = {
    "awaiting approval": "bold yellow",
    "scheduled": "cyan",
    "approved": "green",
    "applied": "green",
    "failed": "bold red",
    "superseded": "dim",
    "nothing to remediate": "dim",
}
_RISK_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan"}


def _local(ts: str) -> str:
    try:
        when = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return ts or ""
    return format_schedule(when)


def run_status_as_dict(status: RunStatus) -> dict:
    return {
        "run_id": status.run_id,
        "state": status.state,
        "manifest": status.manifest,
        "packs": [asdict(p) for p in status.packs],
    }


def _pack_counts(status: RunStatus) -> str:
    counts: dict[str, int] = {}
    for p in status.packs:
        key = "scheduled" if p.status == "approved" and p.scheduled_for else p.status
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "—"


def print_runs_table(statuses: list[RunStatus], console: Optional[Console] = None) -> None:
    con = console or Console()
    if not statuses:
        con.print("No audit runs recorded in this output directory yet.")
        return
    table = Table(title="Audit runs (newest first)", box=box.ROUNDED)
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Finished", no_wrap=True)
    table.add_column("Devices", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("Packs")
    table.add_column("State")
    table.add_column("Email", justify="center")
    for st in statuses:
        m = st.manifest
        t = m.get("totals", {})
        devices = str(t.get("audited", 0))
        if t.get("unreachable"):
            devices += f" (+{t['unreachable']} unreachable)"
        note = m.get("notification") or {}
        email = "sent" if note.get("sent") else ("failed" if note.get("error") else "—")
        table.add_row(
            st.run_id,
            _local(m.get("finished_at", "")),
            devices,
            f"{t.get('score_pct', '')}%",
            _pack_counts(st),
            f"[{_STATE_STYLE.get(st.state, '')}]{st.state}[/]",
            email,
        )
    con.print(table)


def print_run_detail(status: RunStatus, command: str, console: Optional[Console] = None) -> None:
    con = console or Console()
    m = status.manifest
    t = m.get("totals", {})
    con.print(Panel(
        f"[bold]Run:[/]       {status.run_id}\n"
        f"[bold]Finished:[/]  {_local(m.get('finished_at', ''))} on {m.get('host', '')}\n"
        f"[bold]Devices:[/]   {t.get('audited', 0)} audited, {t.get('unreachable', 0)} unreachable\n"
        f"[bold]Score:[/]     {t.get('score_pct', '')}%  ({t.get('fail', 0)} fail / "
        f"{t.get('warn', 0)} warn / {t.get('error', 0)} error / {t.get('exception', 0)} exception)\n"
        f"[bold]State:[/]     [{_STATE_STYLE.get(status.state, '')}]{status.state}[/]",
        title="AUDIT RUN", border_style="cyan", expand=False,
    ))

    packs = {p.pack_id: p for p in status.packs}
    table = Table(box=box.ROUNDED, title="Devices")
    table.add_column("Device", style="cyan")
    table.add_column("IP")
    table.add_column("Score", justify="center")
    table.add_column("Fail/Warn", justify="center")
    table.add_column("Pack")
    table.add_column("Risk")
    table.add_column("Changes", justify="center")
    table.add_column("Status")
    for d in m.get("devices", []):
        pack = packs.get(d.get("pack_id", ""))
        status_text = "—"
        if pack:
            status_text = pack.status
            if pack.status == "approved" and pack.scheduled_for:
                status_text = f"scheduled {_local(pack.scheduled_for)}"
        risk = d.get("pack_risk", "")
        table.add_row(
            d["hostname"], d["ip"], f"{d['score_pct']}%", f"{d['fail']}/{d['warn']}",
            d.get("pack_id") or "—",
            f"[{_RISK_STYLE.get(risk, '')}]{risk}[/]" if risk else "—",
            str(d.get("pack_findings") or "—"), status_text,
        )
    con.print(table)

    if m.get("unreachable"):
        un = Table(box=box.ROUNDED, title="Not audited")
        un.add_column("Device", style="cyan")
        un.add_column("IP")
        un.add_column("Reason")
        for u in m["unreachable"]:
            un.add_row(u["hostname"], u["ip"], u["error"])
        con.print(un)

    expired = m.get("exceptions", {}).get("expired", [])
    if expired:
        con.print(f"[bold red]{len(expired)} policy exception(s) expired:[/] "
                  + ", ".join(e["id"] for e in expired))

    pending = status.count("pending")
    if pending:
        con.print(
            f"\n[bold]{pending} pack(s) await approval.[/] Review the scripts listed in "
            "--remediation-list, then:\n"
            f"  {command} --run-approve {status.run_id} --approver NAME --ticket-id ID --apply-now\n"
            f"  {command} --run-approve {status.run_id} --approver NAME --ticket-id ID "
            "--apply-at \"YYYY-MM-DD HH:MM\"\n"
            f"  {command} --run-reject {status.run_id} --approver NAME --reason TEXT",
            highlight=False, markup=True,
        )
    if m.get("reports", {}).get("consolidated_html"):
        con.print(f"[dim]Consolidated report: {m['reports']['consolidated_html']}[/]")


def print_decision(decision: RunDecision, verb: str, console: Optional[Console] = None) -> None:
    con = console or Console()
    for item in decision.acted:
        extra = f" — scheduled {_local(item['scheduled_for'])}" if item.get("scheduled_for") else ""
        con.print(f"[green]✓ {verb}:[/] {item['pack_id']} ({item['hostname']}, "
                  f"{item['risk']} risk){extra}", highlight=False)
    for item in decision.skipped:
        con.print(f"[yellow]– skipped:[/] {item['pack_id']} ({item['hostname']}): "
                  f"{item['reason']}", highlight=False)
