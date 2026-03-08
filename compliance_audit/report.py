"""
Rich-based console + file report generation for compliance audit results.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .compliance_engine import AuditResult, Finding, Status

log = logging.getLogger(__name__)

STATUS_STYLE = {
    Status.PASS:  ("PASS",  "bold green"),
    Status.FAIL:  ("FAIL",  "bold red"),
    Status.WARN:  ("WARN",  "bold yellow"),
    Status.SKIP:  ("SKIP",  "dim"),
    Status.ERROR: ("ERROR", "bold magenta"),
}


def print_report(result: AuditResult, console: Optional[Console] = None) -> None:
    """Print a nicely formatted audit report to the console."""
    con = console or Console()

    # Header panel
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = (
        f"[bold]Device:[/bold]  {result.hostname}  ({result.ip})\n"
        f"[bold]Role:[/bold]    {result.role_display}\n"
        f"[bold]Date:[/bold]    {ts}\n"
        f"[bold]Score:[/bold]   {result.score_pct}%  "
        f"({result.pass_count} pass / {result.fail_count} fail / "
        f"{result.warn_count} warn / {result.error_count} error)"
    )
    con.print(Panel(header, title="COMPLIANCE AUDIT REPORT",
                    border_style="cyan", expand=False))
    con.print()

    # Group findings by category
    categories: dict[str, list[Finding]] = {}
    for f in result.findings:
        if f.status == Status.SKIP:
            continue
        categories.setdefault(f.category, []).append(f)

    for cat, findings in categories.items():
        cat_pass = sum(1 for f in findings if f.status == Status.PASS)
        cat_total = len(findings)
        cat_pct = round(cat_pass / cat_total * 100, 1) if cat_total else 100

        table = Table(
            title=f"{cat.replace('_', ' ').title()}  ({cat_pct}%)",
            box=box.ROUNDED,
            show_lines=False,
            title_style="bold",
            expand=False,
            min_width=100,
        )
        table.add_column("Check", style="cyan", min_width=28)
        table.add_column("Status", justify="center", min_width=6)
        table.add_column("Detail", min_width=50)
        table.add_column("Remediation", style="dim", min_width=30)

        for f in findings:
            label, style = STATUS_STYLE.get(f.status, ("?", ""))
            status_text = Text(label, style=style)
            intf_prefix = f"[{f.interface}] " if f.interface else ""
            table.add_row(
                f.check_name,
                status_text,
                f"{intf_prefix}{f.detail}",
                f.remediation or "",
            )

        con.print(table)
        con.print()

    # Summary bar
    bar_parts = []
    if result.fail_count:
        bar_parts.append(f"[bold red]{result.fail_count} FAIL[/]")
    if result.warn_count:
        bar_parts.append(f"[bold yellow]{result.warn_count} WARN[/]")
    if result.error_count:
        bar_parts.append(f"[bold magenta]{result.error_count} ERROR[/]")
    bar_parts.append(f"[bold green]{result.pass_count} PASS[/]")
    con.print(Panel(" | ".join(bar_parts), title="Summary", border_style="cyan",
                    expand=False))
    con.print()


def save_json(result: AuditResult, output_dir: str) -> Path:
    """Dump the audit result as JSON."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"{result.hostname}_{ts}.json"
    payload = {
        "hostname": result.hostname,
        "ip": result.ip,
        "role": result.role,
        "role_display": result.role_display,
        "score_pct": result.score_pct,
        "pass": result.pass_count,
        "fail": result.fail_count,
        "warn": result.warn_count,
        "error": result.error_count,
        "findings": [
            {
                "check": f.check_name,
                "status": f.status.value,
                "detail": f.detail,
                "category": f.category,
                "interface": f.interface,
                "remediation": f.remediation,
            }
            for f in result.findings
            if f.status != Status.SKIP
        ],
    }
    filename.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("JSON report saved to %s", filename)
    return filename


def save_html(result: AuditResult, output_dir: str) -> Path:
    """Save a Rich-rendered HTML report."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"{result.hostname}_{ts}.html"

    console = Console(record=True, width=140)
    print_report(result, console=console)
    html = console.export_html(inline_styles=True)
    filename.write_text(html, encoding="utf-8")
    log.info("HTML report saved to %s", filename)
    return filename
