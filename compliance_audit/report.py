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


def save_consolidated_html(results: list[AuditResult], output_dir: str) -> Path:
    """Save a consolidated HTML report for multiple devices."""
    if not results:
        raise ValueError("No results to generate consolidated report")

    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"consolidated_report_{ts}.html"

    console = Console(record=True, width=140)

    # Summary page
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_pass = sum(r.pass_count for r in results)
    total_fail = sum(r.fail_count for r in results)
    total_warn = sum(r.warn_count for r in results)
    total_error = sum(r.error_count for r in results)
    total_checks = total_pass + total_fail + total_warn + total_error
    overall_score = round(total_pass / total_checks * 100, 1) if total_checks else 100

    summary_header = (
        f"[bold]Audit Date:[/bold] {ts_str}\n"
        f"[bold]Devices Audited:[/bold] {len(results)}\n"
        f"[bold]Overall Score:[/bold] {overall_score}%  "
        f"({total_pass} pass / {total_fail} fail / {total_warn} warn / {total_error} error)"
    )
    console.print(Panel(summary_header, title="CONSOLIDATED COMPLIANCE AUDIT REPORT",
                        border_style="cyan", expand=False))
    console.print()

    # Summary table of all devices
    summary_table = Table(
        title="Device Summary",
        box=box.ROUNDED,
        show_lines=False,
        title_style="bold cyan",
        expand=False,
    )
    summary_table.add_column("Hostname", style="cyan", min_width=30)
    summary_table.add_column("IP Address", min_width=15)
    summary_table.add_column("Role", min_width=20)
    summary_table.add_column("Score", justify="center", min_width=8)
    summary_table.add_column("Pass", justify="center", min_width=6, style="green")
    summary_table.add_column("Fail", justify="center", min_width=6, style="red")
    summary_table.add_column("Warn", justify="center", min_width=6, style="yellow")
    summary_table.add_column("Error", justify="center", min_width=6, style="magenta")

    for r in results:
        score_style = "bold green" if r.fail_count == 0 else "bold red" if r.fail_count > 5 else "bold yellow"
        summary_table.add_row(
            r.hostname,
            r.ip,
            r.role_display,
            Text(f"{r.score_pct}%", style=score_style),
            str(r.pass_count),
            str(r.fail_count),
            str(r.warn_count),
            str(r.error_count),
        )

    console.print(summary_table)
    console.print()
    console.print()

    # Individual device reports
    for i, result in enumerate(results):
        if i > 0:
            console.print()
            console.rule(style="cyan")
            console.print()
        print_report(result, console=console)

    html = console.export_html(inline_styles=True)
    filename.write_text(html, encoding="utf-8")
    log.info("Consolidated HTML report saved to %s", filename)
    return filename
