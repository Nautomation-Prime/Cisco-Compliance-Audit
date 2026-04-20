"""
Rich-based console + file report generation for compliance audit results.
"""

import csv
import html as html_mod
import json
import logging
import re
from dataclasses import dataclass
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


def _safe_hostname(name: str) -> str:
    """Sanitise a hostname for use in filenames (strip path separators etc.)."""
    return re.sub(r"[^\w.\-]", "_", name) if name else "unknown"


STATUS_STYLE = {
    Status.PASS: ("PASS", "bold green"),
    Status.FAIL: ("FAIL", "bold red"),
    Status.WARN: ("WARN", "bold yellow"),
    Status.SKIP: ("SKIP", "dim"),
    Status.ERROR: ("ERROR", "bold magenta"),
}

SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "critical": ("CRIT", "bold white on dark_red"),
    "high":     ("HIGH", "bold red"),
    "medium":   ("MED",  "bold yellow"),
    "low":      ("LOW",  "dim cyan"),
    "info":     ("INFO", "dim"),
}

# ─── HTML colour constants ─────────────────────────────────────────
_STATUS_CSS = {
    "PASS": ("#22c55e", "#052e16"),
    "FAIL": ("#ef4444", "#450a0a"),
    "WARN": ("#eab308", "#422006"),
    "ERROR": ("#c026d3", "#4a044e"),
    "SKIP": ("#64748b", "#1e293b"),
}

_SEVERITY_CSS: dict[str, tuple[str, str]] = {
    "critical": ("#ef4444", "#450a0a"),
    "high":     ("#f97316", "#431407"),
    "medium":   ("#eab308", "#422006"),
    "low":      ("#64748b", "#1e293b"),
    "info":     ("#94a3b8", "#0f172a"),
}

_PARSER_ENGINE_CSS = {
    "genie": ("#22c55e", "#052e16"),
    "raw-only": ("#f97316", "#431407"),
    "missing-output": ("#94a3b8", "#0f172a"),
}


def print_report(result: AuditResult, console: Optional[Console] = None) -> None:
    """Print a nicely formatted audit report to the console."""
    con = console or Console()

    # Header panel
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version_line = ""
    if result.ios_version:
        version_line = f"\n[bold]IOS-XE:[/bold]  {result.ios_version}"
    timing_line = ""
    if result.duration_secs:
        timing_line = f"  ({result.duration_secs}s)"
    header = (
        f"[bold]Device:[/bold]  {result.hostname}  ({result.ip})\n"
        f"[bold]Role:[/bold]    {result.role_display}"
        f"{version_line}\n"
        f"[bold]Date:[/bold]    {result.audit_ts or ts}{timing_line}\n"
        f"[bold]Score:[/bold]   {result.score_pct}%  "
        f"({result.pass_count} pass / {result.fail_count} fail / "
        f"{result.warn_count} warn / {result.error_count} error)"
    )
    con.print(
        Panel(
            header, title="COMPLIANCE AUDIT REPORT", border_style="cyan", expand=False
        )
    )
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
        table.add_column("Sev", justify="center", min_width=4)
        table.add_column("Detail", min_width=50)
        table.add_column("Remediation", style="dim", min_width=30)

        for f in findings:
            label, style = STATUS_STYLE.get(f.status, ("?", ""))
            status_text = Text(label, style=style)
            sev_label, sev_style = SEVERITY_STYLE.get(
                getattr(f, "severity", "medium"), ("MED", "bold yellow")
            )
            sev_text = Text(sev_label, style=sev_style)
            intf_prefix = f"[{f.interface}] " if f.interface else ""
            table.add_row(
                f.check_name,
                status_text,
                sev_text,
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
    con.print(
        Panel(" | ".join(bar_parts), title="Summary", border_style="cyan", expand=False)
    )
    con.print()


def save_json(result: AuditResult, output_dir: str) -> Path | None:
    """Dump the audit result as JSON."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _safe_hostname(result.hostname)
    filename = outdir / f"{safe}_{ts}.json"
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
        "ios_version": result.ios_version,
        "tool_version": result.tool_version,
        "duration_secs": result.duration_secs,
        "audit_ts": result.audit_ts,
        "findings": [
            {
                "check": f.check_name,
                "status": f.status.value,
                "severity": getattr(f, "severity", "medium"),
                "tags": getattr(f, "tags", []),
                "detail": f.detail,
                "category": f.category,
                "interface": f.interface,
                "remediation": f.remediation,
            }
            for f in result.findings
            if f.status != Status.SKIP
        ],
    }
    structured_parsing = _get_structured_parsing_payload(result)
    if structured_parsing:
        payload["structured_parsing"] = structured_parsing
    roi = _get_result_roi(result)
    if roi:
        payload["roi"] = roi
    try:
        filename.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write JSON report %s: %s", filename, exc)
        return None
    log.info("JSON report saved to %s", filename)
    return filename


# ═══════════════════════════════════════════════════════════════════
#  HTML helpers
# ═══════════════════════════════════════════════════════════════════


def _esc(text: str) -> str:
    """HTML-escape helper."""
    return html_mod.escape(str(text))


def _status_badge(status: str) -> str:
    fg, bg = _STATUS_CSS.get(status, ("#94a3b8", "#1e293b"))
    return (
        f'<span class="badge badge-{status.lower()}" '
        f'style="color:{fg};background:{bg};">{_esc(status)}</span>'
    )


def _score_colour(pct: float) -> str:
    if pct >= 90:
        return "#22c55e"
    if pct >= 70:
        return "#eab308"
    return "#ef4444"


def _get_result_roi(result: AuditResult) -> dict | None:
    """Return ROI payload from a result if available."""
    roi = getattr(result, "_roi", None) or getattr(result, "roi", None)
    return roi if isinstance(roi, dict) else None


def _get_structured_parsing_payload(result: AuditResult) -> dict | None:
    """Return structured parsing metadata if the result carries it."""
    if not result.structured_parse_engine:
        return None

    return {
        "primary_engine": "genie",
        "summary": result.structured_parse_summary,
        "counts": dict(result.structured_parse_counts),
        "commands": {
            command: result.structured_parse_engine[command]
            for command in sorted(result.structured_parse_engine)
        },
    }


def _parser_engine_label(engine: str) -> str:
    return {
        "genie": "Genie",
        "raw-only": "Raw fallback",
        "missing-output": "Missing output",
    }.get(engine, engine)


def _parser_engine_badge(engine: str, count: int | None = None) -> str:
    fg, bg = _PARSER_ENGINE_CSS.get(engine, ("#94a3b8", "#1e293b"))
    label = _parser_engine_label(engine)
    if count is not None:
        label = f"{label}: {count}"
    return (
        f'<span class="badge" style="color:{fg};background:{bg};">{_esc(label)}</span>'
    )


def _build_structured_parsing_html(
    result: AuditResult,
    compact: bool = False,
) -> str:
    """Render a structured parsing summary block for HTML reports."""
    payload = _get_structured_parsing_payload(result)
    if not payload:
        return ""

    counts = payload["counts"]
    ordered_engines = ["genie", "raw-only", "missing-output"]
    badges = []
    for engine in ordered_engines:
        if engine in counts:
            badges.append(_parser_engine_badge(engine, counts[engine]))
    for engine in sorted(counts):
        if engine not in ordered_engines:
            badges.append(_parser_engine_badge(engine, counts[engine]))

    table_html = ""
    if not compact:
        rows = []
        for command, engine in payload["commands"].items():
            rows.append(
                "<tr>"
                f"<td>{_esc(command)}</td>"
                f"<td>{_parser_engine_badge(engine)}</td>"
                "</tr>"
            )
        table_html = (
            '<table class="parser-table">'
            "<thead><tr><th>Command</th><th>Engine</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    classes = "parser-wrap compact" if compact else "parser-wrap"
    return (
        f'<div class="{classes}">'
        '<div class="parser-title">Structured Parsing</div>'
        f'<div class="parser-summary">{_esc(payload["summary"])}</div>'
        f'<div class="parser-badges">{"".join(badges)}</div>'
        f"{table_html}"
        "</div>"
    )


def _build_roi_html(roi: dict, title: str = "ROI Estimate") -> str:
    """Render ROI metrics as compact stat cards with efficiency ratio and warnings."""
    rate = float(roi.get("hourly_rate", 0.0) or 0.0)
    currency = _esc(str(roi.get("currency", "GBP")))
    val = roi.get("value_saved")
    value_html = f"{currency} {float(val):.2f}" if val is not None and rate > 0 else "-"

    eff = roi.get("efficiency_ratio")
    eff_html = f"{eff:.1%}" if eff is not None else "-"

    warnings = roi.get("warnings")
    warning_html = ""
    if warnings:
        items = "".join(f"<li>{_esc(w)}</li>" for w in warnings)
        warning_html = f'<div class="roi-warnings"><ul>{items}</ul></div>'

    return (
        '<div class="roi-wrap">'
        f'<div class="roi-title">{_esc(title)}</div>'
        '<div class="roi-grid">'
        f'<div class="roi-card"><div class="roi-value">{float(roi.get("manual_minutes_estimate", 0.0) or 0.0):.1f}m</div><div class="roi-label">Manual Estimate</div></div>'
        f'<div class="roi-card"><div class="roi-value">{float(roi.get("automated_minutes", 0.0) or 0.0):.1f}m</div><div class="roi-label">Automated Runtime</div></div>'
        f'<div class="roi-card"><div class="roi-value" style="color:var(--pass);">{float(roi.get("hours_saved", 0.0) or 0.0):.2f}h</div><div class="roi-label">Time Saved</div></div>'
        f'<div class="roi-card"><div class="roi-value">{value_html}</div><div class="roi-label">Estimated Value</div></div>'
        f'<div class="roi-card"><div class="roi-value">{eff_html}</div><div class="roi-label">Efficiency Ratio</div></div>'
        "</div>"
        f"{warning_html}"
        "</div>"
    )


def _severity_badge(severity: str) -> str:
    fg, bg = _SEVERITY_CSS.get(severity, ("#94a3b8", "#1e293b"))
    return (
        f'<span class="badge badge-sev-{_esc(severity)}" '
        f'style="color:{fg};background:{bg};">{_esc(severity.upper())}</span>'
    )


def _tag_pills(tags: list[str]) -> str:
    if not tags:
        return ""
    pills = "".join(
        f'<span class="tag-pill">{_esc(t)}</span>' for t in tags
    )
    return f'<div class="tag-pills">{pills}</div>'


def _build_findings_table(findings: list[Finding], table_id: str = "") -> str:
    """Return an HTML <table> for a list of findings."""
    rows: list[str] = []
    for f in findings:
        if f.status == Status.SKIP:
            continue
        intf = f"[{_esc(f.interface)}] " if f.interface else ""
        severity = getattr(f, "severity", "medium")
        tags = getattr(f, "tags", [])
        rows.append(
            f'<tr class="finding-row" data-status="{f.status.value}" '
            f'data-severity="{_esc(severity)}" '
            f'data-tags="{_esc("|".join(tags))}">'
            f'<td class="check-name">{_esc(f.check_name)}{_tag_pills(tags)}</td>'
            f'<td class="status-cell">{_status_badge(f.status.value)}</td>'
            f'<td class="sev-cell">{_severity_badge(severity)}</td>'
            f"<td>{intf}{_esc(f.detail)}</td>"
            f'<td class="remediation">{_esc(f.remediation or "")}</td>'
            f"</tr>"
        )
    id_attr = f' id="{table_id}"' if table_id else ""
    return (
        f'<table class="findings-table"{id_attr}>'
        "<thead><tr>"
        "<th>Check</th><th>Status</th><th>Severity</th><th>Detail</th><th>Remediation</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


# ═══════════════════════════════════════════════════════════════════
#  Shared CSS + JS
# ═══════════════════════════════════════════════════════════════════

_CSS = """\
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--border:#475569;
--text:#e2e8f0;--text-dim:#94a3b8;--accent:#22d3ee;--pass:#22c55e;
--fail:#ef4444;--warn:#eab308;--error:#c026d3;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
background:var(--bg);color:var(--text);line-height:1.5;padding:0;}
a{color:var(--accent);text-decoration:none;}
a:hover{text-decoration:underline;}

/* ── Top bar ────────────────────────────────────────────── */
.top-bar{background:var(--surface);border-bottom:1px solid var(--border);
padding:12px 24px;position:sticky;top:0;z-index:100;
display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;}
.top-bar h1{font-size:1.1rem;color:var(--accent);white-space:nowrap;}
.top-bar .meta{font-size:.85rem;color:var(--text-dim);}

/* ── Stat cards ─────────────────────────────────────────── */
.stats{display:flex;gap:12px;padding:20px 24px;flex-wrap:wrap;}
.stat-card{background:var(--surface);border:1px solid var(--border);
border-radius:8px;padding:16px 20px;min-width:130px;flex:1;text-align:center;}
.stat-card .value{font-size:1.8rem;font-weight:700;}
.stat-card .label{font-size:.8rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;}

/* ── ROI cards ─────────────────────────────────────────── */
.roi-wrap{margin:0 24px 16px;padding:14px 16px;background:var(--surface);
border:1px solid var(--border);border-radius:8px;}
.roi-title{font-size:.9rem;color:var(--text-dim);text-transform:uppercase;
letter-spacing:.05em;margin-bottom:10px;}
.roi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;}
.roi-card{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 12px;}
.roi-card .roi-value{font-size:1.2rem;font-weight:700;}
.roi-card .roi-label{font-size:.78rem;color:var(--text-dim);margin-top:2px;}
.roi-warnings{margin-top:10px;padding:8px 12px;background:#422006;border:1px solid #92400e;
border-radius:6px;font-size:.82rem;color:#fbbf24;}
.roi-warnings ul{margin:0;padding-left:18px;}
.roi-warnings li{margin-bottom:2px;}

/* ── Structured parsing ────────────────────────────────── */
.parser-wrap{margin:0 24px 16px;padding:14px 16px;background:var(--surface);
border:1px solid var(--border);border-radius:8px;}
.parser-wrap.compact{margin:0 0 14px;padding:12px 14px;}
.parser-title{font-size:.9rem;color:var(--text-dim);text-transform:uppercase;
letter-spacing:.05em;margin-bottom:8px;}
.parser-summary{font-size:.88rem;margin-bottom:10px;}
.parser-badges{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;}
.parser-table{width:100%;border-collapse:collapse;font-size:.82rem;}
.parser-table th{text-align:left;padding:6px 0;color:var(--text-dim);
font-weight:600;border-bottom:1px solid var(--border);font-size:.76rem;
text-transform:uppercase;letter-spacing:.04em;}
.parser-table td{padding:6px 0;border-bottom:1px solid var(--surface2);}
.parser-table tr:last-child td{border-bottom:none;}

/* ── Filters ────────────────────────────────────────────── */
.filters{padding:0 24px 12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
.filters label{font-size:.85rem;color:var(--text-dim);margin-right:4px;}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);
padding:5px 14px;border-radius:4px;cursor:pointer;font-size:.82rem;transition:all .15s;}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:var(--bg);border-color:var(--accent);}
.search-box{background:var(--surface);border:1px solid var(--border);color:var(--text);
padding:5px 12px;border-radius:4px;font-size:.82rem;width:220px;}
.search-box::placeholder{color:var(--text-dim);}

/* ── Device cards (dashboard) ───────────────────────────── */
.device-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
gap:12px;padding:0 24px 20px;}
.device-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:14px 18px;cursor:pointer;transition:border-color .15s,transform .1s;}
.device-card:hover{border-color:var(--accent);transform:translateY(-1px);}
.device-card .hostname{font-weight:600;color:var(--accent);font-size:.95rem;}
.device-card .ip{font-size:.8rem;color:var(--text-dim);}
.device-card .score-bar{height:6px;border-radius:3px;background:var(--surface2);margin:8px 0 4px;overflow:hidden;}
.device-card .score-fill{height:100%;border-radius:3px;transition:width .3s;}
.device-card .card-stats{display:flex;gap:10px;font-size:.78rem;color:var(--text-dim);}
.device-card .card-stats span{display:flex;align-items:center;gap:3px;}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;}

/* ── Collapsible device sections ────────────────────────── */
.device-section{margin:0 24px 16px;border:1px solid var(--border);border-radius:8px;overflow:hidden;}
.device-header{background:var(--surface);padding:14px 18px;cursor:pointer;
display:flex;align-items:center;justify-content:space-between;user-select:none;
transition:background .15s;}
.device-header:hover{background:var(--surface2);}
.device-header .left{display:flex;align-items:center;gap:12px;}
.device-header .chevron{transition:transform .2s;font-size:1.1rem;color:var(--text-dim);}
.device-header.open .chevron{transform:rotate(90deg);}
.device-header .dev-hostname{font-weight:600;color:var(--accent);}
.device-header .dev-ip{font-size:.85rem;color:var(--text-dim);}
.device-header .dev-score{font-weight:700;font-size:1rem;}
.device-body{display:none;padding:16px 18px;background:var(--bg);}
.device-body.open{display:block;}

/* ── Category sections inside device ────────────────────── */
.category{margin-bottom:14px;}
.category-title{font-size:.95rem;font-weight:600;padding:8px 0 6px;
border-bottom:1px solid var(--border);margin-bottom:8px;display:flex;
align-items:center;gap:8px;}
.category-pct{font-size:.8rem;font-weight:400;color:var(--text-dim);}

/* ── Findings tables ────────────────────────────────────── */
.findings-table{width:100%;border-collapse:collapse;font-size:.84rem;margin-bottom:4px;}
.findings-table th{text-align:left;padding:6px 10px;color:var(--text-dim);font-weight:600;
border-bottom:1px solid var(--border);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;}
.findings-table td{padding:6px 10px;border-bottom:1px solid var(--surface2);vertical-align:top;}
.findings-table tr:last-child td{border-bottom:none;}
.findings-table .check-name{color:var(--accent);white-space:nowrap;font-weight:500;}
.findings-table .remediation{color:var(--text-dim);font-size:.8rem;}
.findings-table .status-cell{white-space:nowrap;}
.findings-table .sev-cell{white-space:nowrap;}

/* ── Badges ─────────────────────────────────────────────── */
.badge{padding:2px 8px;border-radius:3px;font-size:.75rem;font-weight:700;letter-spacing:.04em;}

/* ── Tag pills ───────────────────────────────────────────── */
.tag-pills{display:flex;flex-wrap:wrap;gap:3px;margin-top:3px;}
.tag-pill{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.65rem;
  font-weight:600;background:var(--surface2);color:var(--text-dim);letter-spacing:.03em;}

/* ── Back to top ────────────────────────────────────────── */
.back-top{position:fixed;bottom:24px;right:24px;background:var(--accent);color:var(--bg);
border:none;border-radius:50%;width:40px;height:40px;font-size:1.2rem;cursor:pointer;
opacity:0;pointer-events:none;transition:opacity .2s;display:flex;align-items:center;justify-content:center;}
.back-top.visible{opacity:1;pointer-events:auto;}

/* ── Responsive ─────────────────────────────────────────── */
@media(max-width:768px){.device-grid{grid-template-columns:1fr;}
.top-bar{flex-direction:column;align-items:flex-start;}}
"""

_JS = """\
document.addEventListener('DOMContentLoaded',function(){
  /* ── Collapse / expand ────────────────────────────────── */
  document.querySelectorAll('.device-header').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      hdr.classList.toggle('open');
      hdr.nextElementSibling.classList.toggle('open');
    });
  });

  /* ── Device card click → scroll to section ────────────── */
  document.querySelectorAll('.device-card').forEach(function(card){
    card.addEventListener('click',function(){
      var id=card.dataset.target;
      var sec=document.getElementById(id);
      if(!sec)return;
      var hdr=sec.querySelector('.device-header');
      var body=sec.querySelector('.device-body');
      if(hdr && !hdr.classList.contains('open')){hdr.classList.add('open');body.classList.add('open');}
      sec.scrollIntoView({behavior:'smooth',block:'start'});
    });
  });

  /* ── Filter buttons ───────────────────────────────────── */
  var filterBtns=document.querySelectorAll('.filter-btn[data-filter]');
  filterBtns.forEach(function(btn){
    btn.addEventListener('click',function(){
      filterBtns.forEach(function(b){b.classList.remove('active');});
      btn.classList.add('active');
      var f=btn.dataset.filter;
      document.querySelectorAll('.finding-row').forEach(function(row){
        if(f==='all'){row.style.display='';}
        else{row.style.display=row.dataset.status===f?'':'none';}
      });
    });
  });

  /* ── Search box ───────────────────────────────────────── */
  var searchBox=document.getElementById('search-box');
  if(searchBox){searchBox.addEventListener('input',function(){
    var q=searchBox.value.toLowerCase();
    document.querySelectorAll('.finding-row').forEach(function(row){
      row.style.display=row.textContent.toLowerCase().indexOf(q)>=0?'':'none';
    });
    /* Also filter device sections — hide if ALL rows hidden */
    document.querySelectorAll('.device-section').forEach(function(sec){
      var rows=sec.querySelectorAll('.finding-row');
      var any=false;
      rows.forEach(function(r){if(r.style.display!=='none')any=true;});
      sec.style.display=any||q===''?'':'none';
    });
    /* Reset filter buttons */
    filterBtns.forEach(function(b){b.classList.remove('active');});
    document.querySelector('.filter-btn[data-filter="all"]').classList.add('active');
  });}

  /* ── Back to top ──────────────────────────────────────── */
  var topBtn=document.getElementById('back-top');
  if(topBtn){
    window.addEventListener('scroll',function(){
      topBtn.classList.toggle('visible',window.scrollY>300);
    });
    topBtn.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'});});
  }

  /* ── Expand / Collapse all ────────────────────────────── */
  var expandBtn=document.getElementById('expand-all');
  var collapseBtn=document.getElementById('collapse-all');
  if(expandBtn){expandBtn.addEventListener('click',function(){
    document.querySelectorAll('.device-header').forEach(function(h){h.classList.add('open');});
    document.querySelectorAll('.device-body').forEach(function(b){b.classList.add('open');});
  });}
  if(collapseBtn){collapseBtn.addEventListener('click',function(){
    document.querySelectorAll('.device-header').forEach(function(h){h.classList.remove('open');});
    document.querySelectorAll('.device-body').forEach(function(b){b.classList.remove('open');});
  });}
});
"""


# ═══════════════════════════════════════════════════════════════════
#  Single-device HTML report
# ═══════════════════════════════════════════════════════════════════


def save_html(result: AuditResult, output_dir: str) -> Path | None:
    """Save a standalone HTML report for a single device."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _safe_hostname(result.hostname)
    filename = outdir / f"{safe}_{ts}.html"

    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sc = _score_colour(result.score_pct)
    roi = _get_result_roi(result)
    roi_html = _build_roi_html(roi) if roi else ""
    parser_html = _build_structured_parsing_html(result)

    # Build category sections
    categories: dict[str, list[Finding]] = {}
    for f in result.findings:
        if f.status == Status.SKIP:
            continue
        categories.setdefault(f.category, []).append(f)

    sections_html: list[str] = []
    for cat, findings in categories.items():
        cat_pass = sum(1 for f in findings if f.status == Status.PASS)
        cat_total = len(findings)
        cat_pct = round(cat_pass / cat_total * 100, 1) if cat_total else 100
        title = cat.replace("_", " ").title()
        tbl = _build_findings_table(findings)
        sections_html.append(
            f'<div class="category">'
            f'<div class="category-title">{_esc(title)} '
            f'<span class="category-pct">({cat_pct}%)</span></div>'
            f"{tbl}</div>"
        )

    body = f"""\
<div class="top-bar">
  <h1>Compliance Audit Report</h1>
  <span class="meta">{_esc(ts_str)}</span>
</div>
<div class="stats">
  <div class="stat-card"><div class="value" style="color:{sc}">{result.score_pct}%</div><div class="label">Score</div></div>
  <div class="stat-card"><div class="value" style="color:var(--pass)">{result.pass_count}</div><div class="label">Pass</div></div>
  <div class="stat-card"><div class="value" style="color:var(--fail)">{result.fail_count}</div><div class="label">Fail</div></div>
  <div class="stat-card"><div class="value" style="color:var(--warn)">{result.warn_count}</div><div class="label">Warn</div></div>
  <div class="stat-card"><div class="value" style="color:var(--error)">{result.error_count}</div><div class="label">Error</div></div>
</div>
{roi_html}
<div style="padding:0 24px 12px;">
  <div style="font-size:.95rem;"><strong style="color:var(--accent);">{_esc(result.hostname)}</strong>
  <span style="color:var(--text-dim);"> ({_esc(result.ip)}) &mdash; {_esc(result.role_display)}</span></div>
  <div style="font-size:.85rem;color:var(--text-dim);margin-top:4px;">
    {f"IOS-XE: {_esc(result.ios_version)} &nbsp;|&nbsp; " if result.ios_version else ""}Tool v{_esc(result.tool_version)}{f" &nbsp;|&nbsp; Duration: {result.duration_secs}s" if result.duration_secs else ""}
  </div>
</div>
{parser_html}
<div class="filters">
  <label>Filter:</label>
  <button class="filter-btn active" data-filter="all">All</button>
  <button class="filter-btn" data-filter="FAIL">Fail</button>
  <button class="filter-btn" data-filter="WARN">Warn</button>
  <button class="filter-btn" data-filter="PASS">Pass</button>
  <input class="search-box" id="search-box" type="text" placeholder="Search checks...">
</div>
<div style="padding:0 24px 24px;">
  {"".join(sections_html)}
</div>
"""

    page = _wrap_html(f"{result.hostname} — Compliance Audit", body)
    try:
        filename.write_text(page, encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write HTML report %s: %s", filename, exc)
        return None
    log.info("HTML report saved to %s", filename)
    return filename


# ═══════════════════════════════════════════════════════════════════
#  Consolidated multi-device HTML report
# ═══════════════════════════════════════════════════════════════════


def save_consolidated_html(results: list[AuditResult], output_dir: str) -> Path | None:
    """Save a consolidated HTML report with dashboard, filtering, and collapsible devices."""
    if not results:
        raise ValueError("No results to generate consolidated report")

    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"consolidated_report_{ts}.html"

    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_pass = sum(r.pass_count for r in results)
    total_fail = sum(r.fail_count for r in results)
    total_warn = sum(r.warn_count for r in results)
    total_error = sum(r.error_count for r in results)
    total_checks = total_pass + total_fail + total_warn + total_error
    overall_score = round(total_pass / total_checks * 100, 1) if total_checks else 100
    sc = _score_colour(overall_score)

    aggregate_roi = {
        "manual_minutes_estimate": 0.0,
        "automated_minutes": 0.0,
        "hours_saved": 0.0,
        "hourly_rate": 0.0,
        "currency": "GBP",
        "value_saved": None,
        "efficiency_ratio": None,
        "warnings": [],
    }
    roi_count = 0
    has_value = False
    value_total = 0.0
    for r in results:
        roi = _get_result_roi(r)
        if not roi:
            continue
        roi_count += 1
        aggregate_roi["manual_minutes_estimate"] += float(
            roi.get("manual_minutes_estimate", 0.0) or 0.0
        )
        aggregate_roi["automated_minutes"] += float(
            roi.get("automated_minutes", 0.0) or 0.0
        )
        aggregate_roi["hours_saved"] += float(roi.get("hours_saved", 0.0) or 0.0)
        v = roi.get("value_saved")
        if v is not None:
            has_value = True
            value_total += float(v)
        aggregate_roi["hourly_rate"] = float(
            roi.get("hourly_rate", aggregate_roi["hourly_rate"]) or 0.0
        )
        aggregate_roi["currency"] = str(roi.get("currency", aggregate_roi["currency"]))
        w = roi.get("warnings")
        if w:
            for msg in w:
                if msg not in aggregate_roi["warnings"]:
                    aggregate_roi["warnings"].append(msg)

    if has_value:
        aggregate_roi["value_saved"] = round(value_total, 2)
    agg_manual = aggregate_roi["manual_minutes_estimate"]
    agg_auto = aggregate_roi["automated_minutes"]
    if agg_manual > 0:
        aggregate_roi["efficiency_ratio"] = round(agg_auto / agg_manual, 3)
    if not aggregate_roi["warnings"]:
        aggregate_roi["warnings"] = None

    roi_html = ""
    if roi_count:
        roi_html = _build_roi_html(
            aggregate_roi,
            title=f"ROI Estimate ({roi_count} device(s))",
        )

    # ── Device cards for the dashboard ─────────────────────
    cards: list[str] = []
    for i, r in enumerate(results):
        c = _score_colour(r.score_pct)
        cards.append(
            f'<div class="device-card" data-target="dev-{i}">'
            f'<div class="hostname">{_esc(r.hostname)}</div>'
            f'<div class="ip">{_esc(r.ip)} &mdash; {_esc(r.role_display)}</div>'
            f'<div class="score-bar"><div class="score-fill" style="width:{r.score_pct}%;background:{c};"></div></div>'
            f'<div class="card-stats">'
            f'<span style="color:{c};font-weight:700;">{r.score_pct}%</span>'
            f'<span><span class="dot" style="background:var(--pass);"></span>{r.pass_count}P</span>'
            f'<span><span class="dot" style="background:var(--fail);"></span>{r.fail_count}F</span>'
            f'<span><span class="dot" style="background:var(--warn);"></span>{r.warn_count}W</span>'
            f"</div></div>"
        )

    # ── Collapsible per-device sections ────────────────────
    sections: list[str] = []
    for i, r in enumerate(results):
        c = _score_colour(r.score_pct)
        parser_html = _build_structured_parsing_html(r, compact=True)

        # Build category HTML inside the device
        categories: dict[str, list[Finding]] = {}
        for f in r.findings:
            if f.status == Status.SKIP:
                continue
            categories.setdefault(f.category, []).append(f)

        cat_html: list[str] = []
        for cat, findings in categories.items():
            cat_pass = sum(1 for f in findings if f.status == Status.PASS)
            cat_total = len(findings)
            cat_pct = round(cat_pass / cat_total * 100, 1) if cat_total else 100
            title = cat.replace("_", " ").title()
            tbl = _build_findings_table(findings)
            cat_html.append(
                f'<div class="category">'
                f'<div class="category-title">{_esc(title)} '
                f'<span class="category-pct">({cat_pct}%)</span></div>'
                f"{tbl}</div>"
            )

        meta_parts = []
        if r.ios_version:
            meta_parts.append(f"IOS-XE: {_esc(r.ios_version)}")
        if r.duration_secs:
            meta_parts.append(f"{r.duration_secs}s")
        meta_str = (
            f' <span class="dev-meta" style="color:var(--text-dim);font-size:.8rem;margin-left:8px;">({" | ".join(meta_parts)})</span>'
            if meta_parts
            else ""
        )

        sections.append(
            f'<div class="device-section" id="dev-{i}">'
            f'<div class="device-header">'
            f'<div class="left">'
            f'<span class="chevron">&#9654;</span>'
            f'<span class="dev-hostname">{_esc(r.hostname)}</span>'
            f'<span class="dev-ip">{_esc(r.ip)} &mdash; {_esc(r.role_display)}{meta_str}</span>'
            f"</div>"
            f'<span class="dev-score" style="color:{c};">{r.score_pct}%</span>'
            f"</div>"
            f'<div class="device-body">{parser_html}{"".join(cat_html)}</div>'
            f"</div>"
        )

    body = f"""\
<div class="top-bar">
  <h1>Consolidated Compliance Audit</h1>
  <span class="meta">{_esc(ts_str)} &mdash; {len(results)} device(s)</span>
</div>
<div class="stats">
  <div class="stat-card"><div class="value" style="color:{sc}">{overall_score}%</div><div class="label">Overall Score</div></div>
  <div class="stat-card"><div class="value">{len(results)}</div><div class="label">Devices</div></div>
  <div class="stat-card"><div class="value" style="color:var(--pass)">{total_pass}</div><div class="label">Pass</div></div>
  <div class="stat-card"><div class="value" style="color:var(--fail)">{total_fail}</div><div class="label">Fail</div></div>
  <div class="stat-card"><div class="value" style="color:var(--warn)">{total_warn}</div><div class="label">Warn</div></div>
  <div class="stat-card"><div class="value" style="color:var(--error)">{total_error}</div><div class="label">Error</div></div>
</div>
{roi_html}
<div class="device-grid">{"".join(cards)}</div>
<div class="filters">
  <label>Filter:</label>
  <button class="filter-btn active" data-filter="all">All</button>
  <button class="filter-btn" data-filter="FAIL">Fail Only</button>
  <button class="filter-btn" data-filter="WARN">Warn Only</button>
  <button class="filter-btn" data-filter="PASS">Pass Only</button>
  <input class="search-box" id="search-box" type="text" placeholder="Search checks...">
  <button class="filter-btn" id="expand-all">Expand All</button>
  <button class="filter-btn" id="collapse-all">Collapse All</button>
</div>
{"".join(sections)}
<button class="back-top" id="back-top" title="Back to top">&#9650;</button>
"""

    page = _wrap_html("Consolidated Compliance Audit Report", body)
    try:
        filename.write_text(page, encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write consolidated HTML report %s: %s", filename, exc)
        return None
    log.info("Consolidated HTML report saved to %s", filename)
    return filename


# ═══════════════════════════════════════════════════════════════════
#  HTML wrapper
# ═══════════════════════════════════════════════════════════════════


def _wrap_html(title: str, body: str) -> str:
    """Wrap body content in a complete HTML document."""
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        f"</head>\n<body>\n{body}\n"
        f"<script>{_JS}</script>\n"
        "</body>\n</html>"
    )


# ═══════════════════════════════════════════════════════════════════
#  CSV export
# ═══════════════════════════════════════════════════════════════════


def save_csv(results: list[AuditResult], output_dir: str) -> Path | None:
    """Export all findings from one or more devices as a single CSV file."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"compliance_audit_{ts}.csv"

    try:
        with open(filename, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "hostname",
                    "ip",
                    "role",
                    "category",
                    "check",
                    "status",
                    "severity",
                    "tags",
                    "interface",
                    "detail",
                    "remediation",
                ]
            )
            for r in results:
                for f in r.findings:
                    if f.status == Status.SKIP:
                        continue
                    writer.writerow(
                        [
                            r.hostname,
                            r.ip,
                            r.role,
                            f.category,
                            f.check_name,
                            f.status.value,
                            getattr(f, "severity", "medium"),
                            "|".join(getattr(f, "tags", [])),
                            f.interface,
                            f.detail,
                            f.remediation,
                        ]
                    )
    except OSError as exc:
        log.error("Failed to write CSV report %s: %s", filename, exc)
        return None

    log.info("CSV report saved to %s", filename)
    return filename


# ═══════════════════════════════════════════════════════════════════
#  Remediation script generator
# ═══════════════════════════════════════════════════════════════════


def save_remediation_script(result: AuditResult, output_dir: str) -> Path | None:
    """
    Generate a per-device IOS-XE config snippet that remediates all FAILs.

    Returns the Path to the script file, or None if there's nothing to fix.
    """
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _safe_hostname(result.hostname)
    filename = outdir / f"{safe}_remediation_{ts}.txt"

    # Collect all FAIL findings that have a remediation command
    fails = [f for f in result.findings if f.status == Status.FAIL and f.remediation]
    if not fails:
        return None

    # Separate global commands from interface-level commands
    global_cmds: list[str] = []
    intf_cmds: dict[str, list[str]] = {}  # {interface_name: [commands]}

    for f in fails:
        remed = f.remediation.strip()
        if not remed:
            continue
        if f.interface and not f.interface.startswith("line "):
            intf_cmds.setdefault(f.interface, []).append(remed)
        elif f.interface and f.interface.startswith("line "):
            # VTY/console line commands
            intf_cmds.setdefault(f.interface, []).append(remed)
        else:
            global_cmds.append(remed)

    lines: list[str] = []
    lines.append(f"! Remediation script for {result.hostname} ({result.ip})")
    lines.append(
        f"! Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    lines.append(f"! Findings to fix: {len(fails)}")
    lines.append("!")
    lines.append("configure terminal")
    lines.append("!")

    # Global commands (deduplicated, order preserved)
    if global_cmds:
        lines.append("! --- Global Configuration ---")
        seen: set[str] = set()
        for cmd in global_cmds:
            if cmd not in seen:
                seen.add(cmd)
                lines.append(cmd)
        lines.append("!")

    # Interface commands
    for intf_name in sorted(intf_cmds.keys()):
        cmds = intf_cmds[intf_name]
        if intf_name.startswith("line "):
            lines.append(f"{intf_name}")
        else:
            lines.append(f"interface {intf_name}")
        seen_intf: set[str] = set()
        for cmd in cmds:
            if cmd not in seen_intf:
                seen_intf.add(cmd)
                lines.append(f" {cmd}")
        lines.append("!")

    lines.append("end")
    lines.append("write memory")
    lines.append("!")

    try:
        filename.write_text("\n".join(lines), encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write remediation script %s: %s", filename, exc)
        return None
    log.info("Remediation script saved to %s", filename)
    return filename


# ═══════════════════════════════════════════════════════════════════
#  Delta / baseline comparison report
# ═══════════════════════════════════════════════════════════════════


def load_baseline(baseline_path: str) -> dict | None:
    """Load a previous JSON audit result as a baseline for comparison."""
    p = Path(baseline_path)
    if not p.exists():
        log.warning("Baseline file not found: %s", baseline_path)
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Failed to load baseline %s: %s", baseline_path, exc)
        return None


def _find_latest_baseline(output_dir: str, hostname: str) -> Path | None:
    """Find the most recent JSON audit file for a given hostname."""
    outdir = Path(output_dir)
    if not outdir.exists():
        return None
    safe = _safe_hostname(hostname)
    audit_name = re.compile(rf"^{re.escape(safe)}_\d{{8}}_\d{{6}}\.json$")
    candidates = sorted(
        [path for path in outdir.glob(f"{safe}_*.json") if audit_name.match(path.name)],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    # Return the second-most-recent (the most recent is the one just written)
    return candidates[1] if len(candidates) >= 2 else None


@dataclass
class DeltaEntry:
    """One finding that changed between baseline and current."""

    check_name: str
    category: str
    interface: str
    old_status: str
    new_status: str
    detail: str
    remediation: str


def _delta_finding_key(
    check_name: str,
    category: str,
    interface: str,
    remediation: str,
    detail: str,
) -> tuple[str, str, str, str]:
    """Return a stable identity for delta comparisons.

    Some checks intentionally emit multiple findings with the same check name and
    interface, such as storm-control broadcast and multicast findings. Use the
    remediation command as the primary discriminator so those sibling findings do
    not overwrite each other in delta maps.
    """
    discriminator = remediation or detail
    return (check_name, category, interface, discriminator)


def compute_delta(
    baseline: dict,
    current: AuditResult,
) -> dict:
    """
    Compare baseline JSON to current AuditResult.

    Returns a dict with:
      - resolved: findings that were FAIL/WARN and are now PASS
      - new_failures: findings that are now FAIL/WARN but were PASS or absent
      - unchanged_fails: still failing
      - score_change: current - baseline score
    """
    # Build lookup from baseline using a stable identity for repeated findings.
    base_map: dict[tuple[str, str, str, str], dict] = {}
    for f in baseline.get("findings", []):
        key = _delta_finding_key(
            f.get("check", ""),
            f.get("category", ""),
            f.get("interface", ""),
            f.get("remediation", ""),
            f.get("detail", ""),
        )
        base_map[key] = f

    resolved: list[dict] = []
    new_failures: list[dict] = []
    unchanged_fails: list[dict] = []

    for f in current.findings:
        if f.status == Status.SKIP:
            continue
        key = _delta_finding_key(
            f.check_name,
            f.category,
            f.interface,
            f.remediation,
            f.detail,
        )
        base_finding = base_map.pop(key, None)

        if f.status in (Status.FAIL, Status.WARN):
            if base_finding and base_finding.get("status") in ("FAIL", "WARN"):
                unchanged_fails.append(
                    {
                        "check": f.check_name,
                        "category": f.category,
                        "interface": f.interface,
                        "status": f.status.value,
                        "detail": f.detail,
                        "remediation": f.remediation,
                    }
                )
            else:
                new_failures.append(
                    {
                        "check": f.check_name,
                        "category": f.category,
                        "interface": f.interface,
                        "old_status": base_finding.get("status", "N/A")
                        if base_finding
                        else "NEW",
                        "new_status": f.status.value,
                        "detail": f.detail,
                        "remediation": f.remediation,
                    }
                )
        elif f.status == Status.PASS and base_finding:
            if base_finding.get("status") in ("FAIL", "WARN"):
                resolved.append(
                    {
                        "check": f.check_name,
                        "category": f.category,
                        "interface": f.interface,
                        "old_status": base_finding["status"],
                        "new_status": "PASS",
                        "detail": f.detail,
                    }
                )

    # Any remaining in base_map that were FAIL/WARN but absent now = resolved
    for key, bf in base_map.items():
        if bf.get("status") in ("FAIL", "WARN"):
            resolved.append(
                {
                    "check": bf.get("check", key[0]),
                    "category": bf.get("category", ""),
                    "interface": bf.get("interface", key[1]),
                    "old_status": bf["status"],
                    "new_status": "REMOVED",
                    "detail": "Check no longer present in audit",
                }
            )

    base_score = baseline.get("score_pct", 0)
    return {
        "baseline_score": base_score,
        "current_score": current.score_pct,
        "score_change": round(current.score_pct - base_score, 1),
        "resolved_count": len(resolved),
        "new_failure_count": len(new_failures),
        "unchanged_fail_count": len(unchanged_fails),
        "resolved": resolved,
        "new_failures": new_failures,
        "unchanged_fails": unchanged_fails,
    }


def save_delta_report(
    delta: dict,
    hostname: str,
    output_dir: str,
) -> Path:
    """Save a JSON delta report showing what changed since the baseline."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = outdir / f"{hostname}_delta_{ts}.json"
    filename.write_text(json.dumps(delta, indent=2), encoding="utf-8")
    log.info("Delta report saved to %s", filename)
    return filename


def print_delta_summary(
    delta: dict, hostname: str, console: Optional[Console] = None
) -> None:
    """Print a coloured delta summary to the console."""
    con = console or Console()
    sc = delta["score_change"]
    sc_style = "green" if sc > 0 else "red" if sc < 0 else "yellow"
    arrow = "▲" if sc > 0 else "▼" if sc < 0 else "─"

    con.print(
        Panel(
            f"[bold]Baseline:[/] {delta['baseline_score']}% → "
            f"[bold]Current:[/] {delta['current_score']}%  "
            f"[{sc_style}]{arrow} {sc:+.1f}%[/]\n"
            f"[green]Resolved: {delta['resolved_count']}[/]  "
            f"[red]New failures: {delta['new_failure_count']}[/]  "
            f"[yellow]Unchanged fails: {delta['unchanged_fail_count']}[/]",
            title=f"DELTA — {hostname}",
            border_style="cyan",
            expand=False,
        )
    )

    if delta["new_failures"]:
        table = Table(title="New Failures", box=box.ROUNDED, expand=False)
        table.add_column("Check", style="cyan")
        table.add_column("Interface")
        table.add_column("Status", style="bold red")
        table.add_column("Detail")
        for nf in delta["new_failures"]:
            table.add_row(
                nf["check"], nf.get("interface", ""), nf["new_status"], nf["detail"]
            )
        con.print(table)

    if delta["resolved"]:
        table = Table(title="Resolved", box=box.ROUNDED, expand=False)
        table.add_column("Check", style="cyan")
        table.add_column("Interface")
        table.add_column("Was", style="yellow")
        table.add_column("Now", style="green")
        for r in delta["resolved"]:
            table.add_row(
                r["check"], r.get("interface", ""), r["old_status"], r["new_status"]
            )
        con.print(table)
