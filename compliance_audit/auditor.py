"""
Main orchestrator — connects to devices, collects data, runs the
compliance engine, and produces reports.

Supports concurrent device auditing via ThreadPoolExecutor.
The number of parallel workers is controlled by ``audit_settings.max_workers``
in the compliance YAML config (default: 5, set to 1 for sequential).
"""

import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.table import Table
from rich import box

from .credentials import CredentialHandler
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .hostname_parser import parse_hostname
from .collector import DataCollector, OfflineCollector
from .port_classifier import classify_ports
from .compliance_engine import ComplianceEngine, AuditResult, Finding, Status
from .report import (
    print_report, save_json, save_html, save_consolidated_html,
    save_csv, save_remediation_script,
    _find_latest_baseline, load_baseline, compute_delta,
    save_delta_report, print_delta_summary,
)

log = logging.getLogger(__name__)
console = Console()


def _get_roi_settings(audit_settings: dict) -> dict:
    """Return ROI settings with safe defaults."""
    roi = audit_settings.get("roi", {})
    if not isinstance(roi, dict):
        roi = {}
    return {
        "enabled": bool(roi.get("enabled", False)),
        "manual_minutes_per_device": float(roi.get("manual_minutes_per_device", 20.0)),
        "manual_minutes_per_check": float(roi.get("manual_minutes_per_check", 0.25)),
        "automation_overhead_minutes_per_device": float(
            roi.get("automation_overhead_minutes_per_device", 2.0)
        ),
        "hourly_rate": float(roi.get("hourly_rate", 0.0)),
        "currency": str(roi.get("currency", "GBP")),
    }


def _estimate_roi_for_result(result: AuditResult, roi_settings: dict) -> dict:
    """Estimate per-device automation value using a simple, configurable model."""
    manual_minutes = (
        roi_settings["manual_minutes_per_device"]
        + (roi_settings["manual_minutes_per_check"] * result.total)
    )
    automated_minutes = (result.duration_secs / 60.0) + roi_settings[
        "automation_overhead_minutes_per_device"
    ]
    minutes_saved = max(0.0, manual_minutes - automated_minutes)
    hours_saved = minutes_saved / 60.0
    value_saved = hours_saved * roi_settings["hourly_rate"]

    return {
        "manual_minutes_estimate": round(manual_minutes, 1),
        "automated_minutes": round(automated_minutes, 1),
        "minutes_saved": round(minutes_saved, 1),
        "hours_saved": round(hours_saved, 2),
        "hourly_rate": round(roi_settings["hourly_rate"], 2),
        "currency": roi_settings["currency"],
        "value_saved": round(value_saved, 2),
        "assumptions": {
            "manual_minutes_per_device": roi_settings["manual_minutes_per_device"],
            "manual_minutes_per_check": roi_settings["manual_minutes_per_check"],
            "automation_overhead_minutes_per_device": (
                roi_settings["automation_overhead_minutes_per_device"]
            ),
        },
    }


def _summarize_roi(results: list[AuditResult], roi_settings: dict) -> dict:
    """Aggregate ROI metrics across all audited devices."""
    manual = 0.0
    automated = 0.0
    saved = 0.0
    value = 0.0
    device_count = 0

    for r in results:
        roi = getattr(r, "_roi", None)
        if not roi:
            continue
        device_count += 1
        manual += float(roi.get("manual_minutes_estimate", 0.0))
        automated += float(roi.get("automated_minutes", 0.0))
        saved += float(roi.get("minutes_saved", 0.0))
        value += float(roi.get("value_saved", 0.0))

    return {
        "enabled": bool(roi_settings.get("enabled", False)),
        "device_count": device_count,
        "manual_minutes_estimate": round(manual, 1),
        "automated_minutes": round(automated, 1),
        "minutes_saved": round(saved, 1),
        "hours_saved": round(saved / 60.0, 2),
        "hourly_rate": round(float(roi_settings.get("hourly_rate", 0.0)), 2),
        "currency": str(roi_settings.get("currency", "GBP")),
        "value_saved": round(value, 2),
        "assumptions": {
            "manual_minutes_per_device": float(roi_settings.get("manual_minutes_per_device", 0.0)),
            "manual_minutes_per_check": float(roi_settings.get("manual_minutes_per_check", 0.0)),
            "automation_overhead_minutes_per_device": float(
                roi_settings.get("automation_overhead_minutes_per_device", 0.0)
            ),
        },
    }


def load_compliance_config(path: str) -> dict:
    """Load and validate the compliance YAML configuration file."""
    p = Path(path)
    if not p.exists():
        # Try relative to this module's directory
        p = Path(__file__).parent / path
    if not p.exists():
        console.print(f"[bold red]Config not found:[/] {path}")
        sys.exit(1)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        console.print(f"[bold red]Malformed YAML in config:[/] {exc}")
        sys.exit(1)

    # Validate required top-level keys exist and have correct types
    _EXPECTED_KEYS = {
        "connection": dict,
        "compliance": dict,
    }
    for key, expected_type in _EXPECTED_KEYS.items():
        val = cfg.get(key)
        if val is None:
            console.print(f"[bold yellow]Warning:[/] config missing required "
                          f"section [cyan]'{key}'[/] — using defaults.")
        elif not isinstance(val, expected_type):
            console.print(f"[bold red]Config error:[/] '{key}' must be a "
                          f"{expected_type.__name__}, got {type(val).__name__}")
            sys.exit(1)

    return cfg


def _resolve_config_path(path: str) -> Path:
    """Return the resolved path to the config file (used for sibling lookups)."""
    p = Path(path)
    if p.exists():
        return p.parent
    alt = Path(__file__).parent / path
    if alt.exists():
        return alt.parent
    return Path(__file__).parent


def load_device_inventory(inventory_path: str | None, config_path: str) -> list[dict]:
    """Load the device inventory from a dedicated YAML file.

    Resolution order for *inventory_path*:
    1. Explicit CLI value (--inventory).
    2. ``inventory_file`` key inside the main config YAML.
    3. ``devices.yaml`` next to the config file.
    """
    cfg_dir = _resolve_config_path(config_path)

    if inventory_path is None:
        cfg = load_compliance_config(config_path)
        inventory_path = cfg.get("inventory_file", "devices.yaml")

    p = Path(inventory_path)
    if not p.is_absolute():
        p = cfg_dir / p
    if not p.exists():
        p = Path(__file__).parent / inventory_path
    if not p.exists():
        return []

    with open(p, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("devices", []) or []


@dataclass
class _DeviceJob:
    """All parameters needed to audit a single device."""
    hostname: str
    ip: str
    username: str
    password: str = field(repr=False)
    device_type: str
    jump: Optional[JumpManager]
    enable_secret: Optional[str] = field(repr=False)
    timeout: int
    compliance_policy: dict
    role_config: Optional[list]
    endpoint_config: Optional[dict]
    audit_settings: dict
    explicit_role: Optional[str] = None  # NEW: explicit role from devices.yaml


def _audit_single_device(job: _DeviceJob) -> Optional[AuditResult]:
    """
    Audit one device end-to-end (connect → collect → classify → check).

    Designed to run inside a thread. Returns None on connection failure.
    In dry-run mode, loads data from files instead of SSH.
    """
    hostname, ip = job.hostname, job.ip
    log.info("Starting audit of %s (%s)", hostname, ip)
    t_start = time.monotonic()

    # Parse hostname for role (with optional explicit role override from devices.yaml)
    host_info = parse_hostname(hostname, role_config=job.role_config, explicit_role=job.explicit_role)

    dry_run_dir = job.audit_settings.get("_dry_run_dir")

    if dry_run_dir:
        # ── Dry-run / offline mode ─────────────────────────
        offline = OfflineCollector(dry_run_dir)
        data = offline.collect(hostname, ip=ip)
        if data is None:
            log.error("Dry-run: no data found for %s", hostname)
            return None
        conn = None
    else:
        # ── Live SSH connection ────────────────────────────
        connector = DeviceConnector(
            ip=ip,
            username=job.username,
            password=job.password,
            device_type=job.device_type,
            jump=job.jump,
            retries=job.audit_settings.get("retries",
                     job.audit_settings.get("_connection", {}).get("retries", 3)),
            **({"secret": job.enable_secret} if job.enable_secret else {}),
        )
        try:
            conn = connector.connect()
        except Exception as exc:
            log.error("Connection to %s (%s) failed: %s", hostname, ip, exc)
            return None

        try:
            collector = DataCollector(timeout=job.timeout)
            data = collector.collect(conn, ip=ip)
            data.hostname = hostname
        except Exception as exc:
            log.error("Data collection from %s (%s) failed: %s", hostname, ip, exc)
            try:
                conn.disconnect()
            except Exception:
                pass
            return None

    try:
        # Classify ports
        ports = classify_ports(
            data,
            role_config=job.role_config,
            endpoint_config=job.endpoint_config,
        )

        # Audit
        engine = ComplianceEngine(job.compliance_policy)
        result = engine.audit(data, host_info, ports)
    except Exception as exc:
        log.exception("Compliance engine failed for %s (%s)", hostname, ip)
        result = AuditResult(
            hostname=hostname, ip=ip,
            role=host_info.role, role_display=host_info.role_display,
            findings=[Finding(
                check_name="engine_error",
                status=Status.ERROR,
                detail=f"Compliance engine crashed: {exc}",
                category="internal",
            )],
        )

    try:
        # Populate metadata
        result.duration_secs = round(time.monotonic() - t_start, 1)
        result.audit_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        from . import __version__
        result.tool_version = __version__

        # Extract IOS-XE version from Genie data
        if data.version:
            ver = data.version.get("version", {})
            result.ios_version = ver.get("version", "") or ver.get("xe_version", "")

        # Attach ROI data before saving reports so individual reports include ROI
        roi_settings = _get_roi_settings(job.audit_settings)
        if roi_settings.get("enabled", False):
            result._roi = _estimate_roi_for_result(result, roi_settings)

        # Save per-device reports
        out_dir = job.audit_settings.get("output_dir", "./reports")
        # Import locally to avoid circular import
        from .remediation_workflow import generate_review_pack, get_remediation_settings
        rem = get_remediation_settings(job.audit_settings)
        if job.audit_settings.get("json_report", True):
            save_json(result, out_dir)
        if job.audit_settings.get("html_report", True):
            save_html(result, out_dir)
        if rem.get("enabled") and rem.get("generate_script"):
            script_path = save_remediation_script(result, out_dir)
            if script_path and rem.get("generate_review_pack"):
                generate_review_pack(result, script_path, out_dir)

        # Delta reporting (compare against previous baseline)
        if job.audit_settings.get("json_report", True):
            baseline_path = _find_latest_baseline(out_dir, hostname)
            if baseline_path:
                baseline = load_baseline(str(baseline_path))
                if baseline:
                    delta = compute_delta(baseline, result)
                    save_delta_report(delta, hostname, out_dir)
                    result._delta = delta  # stash for console output

        log.info("Completed audit of %s — score %s%% (%.1fs)",
                 hostname, result.score_pct, result.duration_secs)
        return result

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def run_audit(
    config_path: str = "compliance_config.yaml",
    device_overrides: Optional[list[str]] = None,
    skip_jump: bool = False,
    categories: Optional[list[str]] = None,
    output_dir: Optional[str] = None,
    dry_run_dir: Optional[str] = None,
    csv_report: Optional[bool] = None,
    inventory_path: Optional[str] = None,
) -> list[AuditResult]:
    """
    Run the full compliance audit pipeline.

    Parameters
    ----------
    config_path : str
        Path to the compliance YAML config.
    device_overrides : list[str] | None
        If given, audit only these IPs/hostnames instead of the inventory.
    skip_jump : bool
        If True, connect directly without jump host.
    categories : list[str] | None
        If given, only run checks in these categories.
    output_dir : str | None
        Override the report output directory from the YAML config.
    dry_run_dir : str | None
        If set, load command outputs from this directory instead of SSH.
    csv_report : bool | None
        If True, override YAML to force CSV generation.

    Returns
    -------
    list[AuditResult]
    """
    # ── Load configuration ─────────────────────────────────
    cfg = load_compliance_config(config_path)
    conn_cfg = cfg.get("connection", {})
    audit_settings = cfg.get("audit_settings", {})
    compliance_policy = cfg.get("compliance", {})
    role_config = cfg.get("hostname_roles") or None
    endpoint_config = cfg.get("endpoint_neighbors") or None

    # Inject audit_settings into policy so the engine can read parking_vlan etc.
    compliance_policy["_audit_settings"] = audit_settings

    # CLI overrides
    if output_dir:
        audit_settings["output_dir"] = output_dir
    if csv_report is not None:
        audit_settings["csv_report"] = csv_report
    if dry_run_dir:
        audit_settings["_dry_run_dir"] = dry_run_dir

    # Inject connection retries into audit_settings so workers can access it
    audit_settings["_connection"] = conn_cfg

    # Filter categories if requested
    if categories:
        filtered = {}
        for cat in categories:
            if cat in compliance_policy:
                filtered[cat] = compliance_policy[cat]
        filtered["_audit_settings"] = audit_settings
        compliance_policy = filtered

    # Warn if no actual compliance checks are configured
    check_cats = [k for k in compliance_policy if not k.startswith("_")]
    if not check_cats:
        console.print("[bold yellow]Warning:[/] No compliance check categories "
                      "found in policy — audits will produce zero findings.")
        log.warning("Compliance policy contains no check categories")

    # ── Build device list ──────────────────────────────────
    devices: list[dict] = []
    if device_overrides:
        for entry in device_overrides:
            if ":" in entry:
                hostname, ip = entry.split(":", 1)
                devices.append({"hostname": hostname, "ip": ip})
            else:
                devices.append({"hostname": entry, "ip": entry})
    else:
        devices = load_device_inventory(inventory_path, config_path)

    # ── Credentials ────────────────────────────────────────
    username, password, enable_secret = "", "", None
    jump: Optional[JumpManager] = None

    if not dry_run_dir:
        cred_store = conn_cfg.get("credential_store", "none")
        keyring_svc = conn_cfg.get("keyring_service", "cisco-compliance-audit")
        cred_handler = CredentialHandler(
            credential_store=cred_store,
            keyring_service=keyring_svc,
        )
        username, password = cred_handler.get_secret_with_fallback()
        enable_secret = cred_handler.get_enable_secret()

        # ── Jump host (optional) ───────────────────────────
        jump_host = conn_cfg.get("jump_host")
        use_jump = conn_cfg.get("use_jump_host", True)
        if jump_host and use_jump and not skip_jump:
            console.print(f"[cyan]Connecting to jump host {jump_host} ...[/]")
            jump = JumpManager(jump_host, username, password)
            jump.connect()
    else:
        console.print("[bold yellow]DRY-RUN MODE[/] — loading saved outputs "
                      f"from [cyan]{dry_run_dir}[/]")
        # In dry-run mode, also auto-discover device folders if no devices given
        if not devices:
            dr_path = Path(dry_run_dir)
            if dr_path.is_dir():
                for child in sorted(dr_path.iterdir()):
                    if child.is_dir():
                        devices.append({"hostname": child.name, "ip": child.name})
                if devices:
                    console.print(f"  Discovered {len(devices)} device(s) from dry-run directory")

    if not devices:
        console.print("[bold yellow]No devices to audit.[/] "
                      "Add devices to devices.yaml or use --device.")
        return []

    # ── Concurrency settings ───────────────────────────────
    max_workers = max(1, min(audit_settings.get("max_workers", 5), 20))
    device_type = conn_cfg.get("device_type", "cisco_xe")
    timeout = audit_settings.get("collect_timeout", 30)
    roi_settings = _get_roi_settings(audit_settings)

    mode_label = "offline" if dry_run_dir else "live"
    console.print(
        f"[cyan]Auditing {len(devices)} device(s) ({mode_label}) with up to "
        f"{max_workers} concurrent worker(s) ...[/]"
    )
    console.print()

    # ── Build jobs ─────────────────────────────────────────
    jobs: list[_DeviceJob] = []
    for dev_entry in devices:
        ip = dev_entry.get("ip", "")
        hostname = dev_entry.get("hostname", ip)
        explicit_role = dev_entry.get("role")  # NEW: get explicit role from devices.yaml
        jobs.append(_DeviceJob(
            hostname=hostname,
            ip=ip,
            username=username,
            password=password,
            device_type=device_type,
            jump=jump,
            enable_secret=enable_secret,
            timeout=timeout,
            compliance_policy=compliance_policy,
            role_config=role_config,
            endpoint_config=endpoint_config,
            audit_settings=audit_settings,
            explicit_role=explicit_role,  # NEW: pass explicit role to job
        ))

    # ── Execute audits concurrently ────────────────────────
    results: list[AuditResult] = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Auditing devices", total=len(jobs))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_job = {
                    executor.submit(_audit_single_device, job): job
                    for job in jobs
                }
                for future in as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        result = future.result()
                        if result is not None:
                            results.append(result)
                            progress.console.print(
                                f"  [green]✓[/] {job.hostname} ({job.ip}) — "
                                f"Score: {result.score_pct}%"
                            )
                        else:
                            progress.console.print(
                                f"  [red]✗[/] {job.hostname} ({job.ip}) — "
                                f"Connection failed"
                            )
                    except Exception as exc:
                        log.exception("Audit of %s failed", job.hostname)
                        progress.console.print(
                            f"  [red]✗[/] {job.hostname} ({job.ip}) — "
                            f"Error: {exc}"
                        )
                    progress.advance(task_id)

    finally:
        if jump:
            jump.close()

    # ── Summary table ────────────────────────────────────────
    out_dir = audit_settings.get("output_dir", "./reports")
    if results:
        if roi_settings.get("enabled", False):
            for r in results:
                r._roi = _estimate_roi_for_result(r, roi_settings)

        console.print()
        console.rule("[bold cyan]AUDIT SUMMARY[/]")
        summary_table = Table(
            box=box.ROUNDED, expand=False, show_lines=False,
            title_style="bold", min_width=90,
        )
        summary_table.add_column("Device", style="cyan", min_width=30)
        summary_table.add_column("IP", min_width=15)
        summary_table.add_column("Role", min_width=12)
        summary_table.add_column("Score", justify="center", min_width=7)
        summary_table.add_column("Pass", justify="center", style="green")
        summary_table.add_column("Fail", justify="center", style="red")
        summary_table.add_column("Warn", justify="center", style="yellow")
        summary_table.add_column("Error", justify="center", style="magenta")

        for r in results:
            score_style = "bold green" if r.fail_count == 0 else "bold red"
            summary_table.add_row(
                r.hostname,
                r.ip,
                r.role_display or r.role or "",
                f"[{score_style}]{r.score_pct}%[/]",
                str(r.pass_count),
                str(r.fail_count),
                str(r.warn_count),
                str(r.error_count),
            )

        console.print(summary_table)
        console.print()

        # Print delta summaries (brief) if available
        for r in results:
            delta = getattr(r, "_delta", None)
            if delta:
                print_delta_summary(delta, r.hostname, console=console)

        if roi_settings.get("enabled", False):
            roi_summary = _summarize_roi(results, roi_settings)
            console.print(
                f"[bold cyan]ROI Estimate:[/] "
                f"{roi_summary['hours_saved']}h saved "
                f"({roi_summary['minutes_saved']} min)"
            )
            if roi_summary["hourly_rate"] > 0:
                console.print(
                    f"[bold cyan]Estimated Value:[/] "
                    f"{roi_summary['currency']} {roi_summary['value_saved']:.2f}"
                )

    # ── CSV export ─────────────────────────────────────────
    if results and audit_settings.get("csv_report", True):
        csv_path = save_csv(results, out_dir)
        console.print(f"  [bold cyan]CSV report:[/] {csv_path}")

    # ── Consolidated HTML report ───────────────────────────
    if results and audit_settings.get("html_report", True):
        p = save_consolidated_html(results, out_dir)
        console.print(f"  [bold cyan]HTML report:[/] {p}")
        console.print()

    return results
