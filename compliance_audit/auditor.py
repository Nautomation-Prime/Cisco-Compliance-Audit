"""
Main orchestrator — connects to devices, collects data, runs the
compliance engine, and produces reports.

Supports concurrent device auditing via ThreadPoolExecutor.
The number of parallel workers is controlled by ``audit_settings.max_workers``
in the compliance YAML config (default: 5, set to 1 for sequential).
"""

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from .credentials import CredentialHandler
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .hostname_parser import parse_hostname
from .collector import DataCollector
from .port_classifier import classify_ports
from .compliance_engine import ComplianceEngine, AuditResult
from .report import print_report, save_json, save_html, save_consolidated_html

log = logging.getLogger(__name__)
console = Console()


def load_compliance_config(path: str) -> dict:
    """Load the compliance YAML configuration file."""
    p = Path(path)
    if not p.exists():
        # Try relative to this module's directory
        p = Path(__file__).parent / path
    if not p.exists():
        console.print(f"[bold red]Config not found:[/] {path}")
        sys.exit(1)
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass
class _DeviceJob:
    """All parameters needed to audit a single device."""
    hostname: str
    ip: str
    username: str
    password: str
    device_type: str
    jump: Optional[JumpManager]
    enable_secret: Optional[str]
    timeout: int
    compliance_policy: dict
    role_config: Optional[list]
    endpoint_config: Optional[dict]
    audit_settings: dict


def _audit_single_device(job: _DeviceJob) -> Optional[AuditResult]:
    """
    Audit one device end-to-end (connect → collect → classify → check).

    Designed to run inside a thread. Returns None on connection failure.
    """
    hostname, ip = job.hostname, job.ip
    log.info("Starting audit of %s (%s)", hostname, ip)

    # Parse hostname for role
    host_info = parse_hostname(hostname, role_config=job.role_config)

    # Connect
    connector = DeviceConnector(
        ip=ip,
        username=job.username,
        password=job.password,
        device_type=job.device_type,
        jump=job.jump,
        **({"secret": job.enable_secret} if job.enable_secret else {}),
    )
    try:
        conn = connector.connect()
    except Exception as exc:
        log.error("Connection to %s (%s) failed: %s", hostname, ip, exc)
        return None

    try:
        # Collect
        collector = DataCollector(timeout=job.timeout)
        data = collector.collect(conn, ip=ip)
        data.hostname = hostname

        # Classify ports
        ports = classify_ports(
            data,
            role_config=job.role_config,
            endpoint_config=job.endpoint_config,
        )

        # Audit
        engine = ComplianceEngine(job.compliance_policy)
        result = engine.audit(data, host_info, ports)

        # Save per-device reports
        out_dir = job.audit_settings.get("output_dir", "./reports")
        if job.audit_settings.get("json_report", True):
            save_json(result, out_dir)
        if job.audit_settings.get("html_report", True):
            save_html(result, out_dir)

        log.info("Completed audit of %s — score %s%%", hostname, result.score_pct)
        return result

    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def run_audit(
    config_path: str = "compliance_config.yaml",
    device_overrides: Optional[list[str]] = None,
    skip_jump: bool = False,
    categories: Optional[list[str]] = None,
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

    # Filter categories if requested
    if categories:
        filtered = {}
        for cat in categories:
            if cat in compliance_policy:
                filtered[cat] = compliance_policy[cat]
        filtered["_audit_settings"] = audit_settings
        compliance_policy = filtered

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
        devices = cfg.get("devices", []) or []

    if not devices:
        console.print("[bold yellow]No devices to audit.[/] "
                      "Add devices to compliance_config.yaml or use --device.")
        return []

    # ── Credentials ────────────────────────────────────────
    cred_store = conn_cfg.get("credential_store", "none")
    keyring_svc = conn_cfg.get("keyring_service", "cisco-compliance-audit")
    cred_handler = CredentialHandler(
        credential_store=cred_store,
        keyring_service=keyring_svc,
    )
    username, password = cred_handler.get_secret_with_fallback()
    enable_secret = cred_handler.get_enable_secret()

    # ── Jump host (optional) ───────────────────────────────
    jump: Optional[JumpManager] = None
    jump_host = conn_cfg.get("jump_host")
    use_jump = conn_cfg.get("use_jump_host", True)
    if jump_host and use_jump and not skip_jump:
        console.print(f"[cyan]Connecting to jump host {jump_host} ...[/]")
        jump = JumpManager(jump_host, username, password)
        jump.connect()

    # ── Concurrency settings ───────────────────────────────
    max_workers = max(1, audit_settings.get("max_workers", 5))
    device_type = conn_cfg.get("device_type", "cisco_xe")
    timeout = audit_settings.get("collect_timeout", 30)

    console.print(
        f"[cyan]Auditing {len(devices)} device(s) with up to "
        f"{max_workers} concurrent worker(s) ...[/]"
    )
    console.print()

    # ── Build jobs ─────────────────────────────────────────
    jobs: list[_DeviceJob] = []
    for dev_entry in devices:
        ip = dev_entry.get("ip", "")
        hostname = dev_entry.get("hostname", ip)
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

    # ── Per-device console reports ─────────────────────────
    if results:
        console.print()
        for result in results:
            console.rule(f"[bold cyan]{result.hostname}  ({result.ip})[/]")
            print_report(result, console=console)

    # ── Final summary ──────────────────────────────────────
    if len(results) > 1:
        console.rule("[bold cyan]OVERALL SUMMARY[/]")
        for r in results:
            style = "green" if r.fail_count == 0 else "red"
            console.print(
                f"  {r.hostname:40s}  Score: [{style}]{r.score_pct}%[/]  "
                f"({r.pass_count}P / {r.fail_count}F / {r.warn_count}W)"
            )
        console.print()

        # Generate consolidated HTML report for multiple devices
        out_dir = audit_settings.get("output_dir", "./reports")
        if audit_settings.get("html_report", True):
            p = save_consolidated_html(results, out_dir)
            console.print(f"  [bold cyan]Consolidated HTML report:[/] {p}")
            console.print()

    return results
