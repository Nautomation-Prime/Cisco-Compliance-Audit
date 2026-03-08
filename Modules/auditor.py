"""
Main orchestrator — connects to devices, collects data, runs the
compliance engine, and produces reports.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

from .credentials import CredentialHandler
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .hostname_parser import parse_hostname
from .collector import DataCollector
from .port_classifier import classify_ports
from .compliance_engine import ComplianceEngine, AuditResult
from .report import print_report, save_json, save_html

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
    cred_target = conn_cfg.get("cred_target")
    cred_handler = CredentialHandler(target=cred_target)
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

    # ── Collector + Engine ─────────────────────────────────
    timeout = audit_settings.get("collect_timeout", 30)
    collector = DataCollector(timeout=timeout)
    engine = ComplianceEngine(compliance_policy)
    device_type = conn_cfg.get("device_type", "cisco_xe")
    results: list[AuditResult] = []

    try:
        for dev_entry in devices:
            ip = dev_entry.get("ip", "")
            hostname = dev_entry.get("hostname", ip)
            console.rule(f"[bold cyan]{hostname}  ({ip})[/]")

            # Parse hostname for role
            host_info = parse_hostname(hostname, role_config=role_config)
            if host_info.parsed:
                console.print(f"  Role detected: [bold]{host_info.role_display}[/]")
            else:
                console.print("  [yellow]Hostname did not match naming convention — "
                              "role-specific checks may be skipped.[/]")

            # Connect
            connector = DeviceConnector(
                ip=ip,
                username=username,
                password=password,
                device_type=device_type,
                jump=jump,
                **({"secret": enable_secret} if enable_secret else {}),
            )
            try:
                conn = connector.connect()
            except Exception as exc:
                console.print(f"  [bold red]Connection failed:[/] {exc}")
                log.exception("Connection to %s failed", ip)
                continue

            try:
                # Collect
                console.print("  Collecting device data ...")
                data = collector.collect(conn, ip=ip)
                data.hostname = hostname  # prefer inventory hostname

                # Classify ports
                console.print("  Classifying ports ...")
                ports = classify_ports(data, role_config=role_config, endpoint_config=endpoint_config)
                uplinks = [n for n, p in ports.items() if p.role.value == "trunk_uplink"]
                downlinks = [n for n, p in ports.items() if p.role.value == "trunk_downlink"]
                endpoints = [n for n, p in ports.items() if p.role.value == "trunk_endpoint"]
                if uplinks:
                    console.print(f"    Uplinks  : {', '.join(uplinks)}")
                if downlinks:
                    console.print(f"    Downlinks: {', '.join(downlinks)}")
                if endpoints:
                    ep_detail = [f"{n} ({ports[n].cdp_neighbor})" for n in endpoints]
                    console.print(f"    Endpoints: {', '.join(ep_detail)}")

                # Audit
                console.print("  Running compliance checks ...")
                result = engine.audit(data, host_info, ports)
                results.append(result)

                # Print report
                print_report(result, console=console)

                # Save reports
                out_dir = audit_settings.get("output_dir", "./reports")
                if audit_settings.get("json_report", True):
                    p = save_json(result, out_dir)
                    console.print(f"  [dim]JSON → {p}[/]")
                if audit_settings.get("html_report", True):
                    p = save_html(result, out_dir)
                    console.print(f"  [dim]HTML → {p}[/]")

            finally:
                try:
                    conn.disconnect()
                except Exception:
                    pass

    finally:
        if jump:
            jump.close()

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

    return results
