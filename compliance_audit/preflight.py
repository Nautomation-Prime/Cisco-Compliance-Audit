"""
Pre-flight checks for --dry-run and --health modes.

Validates connectivity, credentials, and dependencies before committing
to a full audit run.
"""

from __future__ import annotations

import importlib
import os
import platform
import socket
import sys
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── dependency manifest ─────────────────────────────────────────────────────
_REQUIRED_DEPS: list[tuple[str, str]] = [
    ("netmiko",      "SSH device connections"),
    ("paramiko",     "Jump-host SSH tunnelling"),
    ("rich",         "Console output & HTML reports"),
    ("yaml",         "YAML config parsing"),
    ("questionary",  "Interactive CLI wizard"),
    ("textual",      "Full-screen TUI"),
    ("keyring",      "OS credential store"),
    ("pydantic",     "Config validation"),
]

_OPTIONAL_DEPS: list[tuple[str, str]] = [
    ("genie",        "Structured Cisco parsers (Linux/WSL only)"),
    ("pyats",        "PyATS test framework (Linux/WSL only)"),
]


# ─── health check ────────────────────────────────────────────────────────────

def run_health_check(config_path: str = "assets/compliance_config") -> None:
    """Print a dependency + config health table and exit."""
    console.print()
    _print_env_info()
    _print_dependency_table()
    _print_config_health(config_path)
    console.print()


def _print_env_info() -> None:
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    plat = f"{platform.system()} {platform.release()} ({platform.machine()})"
    console.print(f"[bold cyan]Python:[/]   {py}")
    console.print(f"[bold cyan]Platform:[/] {plat}")
    console.print()


def _print_dependency_table() -> None:
    tbl = Table(title="Dependency Check", box=box.ROUNDED, show_lines=False,
                title_style="bold", expand=False, min_width=70)
    tbl.add_column("Package", style="cyan", min_width=18)
    tbl.add_column("Purpose", min_width=38)
    tbl.add_column("Status", justify="center", min_width=10)

    for pkg, purpose in _REQUIRED_DEPS:
        ok = _can_import(pkg)
        status = "[bold green]OK[/]" if ok else "[bold red]MISSING[/]"
        tbl.add_row(pkg, purpose, status)

    for pkg, purpose in _OPTIONAL_DEPS:
        ok = _can_import(pkg)
        status = "[bold green]OK[/]" if ok else "[dim]not installed[/]"
        tbl.add_row(f"{pkg} [dim](optional)[/]", purpose, status)

    console.print(tbl)


def _can_import(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False


def _print_config_health(config_path: str) -> None:
    try:
        from .auditor import load_compliance_config
        from .config_schema import validate_compliance_config
        cfg = load_compliance_config(config_path, validate=False)
        errors = validate_compliance_config(cfg)
    except SystemExit:
        console.print(f"\n[bold red]Config:[/] Failed to load '{config_path}'")
        return
    except Exception as exc:
        console.print(f"\n[bold red]Config error:[/] {exc}")
        return

    if errors:
        console.print(f"\n[bold red]Config validation failed ({len(errors)} error(s)):[/]")
        for err in errors:
            console.print(f"  {err}", style="red", markup=False, highlight=False)
    else:
        n_checks = _count_checks(cfg)
        console.print(
            f"\n[bold green]Config OK[/] — loaded '{config_path}' "
            f"({n_checks} checks defined)"
        )


def _count_checks(cfg: dict) -> int:
    compliance = cfg.get("compliance", {})
    total = 0
    for section in ("management_plane", "control_plane", "data_plane"):
        section_checks = compliance.get(section, {})
        if isinstance(section_checks, dict):
            total += len(section_checks)
    return total


# ─── dry-run preflight ───────────────────────────────────────────────────────

def run_dry_run(
    config_path: str,
    device_overrides: Optional[list[str]],
    skip_jump: bool,
    inventory_path: Optional[str] = None,
    site_filter: Optional[list[str]] = None,
    ip_filter: Optional[str] = None,
) -> None:
    """Run pre-flight checks without connecting to devices (no audit)."""
    console.print("\n[bold cyan]Pre-flight check[/] — validating config and reachability\n")

    # 1. Load + validate config
    try:
        from .auditor import load_compliance_config
        from .config_schema import validate_compliance_config
        cfg = load_compliance_config(config_path, validate=False)
    except SystemExit:
        console.print("[bold red]FAIL[/] Could not load config — aborting preflight.")
        sys.exit(2)

    errors = validate_compliance_config(cfg)
    if errors:
        console.print("[bold red]Config validation failed:[/]")
        for err in errors:
            console.print(f"  {err}", markup=False, highlight=False)
        sys.exit(2)
    console.print("[bold green]PASS[/] Config loaded and valid")

    # 2. Resolve devices
    try:
        devices = _resolve_preflight_devices(
            config_path, device_overrides, inventory_path, site_filter, ip_filter
        )
    except Exception as exc:
        console.print(f"[bold red]FAIL[/] Could not resolve device list: {exc}")
        sys.exit(2)
    console.print(f"[bold green]PASS[/] Device list resolved — {len(devices)} device(s)")

    # 3. Credential check
    _check_credentials(cfg)

    # 4. Jump host reachability
    conn = cfg.get("connection", {})
    use_jump = conn.get("use_jump_host", False) and not skip_jump
    if use_jump:
        jump_host = conn.get("jump_host", "")
        _tcp_row("Jump host", jump_host, 22)

    # 5. Device TCP reachability
    _print_device_reachability(devices)

    console.print("\n[bold cyan]Pre-flight complete[/] — run without --dry-run to start audit.\n")


def _resolve_preflight_devices(
    config_path: str,
    device_overrides: Optional[list[str]],
    inventory_path: Optional[str],
    site_filter: Optional[list[str]],
    ip_filter: Optional[str] = None,
) -> list[tuple[str, str]]:
    """Return list of (hostname, ip) tuples from config or CLI overrides."""
    if device_overrides:
        from .auditor import parse_device_overrides
        result = [(d["hostname"], d["ip"]) for d in parse_device_overrides(device_overrides)]
    else:
        from .auditor import load_device_inventory
        entries = load_device_inventory(inventory_path, config_path, site_filter)
        result = [(e.get("hostname", e.get("ip", "")), e["ip"]) for e in entries]

    if ip_filter:
        from .auditor import filter_devices_by_ip
        kept, unresolved = filter_devices_by_ip(
            [{"hostname": h, "ip": ip} for h, ip in result], ip_filter
        )
        for name in unresolved:
            console.print(f"[yellow]WARN[/] {name} did not resolve — excluded by --ip-filter")
        result = [(d["hostname"], d["ip"]) for d in kept]

    return result


def _check_credentials(cfg: dict) -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    user = os.environ.get("SWITCH_USER") or os.environ.get("CREDENTIAL_USER")
    if user:
        console.print(f"[bold green]PASS[/] Credentials found in environment (user: {user})")
        return

    conn = cfg.get("connection", {})
    if conn.get("credential_store") == "keyring":
        console.print("[dim]  Keyring store configured — credentials verified at runtime[/]")
        return

    console.print(
        "[bold yellow]![/] No credentials pre-configured — "
        "you will be prompted interactively. "
        "Tip: copy .env.example to .env and fill in credentials."
    )


def _print_device_reachability(devices: list[tuple[str, str]]) -> None:
    if not devices:
        return

    tbl = Table(title="Device Reachability (TCP :22)", box=box.ROUNDED,
                show_lines=False, expand=False, min_width=60)
    tbl.add_column("Hostname", style="cyan", min_width=25)
    tbl.add_column("IP", min_width=16)
    tbl.add_column("TCP :22", justify="center", min_width=12)

    for hostname, ip in devices:
        reachable = _tcp_check(ip, 22)
        status = "[bold green]OK[/]" if reachable else "[bold red]UNREACHABLE[/]"
        tbl.add_row(hostname, ip, status)

    console.print(tbl)


def _tcp_row(label: str, host: str, port: int) -> None:
    reachable = _tcp_check(host, port)
    if reachable:
        console.print(f"[bold green]OK[/]   {label} {host}:{port} reachable")
    else:
        console.print(f"[bold red]FAIL[/] {label} {host}:{port} unreachable")


def _tcp_check(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False
