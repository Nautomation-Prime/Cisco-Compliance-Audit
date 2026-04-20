"""
Remediation application module with progress tracking.

This module handles the application of remediation commands to devices
with real-time progress indicators to show users the current status.
"""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from netmiko.base_connection import BaseConnection
from netmiko.exceptions import NetmikoBaseException
from paramiko.ssh_exception import SSHException
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm

log = logging.getLogger(__name__)
console = Console()

REMEDIATION_ERRORS = (
    AttributeError,
    NetmikoBaseException,
    OSError,
    RuntimeError,
    SSHException,
    TimeoutError,
    TypeError,
    ValueError,
)
SCRIPT_PARSE_ERRORS = (OSError, UnicodeError, ValueError)
DISCONNECT_ERRORS = (
    AttributeError,
    NetmikoBaseException,
    OSError,
    RuntimeError,
    SSHException,
)


@dataclass
class RemediationResult:
    """Result of applying remediation to a device."""

    hostname: str
    ip: str
    success: bool
    commands_applied: int
    total_commands: int
    error_message: Optional[str] = None
    duration_secs: float = 0.0


def parse_remediation_script(script_path: Path) -> tuple[str, str, list[str]]:
    """
    Parse a remediation script file and extract hostname, IP, and commands.

    Args:
        script_path: Path to the remediation script file

    Returns:
        Tuple of (hostname, ip, commands_list)

    Raises:
        ValueError: If the script format is invalid
    """
    if not script_path.exists():
        raise ValueError(f"Remediation script not found: {script_path}")

    content = script_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    hostname = ""
    ip = ""
    commands = []
    in_config = False

    for line in lines:
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("!"):
            # Extract hostname and IP from header comment
            if "Remediation script for" in line:
                parts = line.split("(")
                if len(parts) >= 2:
                    hostname_part = (
                        parts[0]
                        .replace("!", "")
                        .replace("Remediation script for", "")
                        .strip()
                    )
                    ip_part = parts[1].replace(")", "").strip()
                    hostname = hostname_part
                    ip = ip_part
            continue

        # Track when we enter config mode
        if line == "configure terminal":
            in_config = True
            continue

        # Track when we exit config mode
        if line in ("end", "write memory"):
            in_config = False
            continue

        # Collect configuration commands
        if in_config:
            commands.append(line)

    if not hostname or not ip:
        raise ValueError(f"Could not parse hostname/IP from {script_path}")

    if not commands:
        raise ValueError(f"No configuration commands found in {script_path}")

    return hostname, ip, commands


def apply_remediation_to_device(
    connection: BaseConnection,
    commands: list[str],
    hostname: str,
    ip: str,
    progress: Progress,
    task_id: int,
) -> RemediationResult:
    """
    Apply remediation commands to a single device with progress tracking.

    Args:
        connection: Active Netmiko connection to the device
        commands: List of configuration commands to apply
        hostname: Device hostname for logging
        ip: Device IP address for logging
        progress: Rich Progress instance for tracking
        task_id: Progress task ID to update

    Returns:
        RemediationResult with success status and details
    """
    start_time = time.monotonic()
    result = RemediationResult(
        hostname=hostname,
        ip=ip,
        success=False,
        commands_applied=0,
        total_commands=len(commands),
    )

    try:
        # Update progress description
        progress.update(task_id, description=f"[cyan]Applying config to {hostname}")

        # Use send_config_set to apply all commands in one go
        # This is more robust than applying commands one by one
        log.debug("Applying %d commands to %s", len(commands), hostname)

        output = connection.send_config_set(
            config_commands=commands,
            cmd_verify=False,  # Don't verify each command individually (faster)
            read_timeout=60,
        )

        # Check output for common error patterns
        output_lower = output.lower()
        if any(
            err in output_lower
            for err in ["invalid", "error", "failed", "incomplete", "% "]
        ):
            # Log the potentially problematic output
            log.warning(
                "Possible errors in output from %s:\n%s",
                hostname,
                output,
            )
            progress.console.print(
                f"  [yellow]⚠[/] {hostname}: Check logs for potential errors"
            )

        result.commands_applied = len(commands)

        # Update progress for each command (visual feedback)
        progress.update(task_id, completed=len(commands))

        # Save configuration
        progress.update(task_id, description=f"[cyan]Saving config on {hostname}")
        save_output = connection.send_command(
            "write memory",
            expect_string=r"#",
            read_timeout=60,
        )
        log.debug("Save output on %s: %s", hostname, save_output)

        # Check if save was successful
        if "OK" not in save_output and "built" not in save_output.lower():
            log.warning("Unexpected save output on %s: %s", hostname, save_output)

        result.success = True
        result.duration_secs = round(time.monotonic() - start_time, 1)

    except REMEDIATION_ERRORS as exc:
        log.exception("Remediation failed on %s", hostname)
        result.error_message = str(exc)
        result.duration_secs = round(time.monotonic() - start_time, 1)

    return result


def apply_remediation_scripts(
    script_paths: list[Path],
    device_connector_factory,
) -> list[RemediationResult]:
    """
    Apply remediation scripts to multiple devices with progress indicators.

    Args:
        script_paths: List of paths to remediation script files
        device_connector_factory: Callable that creates DeviceConnector instances

    Returns:
        List of RemediationResult objects
    """
    if not script_paths:
        console.print("[yellow]No remediation scripts to apply[/]")
        return []

    # Parse all scripts first to validate
    console.print(f"\n[bold]Parsing {len(script_paths)} remediation script(s)...[/]")

    parsed_scripts = []
    for script_path in script_paths:
        try:
            hostname, ip, commands = parse_remediation_script(script_path)
            parsed_scripts.append((script_path, hostname, ip, commands))
            console.print(
                f"  [green]✓[/] {script_path.name}: "
                f"{len(commands)} commands for {hostname} ({ip})"
            )
        except SCRIPT_PARSE_ERRORS as exc:
            console.print(f"  [red]✗[/] {script_path.name}: {exc}")
            log.error("Failed to parse %s: %s", script_path, exc)

    if not parsed_scripts:
        console.print("[red]No valid remediation scripts found[/]")
        return []

    # Show summary and ask for confirmation
    total_commands = sum(len(cmds) for _, _, _, cmds in parsed_scripts)
    console.print(
        f"\n[bold]Ready to apply remediation:[/]\n"
        f"  • Devices: {len(parsed_scripts)}\n"
        f"  • Total commands: {total_commands}\n"
    )

    # Ask for confirmation
    if not Confirm.ask(
        "[bold red]Apply these changes to the devices?[/]",
        default=False,
    ):
        console.print("[yellow]Remediation cancelled by user[/]")
        return []

    # Apply remediation to each device
    results = []
    console.print(
        f"\n[bold]Applying remediation to {len(parsed_scripts)} device(s)...[/]"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for script_path, hostname, ip, commands in parsed_scripts:
            # Create a progress task for this device
            task_id = progress.add_task(
                f"[cyan]Connecting to {hostname}",
                total=len(commands),
            )

            connection = None
            try:
                # Create connection
                progress.update(task_id, description=f"[cyan]Connecting to {hostname}")
                connector = device_connector_factory(ip, hostname)
                connection = connector.connect()
                log.info("Connected to %s (%s)", hostname, ip)

                # Apply remediation
                result = apply_remediation_to_device(
                    connection=connection,
                    commands=commands,
                    hostname=hostname,
                    ip=ip,
                    progress=progress,
                    task_id=task_id,
                )
                results.append(result)

                # Display result
                if result.success:
                    progress.console.print(
                        f"  [green]✓[/] {hostname} ({ip}) — "
                        f"{result.commands_applied}/{result.total_commands} "
                        "commands applied "
                        f"({result.duration_secs}s)"
                    )
                else:
                    progress.console.print(
                        f"  [red]✗[/] {hostname} ({ip}) — "
                        f"{result.error_message or 'Unknown error'}"
                    )

            except REMEDIATION_ERRORS as exc:
                log.exception("Failed to apply remediation to %s", hostname)
                result = RemediationResult(
                    hostname=hostname,
                    ip=ip,
                    success=False,
                    commands_applied=0,
                    total_commands=len(commands),
                    error_message=f"Connection or setup failed: {exc}",
                )
                results.append(result)
                progress.console.print(
                    f"  [red]✗[/] {hostname} ({ip}) — Connection failed: {exc}"
                )

            finally:
                # Clean up connection
                if connection:
                    try:
                        connection.disconnect()
                        log.debug("Disconnected from %s", hostname)
                    except DISCONNECT_ERRORS:
                        pass

                # Mark task as complete
                progress.update(task_id, completed=len(commands))

    # Display final summary
    console.print("\n[bold]Remediation Summary:[/]")
    success_count = sum(1 for r in results if r.success)
    fail_count = len(results) - success_count

    console.print(f"  • Successful: [green]{success_count}[/]")
    console.print(f"  • Failed: [red]{fail_count}[/]")

    return results
