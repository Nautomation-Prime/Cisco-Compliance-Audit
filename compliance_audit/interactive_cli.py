"""Guided interactive CLI experience."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from .auditor import load_compliance_config, run_audit
from .cli_discovery import print_options_table
from .remediation_cli import (
    limit_review_entries,
    print_remediation_list_hints,
    print_review_entries_table,
    review_entries_as_csv,
    review_entries_as_json,
    sort_review_entries,
)
from .remediation_workflow import (
    apply_all_approved_packs,
    apply_approved_pack,
    approve_review_pack,
    get_remediation_settings,
    list_review_packs,
    reject_review_pack,
)

console = Console()


@dataclass
class AuditWizardConfig:
    config_path: str
    inventory_path: Optional[str]
    devices: list[str]
    skip_jump: bool
    categories: Optional[list[str]]
    output_dir: Optional[str]
    dry_run_dir: Optional[str]
    csv_report: Optional[bool]
    verbose: int
    fail_threshold: Optional[float]


def _load_questionary():
    try:
        import questionary
    except ImportError as exc:
        raise RuntimeError(
            "Interactive mode requires 'questionary'. Install dependencies from requirements.txt."
        ) from exc
    return questionary


def _quote(value: str) -> str:
    """Quote a value for shell display if it contains spaces."""
    return f'"{value}"' if " " in value else value


def _build_audit_preview(cfg: AuditWizardConfig) -> str:
    cmd = ["python", "-m", "compliance_audit"]
    if cfg.config_path != "compliance_config.yaml":
        cmd.extend(["--config", _quote(cfg.config_path)])
    if cfg.inventory_path:
        cmd.extend(["--inventory", _quote(cfg.inventory_path)])
    for dev in cfg.devices:
        cmd.extend(["--device", _quote(dev)])
    if cfg.skip_jump:
        cmd.append("--no-jump")
    if cfg.categories:
        cmd.append("--categories")
        cmd.extend(cfg.categories)
    if cfg.output_dir:
        cmd.extend(["--output-dir", _quote(cfg.output_dir)])
    if cfg.dry_run_dir:
        cmd.extend(["--dry-run", _quote(cfg.dry_run_dir)])
    if cfg.csv_report is True:
        cmd.append("--csv")
    if cfg.csv_report is False:
        cmd.append("--no-csv")
    if cfg.fail_threshold is not None:
        cmd.extend(["--fail-threshold", str(cfg.fail_threshold)])
    if cfg.verbose > 0:
        cmd.append("-" + ("v" * cfg.verbose))
    return " ".join(cmd)


def _configure_logging(verbose: int) -> None:
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _collect_devices(questionary) -> list[str]:
    devices: list[str] = []
    while True:
        value = questionary.text(
            "Add a device (IP or hostname:IP). Leave blank to continue:", default=""
        ).ask()
        if value is None:
            return devices
        value = value.strip()
        if not value:
            return devices
        devices.append(value)


def _run_audit_wizard(questionary) -> None:
    config_path = (
        questionary.text(
            "Compliance config path:", default="compliance_config.yaml"
        ).ask()
        or "compliance_config.yaml"
    ).strip()
    inventory_path_raw = questionary.text(
        "Inventory path (blank keeps default behavior):", default=""
    ).ask()
    inventory_path = (inventory_path_raw or "").strip() or None

    categories = questionary.checkbox(
        "Optional category filter:",
        choices=["management_plane", "control_plane", "data_plane", "role_specific"],
    ).ask()
    if categories == []:
        categories = None

    devices = _collect_devices(questionary)
    skip_jump = bool(questionary.confirm("Skip jump host?", default=False).ask())

    output_dir_raw = questionary.text(
        "Output directory override (blank = config default):", default=""
    ).ask()
    output_dir = (output_dir_raw or "").strip() or None

    dry_run_raw = questionary.text(
        "Dry-run input directory (blank = live SSH):", default=""
    ).ask()
    dry_run_dir = (dry_run_raw or "").strip() or None

    csv_mode = questionary.select(
        "CSV report mode:",
        choices=[
            "Auto (from YAML config)",
            "Force enable CSV (--csv)",
            "Force disable CSV (--no-csv)",
        ],
    ).ask()
    csv_report: Optional[bool]
    if csv_mode == "Force enable CSV (--csv)":
        csv_report = True
    elif csv_mode == "Force disable CSV (--no-csv)":
        csv_report = False
    else:
        csv_report = None

    verbose_label = questionary.select(
        "Verbosity:", choices=["Normal", "Verbose (-v)", "Debug (-vv)"]
    ).ask()
    verbose = {"Normal": 0, "Verbose (-v)": 1, "Debug (-vv)": 2}.get(verbose_label, 0)

    threshold_raw = questionary.text(
        "Fail threshold percent (0-100, blank disables):", default=""
    ).ask()
    fail_threshold: Optional[float] = None
    if threshold_raw and threshold_raw.strip():
        fail_threshold = float(threshold_raw.strip())

    wizard_cfg = AuditWizardConfig(
        config_path=config_path,
        inventory_path=inventory_path,
        devices=devices,
        skip_jump=skip_jump,
        categories=categories,
        output_dir=output_dir,
        dry_run_dir=dry_run_dir,
        csv_report=csv_report,
        verbose=verbose,
        fail_threshold=fail_threshold,
    )

    console.print(
        Panel.fit(
            "Equivalent CLI command\n" + _build_audit_preview(wizard_cfg),
            title="Audit Preview",
            border_style="cyan",
        )
    )

    if not questionary.confirm("Run this audit now?", default=True).ask():
        console.print("Cancelled.")
        return

    _configure_logging(verbose)
    results = run_audit(
        config_path=wizard_cfg.config_path,
        device_overrides=wizard_cfg.devices or None,
        skip_jump=wizard_cfg.skip_jump,
        categories=wizard_cfg.categories,
        output_dir=wizard_cfg.output_dir,
        dry_run_dir=wizard_cfg.dry_run_dir,
        csv_report=wizard_cfg.csv_report,
        inventory_path=wizard_cfg.inventory_path,
    )

    if wizard_cfg.fail_threshold is not None and any(
        r.score_pct < wizard_cfg.fail_threshold for r in results
    ):
        console.print(
            f"Completed with threshold violations below {wizard_cfg.fail_threshold:.1f}%."
        )
    elif any(r.fail_count > 0 for r in results):
        console.print("Completed with compliance failures.")
    else:
        console.print("Completed successfully with no compliance failures.")


def _resolve_remediation_context(
    config_path: str, output_dir_override: Optional[str]
) -> tuple[dict, str]:
    cfg = load_compliance_config(config_path)
    audit_settings = cfg.get("audit_settings", {})
    output_dir = output_dir_override or audit_settings.get("output_dir", "./reports")
    return audit_settings, output_dir


def _run_remediation_wizard(questionary) -> None:
    config_path = (
        questionary.text(
            "Compliance config path:", default="compliance_config.yaml"
        ).ask()
        or "compliance_config.yaml"
    ).strip()
    output_dir_raw = questionary.text(
        "Output directory override (blank = config default):", default=""
    ).ask()
    output_dir_override = (output_dir_raw or "").strip() or None

    audit_settings, output_dir = _resolve_remediation_context(
        config_path, output_dir_override
    )
    rem = get_remediation_settings(audit_settings)
    if not rem.get("enabled", True):
        raise RuntimeError(
            "Remediation workflow is disabled in config (audit_settings.remediation.enabled=false)."
        )

    action = questionary.select(
        "Remediation action:",
        choices=[
            "List review packs",
            "Approve one pack",
            "Reject one pack",
            "Apply one approved pack",
            "Approve all pending packs",
            "Apply all approved packs",
        ],
    ).ask()

    if action is None:
        console.print("Cancelled.")
        return

    if action == "List review packs":
        status_choice = questionary.select(
            "Status filter:",
            choices=[
                "all",
                "pending",
                "approved",
                "rejected",
                "applied",
                "failed",
                "expired",
            ],
        ).ask()
        output_choice = questionary.select(
            "Output format:", choices=["table", "json", "csv"]
        ).ask()
        sort_choice = questionary.select(
            "Sort by:", choices=["created", "risk", "status", "hostname", "findings"]
        ).ask()
        limit_raw = questionary.text(
            "Limit results (blank = no limit):", default=""
        ).ask()
        limit: Optional[int] = (
            int(limit_raw) if (limit_raw and limit_raw.strip()) else None
        )

        rows = list_review_packs(
            output_dir, status=None if status_choice == "all" else status_choice
        )
        if not rows:
            console.print("No remediation review packs found.")
            return

        sorted_rows = sort_review_entries(rows, sort_by=sort_choice)
        shown_rows = limit_review_entries(sorted_rows, limit)

        if output_choice == "json":
            print(review_entries_as_json(shown_rows))
            return
        if output_choice == "csv":
            print(review_entries_as_csv(shown_rows))
            return

        print_review_entries_table(
            shown_rows,
            title="Remediation Review Packs",
            show_created=True,
            console=console,
        )
        print_remediation_list_hints(
            status_filter=None if status_choice == "all" else status_choice,
            shown=len(shown_rows),
            total=len(rows),
            output_format=output_choice,
            console=console,
        )
        return

    if action == "Approve one pack":
        pack_id = (questionary.text("Pack ID to approve:").ask() or "").strip()
        if not pack_id:
            console.print("Cancelled — no pack ID provided.")
            return
        approver = (questionary.text("Approver name:").ask() or "").strip()
        ticket_id = (questionary.text("Ticket ID:").ask() or "").strip()
        expires_raw = questionary.text(
            "Approval expiry hours (blank uses config):", default=""
        ).ask()
        expires_hours = (
            int(expires_raw)
            if (expires_raw and expires_raw.strip())
            else int(rem.get("approval_default_expires_hours", 24))
        )
        path = approve_review_pack(
            output_dir=output_dir,
            pack_id=pack_id,
            approver=approver,
            ticket_id=ticket_id,
            expires_hours=expires_hours,
            require_ticket_id=rem.get("approval_require_ticket_id", True),
        )
        console.print(f"Approved review pack: {path}")
        return

    if action == "Reject one pack":
        pack_id = (questionary.text("Pack ID to reject:").ask() or "").strip()
        if not pack_id:
            console.print("Cancelled — no pack ID provided.")
            return
        approver = (questionary.text("Approver name:").ask() or "").strip()
        reason = (questionary.text("Reject reason:").ask() or "").strip()
        path = reject_review_pack(
            output_dir=output_dir,
            pack_id=pack_id,
            approver=approver,
            reason=reason,
        )
        console.print(f"Rejected review pack: {path}")
        return

    if action == "Apply one approved pack":
        if not rem.get("execution_enabled", True):
            raise RuntimeError(
                "Remediation execution is disabled in config (audit_settings.remediation.execution.enabled=false)."
            )
        pack_id = (questionary.text("Pack ID to apply:").ask() or "").strip()
        if not pack_id:
            console.print("Cancelled — no pack ID provided.")
            return
        skip_jump = bool(questionary.confirm("Skip jump host?", default=False).ask())
        dry_run = bool(questionary.confirm("Apply dry-run mode?", default=False).ask())
        allow_high_risk = bool(
            questionary.confirm("Allow high-risk remediation?", default=False).ask()
        )
        summary = apply_approved_pack(
            config_path=config_path,
            output_dir=output_dir,
            pack_id=pack_id,
            skip_jump=skip_jump,
            dry_run=dry_run,
            allow_high_risk=(
                allow_high_risk or not rem.get("execution_block_high_risk", True)
            ),
            remediation_settings=rem,
        )
        print(json.dumps(summary, indent=2))
        return

    if action == "Approve all pending packs":
        approver = (questionary.text("Approver name:").ask() or "").strip()
        ticket_id = (questionary.text("Ticket ID:").ask() or "").strip()
        expires_raw = questionary.text(
            "Approval expiry hours (blank uses config):", default=""
        ).ask()
        expires_hours = (
            int(expires_raw)
            if (expires_raw and expires_raw.strip())
            else int(rem.get("approval_default_expires_hours", 24))
        )

        rows = list_review_packs(output_dir, status="pending")
        if not rows:
            console.print("No pending remediation review packs found.")
            return

        print_review_entries_table(
            rows,
            title=f"Pending remediation pack(s): {len(rows)}",
            show_created=False,
            console=console,
        )
        if not questionary.confirm(
            f"Approve all {len(rows)} pack(s)?", default=False
        ).ask():
            console.print("Cancelled.")
            return

        approved_count = 0
        failed_count = 0
        for row in rows:
            try:
                approve_review_pack(
                    output_dir=output_dir,
                    pack_id=row.pack_id,
                    approver=approver,
                    ticket_id=ticket_id,
                    expires_hours=expires_hours,
                    require_ticket_id=rem.get("approval_require_ticket_id", True),
                )
                console.print(f"\u2713 Approved: {row.pack_id} ({row.hostname})")
                approved_count += 1
            except RuntimeError as exc:
                console.print(
                    f"Failed to approve {row.pack_id} ({row.hostname}): {exc}"
                )
                failed_count += 1

        console.print(
            f"Bulk approval complete: {approved_count} approved, {failed_count} failed"
        )
        return

    if action == "Apply all approved packs":
        if not rem.get("execution_enabled", True):
            raise RuntimeError(
                "Remediation execution is disabled in config (audit_settings.remediation.execution.enabled=false)."
            )
        skip_jump = bool(questionary.confirm("Skip jump host?", default=False).ask())
        dry_run = bool(questionary.confirm("Apply dry-run mode?", default=False).ask())
        allow_high_risk = bool(
            questionary.confirm("Allow high-risk remediation?", default=False).ask()
        )
        summaries = apply_all_approved_packs(
            config_path=config_path,
            output_dir=output_dir,
            skip_jump=skip_jump,
            dry_run=dry_run,
            allow_high_risk=(
                allow_high_risk or not rem.get("execution_block_high_risk", True)
            ),
            remediation_settings=rem,
        )
        print(json.dumps(summaries, indent=2))


def launch_interactive(parser: argparse.ArgumentParser) -> None:
    """Start the guided interactive CLI shell."""
    questionary = _load_questionary()

    console.print(
        Panel.fit(
            "Premium Interactive CLI\nChoose workflows, preview commands, and run without memorizing flags.",
            title="Cisco Compliance Audit",
            border_style="green",
        )
    )

    while True:
        choice = questionary.select(
            "Main menu:",
            choices=[
                "Run compliance audit wizard",
                "Run remediation workflow wizard",
                "Show all CLI options",
                "Exit",
            ],
        ).ask()

        if choice in (None, "Exit"):
            console.print("Goodbye.")
            return

        try:
            if choice == "Run compliance audit wizard":
                _run_audit_wizard(questionary)
            elif choice == "Run remediation workflow wizard":
                _run_remediation_wizard(questionary)
            elif choice == "Show all CLI options":
                print_options_table(parser, console=console)
        except (RuntimeError, ValueError) as exc:
            console.print(f"Error: {exc}")

        if not questionary.confirm("Return to main menu?", default=True).ask():
            console.print("Goodbye.")
            return
