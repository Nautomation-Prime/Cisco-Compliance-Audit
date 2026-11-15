"""
Entry point for  python -m compliance_audit

Usage examples
--------------
    python -m compliance_audit
    python -m compliance_audit --config custom.yaml
    python -m compliance_audit --device 192.0.2.61
    python -m compliance_audit --device ZZ-LAB1-005ASW001:192.0.2.61
    python -m compliance_audit --no-jump
    python -m compliance_audit --categories management_plane control_plane
    python -m compliance_audit --remediation-list
    python -m compliance_audit --remediation-apply-all
    python -m compliance_audit --remediation-apply-all
    python -m compliance_audit --interactive
    python -m compliance_audit --tui
    python -m compliance_audit --list-options

Scheduled audits
----------------
    python -m compliance_audit --non-interactive --notify      # nightly timer
    python -m compliance_audit --run-show RUN_ID
    python -m compliance_audit --run-approve RUN_ID --approver NAME --ticket-id ID --apply-now
    python -m compliance_audit --run-approve RUN_ID --approver NAME --ticket-id ID --apply-at "2026-11-07 02:00"
    python -m compliance_audit --run-reject RUN_ID --approver NAME --reason TEXT
    python -m compliance_audit --remediation-apply-due --non-interactive   # every few minutes
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from rich.console import Console

from .auditor import load_compliance_config, read_compliance_config, run_audit
from .credentials import interactive_allowed, set_interactive
from .inventory_schema import InventoryError
from .cli_discovery import print_options_table
from .interactive_cli import launch_interactive
from .preflight import run_dry_run, run_health_check
from .remediation_cli import (
    limit_review_entries,
    print_remediation_list_hints,
    print_review_entries_table,
    review_entries_as_csv,
    review_entries_as_json,
    sort_review_entries,
)
from .remediation_workflow import (
    PACK_STATUSES,
    apply_all_approved_packs,
    apply_approved_pack,
    apply_due_packs,
    apply_packs,
    approve_review_pack,
    format_schedule,
    get_review_pack,
    get_remediation_settings,
    get_review_db_path,
    list_review_packs,
    reject_review_pack,
)
from .run_cli import print_decision, print_run_detail, print_runs_table, run_status_as_dict
from .runs import (
    LockHeld,
    RunStatus,
    approve_run,
    exclusive_lock,
    list_manifests,
    load_manifest,
    parse_schedule_time,
    reject_run,
    run_status,
    write_manifest,
)
from .logging_setup import configure_logging
from .textual_app import launch_textual
from .version import get_version_info

console = Console()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m compliance_audit",
        description="Cisco IOS-XE Compliance Auditor",
    )
    p.add_argument(
        "--version",
        action="version",
        version=get_version_info(),
    )
    p.add_argument(
        "-c",
        "--config",
        default="assets/compliance_config",
        help="Path to the compliance config directory (default: assets/compliance_config/)",
    )
    p.add_argument(
        "-d",
        "--device",
        action="append",
        dest="devices",
        help="Device to audit (IP or hostname:IP). Can be repeated.",
    )
    p.add_argument(
        "--no-jump",
        action="store_true",
        help="Connect directly to devices without jump host.",
    )
    p.add_argument(
        "--categories",
        nargs="+",
        help="Only run checks in these categories "
        "(e.g. management_plane control_plane data_plane).",
    )
    p.add_argument(
        "--tags",
        nargs="+",
        metavar="TAG",
        default=None,
        help=(
            "Only surface findings whose tags include at least one of these values "
            "(e.g. --tags pci cis).  Non-matching findings are reported as SKIP."
        ),
    )
    p.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        metavar="LEVEL",
        help=(
            "Hide findings below this severity level "
            "(critical > high > medium > low > info).  "
            "Lower-severity findings are reported as SKIP."
        ),
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v INFO, -vv DEBUG).",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Override the report output directory (default: from YAML config).",
    )
    p.add_argument(
        "--fail-threshold",
        type=float,
        default=None,
        metavar="PCT",
        help="Exit with code 1 if any device scores below this percentage (e.g. 80).",
    )
    p.add_argument(
        "-i",
        "--inventory",
        default=None,
        help=(
            "Path to the device inventory YAML (default: assets/devices/devices.yaml next to config)."
        ),
    )
    p.add_argument(
        "--site",
        nargs="+",
        metavar="SITE",
        default=None,
        help=(
            "Only audit devices belonging to these site group(s) from the inventory "
            "(e.g. --site site_lab or --site site_lab site_brn).  "
            "Group names are matched case-insensitively against the 'groups:' keys "
            "in assets/devices/devices.yaml."
        ),
    )
    p.add_argument(
        "--ip-filter",
        default=None,
        metavar="RANGE",
        help=(
            "Restrict discovery to devices whose IP address falls within the given range.  "
            "Accepts CIDR notation (e.g. 192.168.0.0/24) or a hyphen-separated range "
            "(e.g. 192.168.0.1-192.168.0.254)."
        ),
    )
    p.add_argument(
        "--csv",
        action="store_true",
        default=None,
        dest="csv_report",
        help="Generate a CSV report (overrides config file).",
    )
    p.add_argument(
        "--no-csv",
        action="store_false",
        dest="csv_report",
        help="Disable CSV report generation (overrides config file).",
    )

    # Remediation lifecycle operations
    p.add_argument(
        "--remediation-list",
        nargs="?",
        const="all",
        default=None,
        metavar="STATUS",
        choices=["all", *PACK_STATUSES],
        help="List remediation review packs (optionally filtered by status).",
    )
    p.add_argument(
        "--remediation-output",
        choices=["table", "json", "csv"],
        default="table",
        help=(
            "Output format for remediation operations "
            "(list supports table/json/csv; non-list supports table/json)."
        ),
    )
    p.add_argument(
        "--remediation-sort",
        choices=["created", "risk", "status", "hostname", "findings"],
        default="created",
        help="Sort order for --remediation-list (default: created).",
    )
    p.add_argument(
        "--remediation-limit",
        type=int,
        default=None,
        metavar="N",
        help="Show only the first N entries for --remediation-list after sorting.",
    )
    p.add_argument(
        "--remediation-approve",
        metavar="PACK_ID",
        default=None,
        help="Approve a remediation review pack.",
    )
    p.add_argument(
        "--remediation-approve-all",
        action="store_true",
        help=(
            "Approve all pending remediation review packs "
            "(requires --approver and --ticket-id)."
        ),
    )
    p.add_argument(
        "--remediation-reject",
        metavar="PACK_ID",
        default=None,
        help="Reject a remediation review pack.",
    )
    p.add_argument(
        "--remediation-apply",
        metavar="PACK_ID",
        default=None,
        help="Apply an approved remediation review pack.",
    )
    p.add_argument(
        "--approver",
        default="",
        help="Approver/operator name for approve/reject operations.",
    )
    p.add_argument(
        "--ticket-id",
        default="",
        help="Change ticket ID required when approving.",
    )
    p.add_argument(
        "--reason",
        default="",
        help="Reason required when rejecting.",
    )
    p.add_argument(
        "--expires-hours",
        type=int,
        default=None,
        help="Approval expiry in hours (default: from config, fallback 24).",
    )
    p.add_argument(
        "--allow-high-risk",
        action="store_true",
        help="Allow applying approved packs containing high-risk commands.",
    )
    p.add_argument(
        "--remediation-no-confirm",
        action="store_true",
        help="Skip interactive confirmation prompts for bulk remediation operations.",
    )

    p.add_argument(
        "--remediation-apply-all",
        action="store_true",
        help=(
            "Apply all currently approved remediation packs in sequence "
            "(packs scheduled for later are left for --remediation-apply-due)."
        ),
    )
    p.add_argument(
        "--remediation-apply-due",
        action="store_true",
        help=(
            "Apply approved packs whose scheduled time has arrived. Run it from a "
            "frequent timer, e.g. every 5 minutes."
        ),
    )

    sched = p.add_argument_group("scheduled audits and run approval")
    sched.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Never prompt: fail with a clear error if credentials are missing or a "
            "confirmation would be needed. Use for cron/systemd jobs."
        ),
    )
    sched.add_argument(
        "--notify",
        action="store_true",
        help="Email the run summary after the audit (notifications.yaml).",
    )
    sched.add_argument(
        "--notify-test",
        action="store_true",
        help="Send a test email using notifications.yaml, then exit.",
    )
    sched.add_argument(
        "--run-list",
        action="store_true",
        help="List recent audit runs with their remediation state (newest first).",
    )
    sched.add_argument(
        "--run-show",
        metavar="RUN_ID",
        default=None,
        help="Show one run: devices, scores, packs, unreachable devices.",
    )
    sched.add_argument(
        "--run-approve",
        metavar="RUN_ID",
        default=None,
        help=(
            "Approve every pending pack from a run (needs --approver; --ticket-id if "
            "required). Add --apply-now or --apply-at TIME to schedule the change."
        ),
    )
    sched.add_argument(
        "--run-reject",
        metavar="RUN_ID",
        default=None,
        help="Reject every pending or approved pack from a run (needs --approver and --reason).",
    )
    sched.add_argument(
        "--run-notify",
        metavar="RUN_ID",
        default=None,
        help="Re-send the run email for a run.",
    )
    when = sched.add_mutually_exclusive_group()
    when.add_argument(
        "--apply-now",
        action="store_true",
        help="With --run-approve: apply the approved packs immediately.",
    )
    when.add_argument(
        "--apply-at",
        metavar="TIME",
        default=None,
        help=(
            "With --run-approve: apply at this time — 'YYYY-MM-DD HH:MM' or 'HH:MM' "
            "(host local time) or ISO-8601 with an offset. Applied by --remediation-apply-due."
        ),
    )
    p.add_argument(
        "--interactive",
        action="store_true",
        help="Launch guided interactive CLI wizard mode.",
    )
    p.add_argument(
        "--tui",
        action="store_true",
        help="Launch full-screen Textual terminal application.",
    )
    p.add_argument(
        "--list-options",
        action="store_true",
        help="Print all available CLI options in a table and exit.",
    )
    p.add_argument(
        "--health",
        action="store_true",
        help="Check dependencies and config validity, then exit.",
    )
    p.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate all YAML config files and report errors, then exit.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config, resolve credentials, and test TCP reachability without auditing.",
    )
    p.add_argument(
        "--framework",
        nargs="+",
        metavar="NAME",
        default=None,
        help=(
            "Only surface findings that have a framework_controls entry matching one of "
            "these names (e.g. --framework cis pci).  "
            "Use --framework cis to see only CIS-mapped checks."
        ),
    )
    return p


def _handle_remediation_mode(args: argparse.Namespace) -> bool:
    """Handle remediation lifecycle CLI modes; return True if a mode was executed."""
    cfg = load_compliance_config(args.config)
    audit_settings = cfg.get("audit_settings", {})
    rem = get_remediation_settings(audit_settings)
    out_dir = str(
        Path(args.output_dir or audit_settings.get("output_dir", "./reports"))
        .expanduser()
        .resolve()
    )

    def _print_json(payload: dict | list[dict]) -> None:
        print(json.dumps(payload, indent=2))

    def _csv_output_guard() -> None:
        if args.remediation_output == "csv":
            raise RuntimeError(
                "--remediation-output csv is only supported with --remediation-list"
            )

    remediation_mode_requested = any(
        [
            args.remediation_list is not None,
            bool(args.remediation_approve),
            bool(args.remediation_approve_all),
            bool(args.remediation_reject),
            bool(args.remediation_apply),
            bool(args.remediation_apply_all),
        ]
    )
    if remediation_mode_requested and not rem.get("enabled", True):
        raise RuntimeError(
            "Remediation workflow is disabled in config "
            "(audit_settings.remediation.enabled=false)."
        )

    if args.remediation_list is not None:
        if args.remediation_limit is not None and args.remediation_limit <= 0:
            raise RuntimeError("--remediation-limit must be greater than 0")

        status = None if args.remediation_list == "all" else args.remediation_list
        rows = list_review_packs(out_dir, status=status)
        if not rows:
            if args.remediation_output == "json":
                print("[]")
            else:
                print(
                    "No remediation review packs found in "
                    f"{get_review_db_path(out_dir)}"
                )
            return True

        sorted_rows = sort_review_entries(rows, sort_by=args.remediation_sort)
        shown_rows = limit_review_entries(sorted_rows, args.remediation_limit)

        if args.remediation_output == "json":
            print(review_entries_as_json(shown_rows))
            return True

        if args.remediation_output == "csv":
            print(review_entries_as_csv(shown_rows))
            return True

        print_review_entries_table(
            shown_rows,
            title="Remediation Review Packs",
            show_created=True,
            console=console,
        )
        print_remediation_list_hints(
            status_filter=status,
            shown=len(shown_rows),
            total=len(rows),
            output_format=args.remediation_output,
            console=console,
        )
        return True

    if args.remediation_approve:
        _csv_output_guard()
        if not args.approver:
            raise RuntimeError("--approver is required for --remediation-approve")
        if rem.get("approval_require_ticket_id", True) and not args.ticket_id:
            raise RuntimeError("--ticket-id is required for --remediation-approve")
        expires_hours = args.expires_hours
        if expires_hours is None:
            expires_hours = rem.get("approval_default_expires_hours", 24)
        path = approve_review_pack(
            output_dir=out_dir,
            pack_id=args.remediation_approve,
            approver=args.approver,
            ticket_id=args.ticket_id,
            expires_hours=expires_hours,
            require_ticket_id=rem.get("approval_require_ticket_id", True),
        )
        if args.remediation_output == "json":
            pack = get_review_pack(out_dir, args.remediation_approve)
            _print_json(
                {
                    "operation": "approve_review_pack",
                    "pack_id": args.remediation_approve,
                    "status": pack["lifecycle"]["status"],
                    "pack_path": str(path),
                    "approved_by": pack["approval"].get("approved_by", ""),
                    "approved_at": pack["approval"].get("approved_at", ""),
                    "ticket_id": pack["approval"].get("ticket_id", ""),
                    "expires_at": pack["approval"].get("expires_at", ""),
                }
            )
        else:
            print(f"Approved review pack: {path}")
        return True

    if args.remediation_approve_all:
        _csv_output_guard()
        if not args.approver:
            raise RuntimeError("--approver is required for --remediation-approve-all")
        if rem.get("approval_require_ticket_id", True) and not args.ticket_id:
            raise RuntimeError("--ticket-id is required for --remediation-approve-all")
        expires_hours = args.expires_hours
        if expires_hours is None:
            expires_hours = rem.get("approval_default_expires_hours", 24)

        # Get all pending packs
        rows = list_review_packs(out_dir, status="pending")
        if not rows:
            if args.remediation_output == "json":
                _print_json(
                    {
                        "operation": "approve_all_review_packs",
                        "approved": 0,
                        "failed": 0,
                        "results": [],
                    }
                )
            else:
                print("No pending remediation review packs found.")
            return True

        if args.remediation_output == "table":
            print_review_entries_table(
                rows,
                title=f"Pending remediation pack(s): {len(rows)}",
                show_created=False,
                console=console,
            )

        needs_confirm = (
            args.remediation_output == "table" and not args.remediation_no_confirm
        )
        if needs_confirm and not interactive_allowed():
            raise RuntimeError(
                "Confirmation needed but this run is non-interactive; "
                "add --remediation-no-confirm."
            )
        if needs_confirm:
            from rich.prompt import Confirm

            if not Confirm.ask(f"\n[yellow]Approve all {len(rows)} pack(s)?[/]"):
                print("Cancelled.")
                return True

        # Approve each pack
        approved_count = 0
        failed_count = 0
        results: list[dict] = []
        for row in rows:
            try:
                path = approve_review_pack(
                    output_dir=out_dir,
                    pack_id=row.pack_id,
                    approver=args.approver,
                    ticket_id=args.ticket_id,
                    expires_hours=expires_hours,
                    require_ticket_id=rem.get("approval_require_ticket_id", True),
                )
                if args.remediation_output == "table":
                    print(f"✓ Approved: {row.pack_id} ({row.hostname})")
                approved_count += 1
                results.append(
                    {
                        "pack_id": row.pack_id,
                        "hostname": row.hostname,
                        "status": "approved",
                        "pack_path": str(path),
                    }
                )
            except RuntimeError as exc:
                if args.remediation_output == "table":
                    print(f"✗ Failed to approve {row.pack_id} ({row.hostname}): {exc}")
                failed_count += 1
                results.append(
                    {
                        "pack_id": row.pack_id,
                        "hostname": row.hostname,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        if args.remediation_output == "json":
            _print_json(
                {
                    "operation": "approve_all_review_packs",
                    "approved": approved_count,
                    "failed": failed_count,
                    "results": results,
                }
            )
        else:
            print(
                "\nBulk approval complete: "
                f"{approved_count} approved, {failed_count} failed"
            )
        return True

    if args.remediation_reject:
        _csv_output_guard()
        if not args.approver:
            raise RuntimeError("--approver is required for --remediation-reject")
        if not args.reason:
            raise RuntimeError("--reason is required for --remediation-reject")
        path = reject_review_pack(
            output_dir=out_dir,
            pack_id=args.remediation_reject,
            approver=args.approver,
            reason=args.reason,
        )
        if args.remediation_output == "json":
            pack = get_review_pack(out_dir, args.remediation_reject)
            _print_json(
                {
                    "operation": "reject_review_pack",
                    "pack_id": args.remediation_reject,
                    "status": pack["lifecycle"]["status"],
                    "pack_path": str(path),
                    "rejected_by": pack["approval"].get("rejected_by", ""),
                    "rejected_at": pack["approval"].get("rejected_at", ""),
                    "reject_reason": pack["approval"].get("reject_reason", ""),
                }
            )
        else:
            print(f"Rejected review pack: {path}")
        return True

    if args.remediation_apply:
        _csv_output_guard()
        if not rem.get("execution_enabled", False):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false)."
            )
        with exclusive_lock(out_dir, "apply"):
            summary = apply_approved_pack(
                config_path=args.config,
                output_dir=out_dir,
                pack_id=args.remediation_apply,
                skip_jump=args.no_jump,
                allow_high_risk=(
                    args.allow_high_risk or not rem.get("execution_block_high_risk", True)
                ),
                remediation_settings=rem,
            )
        if args.remediation_output == "json":
            _print_json(summary)
        else:
            print(
                "Remediation apply result: "
                f"{summary.get('status')} for {summary.get('pack_id')}"
            )
        return True

    if args.remediation_apply_all:
        _csv_output_guard()
        if not rem.get("execution_enabled", False):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false)."
            )
        if not rem.get("execution_allow_bulk_apply", True):
            raise RuntimeError(
                "Bulk remediation apply is disabled in config "
                "(audit_settings.remediation.execution.allow_bulk_apply=false)."
            )
        with exclusive_lock(out_dir, "apply"):
            summaries = apply_all_approved_packs(
                config_path=args.config,
                output_dir=out_dir,
                skip_jump=args.no_jump,
                allow_high_risk=(
                    args.allow_high_risk or not rem.get("execution_block_high_risk", True)
                ),
                remediation_settings=rem,
            )
        if args.remediation_output == "json":
            succeeded = sum(
                1 for item in summaries if item.get("status") in {"success", "dry-run"}
            )
            _print_json(
                {
                    "operation": "apply_all_approved_packs",
                    "count": len(summaries),
                    "succeeded": succeeded,
                    "failed": len(summaries) - succeeded,
                    "results": summaries,
                }
            )
        else:
            print(f"Applied {len(summaries)} approved remediation pack(s).")
        return True

    return False


def _resolve_out_dir(args: argparse.Namespace, audit_settings: dict) -> str:
    return str(
        Path(args.output_dir or audit_settings.get("output_dir", "./reports"))
        .expanduser()
        .resolve()
    )


def _tool_command(args: argparse.Namespace, out_dir: str) -> str:
    """How to re-invoke the tool against the same config and output directory."""
    import shlex

    return (
        f"{shlex.quote(sys.executable)} -m compliance_audit "
        f"-c {shlex.quote(str(args.config))} -o {shlex.quote(out_dir)}"
    )


def _exit_if_failed(summaries: list[dict]) -> None:
    if any(s.get("status") not in {"success", "dry-run"} for s in summaries):
        sys.exit(1)


def _handle_run_mode(args: argparse.Namespace) -> bool:
    """Run-level commands (list/show/approve/reject/notify) and scheduled apply."""
    requested = any([
        args.run_list, args.run_show, args.run_approve, args.run_reject,
        args.run_notify, args.remediation_apply_due,
    ])
    if (args.apply_now or args.apply_at) and not args.run_approve:
        raise RuntimeError("--apply-now / --apply-at are used with --run-approve RUN_ID")
    if not requested:
        return False

    cfg = load_compliance_config(args.config)
    audit_settings = cfg.get("audit_settings", {})
    rem = get_remediation_settings(audit_settings)
    out_dir = _resolve_out_dir(args, audit_settings)
    as_json = args.remediation_output == "json"
    allow_high_risk = args.allow_high_risk or not rem.get("execution_block_high_risk", True)

    def _print_json(payload) -> None:
        print(json.dumps(payload, indent=2))

    if args.run_list:
        manifests = list_manifests(out_dir, limit=args.remediation_limit or 20)
        statuses = [
            RunStatus(m, list_review_packs(out_dir, run_id=m["run_id"])) for m in manifests
        ]
        if as_json:
            _print_json([run_status_as_dict(st) for st in statuses])
        else:
            print_runs_table(statuses, console=console)
        return True

    if args.run_show:
        status = run_status(out_dir, args.run_show)
        if as_json:
            _print_json(run_status_as_dict(status))
        else:
            print_run_detail(status, _tool_command(args, out_dir), console=console)
        return True

    if args.run_notify:
        from .notifications import notify_run

        manifest = load_manifest(out_dir, args.run_notify)
        outcome = notify_run(cfg, manifest, force=True)
        write_manifest(out_dir, {**manifest, "notification": outcome})
        if as_json:
            _print_json(outcome)
        if not outcome.get("sent"):
            raise RuntimeError(
                f"Run email not sent: {outcome.get('error') or outcome.get('skipped')}"
            )
        if not as_json:
            print(f"Run email for {manifest['run_id']} sent to {', '.join(outcome['to'])}")
        return True

    if args.run_reject:
        if not rem.get("enabled", True):
            raise RuntimeError("Remediation workflow is disabled in config.")
        if not args.approver:
            raise RuntimeError("--approver is required for --run-reject")
        if not args.reason:
            raise RuntimeError("--reason is required for --run-reject")
        decision = reject_run(out_dir, args.run_reject, approver=args.approver, reason=args.reason)
        if as_json:
            _print_json({"operation": "reject_run", **decision.to_dict()})
        else:
            print_decision(decision, "rejected", console=console)
        return True

    if args.run_approve:
        if not rem.get("enabled", True):
            raise RuntimeError("Remediation workflow is disabled in config.")
        if not args.approver:
            raise RuntimeError("--approver is required for --run-approve")
        if rem.get("approval_require_ticket_id", True) and not args.ticket_id:
            raise RuntimeError("--ticket-id is required for --run-approve")
        scheduled = parse_schedule_time(args.apply_at) if args.apply_at else None
        if (args.apply_now or scheduled) and not rem.get("execution_enabled", False):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false), so the run "
                "cannot be applied. Approve without --apply-now/--apply-at, or enable it."
            )
        expires_hours = args.expires_hours or rem.get("approval_default_expires_hours", 24)

        status = run_status(out_dir, args.run_approve)
        candidates = [p for p in status.packs if p.status in ("pending", "approved")]
        if args.remediation_output == "table" and not args.remediation_no_confirm:
            if not interactive_allowed():
                raise RuntimeError(
                    "Confirmation needed but this run is non-interactive; "
                    "add --remediation-no-confirm."
                )
            from rich.prompt import Confirm

            print_run_detail(status, _tool_command(args, out_dir), console=console)
            action = (
                "and apply them now" if args.apply_now
                else f"to apply at {format_schedule(scheduled)}" if scheduled
                else "(apply later)"
            )
            if not Confirm.ask(
                f"\n[yellow]Approve {len(candidates)} pack(s) from {status.run_id} {action}?[/]"
            ):
                print("Cancelled.")
                return True

        decision = approve_run(
            out_dir,
            args.run_approve,
            approver=args.approver,
            ticket_id=args.ticket_id,
            expires_hours=expires_hours,
            require_ticket_id=rem.get("approval_require_ticket_id", True),
            scheduled_for=scheduled,
            allow_high_risk=allow_high_risk,
            block_high_risk=rem.get("execution_block_high_risk", True),
        )
        if not as_json:
            print_decision(decision, "approved", console=console)
            if scheduled:
                console.print(
                    f"Scheduled for {format_schedule(scheduled)} — applied by "
                    "--remediation-apply-due (the apply timer)."
                )

        summaries: list[dict] = []
        if args.apply_now:
            from .notifications import notify_apply

            with exclusive_lock(out_dir, "apply"):
                summaries = apply_packs(
                    args.config,
                    out_dir,
                    [item["pack_id"] for item in decision.acted],
                    skip_jump=args.no_jump,
                    allow_high_risk=allow_high_risk,
                    remediation_settings=rem,
                    title=f"Applying run {status.run_id}",
                )
            notify_apply(
                cfg, summaries,
                trigger=f"approved by {args.approver}, applied immediately",
                output_dir=out_dir,
            )
        if as_json:
            _print_json({"operation": "approve_run", **decision.to_dict(),
                         "scheduled_for": format_schedule(scheduled) if scheduled else "",
                         "applied": summaries})
        _exit_if_failed(summaries)
        return True

    if args.remediation_apply_due:
        if not rem.get("enabled", True) or not rem.get("execution_enabled", False):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false)."
            )
        from .notifications import notify_apply

        with exclusive_lock(out_dir, "apply"):
            summaries = apply_due_packs(
                args.config, out_dir, skip_jump=args.no_jump, remediation_settings=rem
            )
        if summaries:
            notify_apply(cfg, summaries, trigger="scheduled apply", output_dir=out_dir)
        if as_json:
            _print_json({"operation": "apply_due_packs", "results": summaries})
        _exit_if_failed(summaries)
        return True

    return False


def main() -> None:
    """Parse CLI arguments and run audit or remediation lifecycle actions."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.list_options:
        print_options_table(parser, console=console)
        return

    if args.non_interactive:
        set_interactive(False)

    if args.health:
        run_health_check(args.config)
        return

    if args.validate_config:
        from .config_schema import validate_compliance_config
        cfg = load_compliance_config(args.config, validate=False)
        errors = validate_compliance_config(cfg)
        if errors:
            console.print(f"[bold red]Config validation failed ({len(errors)} error(s)):[/]")
            for err in errors:
                console.print(f"  {err}", markup=False, highlight=False)
            sys.exit(2)
        console.print("[bold green]Config valid[/] — no errors found.")
        _print_exception_register_status(cfg)
        return

    if args.notify_test:
        from .notifications import NotificationError, send_test_email

        cfg = load_compliance_config(args.config)
        try:
            settings = send_test_email(cfg)
        except NotificationError as exc:
            console.print(f"[bold red]Test email failed:[/] {exc}", highlight=False)
            sys.exit(2)
        console.print(
            f"[green]Test email sent[/] via {settings.smtp_host}:{settings.smtp_port} "
            f"to {', '.join(settings.to + settings.cc)}"
        )
        return

    if args.dry_run:
        run_dry_run(
            config_path=args.config,
            device_overrides=args.devices,
            skip_jump=args.no_jump,
            inventory_path=args.inventory,
            site_filter=args.site,
            ip_filter=args.ip_filter,
        )
        return

    if args.tui:
        configure_logging()
        launch_textual(parser)
        return

    if args.interactive:
        configure_logging()
        launch_interactive(parser)
        return

    # Logging setup — configure_logging writes INFO+ to console and DEBUG to logs/debug.log
    configure_logging()
    # Honour --verbose by raising the console handler level
    if args.verbose:
        import logging as _logging
        level = _logging.INFO if args.verbose == 1 else _logging.DEBUG
        for h in _logging.getLogger().handlers:
            if isinstance(h, _logging.StreamHandler) and not isinstance(h, _logging.FileHandler):
                h.setLevel(level)

    # Run-level and remediation lifecycle modes (list/approve/reject/apply)
    try:
        if _handle_run_mode(args):
            return
        if _handle_remediation_mode(args):
            return
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        sys.exit(2)

    if args.notify:
        from .notifications import NotificationError, email_settings

        try:
            notify_cfg = load_compliance_config(args.config)
        except SystemExit:
            # Invalid config: the loader has printed why; still tell recipients.
            _notify_failure(
                args,
                "The compliance config failed to load or validate. Run "
                "python -m compliance_audit --validate-config on the host for details.",
            )
            raise
        try:
            if not email_settings(notify_cfg).enabled:
                raise NotificationError(
                    "--notify needs notifications.email.enabled: true in notifications.yaml"
                )
        except NotificationError as exc:
            console.print(f"[bold red]Notification config error:[/] {exc}", highlight=False)
            sys.exit(2)

    try:
        results = run_audit(
            config_path=args.config,
            device_overrides=args.devices,
            skip_jump=args.no_jump,
            categories=args.categories,
            output_dir=args.output_dir,
            csv_report=args.csv_report,
            inventory_path=args.inventory,
            tags_filter=args.tags,
            min_severity=args.min_severity,
            site_filter=args.site,
            framework_filter=args.framework,
            ip_filter=args.ip_filter,
            notify=args.notify,
        )
    except InventoryError as exc:
        console.print("[bold red]Device list error:[/]")
        console.print(str(exc), markup=False, highlight=False)
        _notify_failure(args, f"Device list error: {exc}")
        sys.exit(2)
    except LockHeld as exc:
        # The previous run is still going — not a failure worth an email.
        console.print(f"[bold yellow]Skipped:[/] {exc}", highlight=False)
        sys.exit(2)
    except RuntimeError as exc:
        console.print(f"[bold red]Audit could not run:[/] {exc}", highlight=False)
        _notify_failure(args, str(exc))
        sys.exit(2)

    # Exit code: threshold-based or any-fail
    if args.fail_threshold is not None:
        if not (0 <= args.fail_threshold <= 100):
            parser.error("--fail-threshold must be between 0 and 100")
        if any(r.score_pct < args.fail_threshold for r in results):
            sys.exit(1)
    elif any(r.has_failures for r in results):
        # A FAIL — or, with exception_settings.fail_on_expired, a finding
        # under an expired policy exception.
        sys.exit(1)


def _notify_failure(args: argparse.Namespace, message: str) -> None:
    """With --notify, email that the audit could not run (best effort)."""
    if not args.notify:
        return
    from .notifications import notify_failure

    try:
        cfg = read_compliance_config(args.config, validate=False)
    except (OSError, ValueError):
        return
    outcome = notify_failure(cfg, message)
    if outcome.get("error"):
        console.print(f"[red]Failure email not sent:[/] {outcome['error']}", highlight=False)


def _print_exception_register_status(cfg: dict) -> None:
    """After a successful --validate-config, summarise the exception register.

    Informational only (exit code stays 0): an expired exception is a review
    item, not a config error.
    """
    from .policy_exceptions import ExceptionRegister

    register = ExceptionRegister.from_config(cfg)
    if not len(register):
        return
    counts = register.state_counts()
    parts = [f"{n} {state}" for state, n in counts.items() if n]
    console.print(f"[cyan]Policy exceptions:[/] {len(register)} defined ({', '.join(parts)})")
    for rule in register:
        state, days = register.state_of(rule)
        if state == "expired":
            console.print(
                f"  [bold red]EXPIRED[/] {rule.id} — expired {rule.expires_text} "
                f"({-days} day(s) ago); review, renew or remove it",
                highlight=False,
            )
        elif state == "expiring":
            console.print(
                f"  [yellow]expiring[/] {rule.id} — expires {rule.expires_text} "
                f"(in {days} day(s))",
                highlight=False,
            )


if __name__ == "__main__":
    main()
