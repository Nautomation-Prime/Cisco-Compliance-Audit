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
"""

import argparse
import json
import logging
import sys

from rich.console import Console

from .auditor import load_compliance_config, run_audit
from .cli_discovery import print_options_table
from .interactive_cli import launch_interactive
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
from .textual_app import launch_textual

console = Console()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m compliance_audit",
        description="Cisco IOS-XE Compliance Auditor",
    )
    p.add_argument(
        "-c",
        "--config",
        default="compliance_config",
        help="Path to the compliance config directory (default: compliance_config/)",
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
        "(e.g. management_plane control_plane data_plane role_specific).",
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
            "Path to the device inventory YAML (default: devices.yaml next to config)."
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
        choices=[
            "all",
            "pending",
            "approved",
            "rejected",
            "applied",
            "failed",
            "expired",
        ],
        help="List remediation review packs (optionally filtered by status).",
    )
    p.add_argument(
        "--remediation-output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format for --remediation-list (default: table).",
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
        "--remediation-apply-all",
        action="store_true",
        help="Apply all currently approved remediation packs in sequence.",
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
    return p


def _handle_remediation_mode(args: argparse.Namespace) -> bool:
    """Handle remediation lifecycle CLI modes; return True if a mode was executed."""
    cfg = load_compliance_config(args.config)
    audit_settings = cfg.get("audit_settings", {})
    rem = get_remediation_settings(audit_settings)
    out_dir = args.output_dir or audit_settings.get("output_dir", "./reports")

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
            print("No remediation review packs found.")
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
        print(f"Approved review pack: {path}")
        return True

    if args.remediation_approve_all:
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
            print("No pending remediation review packs found.")
            return True

        print_review_entries_table(
            rows,
            title=f"Pending remediation pack(s): {len(rows)}",
            show_created=False,
            console=console,
        )

        # Confirm before approving all
        from rich.prompt import Confirm

        if not Confirm.ask(f"\n[yellow]Approve all {len(rows)} pack(s)?[/]"):
            print("Cancelled.")
            return True

        # Approve each pack
        approved_count = 0
        failed_count = 0
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
                print(f"✓ Approved: {row.pack_id} ({row.hostname})")
                approved_count += 1
            except RuntimeError as exc:
                print(f"✗ Failed to approve {row.pack_id} ({row.hostname}): {exc}")
                failed_count += 1

        print(
            "\nBulk approval complete: "
            f"{approved_count} approved, {failed_count} failed"
        )
        return True

    if args.remediation_reject:
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
        print(f"Rejected review pack: {path}")
        return True

    if args.remediation_apply:
        if not rem.get("execution_enabled", True):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false)."
            )
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
        print(json.dumps(summary, indent=2))
        return True

    if args.remediation_apply_all:
        if not rem.get("execution_enabled", False):
            raise RuntimeError(
                "Remediation execution is disabled in config "
                "(audit_settings.remediation.execution.enabled=false)."
            )
        summaries = apply_all_approved_packs(
            config_path=args.config,
            output_dir=out_dir,
            skip_jump=args.no_jump,
            allow_high_risk=(
                args.allow_high_risk or not rem.get("execution_block_high_risk", True)
            ),
            remediation_settings=rem,
        )
        print(json.dumps(summaries, indent=2))
        return True

    return False


def main() -> None:
    """Parse CLI arguments and run audit or remediation lifecycle actions."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.list_options:
        print_options_table(parser, console=console)
        return

    if args.tui:
        launch_textual(parser)
        return

    if args.interactive:
        launch_interactive(parser)
        return

    # Logging setup
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Remediation lifecycle mode (list/approve/reject/apply)
    try:
        if _handle_remediation_mode(args):
            return
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        sys.exit(2)

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
    )

    # Exit code: threshold-based or any-fail
    if args.fail_threshold is not None:
        if not (0 <= args.fail_threshold <= 100):
            parser.error("--fail-threshold must be between 0 and 100")
        if any(r.score_pct < args.fail_threshold for r in results):
            sys.exit(1)
    elif any(r.fail_count > 0 for r in results):
        sys.exit(1)


main()
