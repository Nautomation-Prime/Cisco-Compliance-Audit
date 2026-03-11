"""
Entry point for  python -m compliance_audit

Usage examples
--------------
    python -m compliance_audit
    python -m compliance_audit --config custom.yaml
    python -m compliance_audit --device 10.1.1.1
    python -m compliance_audit --device GB-MKD1-005ASW001:10.1.1.1
    python -m compliance_audit --no-jump
    python -m compliance_audit --categories management_plane control_plane
"""

import argparse
import logging
import sys

from .auditor import run_audit


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m compliance_audit",
        description="Cisco IOS-XE Compliance Auditor",
    )
    p.add_argument(
        "-c", "--config",
        default="compliance_config.yaml",
        help="Path to the compliance YAML config (default: compliance_config.yaml)",
    )
    p.add_argument(
        "-d", "--device",
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
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v INFO, -vv DEBUG).",
    )
    p.add_argument(
        "-o", "--output-dir",
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
        "--dry-run",
        default=None,
        metavar="DIR",
        help="Offline mode — read previously saved command outputs from DIR instead of SSH.",
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
    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Logging setup
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    results = run_audit(
        config_path=args.config,
        device_overrides=args.devices,
        skip_jump=args.no_jump,
        categories=args.categories,
        output_dir=args.output_dir,
        dry_run_dir=args.dry_run,
        csv_report=args.csv_report,
    )

    # Exit code: threshold-based or any-fail
    if args.fail_threshold is not None:
        if any(r.score_pct < args.fail_threshold for r in results):
            sys.exit(1)
    elif any(r.fail_count > 0 for r in results):
        sys.exit(1)


main()
