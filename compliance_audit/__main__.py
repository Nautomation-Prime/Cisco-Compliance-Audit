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
    )

    # Exit code: 0 if all pass, 1 if any fail
    if any(r.fail_count > 0 for r in results):
        sys.exit(1)


main()
