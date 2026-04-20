"""
Main orchestrator — connects to devices, collects data, runs the
compliance engine, and produces reports.

Supports concurrent device auditing via ThreadPoolExecutor.
The number of parallel workers is controlled by ``audit_settings.max_workers``
in the compliance YAML config (default: 5, set to 1 for sequential).
"""

import logging
import math
import re
import socket
import sys
import time
import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from netmiko.exceptions import NetmikoBaseException
from paramiko.ssh_exception import SSHException
from rich import box
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)
from rich.table import Table

from .collector import DataCollector
from .compliance_engine import AuditResult, ComplianceEngine, Finding, Status
from .credentials import CredentialHandler
from .hostname_parser import parse_hostname
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .port_classifier import classify_ports
from .remediation_workflow import (
    generate_review_pack,
    get_remediation_settings,
)
from .report import (
    _find_latest_baseline,
    compute_delta,
    load_baseline,
    print_delta_summary,
    save_consolidated_html,
    save_csv,
    save_delta_report,
    save_html,
    save_json,
    save_remediation_script,
)

log = logging.getLogger(__name__)
console = Console()


def _get_roi_settings(audit_settings: dict) -> dict:
    """Return ROI settings with safe defaults."""
    roi = audit_settings.get("roi", {})
    if not isinstance(roi, dict):
        roi = {}

    def _as_non_negative_float(value, default: float) -> float:
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return default

    base_manual_per_device = _as_non_negative_float(
        roi.get("manual_minutes_per_device", 15.0), 15.0
    )
    base_manual_per_check = _as_non_negative_float(
        roi.get("manual_minutes_per_check", 0.5), 0.5
    )
    base_overhead = _as_non_negative_float(
        roi.get("automation_overhead_minutes_per_device", 2.0), 2.0
    )
    base_validation = _as_non_negative_float(
        roi.get("validation_minutes_per_device", 0.0), 0.0
    )
    min_runtime_seconds = _as_non_negative_float(
        roi.get("min_runtime_seconds", 0.0), 0.0
    )
    # Diminishing-returns inflection point: once check count exceeds this
    # value the per-check effort starts to plateau logarithmically.
    check_scaling_inflection = _as_non_negative_float(
        roi.get("check_scaling_inflection", 20.0), 20.0
    )
    # Maximum per-device value sanity cap (minutes).  0 = no cap.
    max_manual_minutes_per_device = _as_non_negative_float(
        roi.get("max_manual_minutes_per_device", 120.0), 120.0
    )

    profiles = roi.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}

    def _build_profile(raw: dict) -> dict:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "manual_minutes_per_device": _as_non_negative_float(
                raw.get("manual_minutes_per_device", base_manual_per_device),
                base_manual_per_device,
            ),
            "manual_minutes_per_check": _as_non_negative_float(
                raw.get("manual_minutes_per_check", base_manual_per_check),
                base_manual_per_check,
            ),
            "automation_overhead_minutes_per_device": _as_non_negative_float(
                raw.get("automation_overhead_minutes_per_device", base_overhead),
                base_overhead,
            ),
            "validation_minutes_per_device": _as_non_negative_float(
                raw.get("validation_minutes_per_device", base_validation),
                base_validation,
            ),
        }

    roi_profiles = {
        "audit": _build_profile(profiles.get("audit", {})),
        "post_remediation": _build_profile(profiles.get("post_remediation", {})),
    }

    return {
        "enabled": bool(roi.get("enabled", False)),
        "manual_minutes_per_device": base_manual_per_device,
        "manual_minutes_per_check": base_manual_per_check,
        "automation_overhead_minutes_per_device": base_overhead,
        "validation_minutes_per_device": base_validation,
        "min_runtime_seconds": min_runtime_seconds,
        "check_scaling_inflection": check_scaling_inflection,
        "max_manual_minutes_per_device": max_manual_minutes_per_device,
        "hourly_rate": _as_non_negative_float(roi.get("hourly_rate", 0.0), 0.0),
        "currency": str(roi.get("currency", "GBP")),
        "profiles": roi_profiles,
    }


def _estimate_manual_minutes(
    total_checks: int,
    manual_minutes_per_device: float,
    manual_minutes_per_check: float,
    check_scaling_inflection: float,
    max_manual_minutes: float,
) -> float:
    """Estimate manual audit effort with diminishing-returns scaling.

    Model:
        manual = base_per_device
               + per_check × inflection × ln(1 + checks / inflection)

    For small check counts this is approximately linear (≈ per_check × checks).
    As check count grows past the inflection point the curve flattens
    logarithmically — reflecting that an engineer reviewing config gets
    faster once context is established.

    An optional hard cap (max_manual_minutes) prevents runaway estimates
    on devices with hundreds of evaluated checks.
    """
    if total_checks <= 0:
        return manual_minutes_per_device

    inflection = max(check_scaling_inflection, 1.0)
    scaled = (
        manual_minutes_per_check
        * inflection
        * math.log(1.0 + total_checks / inflection)
    )
    manual = manual_minutes_per_device + scaled

    if max_manual_minutes > 0:
        manual = min(manual, max_manual_minutes)
    return manual


def _estimate_roi_for_result(
    result: AuditResult,
    roi_settings: dict,
    context: str = "audit",
) -> dict:
    """Estimate per-device automation value with diminishing-returns model."""
    profiles = roi_settings.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
    profile = profiles.get(context, profiles.get("audit", {}))
    if not isinstance(profile, dict):
        profile = {}

    manual_minutes_per_device = float(
        profile.get(
            "manual_minutes_per_device",
            roi_settings.get("manual_minutes_per_device", 15.0),
        )
    )
    manual_minutes_per_check = float(
        profile.get(
            "manual_minutes_per_check",
            roi_settings.get("manual_minutes_per_check", 0.5),
        )
    )
    overhead_minutes = float(
        profile.get(
            "automation_overhead_minutes_per_device",
            roi_settings.get("automation_overhead_minutes_per_device", 2.0),
        )
    )
    validation_minutes = float(
        profile.get(
            "validation_minutes_per_device",
            roi_settings.get("validation_minutes_per_device", 0.0),
        )
    )
    check_scaling_inflection = float(roi_settings.get("check_scaling_inflection", 20.0))
    max_manual_minutes = float(roi_settings.get("max_manual_minutes_per_device", 120.0))

    min_runtime_seconds = float(roi_settings.get("min_runtime_seconds", 0.0))
    actual_runtime = float(result.duration_secs)
    runtime_floor_applied = actual_runtime < min_runtime_seconds
    effective_runtime_seconds = max(actual_runtime, min_runtime_seconds)

    if runtime_floor_applied:
        log.debug(
            "ROI runtime floor applied for %s: actual %.1fs → floor %.1fs",
            result.hostname,
            actual_runtime,
            min_runtime_seconds,
        )

    # ── Manual estimate (diminishing-returns model) ────────
    manual_minutes = _estimate_manual_minutes(
        total_checks=result.total,
        manual_minutes_per_device=manual_minutes_per_device,
        manual_minutes_per_check=manual_minutes_per_check,
        check_scaling_inflection=check_scaling_inflection,
        max_manual_minutes=max_manual_minutes,
    )

    # ── Automated estimate ─────────────────────────────────
    automated_minutes = (
        (effective_runtime_seconds / 60.0) + overhead_minutes + validation_minutes
    )

    # ── Derived metrics ────────────────────────────────────
    minutes_saved = max(0.0, manual_minutes - automated_minutes)
    hours_saved = minutes_saved / 60.0
    hourly_rate = float(roi_settings.get("hourly_rate", 0.0))
    value_saved = hours_saved * hourly_rate if hourly_rate > 0 else None

    # Efficiency ratio: < 1.0 means automation is faster than manual
    efficiency_ratio = (
        round(automated_minutes / manual_minutes, 3) if manual_minutes > 0 else None
    )

    # ── Sanity warnings ────────────────────────────────────
    warnings: list[str] = []
    if minutes_saved == 0.0 and manual_minutes > 0:
        warnings.append(
            "Automated time exceeds manual estimate — check overhead settings"
        )
    if runtime_floor_applied:
        warnings.append(
            f"Runtime floor applied (actual {actual_runtime:.1f}s "
            f"→ floor {min_runtime_seconds:.1f}s)"
        )
    if value_saved is not None and value_saved > 500:
        warnings.append(
            f"High per-device value estimate "
            f"({roi_settings['currency']} {value_saved:.2f}) — "
            f"verify hourly_rate and assumptions"
        )

    return {
        "context": context,
        "total_checks_evaluated": result.total,
        "duration_secs": round(effective_runtime_seconds, 1),
        "actual_duration_secs": round(actual_runtime, 1),
        "runtime_floor_applied": runtime_floor_applied,
        "manual_minutes_estimate": round(manual_minutes, 1),
        "automated_minutes": round(automated_minutes, 1),
        "minutes_saved": round(minutes_saved, 1),
        "hours_saved": round(hours_saved, 2),
        "efficiency_ratio": efficiency_ratio,
        "hourly_rate": round(hourly_rate, 2),
        "currency": roi_settings["currency"],
        "value_saved": round(value_saved, 2) if value_saved is not None else None,
        "warnings": warnings if warnings else None,
        "assumptions": {
            "context": context,
            "model": "diminishing_returns_log",
            "manual_minutes_per_device": manual_minutes_per_device,
            "manual_minutes_per_check": manual_minutes_per_check,
            "check_scaling_inflection": check_scaling_inflection,
            "max_manual_minutes_per_device": max_manual_minutes,
            "automation_overhead_minutes_per_device": overhead_minutes,
            "validation_minutes_per_device": validation_minutes,
            "min_runtime_seconds": min_runtime_seconds,
        },
    }


def _summarize_roi(results: list[AuditResult], roi_settings: dict) -> dict:
    """Aggregate ROI metrics across all audited devices."""
    manual = 0.0
    automated = 0.0
    saved = 0.0
    value = 0.0
    total_checks = 0
    device_count = 0
    all_warnings: list[str] = []

    for r in results:
        roi = getattr(r, "_roi", None)
        if not roi:
            continue
        device_count += 1
        manual += float(roi.get("manual_minutes_estimate", 0.0))
        automated += float(roi.get("automated_minutes", 0.0))
        saved += float(roi.get("minutes_saved", 0.0))
        total_checks += int(roi.get("total_checks_evaluated", 0))
        v = roi.get("value_saved")
        if v is not None:
            value += float(v)
        w = roi.get("warnings")
        if w:
            for msg in w:
                prefixed = f"{r.hostname}: {msg}"
                if prefixed not in all_warnings:
                    all_warnings.append(prefixed)

    hourly_rate = float(roi_settings.get("hourly_rate", 0.0))
    efficiency_ratio = round(automated / manual, 3) if manual > 0 else None

    # Pull assumptions from the active profile for the summary context
    active_profile = roi_settings.get("profiles", {}).get("audit", {})

    return {
        "enabled": bool(roi_settings.get("enabled", False)),
        "device_count": device_count,
        "total_checks_evaluated": total_checks,
        "manual_minutes_estimate": round(manual, 1),
        "automated_minutes": round(automated, 1),
        "minutes_saved": round(saved, 1),
        "hours_saved": round(saved / 60.0, 2),
        "efficiency_ratio": efficiency_ratio,
        "hourly_rate": round(hourly_rate, 2),
        "currency": str(roi_settings.get("currency", "GBP")),
        "value_saved": round(value, 2) if hourly_rate > 0 else None,
        "warnings": all_warnings if all_warnings else None,
        "assumptions": {
            "model": "diminishing_returns_log",
            "manual_minutes_per_device": float(
                active_profile.get(
                    "manual_minutes_per_device",
                    roi_settings.get("manual_minutes_per_device", 0.0),
                )
            ),
            "manual_minutes_per_check": float(
                active_profile.get(
                    "manual_minutes_per_check",
                    roi_settings.get("manual_minutes_per_check", 0.0),
                )
            ),
            "check_scaling_inflection": float(
                roi_settings.get("check_scaling_inflection", 20.0)
            ),
            "max_manual_minutes_per_device": float(
                roi_settings.get("max_manual_minutes_per_device", 120.0)
            ),
            "automation_overhead_minutes_per_device": float(
                active_profile.get(
                    "automation_overhead_minutes_per_device",
                    roi_settings.get("automation_overhead_minutes_per_device", 0.0),
                )
            ),
            "validation_minutes_per_device": float(
                active_profile.get(
                    "validation_minutes_per_device",
                    roi_settings.get("validation_minutes_per_device", 0.0),
                )
            ),
            "min_runtime_seconds": float(roi_settings.get("min_runtime_seconds", 0.0)),
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
    expected_keys = {
        "connection": dict,
        "compliance": dict,
    }
    for key, expected_type in expected_keys.items():
        val = cfg.get(key)
        if val is None:
            console.print(
                f"[bold yellow]Warning:[/] config missing required "
                f"section [cyan]'{key}'[/] — using defaults."
            )
        elif not isinstance(val, expected_type):
            console.print(
                f"[bold red]Config error:[/] '{key}' must be a "
                f"{expected_type.__name__}, got {type(val).__name__}"
            )
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


def _normalise_device_entry(entry, *, location: str = "devices") -> dict:
    """Turn a bare string or dict into a normalised ``{hostname, ip}`` dict.

    Accepted forms:
      - ``"192.0.2.61"``          → ip-only  (hostname discovered at connect)
        Example hostname: ``"ZZ-LAB1-001ASW001"`` → hostname used as connection target (DNS)
      - ``{hostname: …, ip: …}``  → explicit (current format)
      - ``{hostname: …}``         → hostname used as connection target
      - ``{ip: …}``              → ip-only

    Raises ``ValueError`` for entries that cannot be normalised.
    *location* is included in error messages to help the user find the problem.
    """
    if isinstance(entry, str):
        value = entry.strip()
        if not value:
            raise ValueError(
                f"Empty string in {location} — each entry must be a "
                "hostname, IP address, or {{hostname: …, ip: …}} mapping."
            )
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return {"ip": value, "hostname": value}
        return {"hostname": value, "ip": value}
    if isinstance(entry, dict):
        out = dict(entry)
        if "hostname" not in out and "ip" not in out:
            raise ValueError(
                f"Device entry in {location} must contain at least "
                f"'hostname' or 'ip': {entry!r}"
            )
        if "hostname" in out and "ip" not in out:
            out["ip"] = out["hostname"]
        elif "ip" in out and "hostname" not in out:
            out["hostname"] = out["ip"]
        return out
    raise ValueError(
        f"Invalid entry in {location} (expected string or mapping, "
        f"got {type(entry).__name__}): {entry!r}"
    )


def _flatten_inventory(data: dict) -> list[dict]:
    """Merge flat ``devices:`` list and Ansible-style ``groups:`` into one list.

    Group-level keys (currently only ``role``) are inherited by every device
    in that group unless the device specifies its own value.

    Validates every entry and deduplicates by connection target (``ip``).
    """
    flat: list[dict] = []
    errors: list[str] = []

    # ── Flat devices list ─────────────────────────────────────
    for idx, raw in enumerate(data.get("devices", []) or []):
        try:
            flat.append(_normalise_device_entry(raw, location=f"devices[{idx}]"))
        except ValueError as exc:
            errors.append(str(exc))

    # ── Grouped devices ──────────────────────────────────────
    for group_name, group_body in (data.get("groups") or {}).items():
        if not isinstance(group_body, dict):
            errors.append(
                f"Group '{group_name}' is not a mapping — expected "
                "keys like 'role' and 'devices'."
            )
            continue
        group_role = group_body.get("role")
        for idx, raw in enumerate(group_body.get("devices") or []):
            try:
                entry = _normalise_device_entry(
                    raw, location=f"groups.{group_name}.devices[{idx}]"
                )
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if group_role and "role" not in entry:
                entry["role"] = group_role
            entry.setdefault("_group", group_name)
            flat.append(entry)

    if errors:
        raise ValueError("Inventory validation failed:\n  • " + "\n  • ".join(errors))

    # ── Deduplicate by connection target ───────────────────────
    seen: dict[str, str] = {}  # ip → first location label
    unique: list[dict] = []
    for entry in flat:
        ip = entry["ip"]
        source = entry.get("_group", "devices")
        if ip in seen:
            log.warning(
                "Duplicate device '%s' (already loaded from %s) — skipping.",
                ip,
                seen[ip],
            )
            continue
        seen[ip] = source
        unique.append(entry)

    return unique


def load_device_inventory(inventory_path: str | None, config_path: str) -> list[dict]:
    """Load the device inventory from a dedicated YAML file.

    Resolution order for *inventory_path*:
    1. Explicit CLI value (--inventory).
    2. ``inventory_file`` key inside the main config YAML.
    3. ``devices.yaml`` next to the config file.

    Supports both a flat ``devices:`` list and Ansible-style ``groups:``.
    """
    cfg_dir = _resolve_config_path(config_path)

    if inventory_path is None:
        cfg = load_compliance_config(config_path)
        inventory_path = cfg.get("inventory_file", "devices.yaml")

    p = Path(inventory_path or "devices.yaml")
    if not p.is_absolute():
        p = cfg_dir / p
    if not p.exists():
        p = Path(__file__).parent / (inventory_path or "devices.yaml")
    if not p.exists():
        return []

    with open(p, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return _flatten_inventory(data)


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
    """
    hostname, ip = job.hostname, job.ip
    log.info("Starting audit of %s (%s)", hostname, ip)
    t_start = time.monotonic()

    # Parse hostname for role (with optional explicit role override from devices.yaml)
    host_info = parse_hostname(
        hostname, role_config=job.role_config, explicit_role=job.explicit_role
    )

    # ── Live SSH connection ────────────────────────────
    connector_kwargs = {
        "ip": ip,
        "username": job.username,
        "password": job.password,
        "device_type": job.device_type,
        "jump": job.jump,
        "retries": job.audit_settings.get(
            "retries",
            job.audit_settings.get("_connection", {}).get("retries", 3),
        ),
    }
    if job.enable_secret:
        connector_kwargs["secret"] = job.enable_secret
    connector = DeviceConnector(**connector_kwargs)
    try:
        conn = connector.connect()
    except (
        NetmikoBaseException,
        OSError,
        RuntimeError,
        SSHException,
        TimeoutError,
        TypeError,
        ValueError,
    ) as exc:
        # Detect DNS resolution failures and give a clear message
        if isinstance(exc.__cause__, socket.gaierror) or (
            isinstance(exc, OSError) and "getaddrinfo" in str(exc).lower()
        ):
            log.error(
                "DNS resolution failed for %s (%s) — check that the "
                "hostname resolves or provide an explicit IP.",
                hostname,
                ip,
            )
        else:
            log.error("Connection to %s (%s) failed: %s", hostname, ip, exc)
        return None

    try:
        collector = DataCollector(timeout=job.timeout)
        data = collector.collect(conn, ip=ip)
        # Only overwrite the discovered hostname when the user
        # explicitly provided one (not just an IP echo).
        if job.hostname and job.hostname != job.ip:
            data.hostname = job.hostname
        else:
            # Hostname was discovered from the device prompt.
            # Update local variable and re-parse for role detection.
            hostname = data.hostname
            host_info = parse_hostname(
                hostname,
                role_config=job.role_config,
                explicit_role=job.explicit_role,
            )
    except (
        AttributeError,
        NetmikoBaseException,
        OSError,
        RuntimeError,
        SSHException,
        TimeoutError,
        TypeError,
        ValueError,
    ) as exc:
        log.error("Data collection from %s (%s) failed: %s", hostname, ip, exc)
        try:
            conn.disconnect()
        except (
            AttributeError,
            NetmikoBaseException,
            OSError,
            RuntimeError,
            SSHException,
        ):
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
    except (
        AttributeError,
        LookupError,
        OSError,
        RuntimeError,
        TimeoutError,
        TypeError,
        ValueError,
        re.error,
    ) as exc:
        log.exception("Compliance engine failed for %s (%s)", hostname, ip)
        result = AuditResult(
            hostname=hostname,
            ip=ip,
            role=host_info.role or "unknown",
            role_display=host_info.role_display or "unknown",
            structured_parse_engine=dict(data.structured_parse_engine),
            findings=[
                Finding(
                    check_name="engine_error",
                    status=Status.ERROR,
                    detail=f"Compliance engine crashed: {exc}",
                    category="internal",
                )
            ],
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

        # Save per-device reports
        out_dir = job.audit_settings.get("output_dir", "./reports")
        roi_settings = _get_roi_settings(job.audit_settings)
        if roi_settings.get("enabled", False):
            roi = _estimate_roi_for_result(result, roi_settings, context="audit")
            # Keep both names for backward compatibility with existing callers.
            setattr(result, "_roi", roi)
            setattr(result, "roi", roi)
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
                    setattr(result, "_delta", delta)

        parser_summary = result.structured_parse_summary
        if parser_summary:
            log.info(
                "Completed audit of %s — score %s%% (%.1fs) — structured parsing: %s",
                hostname,
                result.score_pct,
                result.duration_secs,
                parser_summary,
            )
        else:
            log.info(
                "Completed audit of %s — score %s%% (%.1fs)",
                hostname,
                result.score_pct,
                result.duration_secs,
            )
        return result

    finally:
        if conn:
            try:
                conn.disconnect()
            except (
                AttributeError,
                NetmikoBaseException,
                OSError,
                RuntimeError,
                SSHException,
            ):
                pass


def run_audit(
    config_path: str = "compliance_config.yaml",
    device_overrides: Optional[list[str]] = None,
    skip_jump: bool = False,
    categories: Optional[list[str]] = None,
    output_dir: Optional[str] = None,
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
        console.print(
            "[bold yellow]Warning:[/] No compliance check categories "
            "found in policy — audits will produce zero findings."
        )
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

    # ── Inventory summary ──────────────────────────────────
    if devices:
        group_counts: dict[str, int] = {}
        flat_count = 0
        for d in devices:
            grp = d.get("_group")
            if grp:
                group_counts[grp] = group_counts.get(grp, 0) + 1
            else:
                flat_count += 1
        parts: list[str] = []
        if flat_count:
            parts.append(f"{flat_count} from flat list")
        for grp, cnt in group_counts.items():
            parts.append(f"{cnt} from group '{grp}'")
        console.print(
            f"[cyan]Inventory loaded:[/] {len(devices)} device(s) ({', '.join(parts)})"
        )

    # ── Credentials ────────────────────────────────────────
    username, password, enable_secret = "", "", None
    jump: Optional[JumpManager] = None

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

    if not devices:
        console.print(
            "[bold yellow]No devices to audit.[/] "
            "Add devices to devices.yaml or use --device."
        )
        return []

    # ── Concurrency settings ───────────────────────────────
    max_workers = max(1, min(audit_settings.get("max_workers", 5), 20))
    device_type = conn_cfg.get("device_type", "cisco_xe")
    timeout = audit_settings.get("collect_timeout", 30)
    roi_settings = _get_roi_settings(audit_settings)

    mode_label = "live"
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
        explicit_role = dev_entry.get(
            "role"
        )  # NEW: get explicit role from devices.yaml
        jobs.append(
            _DeviceJob(
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
            )
        )

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

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_job = {
                    executor.submit(_audit_single_device, job): job for job in jobs
                }
                for future in concurrent.futures.as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        result = future.result()
                        if result is not None:
                            results.append(result)
                            progress.console.print(
                                f"  [green]OK[/] {job.hostname} ({job.ip}) - "
                                f"Score: {result.score_pct}%"
                            )
                        else:
                            progress.console.print(
                                f"  [red]FAIL[/] {job.hostname} ({job.ip}) - "
                                f"Connection failed"
                            )
                    except (
                        AttributeError,
                        LookupError,
                        NetmikoBaseException,
                        OSError,
                        RuntimeError,
                        SSHException,
                        TimeoutError,
                        TypeError,
                        ValueError,
                        re.error,
                        yaml.YAMLError,
                    ) as exc:
                        log.exception("Audit of %s failed", job.hostname)
                        progress.console.print(
                            f"  [red]FAIL[/] {job.hostname} ({job.ip}) - Error: {exc}"
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
                if not getattr(r, "_roi", None):
                    roi = _estimate_roi_for_result(r, roi_settings, context="audit")
                    setattr(r, "_roi", roi)
                    setattr(r, "roi", roi)

        console.print()
        console.rule("[bold cyan]AUDIT SUMMARY[/]")
        summary_table = Table(
            box=box.ROUNDED,
            expand=False,
            show_lines=False,
            title_style="bold",
            min_width=90,
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
            eff = roi_summary.get("efficiency_ratio")
            eff_str = f"  (efficiency ratio: {eff})" if eff is not None else ""
            console.print(
                f"[bold cyan]ROI Estimate:[/] "
                f"{roi_summary['hours_saved']}h saved "
                f"({roi_summary['minutes_saved']} min){eff_str}"
            )
            val = roi_summary.get("value_saved")
            if val is not None and roi_summary["hourly_rate"] > 0:
                console.print(
                    f"[bold cyan]Estimated Value:[/] "
                    f"{roi_summary['currency']} {val:.2f}"
                )
            roi_warnings = roi_summary.get("warnings")
            if roi_warnings:
                for w in roi_warnings:
                    console.print(f"  [bold yellow]ROI Warning:[/] {w}")

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
