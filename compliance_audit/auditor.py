"""
Main orchestrator — connects to devices, collects data, runs the
compliance engine, and produces reports.

Supports concurrent device auditing via ThreadPoolExecutor.
The number of parallel workers is controlled by ``audit_settings.max_workers``
in the compliance YAML config (default: 5, set to 1 for sequential).
"""

import ipaddress
import logging
import math
import re
import socket
import sqlite3
import sys
import time
import concurrent.futures
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
import paramiko
from pydantic import ValidationError
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
from .config_schema import ConfigValidationError, ensure_valid_config
from .compliance_engine import AuditResult, ComplianceEngine, Finding, Status, SEVERITY_ORDER
from .credentials import CredentialHandler
from .hostname_parser import parse_hostname
from .inventory_schema import (
    InventoryError,
    InventoryFile,
    format_entry_error,
    parse_device_entry,
    parse_device_target,
)
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .policy_exceptions import ExceptionRegister, run_summary
from .port_classifier import classify_ports
from .remediation_workflow import (
    ensure_review_store,
    generate_review_pack,
    get_remediation_settings,
    get_review_db_path,
    supersede_pending_packs,
)
from .runs import build_manifest, exclusive_lock, write_manifest
from .report import (
    _find_latest_baseline,
    compute_delta,
    load_baseline,
    print_delta_summary,
    print_exception_summary,
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
        roi.get("manual_minutes_per_device", 20.0), 20.0
    )
    base_manual_per_check = _as_non_negative_float(
        roi.get("manual_minutes_per_check", 0.25), 0.25
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
        "enabled": bool(roi.get("enabled", True)),
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


def _format_yaml_error(kind: str, path: "Path | str", exc: yaml.YAMLError) -> str:
    """Build a clear, actionable message for a malformed YAML file.

    Includes the file path and, when available, the 1-based line/column and the
    parser's problem description.  A tab-specific hint is appended because a
    literal tab used for indentation is the most common cause of a
    ``yaml.scanner.ScannerError`` and the message is otherwise opaque.
    """
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    if mark is not None:
        location = f"line {mark.line + 1}, column {mark.column + 1} - "
    else:
        location = ""
    return (
        f"Invalid YAML in {kind} '{path}': {location}{problem}. "
        "YAML does not allow tab characters for indentation; use spaces instead."
    )


def read_compliance_config(path: str, *, validate: bool = True) -> dict:
    """Load (and by default validate) the compliance config directory.

    *path* must point to a **directory** containing ``*.yaml`` files.  Every
    file is loaded in sorted order and deep-merged into a single config dict
    (one file per section, e.g. ``management_plane.yaml``, ``data_plane.yaml``).

    Raises ``FileNotFoundError``, ``NotADirectoryError``, ``ValueError`` for
    unreadable YAML, or :class:`ConfigValidationError` when the merged config
    fails the schema.  Use this from library code;
    :func:`load_compliance_config` is the CLI wrapper that prints and exits.
    """
    p = Path(path)
    if not p.exists():
        # Try relative to the project root (assets/ lives one level above this module)
        p = Path(__file__).parent.parent / path
    if not p.exists():
        raise FileNotFoundError(f"Config directory not found: {path}")
    if not p.is_dir():
        raise NotADirectoryError(
            f"Config path must be a directory, not a single file: {path} — "
            "use the compliance_config/ directory format."
        )

    try:
        cfg = _load_config_dir(p)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Error loading config directory {p}: {exc}") from exc
    cfg = _load_exception_files(cfg, p)

    if validate:
        ensure_valid_config(cfg)
    return cfg


def load_compliance_config(path: str, *, validate: bool = True) -> dict:
    """CLI wrapper around :func:`read_compliance_config`.

    Prints a readable message and exits with status 2 — whether the config
    cannot be read or fails schema validation — so a broken config is never
    confused with exit 1, which means a device failed compliance.
    Pass ``validate=False`` to load without the schema check, e.g. when the
    caller reports validation errors itself.
    """
    try:
        cfg = read_compliance_config(path, validate=validate)
    except ConfigValidationError as exc:
        console.print(
            f"[bold red]Config validation failed ({len(exc.errors)} error(s)):[/]"
        )
        for err in exc.errors:
            console.print(f"  {err}", markup=False, highlight=False)
        console.print("Fix the config above, or run [cyan]--validate-config[/] to re-check.")
        sys.exit(2)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Config error:[/] {exc}", highlight=False)
        sys.exit(2)

    # Missing sections are allowed (defaults apply) but worth flagging.  A
    # wrongly-typed section is caught above when validating; this covers
    # validate=False callers.
    for key in ("connection", "compliance"):
        val = cfg.get(key)
        if val is None:
            console.print(
                f"[bold yellow]Warning:[/] config missing required "
                f"section [cyan]'{key}'[/] — using defaults."
            )
        elif not isinstance(val, dict):
            console.print(
                f"[bold red]Config error:[/] '{key}' must be a "
                f"mapping, got {type(val).__name__}"
            )
            sys.exit(2)

    return cfg


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge *overlay* into *base*.  Lists are replaced, not merged."""
    result = dict(base)
    for key, val in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


#: Top-level keys whose lists are concatenated across config files instead
#: of the later file replacing the earlier one, so the exception register can
#: be split over several files (one per site, team or change ticket).
_CONCATENATED_LIST_KEYS = ("exceptions",)

#: Keys an external ``exceptions_file`` may contain.
_EXCEPTION_FILE_KEYS = {"exceptions", "exception_settings"}


def _tag_exception_sources(data: dict, source: str) -> None:
    """Record which file each exception came from, for reports and errors."""
    entries = data.get("exceptions")
    if isinstance(entries, list):
        data["exceptions"] = [
            {**entry, "_source": source} if isinstance(entry, dict) else entry
            for entry in entries
        ]


def _merge_fragment(merged: dict, data: dict) -> dict:
    """Deep-merge one config fragment, concatenating the exception lists."""
    concatenated = {
        key: merged[key] + data[key]
        for key in _CONCATENATED_LIST_KEYS
        if isinstance(merged.get(key), list) and isinstance(data.get(key), list)
    }
    merged = _deep_merge(merged, data)
    merged.update(concatenated)
    return merged


def _load_config_dir(dirpath: Path) -> dict:
    """Load every ``*.yaml`` file in *dirpath* (sorted) and deep-merge them.

    Lists are replaced by later files, except ``exceptions``, which are
    concatenated (see ``_CONCATENATED_LIST_KEYS``).
    """
    merged: dict = {}
    yaml_files = sorted(dirpath.glob("*.yaml"))
    if not yaml_files:
        log.warning("Config directory %s contains no .yaml files", dirpath)
    for yaml_file in yaml_files:
        with open(yaml_file, "r", encoding="utf-8") as fh:
            try:
                data = yaml.safe_load(fh) or {}
                if not isinstance(data, dict):
                    raise ValueError(
                        f"Config file '{yaml_file}' must be a YAML mapping at the top level, got {type(data).__name__}."
                    )
            except yaml.YAMLError as exc:
                raise ValueError(
                    _format_yaml_error("config file", yaml_file, exc)
                ) from exc
        _tag_exception_sources(data, yaml_file.name)
        merged = _merge_fragment(merged, data)
        log.debug("Loaded config fragment: %s", yaml_file.name)
    return merged


def _load_exception_files(cfg: dict, cfg_dir: Path) -> dict:
    """Merge the file(s) named by ``exceptions_file`` into *cfg*.

    Lets the exception register live outside the config directory — e.g. in
    a repository owned by the change/risk team.  Relative paths resolve like
    ``inventory_file``: against the working directory, the config directory,
    then the project root.  An external file may hold only ``exceptions``
    and ``exception_settings``.
    """
    spec = cfg.get("exceptions_file")
    if not spec:
        return cfg
    paths = spec if isinstance(spec, list) else [spec]
    if not all(isinstance(item, str) and item.strip() for item in paths):
        return cfg  # reported by validation
    for raw in paths:
        path = _resolve_inventory_path(raw, cfg_dir)
        if path is None or not path.is_file():
            raise FileNotFoundError(f"exceptions_file not found: {raw}")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ValueError(_format_yaml_error("exceptions file", path, exc)) from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"Exceptions file '{path}' must be a YAML mapping at the top level, "
                f"got {type(data).__name__}."
            )
        unexpected = sorted(set(data) - _EXCEPTION_FILE_KEYS)
        if unexpected:
            raise ValueError(
                f"Exceptions file '{path}' may only contain "
                f"{' / '.join(sorted(_EXCEPTION_FILE_KEYS))}; found: {', '.join(unexpected)}"
            )
        _tag_exception_sources(data, str(raw))
        cfg = _merge_fragment(cfg, data)
        log.debug("Loaded exceptions file: %s", path)
    return cfg


def _resolve_config_path(path: str) -> Path:
    """Return the resolved config directory path (used for sibling lookups)."""
    p = Path(path)
    if p.is_dir():
        return p
    alt = Path(__file__).parent.parent / path
    if alt.is_dir():
        return alt
    return Path(__file__).parent.parent


def _resolve_inventory_path(inventory_path: str, cfg_dir: Path) -> Optional[Path]:
    """Resolve *inventory_path* to an existing file.

    Absolute paths are returned as-is.  Relative paths are tried against the
    current working directory, the config directory *cfg_dir*, and the project
    root (parent of this package), in that order.  The first candidate that
    exists is returned; if none exist, ``None`` is returned.
    """
    p = Path(inventory_path)
    if p.is_absolute():
        return p

    project_root = Path(__file__).parent.parent
    candidates = [
        Path.cwd() / p,   # relative to where the tool was invoked
        cfg_dir / p,      # relative to the config directory (sibling files)
        project_root / p,  # relative to the project root
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    # Fall back to the CWD-relative path so callers get a sensible path in
    # any "not found" diagnostics.
    return candidates[0]


def _normalise_device_entry(entry, *, location: str = "devices") -> dict:
    """Turn a bare string or dict into a normalised ``{hostname, ip}`` dict.

    Accepted forms:
      - ``"192.0.2.61"`` / ``"2001:db8::61"`` → ip-only (hostname discovered at connect)
      - ``"ZZ-LAB1-001ASW001"``  → hostname used as connection target (DNS)
      - ``{hostname: …, ip: …}``  → explicit (current format)
      - ``{hostname: …}``         → hostname used as connection target
      - ``{ip: …}``              → ip-only

    Entries are validated by :class:`~compliance_audit.inventory_schema.DeviceEntry`:
    ``ip`` must be a valid IPv4/IPv6 address and ``hostname`` a valid DNS name.
    Extra keys are preserved.

    Raises ``ValueError`` for entries that cannot be normalised.
    *location* is included in error messages to help the user find the problem.
    """
    if isinstance(entry, str) and not entry.strip():
        raise ValueError(
            f"Empty string in {location} — each entry must be a "
            "hostname, IP address, or {hostname: …, ip: …} mapping."
        )
    if not isinstance(entry, (str, dict)):
        raise ValueError(
            f"Invalid entry in {location} (expected string or mapping, "
            f"got {type(entry).__name__}): {entry!r}"
        )
    try:
        return parse_device_entry(entry).to_dict()
    except ValueError as exc:
        raise ValueError(format_entry_error(exc, location)) from exc


def _flatten_inventory(data: dict) -> list[dict]:
    """Merge flat ``devices:`` list and ``groups:`` into one list.

    Groups are organisational only — they have no role inheritance.
    Validates every entry and deduplicates by connection target (``ip``).
    """
    flat: list[dict] = []
    errors: list[str] = []

    # ── File layout: only ``devices`` and ``groups`` at the top level ──
    if not isinstance(data, dict):
        raise InventoryError(
            "Inventory validation failed:\n  • the file must be a YAML mapping "
            f"with 'devices' and/or 'groups', got {type(data).__name__}"
        )
    try:
        InventoryFile.model_validate(data)
    except ValidationError as exc:
        for e in exc.errors():
            loc = ".".join(str(p) for p in e["loc"])
            if e["type"] == "extra_forbidden":
                msg = "unknown key (expected 'devices' or 'groups'; a group holds 'devices')"
            elif e["type"] == "model_type":
                msg = "must be a mapping with a 'devices' list"
            else:
                msg = e["msg"]
            errors.append(f"{loc}: {msg}")
        raise InventoryError(
            "Inventory validation failed:\n  • " + "\n  • ".join(errors)
        ) from exc

    # ── Flat devices list ─────────────────────────────────────
    for idx, raw in enumerate(data.get("devices", []) or []):
        try:
            flat.append(_normalise_device_entry(raw, location=f"devices[{idx}]"))
        except ValueError as exc:
            errors.append(str(exc))

    # ── Grouped devices ──────────────────────────────────────
    for group_name, group_body in (data.get("groups") or {}).items():
        for idx, raw in enumerate(group_body.get("devices") or []):
            try:
                entry = _normalise_device_entry(
                    raw, location=f"groups.{group_name}.devices[{idx}]"
                )
            except ValueError as exc:
                errors.append(str(exc))
                continue
            entry.setdefault("_group", group_name)
            flat.append(entry)

    if errors:
        raise InventoryError("Inventory validation failed:\n  • " + "\n  • ".join(errors))

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


def parse_device_overrides(specs: list[str]) -> list[dict]:
    """Validate ``--device`` values (``HOST``, ``IP`` or ``HOST:IP``).

    IPv6 addresses are accepted whole.  All bad values are reported together.
    """
    devices: list[dict] = []
    errors: list[str] = []
    for spec in specs:
        try:
            devices.append(parse_device_target(spec).to_dict())
        except ValueError as exc:
            errors.append(format_entry_error(exc, f"--device {spec!r}"))
    if errors:
        raise InventoryError("Invalid --device value(s):\n  • " + "\n  • ".join(errors))
    return devices


class IpFilter:
    """An ``--ip-filter`` value: a CIDR block, an ``a-b`` range or one address.

    Membership is tested arithmetically, so ``10.0.0.0/8`` or an IPv6 /64
    costs nothing to build (the old implementation expanded every host into
    a set, which never finished for an IPv6 prefix).
    """

    def __init__(self, spec: str):
        self.spec = spec.strip()
        self._network = None
        self._range = None
        if "/" in self.spec:
            self._network = ipaddress.ip_network(self.spec, strict=False)
        elif "-" in self.spec:
            lo, _, hi = self.spec.partition("-")
            start = ipaddress.ip_address(lo.strip())
            end = ipaddress.ip_address(hi.strip())
            if start.version != end.version:
                raise ValueError("IP range mixes IPv4 and IPv6 addresses")
            if start > end:
                raise ValueError(f"IP range start {start} is greater than end {end}")
            self._range = (start, end)
        else:
            self._network = ipaddress.ip_network(self.spec)  # single address

    def __contains__(self, value) -> bool:
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        if self._network is not None:
            return ip.version == self._network.version and ip in self._network
        start, end = self._range
        return ip.version == start.version and start <= ip <= end


def _parse_ip_filter(ip_filter: str) -> IpFilter:
    """Parse an ``--ip-filter`` value; raises ``ValueError`` on bad input.

    Accepts CIDR (``192.168.0.0/24``), a range (``192.168.0.1-192.168.0.254``)
    or a single address.  Use ``ip in result`` to test an address.
    """
    return IpFilter(ip_filter)


def _resolve_addresses(hostname: str) -> list[str]:
    """Every address *hostname* resolves to (empty if it does not resolve)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []
    return sorted({info[4][0].split("%")[0] for info in infos})


def filter_devices_by_ip(
    devices: list[dict], ip_filter: str
) -> tuple[list[dict], list[str]]:
    """Keep devices whose address falls inside *ip_filter*.

    Devices listed by hostname only are resolved through DNS and kept if any
    of their addresses match, rather than being dropped silently.  Returns
    ``(kept, unresolved_hostnames)``.
    """
    flt = _parse_ip_filter(ip_filter)
    kept: list[dict] = []
    unresolved: list[str] = []
    for device in devices:
        target = str(device.get("ip", ""))
        if target in flt:
            kept.append(device)
            continue
        try:
            ipaddress.ip_address(target)
            continue  # a literal address outside the filter
        except ValueError:
            pass
        addresses = _resolve_addresses(target)
        if not addresses:
            unresolved.append(target)
        elif any(addr in flt for addr in addresses):
            log.info("--ip-filter: %s resolved to %s", target, ", ".join(addresses))
            kept.append(device)
    return kept, unresolved


def load_device_inventory(
    inventory_path: str | None,
    config_path: str,
    site_filter: Optional[list[str]] = None,
) -> list[dict]:
    """Load the device inventory from a dedicated YAML file.

    Value for *inventory_path* is taken from (in order):
    1. Explicit CLI value (--inventory).
    2. ``inventory_file`` key inside the main config YAML.
    3. The default ``assets/devices/devices.yaml``.

    A *relative* inventory path is then resolved against several base
    directories, in order, and the first existing file wins:
      a. the current working directory,
      b. the config directory (sibling of the config files),
      c. the project root (parent of the ``compliance_audit`` package).

    If *site_filter* is given, only devices whose ``_group`` matches one of
    the supplied site names are returned.  Devices from the flat list (no
    group) are excluded unless explicitly named via ``--device``.

    Supports both a flat ``devices:`` list and ``groups:``.
    """
    default_inventory = "assets/devices/devices.yaml"
    cfg_dir = _resolve_config_path(config_path)

    if inventory_path is None:
        cfg = load_compliance_config(config_path)
        inventory_path = cfg.get("inventory_file", default_inventory)

    inventory_path = inventory_path or default_inventory
    p = _resolve_inventory_path(inventory_path, cfg_dir)
    if p is None or not p.exists():
        log.warning(
            "Device inventory file not found: %s (looked relative to the "
            "current directory, the config directory %s, and the project root %s)",
            inventory_path,
            cfg_dir,
            Path(__file__).parent.parent,
        )
        return []

    with open(p, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise InventoryError(_format_yaml_error("device inventory", p, exc)) from exc
    devices = _flatten_inventory(data)

    if site_filter:
        normalised = [s.lower() for s in site_filter]
        devices = [d for d in devices if (d.get("_group") or "").lower() in normalised]

    return devices


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
    explicit_role: Optional[str] = None  # explicit role from devices.yaml
    group: str = ""                       # site group from inventory (_group key)
    exceptions: Optional[ExceptionRegister] = None  # approved policy exceptions
    error: str = ""  # why the device could not be audited (set by the worker)


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
            job.error = f"DNS resolution failed: {exc}"
        else:
            log.error("Connection to %s (%s) failed: %s", hostname, ip, exc)
            job.error = f"Connection failed: {exc}"
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
        job.error = f"Data collection failed: {exc}"
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
        engine = ComplianceEngine(job.compliance_policy, exceptions=job.exceptions)
        result = engine.audit(data, host_info, ports, group=job.group)
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
        setattr(result, "run_id", str(job.audit_settings.get("_run_id", "")))

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
        report_paths: dict[str, str] = {}
        if job.audit_settings.get("json_report", True):
            json_path = save_json(result, out_dir)
            if json_path:
                report_paths["json"] = str(json_path)
        if job.audit_settings.get("html_report", True):
            html_path = save_html(
                result,
                out_dir,
                report_title=job.audit_settings.get("report_title", ""),
                report_subtitle=job.audit_settings.get("report_subtitle", ""),
            )
            if html_path:
                report_paths["html"] = str(html_path)
        setattr(result, "_report_paths", report_paths)
        if rem.get("enabled") and rem.get("generate_script"):
            script_path = save_remediation_script(result, out_dir)
            if script_path and rem.get("generate_review_pack"):
                pack_path = generate_review_pack(result, script_path, out_dir)
                pack = json.loads(pack_path.read_text(encoding="utf-8"))
                setattr(result, "_pack", {
                    "pack_id": pack["pack_id"],
                    "highest_risk": pack["risk"]["highest"],
                    "findings_count": pack["summary"]["findings_count"],
                    "script_path": str(script_path),
                    "pack_path": str(pack_path),
                })
        if rem.get("enabled") and rem.get("generate_review_pack"):
            # This device has just been re-audited: any pack still pending
            # from an earlier run was written against an older config.
            supersede_pending_packs(
                out_dir, result.hostname, str(getattr(result, "run_id", ""))
            )

        # Delta reporting (compare against previous baseline).  Baselines are
        # the per-device JSON reports, so this needs json_report as well —
        # run_audit warns up-front when that combination is impossible.
        if job.audit_settings.get("delta_report", True) and job.audit_settings.get(
            "json_report", True
        ):
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


def _apply_result_filters(
    results: list[AuditResult],
    tags_filter: Optional[list[str]],
    min_severity: Optional[str],
    framework_filter: Optional[list[str]] = None,
) -> None:
    """Convert findings that don't match tag/severity/framework filters to SKIP in-place.

    Filtering happens *after* the audit so all checks still run; the full
    dataset is preserved in reports while the console summary reflects the
    active filters.
    """
    min_level = SEVERITY_ORDER.get(min_severity or "", 0)
    for result in results:
        for f in result.findings:
            if f.status == Status.SKIP:
                continue
            # Severity threshold
            if min_level > 0:
                finding_level = SEVERITY_ORDER.get(getattr(f, "severity", "medium"), 3)
                if finding_level < min_level:
                    f.status = Status.SKIP
                    f.detail = (
                        f"[filtered: severity '{getattr(f, 'severity', 'medium')}' "
                        f"below threshold '{min_severity}']"
                    )
                    continue
            # Tag filter
            if tags_filter:
                finding_tags = getattr(f, "tags", [])
                if not any(t in finding_tags for t in tags_filter):
                    f.status = Status.SKIP
                    f.detail = (
                        f"[filtered: tags {finding_tags!r} do not match "
                        f"requested {tags_filter!r}]"
                    )
                    continue
            # Framework filter — keep findings that have a control ID for the named framework
            if framework_filter:
                finding_controls = getattr(f, "framework_controls", {})
                if not any(
                    any(fw.lower() in k.lower() for k in finding_controls)
                    for fw in framework_filter
                ):
                    f.status = Status.SKIP
                    f.detail = (
                        f"[filtered: no framework controls matching {framework_filter!r}]"
                    )


def run_audit(
    config_path: str = "assets/compliance_config",
    device_overrides: Optional[list[str]] = None,
    skip_jump: bool = False,
    categories: Optional[list[str]] = None,
    output_dir: Optional[str] = None,
    csv_report: Optional[bool] = None,
    inventory_path: Optional[str] = None,
    tags_filter: Optional[list[str]] = None,
    min_severity: Optional[str] = None,
    site_filter: Optional[list[str]] = None,
    framework_filter: Optional[list[str]] = None,
    ip_filter: Optional[str] = None,
    notify: bool = False,
) -> list[AuditResult]:
    """
    Run the full compliance audit pipeline.

    Parameters
    ----------
    config_path : str
        Path to the compliance config directory (e.g. ``compliance_config/``).
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
    tags_filter : list[str] | None
        If given, only surface findings whose ``tags`` list contains at least
        one of these values.  Unmatched findings become SKIP.
    min_severity : str | None
        If given (critical/high/medium/low/info), findings below this severity
        level become SKIP.
    site_filter : list[str] | None
        If given, only audit devices belonging to these site/group names.
    ip_filter : str | None
        If given, restrict discovered devices to those whose IP address falls
        within the specified range.  Accepts CIDR notation (``192.168.0.0/24``)
        or a hyphen-separated range (``192.168.0.1-192.168.0.254``).
    notify : bool
        Email the run summary afterwards (``notifications.email`` in the
        config).  Used by scheduled runs (``--notify``).

    Every run writes a manifest to ``<output_dir>/runs/<run_id>.json`` and
    holds ``<output_dir>/.locks/audit.lock`` while it runs, so two audits
    never write to the same output directory at once.

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

    # Approved policy exceptions — built once and shared by every worker.
    exception_register = ExceptionRegister.from_config(cfg)
    if len(exception_register):
        counts = exception_register.state_counts()
        log.info(
            "Loaded %d policy exception(s): %s",
            len(exception_register),
            ", ".join(f"{n} {state}" for state, n in counts.items() if n),
        )

    # CLI overrides
    if output_dir:
        audit_settings["output_dir"] = output_dir
    if csv_report is not None:
        audit_settings["csv_report"] = csv_report

    # Resolve the output directory once, up-front.  It is otherwise used as
    # written in YAML ("./reports"), which is relative to the *current working
    # directory* — so the same config lands reports in different places
    # depending on where the tool was launched from.  Resolving here does not
    # move anything; it just makes the location explicit and printable.
    audit_settings["output_dir"] = str(
        Path(audit_settings.get("output_dir", "./reports")).expanduser().resolve()
    )
    log.info("Report output directory: %s", audit_settings["output_dir"])

    # Hold the audit lock for the rest of the run: a scheduled audit that
    # starts while another is still writing to this output directory stops
    # here instead of interleaving reports, packs and manifests.
    with exclusive_lock(audit_settings["output_dir"], "audit"):
        # Create the remediation review database now rather than lazily on the
        # first remediable finding, so a clean run still leaves an (empty) store
        # and the operator can see where it lives.
        if audit_settings.get("delta_report", True) and not audit_settings.get(
            "json_report", True
        ):
            console.print(
                "[bold yellow]Warning:[/] delta reporting is enabled but "
                "[cyan]json_report[/] is off — per-device JSON reports are the "
                "baseline, so no drift will ever be detected."
            )
            log.warning("delta_report enabled with json_report disabled — no baselines")

        review_db: Optional[Path] = None
        _rem_settings = get_remediation_settings(audit_settings)
        if _rem_settings.get("enabled") and _rem_settings.get("generate_review_pack"):
            try:
                review_db = ensure_review_store(audit_settings["output_dir"])
                log.info("Remediation review database: %s", review_db)
            except (OSError, sqlite3.Error) as exc:
                log.warning(
                    "Could not initialise remediation review database at %s: %s",
                    get_review_db_path(audit_settings["output_dir"]),
                    exc,
                )

        # Fall back to config-level defaults when not specified via CLI
        if min_severity is None:
            _cfg_sev = audit_settings.get("default_min_severity")
            if _cfg_sev and isinstance(_cfg_sev, str):
                min_severity = _cfg_sev
        if tags_filter is None:
            _cfg_tags = audit_settings.get("default_tags")
            if _cfg_tags and isinstance(_cfg_tags, list):
                tags_filter = list(_cfg_tags)

        # Inject connection retries into audit_settings so workers can access it
        audit_settings["_connection"] = conn_cfg
        run_started = datetime.now(timezone.utc)
        audit_settings["_run_id"] = run_started.strftime("audit-%Y%m%dT%H%M%S%fZ")

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
            devices = parse_device_overrides(device_overrides)
        else:
            devices = load_device_inventory(inventory_path, config_path, site_filter)

        # ── IP address filter ──────────────────────────────────
        if ip_filter:
            try:
                before = len(devices)
                devices, unresolved = filter_devices_by_ip(devices, ip_filter)
                if unresolved:
                    console.print(
                        f"[bold yellow]Warning:[/] {len(unresolved)} hostname-only "
                        "device(s) did not resolve and were left out of the IP filter: "
                        + ", ".join(unresolved),
                        highlight=False,
                    )
                log.info(
                    "IP filter '%s' matched %d/%d device(s)", ip_filter, len(devices), before
                )
                console.print(
                    f"[cyan]IP filter:[/] {ip_filter}  →  "
                    f"{len(devices)} of {before} device(s) in scope"
                )
            except ValueError as exc:
                raise InventoryError(f"Invalid --ip-filter value '{ip_filter}': {exc}") from exc

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
            host_key_checking = conn_cfg.get("host_key_checking", False)
            hk_policy = (
                paramiko.RejectPolicy() if host_key_checking
                else paramiko.AutoAddPolicy()
            )
            jump = JumpManager(jump_host, username, password, host_key_policy=hk_policy)
            jump.connect()

        if not devices:
            if site_filter:
                console.print(
                    f"[bold yellow]No devices found for site(s): {', '.join(site_filter)}.[/] "
                    "Check that the group names in assets/devices/devices.yaml match."
                )
            else:
                console.print(
                    "[bold yellow]No devices to audit.[/] "
                    "Add devices to assets/devices/devices.yaml or use --device."
                )
            if notify:
                from .notifications import notify_failure

                notify_failure(
                    cfg,
                    "The scheduled audit found no devices to audit"
                    + (f" for site(s) {', '.join(site_filter)}" if site_filter else "")
                    + ". Check the inventory file and any --site / --ip-filter options.",
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
                    explicit_role=explicit_role,  # explicit role from devices.yaml
                    group=dev_entry.get("_group", ""),
                    exceptions=exception_register,
                )
            )

        # ── Execute audits concurrently ────────────────────────
        results: list[AuditResult] = []
        unreachable: list[dict] = []

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
                                unreachable.append({
                                    "hostname": job.hostname,
                                    "ip": job.ip,
                                    "error": job.error or "Connection failed",
                                })
                                progress.console.print(
                                    f"  [red]FAIL[/] {job.hostname} ({job.ip}) - "
                                    f"{job.error or 'Connection failed'}",
                                    highlight=False,
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
                            unreachable.append({
                                "hostname": job.hostname,
                                "ip": job.ip,
                                "error": f"Audit failed: {exc}",
                            })
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
            show_exceptions = len(exception_register) > 0 or any(
                r.exception_count for r in results
            )
            if show_exceptions:
                summary_table.add_column("Exc", justify="center", style="blue")

            for r in results:
                score_style = "bold green" if r.fail_count == 0 else "bold red"
                row = [
                    r.hostname,
                    r.ip,
                    r.role_display or r.role or "",
                    f"[{score_style}]{r.score_pct}%[/]",
                    str(r.pass_count),
                    str(r.fail_count),
                    str(r.warn_count),
                    str(r.error_count),
                ]
                if show_exceptions:
                    exc_cell = str(r.exception_count)
                    if r.expired_exception_count:
                        exc_cell += f" [bold red]({r.expired_exception_count} expired)[/]"
                    row.append(exc_cell)
                summary_table.add_row(*row)

            console.print(summary_table)
            console.print()

            if show_exceptions:
                print_exception_summary(results, exception_register, console=console)

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

        # ── Apply tag / severity / framework filters ──────────────────────
        if results and (tags_filter or min_severity or framework_filter):
            _apply_result_filters(results, tags_filter, min_severity, framework_filter)
            active = []
            if min_severity:
                active.append(f"min-severity={min_severity}")
            if tags_filter:
                active.append(f"tags={tags_filter}")
            if framework_filter:
                active.append(f"framework={framework_filter}")
            console.print(
                f"[cyan]Filters applied:[/] {', '.join(active)}  "
                f"(non-matching findings shown as SKIP)"
            )
            # Per-device reports and remediation scripts are written by the worker
            # threads before filters are known, and deliberately keep the full
            # dataset.  Say so, rather than letting the operator assume a filtered
            # run produced a filtered script.
            console.print(
                "  [dim]Filters affect the console summary, the consolidated "
                "report and the exit code. Per-device reports and remediation "
                "scripts always contain the full, unfiltered result set.[/]"
            )

        # ── CSV export ─────────────────────────────────────────
        report_paths: dict[str, str] = {}
        if results and audit_settings.get("csv_report", False):
            csv_path = save_csv(results, out_dir, run_id=audit_settings.get("_run_id", ""))
            console.print(f"  [bold cyan]CSV report:[/] {csv_path}")
            if csv_path:
                report_paths["csv"] = str(csv_path)

        # ── Consolidated HTML report ───────────────────────────
        if results and audit_settings.get("html_report", True):
            p = save_consolidated_html(
                results,
                out_dir,
                report_title=audit_settings.get("report_title", ""),
                report_subtitle=audit_settings.get("report_subtitle", ""),
                run_id=audit_settings.get("_run_id", ""),
                exception_register=exception_register,
            )
            console.print(f"  [bold cyan]HTML report:[/] {p}")
            if p:
                report_paths["consolidated_html"] = str(p)

        # ── Run manifest ───────────────────────────────────────
        from . import __version__

        exc_summary = run_summary(results, exception_register)
        manifest = build_manifest(
            run_id=audit_settings["_run_id"],
            started_at=run_started,
            results=results,
            unreachable=unreachable,
            config_path=str(_resolve_config_path(config_path).resolve()),
            output_dir=out_dir,
            tool_version=__version__,
            exception_summary={
                "expired": exc_summary["expired"],
                "expiring": exc_summary["expiring"],
                "unused": [row["id"] for row in exc_summary["unused"]],
            },
            reports=report_paths,
            scope={
                "devices": list(device_overrides or []),
                "sites": list(site_filter or []),
                "ip_filter": ip_filter or "",
                "categories": list(categories or []),
                "tags": list(tags_filter or []),
                "min_severity": min_severity or "",
                "frameworks": list(framework_filter or []),
            },
        )
        manifest_file = write_manifest(out_dir, manifest)

        if results or unreachable:
            console.print(f"  [bold cyan]Run ID:[/] {manifest['run_id']}")
            console.print(f"  [bold cyan]Run summary:[/] {manifest_file}")
        if results:
            console.print(f"  [bold cyan]Output directory:[/] {out_dir}")
            if review_db:
                console.print(f"  [bold cyan]Review database:[/] {review_db}")
        if manifest["totals"]["packs"]:
            console.print(
                f"  [bold]{manifest['totals']['packs']} remediation pack(s) await approval.[/] "
                f"Review with [cyan]--run-show {manifest['run_id']}[/], then "
                f"[cyan]--run-approve {manifest['run_id']}[/] (--apply-now or --apply-at TIME) "
                f"or [cyan]--run-reject {manifest['run_id']}[/]."
            )
        console.print()

        # ── Notification ───────────────────────────────────────
        if notify:
            from .notifications import notify_run

            outcome = notify_run(cfg, manifest)
            write_manifest(out_dir, {**manifest, "notification": outcome})
            if outcome.get("sent"):
                console.print(
                    f"[green]Run summary emailed to {', '.join(outcome.get('to', []))}[/]"
                )
            elif outcome.get("skipped"):
                console.print(f"[dim]No email sent: {outcome['skipped']}[/]")
            else:
                console.print(f"[bold red]Email notification failed:[/] {outcome.get('error')}")

        return results
