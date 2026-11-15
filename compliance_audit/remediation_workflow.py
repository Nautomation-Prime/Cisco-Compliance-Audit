"""
Review, approval, and controlled execution workflow for remediation commands.

This module is designed for Linux CLI operation and keeps a durable local
state store (SQLite) so approvals and execution history are auditable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml
from netmiko.exceptions import NetmikoBaseException
from paramiko.ssh_exception import SSHException
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from .collector import DataCollector
from .compliance_engine import AuditResult, ComplianceEngine, Status, _build_check_map
from .credentials import CredentialHandler
from .hostname_parser import parse_hostname
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .policy_exceptions import ExceptionRegister
from .port_classifier import classify_ports
from .remediation_cli import print_review_entries_table
from .report import save_consolidated_html, save_csv, save_html, save_json

log = logging.getLogger(__name__)
console = Console()

DEVICE_OPERATION_ERRORS = (
    AttributeError,
    NetmikoBaseException,
    OSError,
    RuntimeError,
    SSHException,
    TimeoutError,
    TypeError,
    ValueError,
)
WORKFLOW_ERRORS = DEVICE_OPERATION_ERRORS + (LookupError, sqlite3.Error, yaml.YAMLError)


def get_remediation_settings(audit_settings: Optional[dict]) -> dict:
    """Resolve remediation settings from audit_settings.remediation config node."""
    settings = audit_settings or {}
    remediation_node = settings.get("remediation", {})
    if not isinstance(remediation_node, dict):
        remediation_node = {}

    approval = remediation_node.get("approval", {})
    if not isinstance(approval, dict):
        approval = {}
    execution = remediation_node.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}

    enabled = bool(remediation_node.get("enabled", True))

    return {
        "enabled": enabled,
        "generate_script": bool(remediation_node.get("generate_script", enabled)),
        "generate_review_pack": bool(
            remediation_node.get("generate_review_pack", enabled)
        ),
        "approval_default_expires_hours": int(
            approval.get("default_expires_hours", 24)
        ),
        "approval_require_ticket_id": bool(approval.get("require_ticket_id", True)),
        "execution_enabled": bool(execution.get("enabled", False)),
        "execution_linux_only": bool(execution.get("linux_only", True)),
        "execution_block_high_risk": bool(
            execution.get("block_high_risk_by_default", True)
        ),
        "execution_enforce_checksum": bool(execution.get("enforce_checksum", True)),
        "execution_preflight_drift_check": bool(
            execution.get("preflight_drift_check", True)
        ),
        "execution_require_hostname_match": bool(
            execution.get("require_hostname_match", True)
        ),
        "execution_save_config": bool(execution.get("save_config", True)),
        "execution_cmd_verify": bool(execution.get("command_verify", False)),
        "execution_allow_bulk_apply": bool(execution.get("allow_bulk_apply", True)),
        "execution_generate_post_report": bool(
            execution.get("generate_post_report", True)
        ),
        "execution_generate_consolidated_post_report": bool(
            execution.get("generate_consolidated_post_report", True)
        ),
        "execution_post_report_formats": list(
            execution.get("post_report_formats", ["json", "html"])
        ),
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_str() -> str:
    return _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name) if name else "unknown"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _risk_for_command(command: str, category: str, check_name: str) -> str:
    cmd = command.lower()
    cat = (category or "").lower()
    chk = (check_name or "").lower()

    high_tokens = (
        "aaa ",
        "tacacs",
        "radius",
        "snmp-server community",
        "snmp-server host",
        "router ospf",
        "router bgp",
        "router eigrp",
        "ip access-list",
        "control-plane",
        "ip route",
    )
    medium_tokens = (
        "spanning-tree",
        "switchport trunk",
        "ip dhcp snooping",
        "ip arp inspection",
        "vlan",
        "vtp ",
        "storm-control",
    )

    if any(tok in cmd for tok in high_tokens):
        return "high"
    if any(tok in cmd for tok in medium_tokens):
        return "medium"
    if cat in {"management_plane", "control_plane"} and ("aaa" in chk or "snmp" in chk):
        return "high"
    if cat in {"control_plane", "data_plane"}:
        return "medium"
    return "low"


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


@dataclass
class ReviewEntry:
    pack_id: str
    hostname: str
    ip: str
    status: str
    highest_risk: str
    findings_count: int
    created_ts: str
    approved_by: str
    approved_at: str
    ticket_id: str
    expires_at: str
    script_path: str
    pack_path: str
    run_id: str = ""          # audit run that generated the pack ("" = older pack)
    scheduled_for: str = ""   # UTC time an approved pack is due to be applied


#: Lifecycle statuses a review pack can be in.
PACK_STATUSES = (
    "pending",
    "approved",
    "rejected",
    "applied",
    "failed",
    "expired",
    "superseded",
)

#: Columns added after the first release of the review store; created on
#: existing databases by ``ReviewStore._init_schema``.
_MIGRATED_COLUMNS = ("run_id", "scheduled_for")


def _parse_utc(value: str) -> Optional[datetime]:
    """Parse a stored ``YYYY-MM-DDTHH:MM:SSZ`` timestamp; ``None`` if blank/bad."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class ReviewStore:
    """SQLite-backed state for remediation review and execution lifecycle."""

    def __init__(self, db_path: Path):
        """Create a review-state store backed by the given SQLite path."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_reviews (
                    pack_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    highest_risk TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    created_ts TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    ticket_id TEXT,
                    expires_at TEXT,
                    rejected_by TEXT,
                    rejected_at TEXT,
                    reject_reason TEXT,
                    script_path TEXT NOT NULL,
                    script_sha256 TEXT NOT NULL,
                    pack_path TEXT NOT NULL,
                    applied_at TEXT,
                    apply_status TEXT,
                    apply_summary TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reviews_status "
                "ON remediation_reviews(status)"
            )
            existing = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(remediation_reviews)")
            }
            for column in _MIGRATED_COLUMNS:
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE remediation_reviews ADD COLUMN {column} TEXT DEFAULT ''"
                    )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reviews_run ON remediation_reviews(run_id)"
            )

    def upsert_from_pack(self, pack: dict, pack_path: Path) -> None:
        """Insert or update review metadata from a remediation pack."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remediation_reviews (
                    pack_id, hostname, ip, status, highest_risk, findings_count,
                    created_ts, approved_by, approved_at, ticket_id, expires_at,
                    rejected_by, rejected_at, reject_reason,
                    script_path, script_sha256, pack_path,
                    applied_at, apply_status, apply_summary,
                    run_id, scheduled_for
                ) VALUES (
                    :pack_id, :hostname, :ip, :status, :highest_risk, :findings_count,
                    :created_ts, :approved_by, :approved_at, :ticket_id, :expires_at,
                    :rejected_by, :rejected_at, :reject_reason,
                    :script_path, :script_sha256, :pack_path,
                    :applied_at, :apply_status, :apply_summary,
                    :run_id, :scheduled_for
                )
                ON CONFLICT(pack_id) DO UPDATE SET
                    status=excluded.status,
                    approved_by=excluded.approved_by,
                    approved_at=excluded.approved_at,
                    ticket_id=excluded.ticket_id,
                    expires_at=excluded.expires_at,
                    rejected_by=excluded.rejected_by,
                    rejected_at=excluded.rejected_at,
                    reject_reason=excluded.reject_reason,
                    script_path=excluded.script_path,
                    script_sha256=excluded.script_sha256,
                    pack_path=excluded.pack_path,
                    applied_at=excluded.applied_at,
                    apply_status=excluded.apply_status,
                    apply_summary=excluded.apply_summary,
                    run_id=excluded.run_id,
                    scheduled_for=excluded.scheduled_for
                """,
                {
                    "pack_id": pack["pack_id"],
                    "hostname": pack["device"]["hostname"],
                    "ip": pack["device"]["ip"],
                    "status": pack["lifecycle"]["status"],
                    "highest_risk": pack["risk"]["highest"],
                    "findings_count": pack["summary"]["findings_count"],
                    "created_ts": pack["created_ts"],
                    "approved_by": pack["approval"].get("approved_by", ""),
                    "approved_at": pack["approval"].get("approved_at", ""),
                    "ticket_id": pack["approval"].get("ticket_id", ""),
                    "expires_at": pack["approval"].get("expires_at", ""),
                    "rejected_by": pack["approval"].get("rejected_by", ""),
                    "rejected_at": pack["approval"].get("rejected_at", ""),
                    "reject_reason": pack["approval"].get("reject_reason", ""),
                    "script_path": pack["script"]["path"],
                    "script_sha256": pack["script"]["sha256"],
                    "pack_path": str(pack_path),
                    "applied_at": pack["execution"].get("applied_at", ""),
                    "apply_status": pack["execution"].get("status", ""),
                    "apply_summary": pack["execution"].get("summary", ""),
                    "run_id": pack.get("run_id", ""),
                    "scheduled_for": pack["approval"].get("scheduled_for", ""),
                },
            )

    def list(
        self,
        status: Optional[str] = None,
        *,
        run_id: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> list[ReviewEntry]:
        """Return review entries, optionally filtered by status, run and device."""
        q = """
            SELECT pack_id, hostname, ip, status, highest_risk, findings_count,
                   created_ts, approved_by, approved_at, ticket_id, expires_at,
                   script_path, pack_path,
                   COALESCE(run_id, '') AS run_id,
                   COALESCE(scheduled_for, '') AS scheduled_for
            FROM remediation_reviews
        """
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if run_id is not None:
            clauses.append("COALESCE(run_id, '') = ?")
            params.append(run_id)
        if hostname is not None:
            clauses.append("hostname = ?")
            params.append(hostname)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_ts DESC"

        with self._connect() as conn:
            rows = conn.execute(q, tuple(params)).fetchall()

        return [ReviewEntry(**dict(row)) for row in rows]

    def get_pack_path(self, pack_id: str) -> Optional[Path]:
        """Return on-disk pack path for a review-pack ID, if present."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT pack_path FROM remediation_reviews WHERE pack_id = ?",
                (pack_id,),
            ).fetchone()
        if not row:
            return None
        return Path(str(row["pack_path"]))


def _build_command_groups(findings: list[dict]) -> dict:
    global_cmds: list[str] = []
    section_map: dict[str, list[str]] = {}

    for item in findings:
        cmd = (item.get("command") or "").strip()
        if not cmd:
            continue
        interface = (item.get("interface") or "").strip()

        if interface:
            context = (
                interface if interface.startswith("line ") else f"interface {interface}"
            )
            section_map.setdefault(context, []).append(cmd)
        else:
            global_cmds.append(cmd)

    sections = [
        {"context": ctx, "commands": _dedupe_keep_order(cmds)}
        for ctx, cmds in sorted(section_map.items())
    ]

    return {
        "global": _dedupe_keep_order(global_cmds),
        "sections": sections,
    }


def _flatten_apply_commands(command_groups: dict) -> list[str]:
    commands: list[str] = []
    commands.extend(command_groups.get("global", []))

    for section in command_groups.get("sections", []):
        context = (section.get("context") or "").strip()
        if not context:
            continue
        commands.append(context)
        commands.extend(section.get("commands") or [])
        commands.append("exit")

    return commands


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _validate_linux_only() -> None:
    if platform.system() != "Linux":
        raise RuntimeError(
            "Remediation lifecycle commands are Linux-only in this release."
        )


def _load_config(config_path: str) -> dict:
    """Load and validate the compliance config directory.

    Raises ``RuntimeError`` rather than exiting, because this also runs under
    the web/API integration surfaces.
    """
    from .auditor import read_compliance_config

    try:
        return read_compliance_config(config_path)
    except (OSError, ValueError) as exc:
        raise RuntimeError(str(exc)) from exc


def _open_device_connection(config: dict, ip: str, skip_jump: bool):
    conn_cfg = config.get("connection", {})
    cred_store = conn_cfg.get("credential_store", "none")
    keyring_svc = conn_cfg.get("keyring_service", "cisco-compliance-audit")
    cred_handler = CredentialHandler(
        credential_store=cred_store,
        keyring_service=keyring_svc,
    )
    username, password = cred_handler.get_secret_with_fallback()
    enable_secret = cred_handler.get_enable_secret()

    return _open_device_connection_with_creds(
        config, ip, username, password, enable_secret, skip_jump
    )


def _open_device_connection_with_creds(
    config: dict,
    ip: str,
    username: str,
    password: str,
    enable_secret: Optional[str],
    skip_jump: bool,
):
    """Open device connection using provided credentials (no prompting)."""
    conn_cfg = config.get("connection", {})

    jump = None
    jump_host = conn_cfg.get("jump_host")
    use_jump = conn_cfg.get("use_jump_host", True)
    if jump_host and use_jump and not skip_jump:
        jump = JumpManager(jump_host, username, password)
        jump.connect()

    connector = DeviceConnector(
        ip=ip,
        username=username,
        password=password,
        device_type=conn_cfg.get("device_type", "cisco_ios"),
        jump=jump,
        retries=conn_cfg.get("retries", 3),
        **({"secret": enable_secret} if enable_secret else {}),
    )
    return connector.connect(), jump


def _generate_post_remediation_report(
    connection,
    hostname: str,
    ip: str,
    compliance_policy: dict,
    role_config: Optional[list],
    endpoint_config: Optional[dict],
    timeout: int,
    output_dir: str,
    report_formats: list[str],
    progress,
    run_id: str = "",
    exceptions: Optional[ExceptionRegister] = None,
    group: str = "",
) -> AuditResult | None:
    """
    Generate a post-remediation compliance audit report.

    Args:
        connection: Active device connection
        hostname: Device hostname
        ip: Device IP address
        compliance_policy: Compliance configuration
        role_config: Hostname role configuration
        endpoint_config: Endpoint neighbor configuration
        timeout: Collection timeout
        output_dir: Directory to save reports
        report_formats: List of report formats to generate (json, html, csv, txt)
        progress: Rich Progress instance for status updates
    """
    from . import __version__

    task = progress.add_task("[cyan]Generating post-remediation report...", total=None)
    start_time = time.monotonic()

    try:
        # Collect fresh data from the device
        collector = DataCollector(timeout=timeout)
        data = collector.collect(connection, ip=ip)
        data.hostname = hostname

        # Classify ports
        ports = classify_ports(
            data, role_config=role_config, endpoint_config=endpoint_config
        )

        # Run compliance audit
        audit_settings = compliance_policy.get("_audit_settings", {})
        host_info = parse_hostname(hostname, role_config=role_config)
        engine = ComplianceEngine(compliance_policy, exceptions=exceptions)
        result = engine.audit(data, host_info, ports, group=group)
        setattr(result, "run_id", run_id or "")

        # Import lazily to avoid circular import at module load time.
        from .auditor import _estimate_roi_for_result, _get_roi_settings

        # Populate metadata (must come before ROI so duration_secs is available)
        result.duration_secs = round(time.monotonic() - start_time, 1)
        result.audit_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        result.tool_version = __version__

        # Attach ROI data so reports can show savings information
        roi_settings = _get_roi_settings(audit_settings)
        if roi_settings["enabled"]:
            roi = _estimate_roi_for_result(
                result,
                roi_settings,
                context="post_remediation",
            )
            setattr(result, "_roi", roi)
            result.roi = roi

        # Extract IOS-XE version from Genie data
        if data.version:
            ver = data.version.get("version", {})
            result.ios_version = ver.get("version", "") or ver.get("xe_version", "")

        # Create subdirectory for post-remediation reports
        post_report_dir = Path(output_dir) / "post_remediation"
        post_report_dir.mkdir(exist_ok=True)

        # Generate reports in requested formats
        report_paths = []
        if "json" in report_formats:
            path = save_json(result, str(post_report_dir))
            if path:
                report_paths.append(path)

        if "html" in report_formats:
            path = save_html(result, str(post_report_dir))
            if path:
                report_paths.append(path)

        if "csv" in report_formats:
            path = save_csv([result], str(post_report_dir))
            if path:
                report_paths.append(path)

        progress.update(task, description="[green]✓ Post-remediation report generated")
        progress.stop_task(task)

        # Show report paths
        if report_paths:
            progress.console.print("[dim]Post-remediation reports saved:[/]")
            for path in report_paths:
                progress.console.print(f"  [dim]• {path}[/]")

        return result

    except WORKFLOW_ERRORS as exc:
        progress.update(task, description=f"[yellow]⚠ Report generation failed: {exc}")
        progress.stop_task(task)
        log.warning("Post-remediation report generation failed: %s", exc)
        return None


def _generate_consolidated_post_remediation_report(
    results: list[AuditResult],
    output_dir: str,
    report_formats: list[str],
) -> list[Path]:
    """Generate consolidated post-remediation reports from per-device post results."""
    if not results:
        return []

    post_report_dir = Path(output_dir) / "post_remediation"
    post_report_dir.mkdir(exist_ok=True)

    generated_paths: list[Path] = []
    formats = {fmt.lower() for fmt in report_formats}

    if "html" in formats:
        html_path = save_consolidated_html(results, str(post_report_dir))
        if html_path:
            generated_paths.append(html_path)

    if "csv" in formats:
        csv_path = save_csv(results, str(post_report_dir))
        if csv_path:
            generated_paths.append(csv_path)

    return generated_paths


def _collect_fail_set(
    connection,
    hostname: str,
    ip: str,
    compliance_policy: dict,
    role_config: Optional[list],
    endpoint_config: Optional[dict],
    timeout: int,
    exceptions: Optional[ExceptionRegister] = None,
    group: str = "",
) -> set[tuple[str, str]]:
    """``(check, interface)`` of every remediable FAIL on the live device.

    Exceptions are applied exactly as in the audit, so a finding covered by
    one is never in the set — and so never in the apply plan.
    """
    collector = DataCollector(timeout=timeout)
    data = collector.collect(connection, ip=ip)
    data.hostname = hostname

    ports = classify_ports(
        data,
        role_config=role_config,
        endpoint_config=endpoint_config,
    )
    engine = ComplianceEngine(compliance_policy, exceptions=exceptions)
    host_info = parse_hostname(hostname, role_config=role_config)
    result = engine.audit(data, host_info, ports, group=group)

    return {
        (f.check_name, f.interface)
        for f in result.findings
        if f.status == Status.FAIL and f.remediation and f.exception is None
    }


def _split_excepted_items(
    items: list[dict],
    register: ExceptionRegister,
    *,
    hostname: str,
    ip: str,
    role: str,
    group: Optional[str],
    check_map: dict[str, dict],
) -> tuple[list[dict], list[dict]]:
    """Split pack items into ``(still_allowed, covered_by_an_exception)``.

    Checked at apply time against the exceptions in force *now*, so a pack
    generated before an exception was added can never push the excepted
    change — whether the exception is active or already expired, and whether
    or not the preflight drift check is enabled.
    """
    allowed: list[dict] = []
    excepted: list[dict] = []
    for item in items:
        rule = register.covering_rule(
            hostname=hostname,
            ip=ip,
            role=role,
            group=group,
            check_name=item.get("check_name", ""),
            interface=item.get("interface", "") or "",
            detail=item.get("detail", "") or "",
            check_map=check_map,
        )
        if rule is None:
            allowed.append(item)
        else:
            state, _days = register.state_of(rule)
            excepted.append({**item, "exception_id": rule.id, "exception_state": state})
    return allowed, excepted


def _highest_risk(findings: list[dict]) -> str:
    levels = {"low": 1, "medium": 2, "high": 3}
    highest = "low"
    for item in findings:
        level = item.get("risk", "low")
        if levels.get(level, 0) > levels.get(highest, 0):
            highest = level
    return highest


def get_review_db_path(output_dir: str) -> Path:
    """Return the SQLite review-database path for an output directory."""
    return Path(output_dir).expanduser() / "db" / "remediation_reviews.db"


def ensure_review_store(output_dir: str) -> Path:
    """Create the review database (and its schema) if it does not exist yet.

    The store is otherwise only created as a side effect of writing the first
    review pack, so a run that finds nothing to remediate leaves no database
    at all.  Calling this up-front means the file always exists and its path
    can be reported to the operator.
    """
    db_path = get_review_db_path(output_dir)
    ReviewStore(db_path)
    return db_path


def _default_db_path(output_dir: str) -> Path:
    return get_review_db_path(output_dir)


def generate_review_pack(result, script_path: Path, output_dir: str) -> Path:
    """Create a review/approval pack JSON for one device remediation script."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    fails = [
        f for f in result.findings
        if f.status == Status.FAIL and f.remediation and f.exception is None
    ]
    findings: list[dict] = []
    for idx, finding in enumerate(fails, start=1):
        command = finding.remediation.strip()
        if not command:
            continue
        findings.append(
            {
                "item_id": f"{result.hostname}-{idx:04d}",
                "check_name": finding.check_name,
                "category": finding.category,
                "interface": finding.interface,
                "detail": finding.detail,
                "command": command,
                "risk": _risk_for_command(
                    command, finding.category, finding.check_name
                ),
            }
        )

    # The run ID keeps pack IDs unique per run: audit_ts is per-minute and the
    # script name per-second, so two runs of a device close together would
    # otherwise collide and the later pack would overwrite the earlier one.
    pack_id_seed = (
        f"{result.hostname}|{result.ip}|{result.audit_ts}|{script_path.name}"
        f"|{getattr(result, 'run_id', '')}"
    )
    pack_id = hashlib.sha256(pack_id_seed.encode("utf-8")).hexdigest()[:16]

    risk_counts = {
        "low": sum(1 for i in findings if i["risk"] == "low"),
        "medium": sum(1 for i in findings if i["risk"] == "medium"),
        "high": sum(1 for i in findings if i["risk"] == "high"),
    }

    pack = {
        "schema_version": 1,
        "pack_id": pack_id,
        # The audit run that produced this pack — lets a whole run be
        # approved, scheduled or rejected with one command.
        "run_id": str(getattr(result, "run_id", "") or ""),
        "created_ts": _utc_now_str(),
        "device": {
            "hostname": result.hostname,
            "ip": result.ip,
            "role": result.role,
            "role_display": result.role_display,
            "ios_version": result.ios_version,
            # Recorded so apply-time exception checks can match group selectors.
            "group": getattr(result, "group", ""),
        },
        "summary": {
            "score_pct": result.score_pct,
            "findings_count": len(findings),
            "source_audit_ts": result.audit_ts,
            "tool_version": result.tool_version,
        },
        "script": {
            "path": str(script_path),
            "sha256": _sha256_file(script_path),
        },
        "risk": {
            "counts": risk_counts,
            "highest": _highest_risk(findings),
        },
        "lifecycle": {
            "status": "pending",
        },
        "approval": {
            "approved_by": "",
            "approved_at": "",
            "ticket_id": "",
            "expires_at": "",
            "rejected_by": "",
            "rejected_at": "",
            "reject_reason": "",
            "scheduled_for": "",
            "allow_high_risk": False,
        },
        "execution": {
            "status": "",
            "applied_at": "",
            "summary": "",
            "preflight_still_failing": 0,
            "postcheck_resolved": 0,
        },
        "findings": findings,
        "command_groups": _build_command_groups(findings),
        # Informational: findings left out because a policy exception covers
        # them.  Nothing here is ever applied.
        "exceptions_excluded": [
            {
                "check_name": f.check_name,
                "interface": f.interface,
                "exception_id": f.exception.id,
                "exception_state": f.exception.state,
                "expires": f.exception.expires,
            }
            for f in result.findings
            if f.status == Status.EXCEPTION and f.exception is not None
        ],
    }

    filename = outdir / f"{_safe_name(result.hostname)}_review_{pack_id}.json"
    _write_json(filename, pack)

    store = ReviewStore(_default_db_path(output_dir))
    store.upsert_from_pack(pack, filename)
    return filename


def list_review_packs(
    output_dir: str,
    status: Optional[str] = None,
    *,
    run_id: Optional[str] = None,
    hostname: Optional[str] = None,
) -> list[ReviewEntry]:
    """List persisted remediation review packs for an output directory."""
    store = ReviewStore(_default_db_path(output_dir))
    return store.list(status=status, run_id=run_id, hostname=hostname)


def supersede_pending_packs(output_dir: str, hostname: str, current_run_id: str) -> list[str]:
    """Mark *hostname*'s pending packs from earlier runs as ``superseded``.

    Called after a device is re-audited.  A pending pack from an older run
    holds a script written against an older configuration; approving it
    later would try to push stale changes.  Only ``pending`` packs are
    touched — an approved (possibly scheduled) pack is a decision someone
    already made, and the preflight drift check guards it at apply time.

    Returns the IDs of the packs superseded.
    """
    if not current_run_id:
        return []
    store = ReviewStore(_default_db_path(output_dir))
    superseded: list[str] = []
    for entry in store.list(status="pending", hostname=hostname):
        if entry.run_id == current_run_id:
            continue
        pack_path = Path(entry.pack_path)
        if not pack_path.exists():
            continue
        pack = _read_json(pack_path)
        pack["lifecycle"]["status"] = "superseded"
        pack["lifecycle"]["superseded_by_run"] = current_run_id
        pack["lifecycle"]["superseded_at"] = _utc_now_str()
        _write_json(pack_path, pack)
        store.upsert_from_pack(pack, pack_path)
        superseded.append(entry.pack_id)
    if superseded:
        log.info(
            "Superseded %d pending pack(s) for %s by run %s: %s",
            len(superseded), hostname, current_run_id, ", ".join(superseded),
        )
    return superseded


def _load_pack_for_update(
    output_dir: str, pack_id: str
) -> tuple[dict, Path, ReviewStore]:
    store = ReviewStore(_default_db_path(output_dir))
    pack_path = store.get_pack_path(pack_id)
    if not pack_path or not pack_path.exists():
        raise RuntimeError(f"Review pack not found: {pack_id}")
    pack = _read_json(pack_path)
    return pack, pack_path, store


def get_review_pack(output_dir: str, pack_id: str) -> dict:
    """Load one remediation review pack payload by pack ID."""
    pack, _, _ = _load_pack_for_update(output_dir, pack_id)
    return pack


def approve_review_pack(
    output_dir: str,
    pack_id: str,
    approver: str,
    ticket_id: str,
    expires_hours: int = 24,
    require_ticket_id: bool = True,
    *,
    scheduled_for: Optional[datetime] = None,
    allow_high_risk: bool = False,
) -> Path:
    """Approve a pending review pack and set approval metadata.

    *scheduled_for* (UTC) records when the pack may be applied; the
    approval window then runs from that time rather than from now, so a
    change scheduled for next week does not expire before it is due.
    *allow_high_risk* records that the approver accepted high-risk commands,
    so a scheduled apply — which has nobody to pass ``--allow-high-risk`` —
    can proceed.
    """
    if not approver.strip():
        raise RuntimeError("Approver must be provided.")
    if require_ticket_id and not ticket_id.strip():
        raise RuntimeError("Ticket ID must be provided.")

    pack, pack_path, store = _load_pack_for_update(output_dir, pack_id)
    current_status = pack["lifecycle"]["status"]
    if current_status in {"applied", "expired", "rejected", "superseded", "failed"}:
        raise RuntimeError(
            f"Cannot approve a pack with status '{current_status}'. "
            "Generate a fresh pack from a new audit run."
        )
    if scheduled_for is not None and scheduled_for <= _utc_now():
        raise RuntimeError("The scheduled apply time must be in the future.")

    window_start = scheduled_for or _utc_now()
    expires = window_start + timedelta(hours=max(1, expires_hours))
    pack["lifecycle"]["status"] = "approved"
    pack["approval"]["approved_by"] = approver.strip()
    pack["approval"]["approved_at"] = _utc_now_str()
    pack["approval"]["ticket_id"] = ticket_id.strip()
    pack["approval"]["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    pack["approval"]["scheduled_for"] = (
        scheduled_for.strftime("%Y-%m-%dT%H:%M:%SZ") if scheduled_for else ""
    )
    pack["approval"]["allow_high_risk"] = bool(allow_high_risk)
    pack["approval"]["rejected_by"] = ""
    pack["approval"]["rejected_at"] = ""
    pack["approval"]["reject_reason"] = ""

    _write_json(pack_path, pack)
    store.upsert_from_pack(pack, pack_path)
    return pack_path


def reject_review_pack(
    output_dir: str, pack_id: str, approver: str, reason: str
) -> Path:
    """Reject a review pack and record rejection details."""
    if not approver.strip():
        raise RuntimeError("Approver must be provided.")
    if not reason.strip():
        raise RuntimeError("Reject reason must be provided.")

    pack, pack_path, store = _load_pack_for_update(output_dir, pack_id)
    if pack["lifecycle"]["status"] == "applied":
        raise RuntimeError("Cannot reject a pack that was already applied.")

    pack["lifecycle"]["status"] = "rejected"
    pack["approval"]["rejected_by"] = approver.strip()
    pack["approval"]["rejected_at"] = _utc_now_str()
    pack["approval"]["reject_reason"] = reason.strip()

    _write_json(pack_path, pack)
    store.upsert_from_pack(pack, pack_path)
    return pack_path


def apply_approved_pack(
    config_path: str,
    output_dir: str,
    pack_id: str,
    skip_jump: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
    post_report_callback: Optional[Callable[[AuditResult], None]] = None,
    ignore_schedule: bool = False,
) -> dict:
    """Apply a previously approved remediation pack with preflight and postcheck.

    A pack approved with a scheduled time is refused until that time,
    unless *ignore_schedule* is set.
    """
    pack, pack_path, store = _load_pack_for_update(output_dir, pack_id)

    status = pack["lifecycle"]["status"]
    if status != "approved":
        raise RuntimeError(
            f"Pack must be approved before apply; current status: {status}"
        )

    scheduled = _parse_utc(pack["approval"].get("scheduled_for", ""))
    if scheduled is not None and not ignore_schedule and _utc_now() < scheduled:
        raise RuntimeError(
            f"Pack is scheduled to be applied at {format_schedule(scheduled)}; "
            "it is applied by --remediation-apply-due at that time. To apply it "
            "now instead, re-approve it with --apply-now."
        )

    expires_at = pack["approval"].get("expires_at", "")
    if expires_at:
        expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        if _utc_now() > expiry:
            pack["lifecycle"]["status"] = "expired"
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)
            raise RuntimeError("Approval has expired. Re-approve before apply.")

    script_path = Path(pack["script"]["path"])
    if not script_path.exists():
        raise RuntimeError(f"Remediation script not found: {script_path}")
    cfg = _load_config(config_path)
    rem = remediation_settings or get_remediation_settings(
        cfg.get("audit_settings", {})
    )

    if not rem.get("enabled", True):
        raise RuntimeError(
            "Remediation workflow is disabled in config "
            "(audit_settings.remediation.enabled=false)."
        )
    if not rem.get("execution_enabled", True):
        raise RuntimeError(
            "Remediation execution is disabled in config "
            "(audit_settings.remediation.execution.enabled=false)."
        )
    if rem.get("execution_linux_only", True):
        _validate_linux_only()

    if rem.get("execution_enforce_checksum", True):
        current_hash = _sha256_file(script_path)
        if current_hash != pack["script"]["sha256"]:
            raise RuntimeError(
                "Remediation script checksum mismatch; "
                "re-generate and re-approve required."
            )

    highest = pack["risk"]["highest"]
    # The approver may have accepted high-risk commands when approving; that
    # decision travels with the pack so a scheduled apply can honour it.
    allow_high_risk = allow_high_risk or bool(pack["approval"].get("allow_high_risk"))
    if (
        rem.get("execution_block_high_risk", True)
        and highest == "high"
        and not allow_high_risk
    ):
        raise RuntimeError(
            "High-risk pack blocked. Re-run with --allow-high-risk to proceed."
        )

    compliance_policy = cfg.get("compliance", {})
    compliance_policy["_audit_settings"] = cfg.get("audit_settings", {})
    role_config = cfg.get("hostname_roles") or None
    endpoint_config = cfg.get("endpoint_neighbors") or None
    timeout = cfg.get("audit_settings", {}).get("collect_timeout", 30)

    hostname = pack["device"]["hostname"]
    ip = pack["device"]["ip"]

    # ── Policy exceptions: never push an excepted change ─────────────────
    # Re-checked against the exceptions in force now, not when the pack was
    # generated.  Packs written before the group was recorded have no
    # "group" key; None makes group-scoped exceptions count as matching, so
    # an unknown group errs towards not applying.
    exception_register = ExceptionRegister.from_config(cfg)
    pack_group = pack["device"].get("group")
    pack_items, excepted_items = _split_excepted_items(
        pack.get("findings", []),
        exception_register,
        hostname=hostname,
        ip=ip,
        role=pack["device"].get("role", ""),
        group=pack_group,
        check_map=_build_check_map(compliance_policy),
    )
    if excepted_items:
        console.print(
            f"[bold yellow]⚠ Skipping {len(excepted_items)} item(s) now covered by "
            "a policy exception (exceptions are never remediated):[/]"
        )
        for item in excepted_items:
            intf = f" ({item.get('interface')})" if item.get("interface") else ""
            console.print(
                f"    - {item.get('check_name')}{intf} → {item['exception_id']} "
                f"[{item['exception_state']}]",
                markup=False,
                highlight=False,
            )
        log.warning(
            "Pack %s: %d item(s) skipped — covered by policy exceptions %s",
            pack_id,
            len(excepted_items),
            sorted({i["exception_id"] for i in excepted_items}),
        )
    if not pack_items:
        raise RuntimeError(
            "Every finding in this pack is covered by a policy exception — "
            "nothing to apply. Exceptions are never remediated; remove or "
            "narrow the exception and re-run the audit if the change is wanted."
        )
    group_for_audit = pack_group or ""

    connection = None
    jump = None

    # Fetch credentials BEFORE entering Progress context so the status
    # bar does not cover interactive prompts.
    conn_cfg = cfg.get("connection", {})
    cred_store = conn_cfg.get("credential_store", "none")
    keyring_svc = conn_cfg.get("keyring_service", "cisco-compliance-audit")
    cred_handler = CredentialHandler(
        credential_store=cred_store,
        keyring_service=keyring_svc,
    )
    # This may prompt the user interactively - do it before progress starts
    username, password = cred_handler.get_secret_with_fallback()
    enable_secret = cred_handler.get_enable_secret()

    # Create progress indicators
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        try:
            task = progress.add_task(
                f"[cyan]Connecting to {hostname} ({ip})...", total=None
            )
            connection, jump = _open_device_connection_with_creds(
                cfg, ip, username, password, enable_secret, skip_jump=skip_jump
            )
            progress.update(task, description=f"[green]✓ Connected to {hostname}")
            progress.stop_task(task)

            if rem.get("execution_require_hostname_match", True):
                prompt = connection.find_prompt().strip().rstrip("#>")
                if prompt and hostname and hostname.lower() not in prompt.lower():
                    raise RuntimeError(
                        "Device identity mismatch. Expected hostname "
                        f"containing '{hostname}', got prompt '{prompt}'."
                    )

            intended = {
                (item["check_name"], item.get("interface", ""))
                for item in pack_items
            }

            still_failing = intended
            if rem.get("execution_preflight_drift_check", True):
                task = progress.add_task(
                    "[cyan]Running preflight drift check...", total=None
                )
                fail_set = _collect_fail_set(
                    connection,
                    hostname=hostname,
                    ip=ip,
                    compliance_policy=compliance_policy,
                    role_config=role_config,
                    endpoint_config=endpoint_config,
                    timeout=timeout,
                    exceptions=exception_register,
                    group=group_for_audit,
                )
                still_failing = intended.intersection(fail_set)
                progress.update(
                    task,
                    description=(
                        "[green]✓ Preflight check complete "
                        f"({len(still_failing)} findings still failing)"
                    ),
                )
                progress.stop_task(task)

                if not still_failing:
                    raise RuntimeError(
                        "Drift check failed: none of the approved findings "
                        "are currently failing. "
                        "Re-run audit and create a new review pack."
                    )

            # Re-build command list filtered to only the findings still failing
            # and not covered by an exception.  When preflight is disabled and
            # nothing is excepted, still_failing == intended so nothing is
            # dropped.
            if still_failing != intended or excepted_items:
                active_findings = [
                    item
                    for item in pack_items
                    if (item["check_name"], item.get("interface", "")) in still_failing
                ]
                plan_commands = _flatten_apply_commands(
                    _build_command_groups(active_findings)
                )
            else:
                plan_commands = _flatten_apply_commands(pack.get("command_groups", {}))
            if not plan_commands:
                raise RuntimeError("No commands available in approved pack.")

            task = progress.add_task(
                f"[cyan]Applying {len(plan_commands)} commands...", total=None
            )
            output = connection.send_config_set(
                plan_commands,
                cmd_verify=rem.get("execution_cmd_verify", False),
                exit_config_mode=True,
            )
            progress.update(task, description="[green]✓ Commands applied")
            progress.stop_task(task)

            if rem.get("execution_save_config", True):
                task = progress.add_task("[cyan]Saving configuration...", total=None)
                try:
                    connection.save_config()
                except DEVICE_OPERATION_ERRORS:
                    connection.send_command_timing("write memory")
                progress.update(task, description="[green]✓ Configuration saved")
                progress.stop_task(task)

            task = progress.add_task(
                "[cyan]Running post-check verification...", total=None
            )
            post_fail_set = _collect_fail_set(
                connection,
                hostname=hostname,
                ip=ip,
                compliance_policy=compliance_policy,
                role_config=role_config,
                endpoint_config=endpoint_config,
                timeout=timeout,
                exceptions=exception_register,
                group=group_for_audit,
            )
            post_remaining = intended.intersection(post_fail_set)
            resolved = len(still_failing) - len(post_remaining)
            progress.update(
                task,
                description=(
                    f"[green]✓ Post-check complete ({resolved} findings resolved)"
                ),
            )
            progress.stop_task(task)

            if post_remaining:
                progress.console.print(
                    "[yellow]⚠ "
                    f"{len(post_remaining)} finding(s) still failing "
                    "after apply:[/]"
                )
                for check, intf in sorted(post_remaining):
                    progress.console.print(
                        f"    - {check}" + (f" ({intf})" if intf else "")
                    )

            # Generate post-remediation report if enabled
            if rem.get("execution_generate_post_report", False):
                report_formats = rem.get(
                    "execution_post_report_formats", ["json", "html"]
                )
                if not isinstance(report_formats, list):
                    report_formats = ["json", "html"]
                post_report_result = _generate_post_remediation_report(
                    connection=connection,
                    hostname=hostname,
                    ip=ip,
                    compliance_policy=compliance_policy,
                    role_config=role_config,
                    endpoint_config=endpoint_config,
                    timeout=timeout,
                    output_dir=output_dir,
                    report_formats=report_formats,
                    progress=progress,
                    run_id=f"remediation-{pack_id}",
                    exceptions=exception_register,
                    group=group_for_audit,
                )
                if post_report_result and post_report_callback:
                    post_report_callback(post_report_result)

            pack["lifecycle"]["status"] = "applied"
            pack["execution"]["status"] = "success"
            pack["execution"]["applied_at"] = _utc_now_str()
            pack["execution"]["summary"] = (
                f"Applied {len(plan_commands)} commands; resolved {resolved} findings."
            )
            pack["execution"]["preflight_still_failing"] = len(still_failing)
            pack["execution"]["postcheck_resolved"] = resolved
            pack["execution"]["skipped_for_exceptions"] = len(excepted_items)
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)

            exec_log = Path(output_dir) / "remediation_execution.log"
            with exec_log.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "ts": _utc_now_str(),
                            "pack_id": pack_id,
                            "hostname": hostname,
                            "ip": ip,
                            "status": "success",
                            "resolved": resolved,
                        }
                    )
                    + "\n"
                )

            progress.console.print("[bold green]✓ Remediation applied successfully![/]")
            progress.console.print(f"  Commands applied: {len(plan_commands)}")
            progress.console.print(
                f"  Findings resolved: {resolved}/{len(still_failing)}"
            )

            return {
                "pack_id": pack_id,
                "hostname": hostname,
                "ip": ip,
                "status": "success",
                "preflight_still_failing": len(still_failing),
                "resolved": resolved,
                "commands_applied": len(plan_commands),
                "skipped_for_exceptions": len(excepted_items),
                "device_output_preview": output[-1000:],
            }

        except WORKFLOW_ERRORS as exc:
            pack["execution"]["status"] = "failed"
            pack["execution"]["applied_at"] = _utc_now_str()
            pack["execution"]["summary"] = str(exc)
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)
            exec_log = Path(output_dir) / "remediation_execution.log"
            with exec_log.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "ts": _utc_now_str(),
                            "pack_id": pack_id,
                            "hostname": hostname,
                            "ip": ip,
                            "status": "failed",
                            "error": str(exc),
                        }
                    )
                    + "\n"
                )
            progress.console.print(f"[bold red]✗ Remediation failed: {exc}[/]")
            raise
        finally:
            if connection is not None:
                try:
                    connection.disconnect()
                except DEVICE_OPERATION_ERRORS:
                    pass
            if jump is not None:
                jump.close()


def _apply_entries(
    entries: list[ReviewEntry],
    *,
    config_path: str,
    output_dir: str,
    skip_jump: bool,
    allow_high_risk: bool,
    remediation_settings: Optional[dict],
    rem_effective: dict,
    title: str,
    ignore_schedule: bool = False,
) -> list[dict]:
    """Apply *entries* in sequence and write the consolidated post report."""
    print_review_entries_table(
        entries,
        title=title,
        show_created=False,
        console=console,
    )

    summaries: list[dict] = []
    post_report_results: list[AuditResult] = []
    for entry in entries:
        console.print(
            f"\n[bold cyan]Applying pack {entry.pack_id} ({entry.hostname})...[/]"
        )
        try:
            summary = apply_approved_pack(
                config_path=config_path,
                output_dir=output_dir,
                pack_id=entry.pack_id,
                skip_jump=skip_jump,
                allow_high_risk=allow_high_risk,
                remediation_settings=remediation_settings,
                post_report_callback=post_report_results.append,
                ignore_schedule=ignore_schedule,
            )
            summary.setdefault("run_id", entry.run_id)
            summaries.append(summary)
        except WORKFLOW_ERRORS as exc:
            console.print(f"[red]✗ Failed: {exc}[/]")
            summaries.append(
                {
                    "pack_id": entry.pack_id,
                    "hostname": entry.hostname,
                    "ip": entry.ip,
                    "run_id": entry.run_id,
                    "status": "failed",
                    "error": str(exc),
                }
            )

    if (
        rem_effective.get("execution_generate_post_report", False)
        and rem_effective.get("execution_generate_consolidated_post_report", True)
        and post_report_results
    ):
        requested_formats = rem_effective.get(
            "execution_post_report_formats", ["json", "html"]
        )
        if not isinstance(requested_formats, list):
            requested_formats = ["json", "html"]

        consolidated_paths = _generate_consolidated_post_remediation_report(
            post_report_results,
            output_dir=output_dir,
            report_formats=requested_formats,
        )
        if consolidated_paths:
            console.print("[dim]Consolidated post-remediation reports saved:[/]")
            for path in consolidated_paths:
                console.print(f"  [dim]• {path}[/]")

    success = sum(1 for s in summaries if s.get("status") in {"success", "dry-run"})
    failed = len(summaries) - success
    console.print(
        f"\n[bold]Apply complete: {success} succeeded, {failed} failed[/]"
    )
    return summaries


def _effective_settings(config_path: str, remediation_settings: Optional[dict]) -> dict:
    if remediation_settings is not None:
        return remediation_settings
    config_cache = _load_config(config_path)
    return get_remediation_settings(config_cache.get("audit_settings", {}))


def _is_future(entry: ReviewEntry, now: Optional[datetime] = None) -> bool:
    scheduled = _parse_utc(entry.scheduled_for)
    return scheduled is not None and scheduled > (now or _utc_now())


def apply_all_approved_packs(
    config_path: str,
    output_dir: str,
    skip_jump: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
) -> list[dict]:
    """Apply every approved (non-expired) pack that is not scheduled for later."""
    rem_effective = _effective_settings(config_path, remediation_settings)
    if not rem_effective.get("execution_allow_bulk_apply", True):
        raise RuntimeError(
            "Bulk remediation apply is disabled in config "
            "(audit_settings.remediation.execution.allow_bulk_apply=false)."
        )

    store = ReviewStore(_default_db_path(output_dir))
    approved = store.list(status="approved")
    later = [e for e in approved if _is_future(e)]
    entries = [e for e in approved if not _is_future(e)]
    if later:
        console.print(
            f"[yellow]Skipping {len(later)} pack(s) scheduled for later "
            "(they are applied by --remediation-apply-due when due):[/]"
        )
        for e in later:
            console.print(
                f"    - {e.pack_id} ({e.hostname}) at "
                f"{format_schedule(_parse_utc(e.scheduled_for))}",
                markup=False,
                highlight=False,
            )

    if not entries:
        console.print("[yellow]No approved remediation packs ready to apply.[/]")
        return []

    return _apply_entries(
        entries,
        config_path=config_path,
        output_dir=output_dir,
        skip_jump=skip_jump,
        allow_high_risk=allow_high_risk,
        remediation_settings=remediation_settings,
        rem_effective=rem_effective,
        title=f"Approved pack(s) ready to apply: {len(entries)}",
    )


def due_packs(output_dir: str, now: Optional[datetime] = None) -> list[ReviewEntry]:
    """Approved packs whose scheduled apply time has arrived."""
    now = now or _utc_now()
    store = ReviewStore(_default_db_path(output_dir))
    return [
        e for e in store.list(status="approved")
        if e.scheduled_for and not _is_future(e, now)
    ]


def apply_due_packs(
    config_path: str,
    output_dir: str,
    skip_jump: bool = False,
    remediation_settings: Optional[dict] = None,
) -> list[dict]:
    """Apply every approved pack whose scheduled time has arrived.

    Meant to run from a frequent timer (e.g. every 5 minutes).  Packs
    approved without a schedule are left for a person to apply.  High-risk
    packs are applied only when their approval recorded ``--allow-high-risk``.
    """
    rem_effective = _effective_settings(config_path, remediation_settings)
    entries = due_packs(output_dir)
    if not entries:
        console.print("No scheduled remediation packs are due.")
        return []
    if len(entries) > 1 and not rem_effective.get("execution_allow_bulk_apply", True):
        raise RuntimeError(
            f"{len(entries)} scheduled packs are due, but bulk apply is disabled "
            "(audit_settings.remediation.execution.allow_bulk_apply=false)."
        )
    return _apply_entries(
        entries,
        config_path=config_path,
        output_dir=output_dir,
        skip_jump=skip_jump,
        allow_high_risk=False,
        remediation_settings=remediation_settings,
        rem_effective=rem_effective,
        title=f"Scheduled pack(s) due now: {len(entries)}",
    )


def format_schedule(when: Optional[datetime]) -> str:
    """``2026-11-07 02:00 GMT (02:00 UTC)`` — local time first, then UTC."""
    if when is None:
        return ""
    local = when.astimezone()
    utc = when.astimezone(timezone.utc)
    text = local.strftime("%Y-%m-%d %H:%M %Z").strip()
    if local.utcoffset() != utc.utcoffset():
        text += utc.strftime(" (%H:%M UTC)")
    return text


def apply_packs(
    config_path: str,
    output_dir: str,
    pack_ids: list[str],
    *,
    skip_jump: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
    title: str = "Applying approved pack(s)",
) -> list[dict]:
    """Apply the given approved packs now (used by ``--run-approve --apply-now``)."""
    rem_effective = _effective_settings(config_path, remediation_settings)
    if len(pack_ids) > 1 and not rem_effective.get("execution_allow_bulk_apply", True):
        raise RuntimeError(
            f"{len(pack_ids)} packs would be applied together, but bulk apply is disabled "
            "(audit_settings.remediation.execution.allow_bulk_apply=false)."
        )
    wanted = set(pack_ids)
    store = ReviewStore(_default_db_path(output_dir))
    entries = [e for e in store.list(status="approved") if e.pack_id in wanted]
    if not entries:
        return []
    return _apply_entries(
        entries,
        config_path=config_path,
        output_dir=output_dir,
        skip_jump=skip_jump,
        allow_high_risk=allow_high_risk,
        remediation_settings=remediation_settings,
        rem_effective=rem_effective,
        title=f"{title}: {len(entries)}",
    )
