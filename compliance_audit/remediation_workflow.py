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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskID,
)

from .collector import DataCollector
from .compliance_engine import ComplianceEngine, Status
from .credentials import CredentialHandler
from .hostname_parser import parse_hostname
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .port_classifier import classify_ports
from .auditor import _get_roi_settings, _estimate_roi_for_result
from .report import save_json, save_html, save_csv

log = logging.getLogger(__name__)
console = Console()


def get_remediation_settings(audit_settings: Optional[dict]) -> dict:
    """Resolve remediation settings with legacy compatibility defaults."""
    settings = audit_settings or {}
    remediation_node = settings.get("remediation", {})
    if not isinstance(remediation_node, dict):
        remediation_node = {}

    legacy_script = bool(settings.get("remediation_script", True))
    legacy_review = bool(settings.get("remediation_review_pack", True))

    approval = remediation_node.get("approval", {})
    if not isinstance(approval, dict):
        approval = {}
    execution = remediation_node.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}

    enabled = bool(remediation_node.get("enabled", legacy_script))

    return {
        "enabled": enabled,
        "generate_script": bool(remediation_node.get("generate_script", enabled)),
        "generate_review_pack": bool(remediation_node.get("generate_review_pack", legacy_review)),
        "approval_default_expires_hours": int(approval.get("default_expires_hours", 24)),
        "approval_require_ticket_id": bool(approval.get("require_ticket_id", True)),
        "execution_enabled": bool(execution.get("enabled", False)),
        "execution_linux_only": bool(execution.get("linux_only", True)),
        "execution_block_high_risk": bool(execution.get("block_high_risk_by_default", True)),
        "execution_enforce_checksum": bool(execution.get("enforce_checksum", True)),
        "execution_preflight_drift_check": bool(execution.get("preflight_drift_check", True)),
        "execution_require_hostname_match": bool(execution.get("require_hostname_match", True)),
        "execution_save_config": bool(execution.get("save_config", True)),
        "execution_cmd_verify": bool(execution.get("command_verify", False)),
        "execution_generate_post_report": bool(execution.get("generate_post_report", True)),
        "execution_post_report_formats": list(execution.get("post_report_formats", ["json", "html"])),
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


class ReviewStore:
    """SQLite-backed state for remediation review and execution lifecycle."""

    def __init__(self, db_path: Path):
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
                "CREATE INDEX IF NOT EXISTS idx_reviews_status ON remediation_reviews(status)"
            )

    def upsert_from_pack(self, pack: dict, pack_path: Path) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remediation_reviews (
                    pack_id, hostname, ip, status, highest_risk, findings_count,
                    created_ts, approved_by, approved_at, ticket_id, expires_at,
                    rejected_by, rejected_at, reject_reason,
                    script_path, script_sha256, pack_path,
                    applied_at, apply_status, apply_summary
                ) VALUES (
                    :pack_id, :hostname, :ip, :status, :highest_risk, :findings_count,
                    :created_ts, :approved_by, :approved_at, :ticket_id, :expires_at,
                    :rejected_by, :rejected_at, :reject_reason,
                    :script_path, :script_sha256, :pack_path,
                    :applied_at, :apply_status, :apply_summary
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
                    apply_summary=excluded.apply_summary
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
                },
            )

    def list(self, status: Optional[str] = None) -> list[ReviewEntry]:
        q = """
            SELECT pack_id, hostname, ip, status, highest_risk, findings_count,
                   created_ts, approved_by, approved_at, ticket_id, expires_at,
                   script_path, pack_path
            FROM remediation_reviews
        """
        params: tuple = ()
        if status:
            q += " WHERE status = ?"
            params = (status,)
        q += " ORDER BY created_ts DESC"

        with self._connect() as conn:
            rows = conn.execute(q, params).fetchall()

        return [ReviewEntry(**dict(row)) for row in rows]

    def get_pack_path(self, pack_id: str) -> Optional[Path]:
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
            context = interface if interface.startswith("line ") else f"interface {interface}"
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
        raise RuntimeError("Remediation lifecycle commands are Linux-only in this release.")


def _load_config(config_path: str) -> dict:
    cfg_path = Path(config_path)
    if not cfg_path.exists():
        cfg_path = Path(__file__).parent / config_path
    if not cfg_path.exists():
        raise RuntimeError(f"Config file not found: {config_path}")
    with cfg_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


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
    config: dict, ip: str, username: str, password: str, enable_secret: Optional[str], skip_jump: bool
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
) -> None:
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
    from datetime import datetime, timezone
    from . import __version__

    task = progress.add_task(f"[cyan]Generating post-remediation report...", total=None)

    try:
        # Collect fresh data from the device
        collector = DataCollector(timeout=timeout)
        data = collector.collect(connection, ip=ip)
        data.hostname = hostname

        # Classify ports
        ports = classify_ports(data, role_config=role_config, endpoint_config=endpoint_config)

        # Run compliance audit
        audit_settings = compliance_policy.get("_audit_settings", {})
        host_info = parse_hostname(hostname, role_config=role_config)
        engine = ComplianceEngine(compliance_policy)
        result = engine.audit(data, host_info, ports)

        # Attach ROI data so reports can show savings information
        roi_settings = _get_roi_settings(audit_settings)
        if roi_settings["enabled"]:
            result._roi = _estimate_roi_for_result(result, roi_settings)

        # Populate metadata
        result.audit_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        result.tool_version = __version__

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

        progress.update(task, description=f"[green]✓ Post-remediation report generated")
        progress.stop_task(task)

        # Show report paths
        if report_paths:
            progress.console.print(f"[dim]Post-remediation reports saved:[/]")
            for path in report_paths:
                progress.console.print(f"  [dim]• {path}[/]")

    except Exception as exc:
        progress.update(task, description=f"[yellow]⚠ Report generation failed: {exc}")
        progress.stop_task(task)
        log.warning(f"Post-remediation report generation failed: {exc}")


def _collect_fail_set(
    connection,
    hostname: str,
    ip: str,
    compliance_policy: dict,
    role_config: Optional[list],
    endpoint_config: Optional[dict],
    timeout: int,
) -> set[tuple[str, str]]:
    collector = DataCollector(timeout=timeout)
    data = collector.collect(connection, ip=ip)
    data.hostname = hostname

    ports = classify_ports(
        data,
        role_config=role_config,
        endpoint_config=endpoint_config,
    )
    engine = ComplianceEngine(compliance_policy)
    host_info = parse_hostname(hostname, role_config=role_config)
    result = engine.audit(data, host_info, ports)

    return {
        (f.check_name, f.interface)
        for f in result.findings
        if f.status == Status.FAIL and f.remediation
    }


def _highest_risk(findings: list[dict]) -> str:
    levels = {"low": 1, "medium": 2, "high": 3}
    highest = "low"
    for item in findings:
        level = item.get("risk", "low")
        if levels.get(level, 0) > levels.get(highest, 0):
            highest = level
    return highest


def _default_db_path(output_dir: str) -> Path:
    return Path(output_dir) / "remediation_reviews.db"


def generate_review_pack(result, script_path: Path, output_dir: str) -> Path:
    """Create a review/approval pack JSON for one device remediation script."""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    fails = [
        f for f in result.findings
        if f.status == Status.FAIL and f.remediation
    ]
    findings: list[dict] = []
    for idx, finding in enumerate(fails, start=1):
        command = finding.remediation.strip()
        if not command:
            continue
        findings.append({
            "item_id": f"{result.hostname}-{idx:04d}",
            "check_name": finding.check_name,
            "category": finding.category,
            "interface": finding.interface,
            "detail": finding.detail,
            "command": command,
            "risk": _risk_for_command(command, finding.category, finding.check_name),
        })

    pack_id_seed = f"{result.hostname}|{result.ip}|{result.audit_ts}|{script_path.name}"
    pack_id = hashlib.sha256(pack_id_seed.encode("utf-8")).hexdigest()[:16]

    risk_counts = {
        "low": sum(1 for i in findings if i["risk"] == "low"),
        "medium": sum(1 for i in findings if i["risk"] == "medium"),
        "high": sum(1 for i in findings if i["risk"] == "high"),
    }

    pack = {
        "schema_version": 1,
        "pack_id": pack_id,
        "created_ts": _utc_now_str(),
        "device": {
            "hostname": result.hostname,
            "ip": result.ip,
            "role": result.role,
            "role_display": result.role_display,
            "ios_version": result.ios_version,
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
    }

    filename = outdir / f"{_safe_name(result.hostname)}_review_{pack_id}.json"
    _write_json(filename, pack)

    store = ReviewStore(_default_db_path(output_dir))
    store.upsert_from_pack(pack, filename)
    return filename


def list_review_packs(output_dir: str, status: Optional[str] = None) -> list[ReviewEntry]:
    store = ReviewStore(_default_db_path(output_dir))
    return store.list(status=status)


def _load_pack_for_update(output_dir: str, pack_id: str) -> tuple[dict, Path, ReviewStore]:
    store = ReviewStore(_default_db_path(output_dir))
    pack_path = store.get_pack_path(pack_id)
    if not pack_path or not pack_path.exists():
        raise RuntimeError(f"Review pack not found: {pack_id}")
    pack = _read_json(pack_path)
    return pack, pack_path, store


def approve_review_pack(
    output_dir: str,
    pack_id: str,
    approver: str,
    ticket_id: str,
    expires_hours: int = 24,
    require_ticket_id: bool = True,
) -> Path:
    if not approver.strip():
        raise RuntimeError("Approver must be provided.")
    if require_ticket_id and not ticket_id.strip():
        raise RuntimeError("Ticket ID must be provided.")

    pack, pack_path, store = _load_pack_for_update(output_dir, pack_id)
    current_status = pack["lifecycle"]["status"]
    if current_status in {"applied", "expired", "rejected"}:
        raise RuntimeError(
            f"Cannot approve a pack with status '{current_status}'. "
            "Generate a fresh pack from a new audit run."
        )

    expires = _utc_now() + timedelta(hours=max(1, expires_hours))
    pack["lifecycle"]["status"] = "approved"
    pack["approval"]["approved_by"] = approver.strip()
    pack["approval"]["approved_at"] = _utc_now_str()
    pack["approval"]["ticket_id"] = ticket_id.strip()
    pack["approval"]["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    pack["approval"]["rejected_by"] = ""
    pack["approval"]["rejected_at"] = ""
    pack["approval"]["reject_reason"] = ""

    _write_json(pack_path, pack)
    store.upsert_from_pack(pack, pack_path)
    return pack_path


def reject_review_pack(output_dir: str, pack_id: str, approver: str, reason: str) -> Path:
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
    dry_run: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
) -> dict:
    """Apply a previously approved remediation pack with preflight and postcheck."""
    pack, pack_path, store = _load_pack_for_update(output_dir, pack_id)

    status = pack["lifecycle"]["status"]
    if status != "approved":
        raise RuntimeError(f"Pack must be approved before apply; current status: {status}")

    expires_at = pack["approval"].get("expires_at", "")
    if expires_at:
        expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if _utc_now() > expiry:
            pack["lifecycle"]["status"] = "expired"
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)
            raise RuntimeError("Approval has expired. Re-approve before apply.")

    script_path = Path(pack["script"]["path"])
    if not script_path.exists():
        raise RuntimeError(f"Remediation script not found: {script_path}")
    cfg = _load_config(config_path)
    rem = remediation_settings or get_remediation_settings(cfg.get("audit_settings", {}))

    if not rem.get("enabled", True):
        raise RuntimeError("Remediation workflow is disabled in config (audit_settings.remediation.enabled=false).")
    if not rem.get("execution_enabled", True):
        raise RuntimeError("Remediation execution is disabled in config (audit_settings.remediation.execution.enabled=false).")
    if rem.get("execution_linux_only", True):
        _validate_linux_only()

    if rem.get("execution_enforce_checksum", True):
        current_hash = _sha256_file(script_path)
        if current_hash != pack["script"]["sha256"]:
            raise RuntimeError("Remediation script checksum mismatch; re-generate and re-approve required.")

    highest = pack["risk"]["highest"]
    if rem.get("execution_block_high_risk", True) and highest == "high" and not allow_high_risk:
        raise RuntimeError("High-risk pack blocked. Re-run with --allow-high-risk to proceed.")

    compliance_policy = cfg.get("compliance", {})
    compliance_policy["_audit_settings"] = cfg.get("audit_settings", {})
    role_config = cfg.get("hostname_roles") or None
    endpoint_config = cfg.get("endpoint_neighbors") or None
    timeout = cfg.get("audit_settings", {}).get("collect_timeout", 30)

    hostname = pack["device"]["hostname"]
    ip = pack["device"]["ip"]

    connection = None
    jump = None

    # Fetch credentials BEFORE entering Progress context to avoid status bar covering input prompts
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
            task = progress.add_task(f"[cyan]Connecting to {hostname} ({ip})...", total=None)
            connection, jump = _open_device_connection_with_creds(
                cfg, ip, username, password, enable_secret, skip_jump=skip_jump
            )
            progress.update(task, description=f"[green]✓ Connected to {hostname}")
            progress.stop_task(task)

            if rem.get("execution_require_hostname_match", True):
                prompt = connection.find_prompt().strip().rstrip("#>")
                if prompt and hostname and hostname.lower() not in prompt.lower():
                    raise RuntimeError(
                        f"Device identity mismatch. Expected hostname containing '{hostname}', got prompt '{prompt}'."
                    )

            intended = {
                (item["check_name"], item.get("interface", ""))
                for item in pack.get("findings", [])
            }

            still_failing = intended
            if rem.get("execution_preflight_drift_check", True):
                task = progress.add_task(f"[cyan]Running preflight drift check...", total=None)
                fail_set = _collect_fail_set(
                    connection,
                    hostname=hostname,
                    ip=ip,
                    compliance_policy=compliance_policy,
                    role_config=role_config,
                    endpoint_config=endpoint_config,
                    timeout=timeout,
                )
                still_failing = intended.intersection(fail_set)
                progress.update(task, description=f"[green]✓ Preflight check complete ({len(still_failing)} findings still failing)")
                progress.stop_task(task)

                if not still_failing:
                    raise RuntimeError(
                        "Drift check failed: none of the approved findings are currently failing. "
                        "Re-run audit and create a new review pack."
                    )

            # Re-build command list filtered to only the findings still failing.
            # When preflight is disabled still_failing == intended so nothing is dropped.
            if still_failing != intended:
                active_findings = [
                    item for item in pack.get("findings", [])
                    if (item["check_name"], item.get("interface", "")) in still_failing
                ]
                plan_commands = _flatten_apply_commands(_build_command_groups(active_findings))
            else:
                plan_commands = _flatten_apply_commands(pack.get("command_groups", {}))
            if not plan_commands:
                raise RuntimeError("No commands available in approved pack.")

            if dry_run:
                summary = {
                    "pack_id": pack_id,
                    "hostname": hostname,
                    "ip": ip,
                    "planned_command_count": len(plan_commands),
                    "preflight_still_failing": len(still_failing),
                    "status": "dry-run",
                }
                pack["execution"]["status"] = "dry-run"
                pack["execution"]["summary"] = "Dry-run preflight passed; no commands applied."
                pack["execution"]["preflight_still_failing"] = len(still_failing)
                _write_json(pack_path, pack)
                store.upsert_from_pack(pack, pack_path)
                progress.console.print(f"[green]✓ Dry-run complete - {len(plan_commands)} commands ready to apply")
                return summary

            task = progress.add_task(f"[cyan]Applying {len(plan_commands)} commands...", total=None)
            output = connection.send_config_set(
                plan_commands,
                cmd_verify=rem.get("execution_cmd_verify", False),
                exit_config_mode=True,
            )
            progress.update(task, description=f"[green]✓ Commands applied")
            progress.stop_task(task)

            if rem.get("execution_save_config", True):
                task = progress.add_task(f"[cyan]Saving configuration...", total=None)
                try:
                    connection.save_config()
                except Exception:
                    connection.send_command_timing("write memory")
                progress.update(task, description=f"[green]✓ Configuration saved")
                progress.stop_task(task)

            task = progress.add_task(f"[cyan]Running post-check verification...", total=None)
            post_fail_set = _collect_fail_set(
                connection,
                hostname=hostname,
                ip=ip,
                compliance_policy=compliance_policy,
                role_config=role_config,
                endpoint_config=endpoint_config,
                timeout=timeout,
            )
            post_remaining = intended.intersection(post_fail_set)
            resolved = len(still_failing) - len(post_remaining)
            progress.update(task, description=f"[green]✓ Post-check complete ({resolved} findings resolved)")
            progress.stop_task(task)

            if post_remaining:
                progress.console.print(
                    f"[yellow]⚠ {len(post_remaining)} finding(s) still failing after apply:[/]"
                )
                for check, intf in sorted(post_remaining):
                    progress.console.print(f"    - {check}" + (f" ({intf})" if intf else ""))

            # Generate post-remediation report if enabled
            if rem.get("execution_generate_post_report", False):
                report_formats = rem.get("execution_post_report_formats", ["json", "html"])
                if not isinstance(report_formats, list):
                    report_formats = ["json", "html"]
                _generate_post_remediation_report(
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
                )

            pack["lifecycle"]["status"] = "applied"
            pack["execution"]["status"] = "success"
            pack["execution"]["applied_at"] = _utc_now_str()
            pack["execution"]["summary"] = f"Applied {len(plan_commands)} commands; resolved {resolved} findings."
            pack["execution"]["preflight_still_failing"] = len(still_failing)
            pack["execution"]["postcheck_resolved"] = resolved
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)

            exec_log = Path(output_dir) / "remediation_execution.log"
            with exec_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": _utc_now_str(),
                    "pack_id": pack_id,
                    "hostname": hostname,
                    "ip": ip,
                    "status": "success",
                    "resolved": resolved,
                }) + "\n")

            progress.console.print(f"[bold green]✓ Remediation applied successfully![/]")
            progress.console.print(f"  Commands applied: {len(plan_commands)}")
            progress.console.print(f"  Findings resolved: {resolved}/{len(still_failing)}")

            return {
                "pack_id": pack_id,
                "hostname": hostname,
                "ip": ip,
                "status": "success",
                "preflight_still_failing": len(still_failing),
                "resolved": resolved,
                "commands_applied": len(plan_commands),
                "device_output_preview": output[-1000:],
            }

        except Exception as exc:
            pack["execution"]["status"] = "failed"
            pack["execution"]["applied_at"] = _utc_now_str()
            pack["execution"]["summary"] = str(exc)
            _write_json(pack_path, pack)
            store.upsert_from_pack(pack, pack_path)
            exec_log = Path(output_dir) / "remediation_execution.log"
            with exec_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": _utc_now_str(),
                    "pack_id": pack_id,
                    "hostname": hostname,
                    "ip": ip,
                    "status": "failed",
                    "error": str(exc),
                }) + "\n")
            progress.console.print(f"[bold red]✗ Remediation failed: {exc}[/]")
            raise
        finally:
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    pass
            if jump is not None:
                jump.close()


def apply_all_approved_packs(
    config_path: str,
    output_dir: str,
    skip_jump: bool = False,
    dry_run: bool = False,
    allow_high_risk: bool = False,
    remediation_settings: Optional[dict] = None,
) -> list[dict]:
    """Apply every currently approved (non-expired) remediation pack in sequence."""
    store = ReviewStore(_default_db_path(output_dir))
    entries = store.list(status="approved")

    if not entries:
        console.print("[yellow]No approved remediation packs found.[/]")
        return []

    console.print(f"[bold]Found {len(entries)} approved pack(s) to apply:[/]")
    for entry in entries:
        console.print(
            f"  {entry.pack_id} | {entry.hostname:24} | {entry.ip:15} | "
            f"risk={entry.highest_risk:6} | findings={entry.findings_count}"
        )

    summaries: list[dict] = []
    for entry in entries:
        console.print(f"\n[bold cyan]Applying pack {entry.pack_id} ({entry.hostname})...[/]")
        try:
            summary = apply_approved_pack(
                config_path=config_path,
                output_dir=output_dir,
                pack_id=entry.pack_id,
                skip_jump=skip_jump,
                dry_run=dry_run,
                allow_high_risk=allow_high_risk,
                remediation_settings=remediation_settings,
            )
            summaries.append(summary)
        except Exception as exc:
            console.print(f"[red]✗ Failed: {exc}[/]")
            summaries.append({
                "pack_id": entry.pack_id,
                "hostname": entry.hostname,
                "ip": entry.ip,
                "status": "failed",
                "error": str(exc),
            })

    success = sum(1 for s in summaries if s.get("status") in {"success", "dry-run"})
    failed = len(summaries) - success
    console.print(f"\n[bold]Apply-all complete: {success} succeeded, {failed} failed[/]")
    return summaries
