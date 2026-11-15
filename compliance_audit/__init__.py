"""
Cisco IOS-XE Compliance Auditor

Core networking utilities (credentials, jump host, device connections) plus
a full compliance-audit pipeline: data collection → port classification →
policy checks → reporting.
"""

from .__about__ import __version__

from .auditor import run_audit
from .collector import DataCollector, DeviceData
from .compliance_engine import AuditResult, ComplianceEngine, Finding, Status
from .credentials import CredentialHandler
from .hostname_parser import HostnameInfo, parse_hostname
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .policy_exceptions import (
    AppliedException,
    ExceptionRegister,
    ExceptionRule,
    ExceptionSettings,
)
from .port_classifier import PortInfo, PortRole, classify_ports
from .remediation_workflow import (
    apply_approved_pack,
    approve_review_pack,
    ensure_review_store,
    generate_review_pack,
    get_review_db_path,
    get_review_pack,
    list_review_packs,
    reject_review_pack,
)
from .remediation_api import (
    apply_all_approved_packs_api,
    apply_approved_pack_api,
    approve_review_pack_api,
    list_review_packs_api,
    reject_review_pack_api,
    to_json as remediation_api_to_json,
)
from .report_artifacts import (
    get_report_artifact_index_path,
    load_report_artifact_index,
    read_report_content,
    resolve_report_path,
)
from .report import (
    compute_delta,
    load_baseline,
    print_delta_summary,
    print_report,
    save_consolidated_html,
    save_csv,
    save_delta_report,
    save_html,
    save_json,
    save_remediation_script,
)

__all__ = [
    # Core infrastructure
    "CredentialHandler",
    "JumpManager",
    "DeviceConnector",
    # Compliance audit
    "parse_hostname",
    "HostnameInfo",
    "DataCollector",
    "DeviceData",
    "classify_ports",
    "PortRole",
    "PortInfo",
    "ComplianceEngine",
    "AuditResult",
    "Finding",
    "Status",
    # Policy exceptions
    "ExceptionRegister",
    "ExceptionRule",
    "ExceptionSettings",
    "AppliedException",
    "print_report",
    "save_json",
    "save_html",
    "save_consolidated_html",
    "save_csv",
    "save_remediation_script",
    "load_baseline",
    "compute_delta",
    "save_delta_report",
    "print_delta_summary",
    "run_audit",
    "generate_review_pack",
    "get_review_db_path",
    "ensure_review_store",
    "list_review_packs",
    "get_review_pack",
    "approve_review_pack",
    "reject_review_pack",
    "apply_approved_pack",
    "list_review_packs_api",
    "approve_review_pack_api",
    "reject_review_pack_api",
    "apply_approved_pack_api",
    "apply_all_approved_packs_api",
    "remediation_api_to_json",
    "get_report_artifact_index_path",
    "load_report_artifact_index",
    "resolve_report_path",
    "read_report_content",
]

# package logger
import logging

logger = logging.getLogger(__name__)
