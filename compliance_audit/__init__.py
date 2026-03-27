"""
Cisco IOS-XE Compliance Auditor

Core networking utilities (credentials, jump host, device connections) plus
a full compliance-audit pipeline: data collection → port classification →
policy checks → reporting.
"""

__version__ = "4.0"

from .auditor import run_audit
from .collector import DataCollector, DeviceData, OfflineCollector
from .compliance_engine import AuditResult, ComplianceEngine, Finding, Status
from .config_loader import Config
from .credentials import CredentialHandler
from .hostname_parser import HostnameInfo, parse_hostname
from .jump_manager import JumpManager
from .netmiko_utils import DeviceConnector
from .port_classifier import PortInfo, PortRole, classify_ports
from .remediation_workflow import (
    apply_approved_pack,
    approve_review_pack,
    generate_review_pack,
    list_review_packs,
    reject_review_pack,
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
    # Existing
    "CredentialHandler",
    "JumpManager",
    "Config",
    "DeviceConnector",
    # Compliance audit
    "parse_hostname",
    "HostnameInfo",
    "DataCollector",
    "OfflineCollector",
    "DeviceData",
    "classify_ports",
    "PortRole",
    "PortInfo",
    "ComplianceEngine",
    "AuditResult",
    "Finding",
    "Status",
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
    "list_review_packs",
    "approve_review_pack",
    "reject_review_pack",
    "apply_approved_pack",
]

# package logger
import logging

logger = logging.getLogger(__name__)
