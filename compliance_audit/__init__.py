"""
Cisco IOS-XE Compliance Auditor

Core networking utilities (credentials, jump host, device connections) plus
a full compliance-audit pipeline: data collection → port classification →
policy checks → reporting.
"""

__version__ = "4.0"

try:
    from .version import get_version as _get_version
    __version__ = _get_version()
except Exception:
    pass  # Falls back to the literal above if VERSION.txt is missing

from .auditor import run_audit
from .collector import DataCollector, DeviceData
from .compliance_engine import AuditResult, ComplianceEngine, Finding, Status
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
