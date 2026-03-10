"""
Cisco IOS-XE Compliance Auditor

Core networking utilities (credentials, jump host, device connections) plus
a full compliance-audit pipeline: data collection → port classification →
policy checks → reporting.
"""
__version__ = "4.0"

from .credentials import CredentialHandler
from .jump_manager import JumpManager
from .config_loader import Config
from .netmiko_utils import DeviceConnector
from .hostname_parser import parse_hostname, HostnameInfo
from .collector import DataCollector, OfflineCollector, DeviceData
from .port_classifier import classify_ports, PortRole, PortInfo
from .compliance_engine import ComplianceEngine, AuditResult, Finding, Status
from .report import (
    print_report, save_json, save_html, save_consolidated_html,
    save_csv, save_remediation_script,
    load_baseline, compute_delta, save_delta_report, print_delta_summary,
)
from .auditor import run_audit

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
]

# package logger
import logging
logger = logging.getLogger(__name__)