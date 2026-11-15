"""Package metadata for Cisco Compliance Audit."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as package_version

from .version import get_version

__title__ = "cisco-compliance-audit"
__app_name__ = __title__
__description__ = "Cisco IOS-XE compliance auditing tool"
__license__ = "Apache-2.0"
__author__ = "Christopher Davies"

try:
	__version__ = package_version(__title__)
except PackageNotFoundError:
	__version__ = get_version()
