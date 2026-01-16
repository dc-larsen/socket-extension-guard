"""
Socket Extension Guard Client

Scan Chrome extensions for security risks.

Usage:
    from extension_guard import ExtensionGuardClient

    client = ExtensionGuardClient()
    result = client.scan("extension_id")
    print(result.recommendation)
"""

from .client import ExtensionGuardClient
from .models import (
    Alert,
    ExtensionScanResult,
    Severity,
    Recommendation,
    ALERT_DESCRIPTIONS,
)
from .report import generate_html_report

__version__ = "1.0.0"
__all__ = [
    "ExtensionGuardClient",
    "Alert",
    "ExtensionScanResult",
    "Severity",
    "Recommendation",
    "ALERT_DESCRIPTIONS",
    "generate_html_report",
]
