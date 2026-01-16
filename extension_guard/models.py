"""Data models for Extension Guard scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "middle"  # API returns "middle" not "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def weight(self) -> int:
        """Numeric weight for sorting (higher = more severe)."""
        weights = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.UNKNOWN: 0,
        }
        return weights.get(self, 0)

    @property
    def color(self) -> str:
        """CSS color for this severity."""
        colors = {
            Severity.CRITICAL: "#dc2626",  # Red
            Severity.HIGH: "#ea580c",      # Orange
            Severity.MEDIUM: "#ca8a04",    # Yellow
            Severity.LOW: "#65a30d",       # Green
            Severity.UNKNOWN: "#6b7280",   # Gray
        }
        return colors.get(self, "#6b7280")


class Recommendation(Enum):
    """Extension recommendation based on scan results."""
    BLOCK = "block"
    REVIEW = "review"
    ALLOW = "allow"

    @property
    def color(self) -> str:
        colors = {
            Recommendation.BLOCK: "#dc2626",
            Recommendation.REVIEW: "#ca8a04",
            Recommendation.ALLOW: "#16a34a",
        }
        return colors.get(self, "#6b7280")

    @property
    def icon(self) -> str:
        icons = {
            Recommendation.BLOCK: "🚫",
            Recommendation.REVIEW: "⚠️",
            Recommendation.ALLOW: "✓",
        }
        return icons.get(self, "?")


# Alert type descriptions and risk explanations
ALERT_DESCRIPTIONS: dict[str, dict] = {
    # Critical - Malware indicators
    "malware": {
        "title": "Known Malware",
        "description": "This extension contains known malicious code patterns.",
        "risk": "Data theft, credential stealing, unauthorized tracking.",
        "action": "Block immediately. Do not install under any circumstances.",
    },
    "gptAnomaly": {
        "title": "AI-Detected Anomaly",
        "description": "AI analysis detected suspicious or anomalous code patterns.",
        "risk": "Potentially malicious behavior not matching stated purpose.",
        "action": "Review carefully. Verify publisher and extension purpose.",
    },

    # High - Dangerous capabilities
    "chromePermission": {
        "title": "Chrome Permission",
        "description": "Extension requests a Chrome API permission.",
        "risk": "Depends on specific permission. Some grant broad access.",
        "action": "Review each permission against extension's stated purpose.",
    },
    "chromeWildcardHostPermission": {
        "title": "Wildcard Host Permission",
        "description": "Extension can access ALL websites.",
        "risk": "Can read/modify any page you visit. High data exposure.",
        "action": "Only allow for well-known extensions (ad blockers, etc).",
    },

    # Medium - Risky patterns
    "chromeHostPermission": {
        "title": "Host Permission",
        "description": "Extension can access specific websites.",
        "risk": "Can read/modify pages on listed domains.",
        "action": "Verify domains match extension's purpose.",
    },
    "chromeContentScript": {
        "title": "Content Script",
        "description": "Extension injects JavaScript into web pages.",
        "risk": "Can read page content, modify DOM, intercept data.",
        "action": "Normal for many extensions. Verify matches patterns.",
    },
    "usesEval": {
        "title": "Dynamic Code Execution",
        "description": "Extension uses eval() or similar dynamic code execution.",
        "risk": "Can execute arbitrary code. Common malware technique.",
        "action": "High risk if combined with network access.",
    },
    "networkAccess": {
        "title": "Network Access",
        "description": "Extension makes HTTP requests to external servers.",
        "risk": "Can exfiltrate data to remote servers.",
        "action": "Verify destinations match expected functionality.",
    },
    "shellAccess": {
        "title": "Shell/Command Access",
        "description": "Extension contains shell command patterns.",
        "risk": "Unusual for browser extensions. Potential system access.",
        "action": "Block unless explicitly required functionality.",
    },
    "filesystemAccess": {
        "title": "Filesystem Access",
        "description": "Extension accesses local filesystem.",
        "risk": "Can read/write local files.",
        "action": "Only allow for file manager type extensions.",
    },

    # Low - Informational
    "envVars": {
        "title": "Environment Variables",
        "description": "Extension accesses environment variables.",
        "risk": "Low risk in browser context.",
        "action": "Generally acceptable.",
    },
    "obfuscatedCode": {
        "title": "Obfuscated Code",
        "description": "Extension contains obfuscated or heavily minified code.",
        "risk": "Hard to audit. Could hide malicious behavior.",
        "action": "Review publisher reputation carefully.",
    },
}

# High-risk permission combinations
HIGH_RISK_PERMISSIONS = {
    "tabs",           # Access to all tab URLs
    "webRequest",     # Intercept all network requests
    "webRequestBlocking",  # Modify/block requests
    "cookies",        # Access all cookies
    "history",        # Browser history access
    "bookmarks",      # Bookmark access
    "downloads",      # Download management
    "management",     # Manage other extensions
    "nativeMessaging",  # Communicate with native apps
    "debugger",       # Full debugging access (extremely dangerous)
    "tabCapture",     # Capture tab content
    "desktopCapture", # Screen capture
    "pageCapture",    # Save pages as MHTML
}


@dataclass
class Alert:
    """A security alert from extension scanning."""
    type: str
    severity: Severity
    category: str
    file: Optional[str] = None
    permission: Optional[str] = None
    host: Optional[str] = None
    note: Optional[str] = None
    action: str = ""
    key: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        """Create Alert from API response dict."""
        props = data.get("props", {})
        severity_str = data.get("severity", "unknown")
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.UNKNOWN

        return cls(
            type=data.get("type", ""),
            severity=severity,
            category=data.get("category", ""),
            file=data.get("file"),
            permission=props.get("permission"),
            host=props.get("host"),
            note=props.get("note"),
            action=data.get("action", ""),
            key=data.get("key", ""),
        )

    @property
    def description(self) -> dict:
        """Get description info for this alert type."""
        return ALERT_DESCRIPTIONS.get(self.type, {
            "title": self.type,
            "description": f"Alert type: {self.type}",
            "risk": "Unknown risk level.",
            "action": "Review manually.",
        })

    @property
    def display_value(self) -> str:
        """Human-readable value for this alert."""
        if self.permission:
            return self.permission
        if self.host:
            return self.host
        if self.file:
            return self.file
        return ""


@dataclass
class ExtensionScanResult:
    """Complete scan result for a Chrome extension."""
    id: str
    name: str
    version: str
    size: int
    score_overall: float
    score_supply_chain: float
    score_vulnerability: float
    alerts: list[Alert] = field(default_factory=list)
    input_purl: str = ""
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def critical_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity == Severity.CRITICAL]

    @property
    def high_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity == Severity.HIGH]

    @property
    def medium_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity == Severity.MEDIUM]

    @property
    def low_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity == Severity.LOW]

    @property
    def has_malware(self) -> bool:
        """Check if any alert indicates malware."""
        return any(a.type == "malware" for a in self.alerts)

    @property
    def has_wildcard_host(self) -> bool:
        """Check if extension has <all_urls> or wildcard host access."""
        return any(
            a.type in ("chromeWildcardHostPermission", "chromeHostPermission")
            and a.host and ("*" in a.host or "<all_urls>" in a.host)
            for a in self.alerts
        )

    @property
    def has_eval(self) -> bool:
        """Check if extension uses eval."""
        return any(a.type == "usesEval" for a in self.alerts)

    @property
    def has_network(self) -> bool:
        """Check if extension makes network requests."""
        return any(a.type == "networkAccess" for a in self.alerts)

    @property
    def high_risk_permissions(self) -> list[str]:
        """List of high-risk permissions this extension requests."""
        perms = []
        for alert in self.alerts:
            if alert.type == "chromePermission" and alert.permission:
                if alert.permission in HIGH_RISK_PERMISSIONS:
                    perms.append(alert.permission)
        return perms

    @property
    def recommendation(self) -> Recommendation:
        """Get recommended action for this extension."""
        # Immediate block conditions
        if self.has_malware:
            return Recommendation.BLOCK

        if self.error:
            return Recommendation.REVIEW

        # Critical alerts = block
        if len(self.critical_alerts) > 0:
            return Recommendation.BLOCK

        # Very low score = block
        if self.score_overall < 0.3:
            return Recommendation.BLOCK

        # Dangerous combination: eval + network + low score
        if self.has_eval and self.has_network and self.score_overall < 0.5:
            return Recommendation.BLOCK

        # Many high alerts or high-risk permissions = review
        if len(self.high_alerts) > 5:
            return Recommendation.REVIEW

        if len(self.high_risk_permissions) >= 3:
            return Recommendation.REVIEW

        # Wildcard host + eval = review
        if self.has_wildcard_host and self.has_eval:
            return Recommendation.REVIEW

        # Moderate score = review
        if self.score_overall < 0.6:
            return Recommendation.REVIEW

        # Default: allow
        return Recommendation.ALLOW

    @property
    def recommendation_reason(self) -> str:
        """Explanation for the recommendation."""
        if self.has_malware:
            return "Extension contains known malware patterns."

        if self.error:
            return f"Scan error: {self.error}"

        if len(self.critical_alerts) > 0:
            return f"Extension has {len(self.critical_alerts)} critical security alert(s)."

        if self.score_overall < 0.3:
            return f"Very low security score ({self.score_overall:.2f})."

        if self.has_eval and self.has_network and self.score_overall < 0.5:
            return "Dangerous combination: dynamic code execution with network access."

        if len(self.high_alerts) > 5:
            return f"High number of security alerts ({len(self.high_alerts)} high severity)."

        if len(self.high_risk_permissions) >= 3:
            perms = ", ".join(self.high_risk_permissions[:3])
            return f"Multiple high-risk permissions: {perms}."

        if self.has_wildcard_host and self.has_eval:
            return "Full page access combined with dynamic code execution."

        if self.score_overall < 0.6:
            return f"Moderate security score ({self.score_overall:.2f}). Review permissions."

        return "No critical issues detected. Standard permission set."

    @property
    def size_human(self) -> str:
        """Human-readable size."""
        if self.size < 1024:
            return f"{self.size} B"
        elif self.size < 1024 * 1024:
            return f"{self.size / 1024:.1f} KB"
        else:
            return f"{self.size / (1024 * 1024):.1f} MB"

    def alerts_by_type(self) -> dict[str, list[Alert]]:
        """Group alerts by type."""
        by_type: dict[str, list[Alert]] = {}
        for alert in self.alerts:
            if alert.type not in by_type:
                by_type[alert.type] = []
            by_type[alert.type].append(alert)
        return by_type

    def alerts_by_severity(self) -> dict[Severity, list[Alert]]:
        """Group alerts by severity."""
        by_sev: dict[Severity, list[Alert]] = {}
        for alert in self.alerts:
            if alert.severity not in by_sev:
                by_sev[alert.severity] = []
            by_sev[alert.severity].append(alert)
        return by_sev
