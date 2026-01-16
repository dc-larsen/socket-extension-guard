# API Reference

Complete documentation for the Extension Guard Python library.

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from extension_guard import ExtensionGuardClient, generate_html_report

# Initialize client (uses SOCKET_API_KEY env var)
client = ExtensionGuardClient()

# Scan an extension
result = client.scan("cjpalhdlnbpafiamejdnhcphjbkeiagm")

# Check recommendation
if result.recommendation.value == "block":
    print(f"BLOCK: {result.recommendation_reason}")
```

---

## ExtensionGuardClient

The main client for interacting with the Socket Extension Guard API.

### Constructor

```python
ExtensionGuardClient(api_key: Optional[str] = None)
```

**Parameters:**
- `api_key` - Socket API key. If not provided, reads from `SOCKET_API_KEY` environment variable.

**Raises:**
- `ValueError` - If no API key is provided or found.

**Example:**
```python
# Use environment variable
client = ExtensionGuardClient()

# Or provide explicitly
client = ExtensionGuardClient("sk_live_xxxx")
```

### scan()

Scan a single Chrome extension.

```python
scan(extension_id: str) -> ExtensionScanResult
```

**Parameters:**
- `extension_id` - Extension ID (32 lowercase letters) or Chrome Web Store URL.

**Returns:**
- `ExtensionScanResult` object with alerts and recommendation.

**Example:**
```python
# By ID
result = client.scan("cjpalhdlnbpafiamejdnhcphjbkeiagm")

# By URL
result = client.scan("https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm")
```

### scan_batch()

Scan multiple extensions efficiently.

```python
scan_batch(
    extension_ids: list[str],
    batch_size: int = 50
) -> list[ExtensionScanResult]
```

**Parameters:**
- `extension_ids` - List of extension IDs or URLs.
- `batch_size` - Number of extensions per API call (max 100).

**Returns:**
- List of `ExtensionScanResult` objects.

**Example:**
```python
results = client.scan_batch([
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",
    "hdokiejnpimakedhajhdlcegeplioahd",
    "fmkadmapgofadopljbjfkapdkoienihi",
])

for result in results:
    print(f"{result.name}: {result.recommendation.value}")
```

### extract_extension_id()

Extract Chrome extension ID from various input formats.

```python
@staticmethod
extract_extension_id(input_str: str) -> str
```

**Parameters:**
- `input_str` - Extension ID or Chrome Web Store URL.

**Returns:**
- 32-character extension ID.

**Raises:**
- `ValueError` - If no valid extension ID found.

**Supported formats:**
```python
# Raw ID
ExtensionGuardClient.extract_extension_id("cjpalhdlnbpafiamejdnhcphjbkeiagm")

# Chrome Web Store URL
ExtensionGuardClient.extract_extension_id(
    "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
)

# Short URL
ExtensionGuardClient.extract_extension_id(
    "https://chrome.google.com/webstore/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm"
)
```

---

## ExtensionScanResult

Container for scan results.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Extension ID from Chrome Web Store |
| `name` | `str` | Extension display name |
| `version` | `str` | Current version |
| `size` | `int` | Size in bytes |
| `score_overall` | `float` | Overall security score (0-1) |
| `score_supply_chain` | `float` | Supply chain score (0-1) |
| `score_vulnerability` | `float` | Vulnerability score (0-1) |
| `alerts` | `list[Alert]` | All security alerts |
| `input_purl` | `str` | Package URL used for scanning |
| `error` | `Optional[str]` | Error message if scan failed |

### Computed Properties

```python
# Alert lists by severity
result.critical_alerts  # list[Alert]
result.high_alerts      # list[Alert]
result.medium_alerts    # list[Alert]
result.low_alerts       # list[Alert]

# Boolean checks
result.has_malware       # bool
result.has_wildcard_host # bool
result.has_eval          # bool
result.has_network       # bool

# Risk indicators
result.high_risk_permissions  # list[str]

# Recommendation
result.recommendation        # Recommendation enum
result.recommendation_reason # str

# Display helpers
result.size_human  # str (e.g., "1.2 MB")
```

### Methods

```python
# Group alerts
result.alerts_by_type()      # dict[str, list[Alert]]
result.alerts_by_severity()  # dict[Severity, list[Alert]]
```

### Example Usage

```python
result = client.scan("cjpalhdlnbpafiamejdnhcphjbkeiagm")

print(f"Extension: {result.name}")
print(f"Version: {result.version}")
print(f"Size: {result.size_human}")
print(f"Score: {result.score_overall:.2f}")
print(f"Recommendation: {result.recommendation.value}")
print(f"Reason: {result.recommendation_reason}")

if result.critical_alerts:
    print("\nCritical alerts:")
    for alert in result.critical_alerts:
        print(f"  - {alert.type}")

if result.high_risk_permissions:
    print(f"\nHigh-risk permissions: {', '.join(result.high_risk_permissions)}")
```

---

## Alert

Individual security alert.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `type` | `str` | Alert type identifier |
| `severity` | `Severity` | Alert severity level |
| `category` | `str` | Alert category |
| `file` | `Optional[str]` | Source file (if applicable) |
| `permission` | `Optional[str]` | Permission name (for permission alerts) |
| `host` | `Optional[str]` | Host pattern (for host permission alerts) |
| `note` | `Optional[str]` | Additional notes |

### Computed Properties

```python
alert.description   # dict with title, description, risk, action
alert.display_value # str - human-readable value
```

### Example Usage

```python
for alert in result.alerts:
    desc = alert.description
    print(f"[{alert.severity.value}] {desc['title']}")
    if alert.display_value:
        print(f"  Value: {alert.display_value}")
    print(f"  Risk: {desc['risk']}")
    print(f"  Action: {desc['action']}")
```

---

## Severity Enum

Alert severity levels.

```python
from extension_guard.models import Severity

Severity.CRITICAL  # "critical"
Severity.HIGH      # "high"
Severity.MEDIUM    # "middle" (API uses "middle")
Severity.LOW       # "low"
Severity.UNKNOWN   # "unknown"
```

### Properties

```python
severity.weight  # int (4=critical, 3=high, 2=medium, 1=low, 0=unknown)
severity.color   # str (CSS color code)
```

---

## Recommendation Enum

Extension recommendations.

```python
from extension_guard.models import Recommendation

Recommendation.BLOCK   # "block"
Recommendation.REVIEW  # "review"
Recommendation.ALLOW   # "allow"
```

### Properties

```python
recommendation.color  # str (CSS color code)
recommendation.icon   # str (emoji: 🚫, ⚠️, ✓)
```

---

## generate_html_report()

Generate an interactive HTML report from scan results.

```python
from extension_guard import generate_html_report

generate_html_report(
    results: list[ExtensionScanResult],
    title: str = "Extension Guard Report",
    include_raw: bool = False
) -> str
```

**Parameters:**
- `results` - List of scan results.
- `title` - Report title.
- `include_raw` - Include raw API response in report.

**Returns:**
- HTML string.

**Example:**
```python
results = client.scan_batch(extension_ids)

html = generate_html_report(
    results,
    title="Weekly Extension Audit",
    include_raw=True
)

with open("report.html", "w") as f:
    f.write(html)
```

---

## Exceptions

### ExtensionGuardError

Base exception for all Extension Guard errors.

```python
from extension_guard.client import ExtensionGuardError
```

### AuthenticationError

Raised when API authentication fails.

```python
from extension_guard.client import AuthenticationError

try:
    client = ExtensionGuardClient("invalid-key")
    client.scan("...")
except AuthenticationError as e:
    print(f"Auth failed: {e}")
```

### RateLimitError

Raised when API rate limit is exceeded.

```python
from extension_guard.client import RateLimitError

try:
    results = client.scan_batch(many_extensions)
except RateLimitError as e:
    print(f"Rate limited: {e}")
    # Wait and retry
```

---

## Constants

### HIGH_RISK_PERMISSIONS

Set of permission names considered high-risk.

```python
from extension_guard.models import HIGH_RISK_PERMISSIONS

# {'tabs', 'webRequest', 'webRequestBlocking', 'cookies',
#  'history', 'bookmarks', 'downloads', 'management',
#  'nativeMessaging', 'debugger', 'tabCapture',
#  'desktopCapture', 'pageCapture'}
```

### ALERT_DESCRIPTIONS

Dictionary of alert type descriptions.

```python
from extension_guard.models import ALERT_DESCRIPTIONS

desc = ALERT_DESCRIPTIONS.get("malware", {})
print(desc["title"])       # "Known Malware"
print(desc["description"]) # "This extension contains..."
print(desc["risk"])        # "Data theft, credential..."
print(desc["action"])      # "Block immediately..."
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SOCKET_API_KEY` | Socket API key for authentication |

---

## API Endpoint Reference

The client uses Socket's PURL API:

```
POST https://api.socket.dev/v0/purl?alerts=true
Authorization: Basic {api_key}:
Content-Type: application/json

{
  "components": [
    {"purl": "pkg:chrome/cjpalhdlnbpafiamejdnhcphjbkeiagm"}
  ]
}
```

Response includes:
- Extension metadata (name, version, size)
- Security scores (overall, supplyChain, vulnerability)
- Alert array with severity and details
