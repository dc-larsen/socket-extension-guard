# Enterprise Use Cases

Integration patterns for using Extension Guard in enterprise environments.

## Use Case 1: Initial Extension Audit

**Scenario:** You want to understand the security posture of extensions already installed across your organization.

### Step 1: Export Current Extensions

**From Google Workspace Admin Console:**
```bash
# Export from Admin Console > Devices > Chrome > Apps & extensions
# Download as CSV, then extract extension IDs
```

**From Endpoint Detection:**
```bash
# Many EDR tools can list installed extensions
# Export to a text file with one ID per line
```

### Step 2: Scan All Extensions

```bash
# Create extensions.txt with one ID per line
python scan.py --file extensions.txt --html audit-report.html --open
```

### Step 3: Generate Risk Summary

```bash
# JSON output for processing
python scan.py --file extensions.txt --json > audit-results.json
```

```python
import json

with open("audit-results.json") as f:
    results = json.load(f)

# Count by recommendation
block = sum(1 for r in results if r["recommendation"] == "block")
review = sum(1 for r in results if r["recommendation"] == "review")
allow = sum(1 for r in results if r["recommendation"] == "allow")

print(f"BLOCK: {block}")
print(f"REVIEW: {review}")
print(f"ALLOW: {allow}")

# List extensions to block
print("\nExtensions requiring immediate action:")
for r in results:
    if r["recommendation"] == "block":
        print(f"  - {r['name']} ({r['id']}): {r['reason']}")
```

---

## Use Case 2: CI/CD Policy Enforcement

**Scenario:** Automatically scan and enforce extension policies as part of your deployment pipeline.

### GitHub Actions Workflow

```yaml
# .github/workflows/extension-audit.yml
name: Extension Security Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday at 9 AM
  push:
    paths:
      - 'approved-extensions.txt'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Clone Extension Guard
        run: |
          git clone https://github.com/dc-larsen/extension-guard-demo.git
          pip install -r extension-guard-demo/requirements.txt

      - name: Scan Extensions
        env:
          SOCKET_API_KEY: ${{ secrets.SOCKET_API_KEY }}
        run: |
          cd extension-guard-demo
          python scan.py --file ../approved-extensions.txt --json > ../results.json

      - name: Check for Blocked Extensions
        run: |
          python << 'EOF'
          import json
          import sys

          with open("results.json") as f:
              results = json.load(f)

          blocked = [r for r in results if r["recommendation"] == "block"]

          if blocked:
              print("FAILED: The following extensions should be blocked:")
              for r in blocked:
                  print(f"  - {r['name']}: {r['reason']}")
              sys.exit(1)
          else:
              print("PASSED: No extensions require blocking")
          EOF

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: extension-audit-report
          path: results.json
```

---

## Use Case 3: New Extension Request Workflow

**Scenario:** Users request new extensions through a ticketing system. Automate initial security screening.

### Slack Bot Integration

```python
import os
import re
from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from extension_guard import ExtensionGuardClient

slack = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
scanner = ExtensionGuardClient()

def handle_extension_request(event):
    text = event.get("text", "")

    # Extract extension ID or URL from message
    id_match = re.search(r"[a-z]{32}", text)
    if not id_match:
        return "Please provide a valid extension ID or Chrome Web Store URL."

    ext_id = id_match.group()
    result = scanner.scan(ext_id)

    rec = result.recommendation.value.upper()
    icon = result.recommendation.icon

    response = f"""
*Extension Security Scan Results*

*Extension:* {result.name}
*ID:* `{ext_id}`
*Score:* {result.score_overall:.2f}/1.0

*Recommendation:* {icon} *{rec}*
*Reason:* {result.recommendation_reason}

*Alerts:*
• Critical: {len(result.critical_alerts)}
• High: {len(result.high_alerts)}
• Medium: {len(result.medium_alerts)}

"""

    if rec == "BLOCK":
        response += "\n⛔ *This extension cannot be approved.*"
    elif rec == "REVIEW":
        response += "\n👀 *Security team review required before approval.*"
    else:
        response += "\n✅ *Extension passes automated security checks.*"

    return response
```

### ServiceNow Integration

```python
import requests
from extension_guard import ExtensionGuardClient

def scan_for_servicenow(extension_id: str) -> dict:
    """Scan extension and return ServiceNow-compatible response."""
    client = ExtensionGuardClient()
    result = client.scan(extension_id)

    # Map to ServiceNow incident fields
    return {
        "short_description": f"Extension Scan: {result.name}",
        "description": f"""
Extension Guard Security Scan Results

Extension: {result.name}
ID: {extension_id}
Version: {result.version}
Score: {result.score_overall:.2f}/1.0

Recommendation: {result.recommendation.value.upper()}
Reason: {result.recommendation_reason}

Alert Summary:
- Critical: {len(result.critical_alerts)}
- High: {len(result.high_alerts)}
- Medium: {len(result.medium_alerts)}
- Low: {len(result.low_alerts)}

High-Risk Permissions: {', '.join(result.high_risk_permissions) or 'None'}
""",
        "priority": {
            "block": 1,   # Critical
            "review": 2,  # High
            "allow": 4,   # Low
        }[result.recommendation.value],
        "category": "Security",
        "subcategory": "Browser Extension Review",
    }
```

---

## Use Case 4: Scheduled Monitoring

**Scenario:** Continuously monitor approved extensions for security changes.

### Scheduled Scan Script

```python
#!/usr/bin/env python3
"""
Weekly extension monitoring script.
Run via cron: 0 9 * * 1 /path/to/monitor.py
"""

import json
import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

from extension_guard import ExtensionGuardClient

# Configuration
EXTENSIONS_FILE = Path("approved-extensions.txt")
RESULTS_DIR = Path("scan-history")
ALERT_EMAIL = "security@company.com"

def main():
    client = ExtensionGuardClient()

    # Load approved extensions
    with open(EXTENSIONS_FILE) as f:
        extension_ids = [line.strip() for line in f if line.strip()]

    # Scan
    results = client.scan_batch(extension_ids)

    # Save results with timestamp
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    results_file = RESULTS_DIR / f"scan-{timestamp}.json"

    with open(results_file, "w") as f:
        json.dump([{
            "id": r.id,
            "name": r.name,
            "recommendation": r.recommendation.value,
            "score": r.score_overall,
            "alerts": len(r.alerts),
        } for r in results], f, indent=2)

    # Check for issues
    issues = [r for r in results if r.recommendation.value != "allow"]

    if issues:
        send_alert(issues)
        print(f"ALERT: {len(issues)} extensions need attention")
    else:
        print(f"OK: All {len(results)} extensions pass security checks")

def send_alert(issues):
    body = "The following extensions require attention:\n\n"
    for r in issues:
        body += f"- {r.name}: {r.recommendation.value.upper()}\n"
        body += f"  Reason: {r.recommendation_reason}\n\n"

    msg = MIMEText(body)
    msg["Subject"] = f"Extension Security Alert: {len(issues)} issues"
    msg["From"] = "extension-guard@company.com"
    msg["To"] = ALERT_EMAIL

    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)

if __name__ == "__main__":
    main()
```

---

## Use Case 5: Browser Policy Generation

**Scenario:** Generate Chrome/Edge policies based on scan results.

### Chrome Policy Generator

```python
#!/usr/bin/env python3
"""Generate Chrome browser policy from scan results."""

import json
from extension_guard import ExtensionGuardClient

def generate_chrome_policy(extension_ids: list[str]) -> dict:
    client = ExtensionGuardClient()
    results = client.scan_batch(extension_ids)

    # Categorize by recommendation
    blocked = []
    allowed = []

    for result in results:
        ext_id = result.input_purl.replace("pkg:chrome/", "")

        if result.recommendation.value == "block":
            blocked.append(ext_id)
        elif result.recommendation.value == "allow":
            allowed.append(ext_id)
        # "review" extensions are neither blocked nor explicitly allowed

    # Generate Chrome policy JSON
    policy = {
        "ExtensionInstallBlocklist": blocked,
        "ExtensionInstallAllowlist": allowed,
        "ExtensionInstallForcelist": [],  # Extensions to force-install
        "ExtensionSettings": {
            "*": {
                "installation_mode": "blocked",
                "blocked_install_message": "Contact IT to request extension approval"
            }
        }
    }

    # Add individual settings for allowed extensions
    for ext_id in allowed:
        policy["ExtensionSettings"][ext_id] = {
            "installation_mode": "allowed"
        }

    return policy

# Usage
extension_ids = [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
    "hdokiejnpimakedhajhdlcegeplioahd",  # LastPass
]

policy = generate_chrome_policy(extension_ids)
print(json.dumps(policy, indent=2))
```

### Output Example

```json
{
  "ExtensionInstallBlocklist": [],
  "ExtensionInstallAllowlist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",
    "hdokiejnpimakedhajhdlcegeplioahd"
  ],
  "ExtensionInstallForcelist": [],
  "ExtensionSettings": {
    "*": {
      "installation_mode": "blocked",
      "blocked_install_message": "Contact IT to request extension approval"
    },
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
      "installation_mode": "allowed"
    },
    "hdokiejnpimakedhajhdlcegeplioahd": {
      "installation_mode": "allowed"
    }
  }
}
```

---

## Use Case 6: SIEM Integration

**Scenario:** Send extension scan results to your SIEM for correlation and alerting.

### Splunk HTTP Event Collector

```python
import json
import requests
from extension_guard import ExtensionGuardClient

SPLUNK_HEC_URL = "https://splunk.company.com:8088/services/collector/event"
SPLUNK_HEC_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]

def send_to_splunk(result):
    event = {
        "time": int(time.time()),
        "source": "extension-guard",
        "sourcetype": "extension:scan",
        "event": {
            "extension_id": result.input_purl.replace("pkg:chrome/", ""),
            "extension_name": result.name,
            "version": result.version,
            "score_overall": result.score_overall,
            "score_supply_chain": result.score_supply_chain,
            "score_vulnerability": result.score_vulnerability,
            "recommendation": result.recommendation.value,
            "alert_count_critical": len(result.critical_alerts),
            "alert_count_high": len(result.high_alerts),
            "alert_count_medium": len(result.medium_alerts),
            "alert_count_low": len(result.low_alerts),
            "high_risk_permissions": result.high_risk_permissions,
        }
    }

    requests.post(
        SPLUNK_HEC_URL,
        headers={
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        },
        json=event,
    )

# Scan and send to SIEM
client = ExtensionGuardClient()
results = client.scan_batch(extension_ids)

for result in results:
    send_to_splunk(result)
```

---

## Next Steps

- [API Reference](api-reference.md) - Full Python library documentation
- [Understanding Alerts](understanding-alerts.md) - Deep dive on alert types
