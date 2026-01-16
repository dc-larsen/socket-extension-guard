# Extension Decision Framework

A practical guide for deciding whether to BLOCK, REVIEW, or ALLOW a Chrome extension.

## Quick Decision Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXTENSION DECISION TREE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Has malware alert?                                              │
│     YES → BLOCK                                                  │
│     NO  ↓                                                        │
│                                                                  │
│  Has critical alerts?                                            │
│     YES → BLOCK                                                  │
│     NO  ↓                                                        │
│                                                                  │
│  Score < 0.3?                                                    │
│     YES → BLOCK                                                  │
│     NO  ↓                                                        │
│                                                                  │
│  Uses eval + network + score < 0.5?                              │
│     YES → BLOCK                                                  │
│     NO  ↓                                                        │
│                                                                  │
│  Has 5+ high alerts OR 3+ high-risk permissions?                 │
│     YES → REVIEW                                                 │
│     NO  ↓                                                        │
│                                                                  │
│  Has wildcard host + eval?                                       │
│     YES → REVIEW                                                 │
│     NO  ↓                                                        │
│                                                                  │
│  Score < 0.6?                                                    │
│     YES → REVIEW                                                 │
│     NO  → ALLOW                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Automatic BLOCK Conditions

Block immediately if ANY of these are true:

| Condition | Reason |
|-----------|--------|
| `malware` alert present | Known malicious code |
| Any `critical` severity alert | Extremely dangerous behavior |
| Overall score < 0.3 | Very low trust signals |
| eval + network + score < 0.5 | Code injection risk |

## Manual REVIEW Conditions

Require security team review if ANY of these are true:

| Condition | Reason |
|-----------|--------|
| 5+ high severity alerts | Accumulation of risks |
| 3+ high-risk permissions | Excessive capabilities |
| Wildcard host + eval | Full access with code execution |
| Score 0.3-0.6 | Moderate risk indicators |
| Unknown publisher | No trust history |

## ALLOW Conditions

Allow if ALL of these are true:

| Condition | Threshold |
|-----------|-----------|
| No critical or malware alerts | Zero |
| High alerts | < 5 |
| High-risk permissions | < 3 |
| Overall score | ≥ 0.6 |
| No dangerous combinations | See above |

## Permission Risk Reference

### High-Risk Permissions (count towards REVIEW threshold)

```
tabs              - Access all tab URLs
webRequest        - Intercept network requests
webRequestBlocking- Modify/block requests
cookies           - Access all cookies
history           - Browser history
bookmarks         - Bookmark access
downloads         - Download management
management        - Control other extensions
nativeMessaging   - Desktop app communication
debugger          - Full debugging access (CRITICAL)
tabCapture        - Capture tab content
desktopCapture    - Screen capture
pageCapture       - Save pages as MHTML
```

### Acceptable Permissions (don't count towards threshold)

```
storage           - Extension data storage
alarms            - Schedule tasks
notifications     - Show notifications
contextMenus      - Right-click menu items
activeTab         - Current tab only (when clicked)
clipboardRead     - Read clipboard
clipboardWrite    - Write clipboard
```

## Category-Specific Guidance

### Ad Blockers
**Expected permissions:**
- `webRequest`, `webRequestBlocking` (required for blocking)
- `<all_urls>` or `*://*/*` (must see all pages)
- `tabs` (manage tab-specific settings)
- `storage` (save preferences)

**Red flags:**
- `nativeMessaging` (no need for desktop communication)
- `history`, `bookmarks` (unrelated to blocking ads)
- Network requests to unknown analytics servers

### Password Managers
**Expected permissions:**
- `<all_urls>` or `*://*/*` (fill forms everywhere)
- `tabs` (detect login pages)
- `storage` (store encrypted vault)
- `clipboardWrite` (copy passwords)

**Red flags:**
- `webRequest` (shouldn't intercept all traffic)
- `history` (no need to read history)
- eval usage (should use secure practices)

### Developer Tools
**Expected permissions:**
- Specific host permissions (e.g., `*://github.com/*`)
- `storage`, `activeTab`
- `devtools` (inspect page)

**Red flags:**
- `<all_urls>` (should be scoped)
- `cookies`, `history` (unrelated to development)
- Network access to unknown servers

### Productivity Tools
**Expected permissions:**
- Limited host permissions (specific services)
- `storage`, `alarms`, `notifications`

**Red flags:**
- `<all_urls>` (scope should be limited)
- Any high-risk permissions
- eval or network access to unknown destinations

## Enterprise Policy Template

For automated enforcement, use these thresholds in your browser management policy:

```yaml
extension_policy:
  # Automatic blocks
  block:
    - alert_type: malware
    - alert_severity: critical
    - score_overall_lt: 0.3
    - combination:
        has_eval: true
        has_network: true
        score_overall_lt: 0.5

  # Require approval
  review:
    - high_alerts_gt: 5
    - high_risk_permissions_gt: 2
    - combination:
        has_wildcard_host: true
        has_eval: true
    - score_overall_lt: 0.6
    - publisher_unknown: true

  # Auto-allow known safe
  allow:
    - extension_id: cjpalhdlnbpafiamejdnhcphjbkeiagm  # uBlock Origin
    - extension_id: hdokiejnpimakedhajhdlcegeplioahd  # LastPass
    - publisher: "Google"
    - score_overall_gt: 0.8
```

## Integration with Browser Management

### Google Workspace (Chrome Browser Cloud Management)

1. Export extension list from Admin Console
2. Scan with Extension Guard
3. Update blocklist/allowlist based on results
4. Apply policy to organizational units

### Microsoft Intune

1. Extract extension IDs from Edge policies
2. Scan with Extension Guard (`--json` output)
3. Update configuration profile based on results
4. Deploy to device groups

### Manual Review Process

For extensions requiring REVIEW:

1. **Identify business need**
   - Who requested the extension?
   - What problem does it solve?
   - Are there safer alternatives?

2. **Evaluate publisher**
   - Established company or individual?
   - History of security issues?
   - Responsive to vulnerability reports?

3. **Compare permissions to purpose**
   - Do permissions match stated features?
   - Are there unexplained permissions?

4. **Check alternatives**
   - Similar extensions with better scores?
   - Built-in browser features instead?

5. **Document decision**
   - Approval with conditions
   - Denial with reason
   - Time-limited approval for re-review

## Next Steps

- [Enterprise Use Cases](enterprise-use-cases.md) - Automation patterns
- [API Reference](api-reference.md) - Build your own integrations
