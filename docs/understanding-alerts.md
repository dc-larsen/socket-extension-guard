# Understanding Extension Guard Alerts

Extension Guard analyzes Chrome extensions and generates alerts for potentially risky behaviors. This guide explains what each alert means and how to interpret them.

## Alert Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| **Critical** | Known malware or extremely dangerous patterns | Block immediately |
| **High** | Dangerous capabilities or suspicious code | Review carefully before allowing |
| **Medium** | Risky patterns that may be legitimate | Evaluate against stated purpose |
| **Low** | Informational, generally acceptable | Note for audit trail |

## Alert Types Reference

### Critical Severity

#### `malware`
**Known Malware Detected**

The extension contains code patterns that match known malicious extensions. This could include:
- Credential stealing code
- Cryptocurrency mining scripts
- Data exfiltration mechanisms
- Unauthorized tracking

**Action:** Block immediately. Do not install under any circumstances.

#### `gptAnomaly`
**AI-Detected Anomaly**

Socket's AI analysis detected code patterns that appear suspicious or don't match the extension's stated purpose.

**Action:** Review carefully. Verify the publisher's reputation and compare functionality to similar trusted extensions.

---

### High Severity

#### `chromePermission`
**Chrome API Permission**

The extension requests access to a Chrome API. The risk depends on the specific permission:

| Permission | Risk Level | Purpose |
|------------|------------|---------|
| `tabs` | High | Access all tab URLs and titles |
| `webRequest` | High | Intercept all network requests |
| `webRequestBlocking` | High | Modify or block requests |
| `cookies` | High | Access all cookies |
| `history` | High | Read browser history |
| `debugger` | Critical | Full debugging access |
| `nativeMessaging` | High | Communicate with desktop apps |
| `management` | High | Control other extensions |
| `storage` | Low | Store extension data |
| `alarms` | Low | Schedule tasks |

**Action:** Compare requested permissions against the extension's stated features. A password manager needs `tabs` and form access. An ad blocker needs `webRequest`. A theme shouldn't need any sensitive permissions.

#### `chromeWildcardHostPermission`
**Wildcard Host Access**

The extension can access ALL websites you visit. Patterns include:
- `<all_urls>`
- `*://*/*`
- `*://*`

**Risk:** The extension can read and modify content on every page, including banking sites, email, and sensitive applications.

**Action:** Only allow for well-established extensions where broad access is essential (ad blockers, password managers). Reject unknown extensions with this permission.

---

### Medium Severity

#### `chromeHostPermission`
**Specific Host Access**

The extension can access specific websites or domains.

**Examples:**
- `https://github.com/*` - GitHub only
- `https://*.google.com/*` - All Google services
- `https://mail.google.com/*` - Gmail only

**Action:** Verify the domains match the extension's purpose. A GitHub helper should only access GitHub. Suspicious if a "calculator" extension requests banking domains.

#### `chromeContentScript`
**Content Script Injection**

The extension injects JavaScript into web pages. This is normal for many legitimate extensions.

**Common legitimate uses:**
- Ad blockers (block ad elements)
- Password managers (fill forms)
- Accessibility tools (modify page layout)
- Developer tools (inspect elements)

**Action:** Review the target URLs. Injection should be limited to relevant sites. Broad injection patterns warrant review.

#### `usesEval`
**Dynamic Code Execution**

The extension uses `eval()`, `new Function()`, or similar dynamic code execution.

**Risk:** Can execute arbitrary code at runtime, potentially hiding malicious behavior or loading remote code.

**Action:** High risk if combined with network access. Some legitimate extensions use eval for JSON parsing (legacy) or templating. Modern extensions should avoid eval.

#### `networkAccess`
**External Network Requests**

The extension makes HTTP requests to external servers.

**Legitimate uses:**
- Sync data to cloud services
- Fetch extension updates
- Load remote resources

**Risk:** Can exfiltrate browsing data, credentials, or other sensitive information.

**Action:** Check where requests go. Requests to well-known services (Google, AWS) with clear purpose are acceptable. Unknown destinations warrant investigation.

#### `shellAccess`
**Shell/Command Patterns**

The extension contains code patterns suggesting shell or command execution.

**Risk:** Highly unusual for browser extensions. Could indicate attempts to escape the browser sandbox.

**Action:** Block unless there's a clear, documented reason for this capability.

#### `filesystemAccess`
**Local Filesystem Access**

The extension accesses the local filesystem through the File System API.

**Legitimate uses:**
- File management extensions
- Download managers
- Code editors

**Action:** Verify the extension's purpose requires filesystem access.

---

### Low Severity

#### `obfuscatedCode`
**Obfuscated Code**

The extension contains minified or obfuscated JavaScript that's difficult to audit.

**Note:** Many extensions minify code for size optimization. True obfuscation (variable mangling, string encoding) is more concerning.

**Action:** Review publisher reputation. Established publishers with obfuscated code are lower risk than unknown publishers.

#### `envVars`
**Environment Variable Access**

The extension references environment variables.

**Risk:** Low in browser context since extensions can't access system environment variables.

**Action:** Generally acceptable. Note for completeness.

## Alert Combinations

Some combinations of alerts warrant additional scrutiny:

| Combination | Risk | Reason |
|-------------|------|--------|
| `usesEval` + `networkAccess` | High | Can download and execute remote code |
| `chromeWildcardHostPermission` + `usesEval` | High | Full page access with dynamic execution |
| `webRequest` + `networkAccess` | High | Can intercept and exfiltrate all traffic |
| `tabs` + `networkAccess` | High | Can track and report all browsing |

## Score Interpretation

Extension Guard provides three scores (0.0 - 1.0):

| Score | Range | Meaning |
|-------|-------|---------|
| **Overall** | 0.0-1.0 | Combined security assessment |
| **Supply Chain** | 0.0-1.0 | Publisher trust, update patterns |
| **Vulnerability** | 0.0-1.0 | Known security issues |

**Score guidance:**
- 0.7+ : Generally safe
- 0.4-0.7 : Review recommended
- <0.4 : High risk, consider blocking

## Next Steps

- [Decision Framework](decision-framework.md) - How to make BLOCK/ALLOW decisions
- [Enterprise Use Cases](enterprise-use-cases.md) - Automated policy enforcement
