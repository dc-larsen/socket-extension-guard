<p align="center">
  <img src="docs/assets/banner.png" alt="Extension Guard" width="800">
</p>

# Socket Extension Guard

Scan Chrome extensions for security risks using Socket's Extension Guard API. Get actionable insights to decide whether to allow or block extensions in your organization.

## Quick Start

**1. Get your API token** from [Socket Dashboard → Settings → API Tokens](https://socket.dev/dashboard/settings/api-tokens)

Required scope: **Full Access** (for extension scanning)

**2. Clone and configure**

```bash
git clone https://github.com/dc-larsen/socket-extension-guard.git
cd socket-extension-guard
cp .env.example .env
# Edit .env and add your SOCKET_API_KEY
```

**3. Run the demo**

```bash
# Install dependencies
pip install -r requirements.txt

# Scan sample extensions and open results in browser
python demo.py
```

This scans a curated set of extensions (good, risky, and known-bad) and opens an interactive HTML report.

## What You Get

- **Security scores** (0-1) for overall risk, supply chain, and vulnerabilities
- **Detailed alerts** with severity levels (critical, high, medium, low)
- **Permission analysis** showing what each extension can access
- **Clear recommendations** on whether to block or allow

## Use Cases

| Goal | Command |
|------|---------|
| Scan a single extension | `python scan.py <extension_id>` |
| Scan from Chrome Web Store URL | `python scan.py "https://chromewebstore.google.com/detail/..."` |
| Scan multiple extensions | `python scan.py ext1 ext2 ext3` |
| Scan from CSV/list file | `python scan.py --file extensions.txt` |
| Generate HTML report | `python scan.py <id> --html report.html` |
| JSON output for automation | `python scan.py <id> --json` |

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Understanding Alerts](docs/understanding-alerts.md)
- [Decision Framework](docs/decision-framework.md)
- [API Reference](docs/api-reference.md)
- [Enterprise Use Cases](docs/enterprise-use-cases.md)

## Example Output

```
Extension: uBlock Origin (cjpalhdlnbpafiamejdnhcphjbkeiagm)
Version:   1.68.0
Score:     0.44/1.0 (Moderate Risk)

Alerts (21 total):
  CRITICAL: 0
  HIGH:     10  ← Review required
  MEDIUM:   8
  LOW:      3

High-severity alerts:
  • chromePermission: tabs
  • chromePermission: storage
  • chromePermission: <all_urls>
  • chromePermission: webRequest
  ...

Recommendation: REVIEW - Popular extension with broad permissions.
                Verify this is the legitimate uBlock Origin.
```

## Should I Block This Extension?

Use this decision matrix:

| Scenario | Score | Critical Alerts | Action |
|----------|-------|-----------------|--------|
| Known malware | Any | Yes (malware type) | **BLOCK immediately** |
| Unknown + low score | < 0.3 | Any | **BLOCK** |
| Unknown + broad permissions | Any | `<all_urls>` + eval | **BLOCK** |
| Popular + verified publisher | > 0.5 | None | **Allow** |
| Internal/corp extension | Any | None | **Allow** (verify source) |

See [Decision Framework](docs/decision-framework.md) for detailed guidance.

## Requirements

- Python 3.9+
- Socket API key with Full Access scope
- Internet connection

## License

MIT

## Support

- [Socket Documentation](https://docs.socket.dev)
- [Extension Guard Docs](https://docs.socket.dev/docs/language-support#extension-scanning)
- Questions? Contact your Socket account team
