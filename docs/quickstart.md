# Quickstart Guide

Get started scanning Chrome extensions in under 5 minutes.

## Prerequisites

- Python 3.9+
- Socket API key ([get one here](https://socket.dev/dashboard/settings/api-tokens))

## Installation

```bash
# Clone the repository
git clone https://github.com/dc-larsen/extension-guard-demo.git
cd extension-guard-demo

# Install dependencies
pip install -r requirements.txt

# Set your API key
export SOCKET_API_KEY="your-api-key-here"
```

## Run the Demo

The demo scans popular extensions and opens an interactive report:

```bash
python demo.py
```

This will:
1. Scan 7 curated extensions (uBlock Origin, LastPass, React DevTools, etc.)
2. Generate an HTML report
3. Open the report in your default browser

## Scan Your Own Extensions

### Single Extension

```bash
# By extension ID
python scan.py cjpalhdlnbpafiamejdnhcphjbkeiagm

# By Chrome Web Store URL
python scan.py "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
```

### Multiple Extensions

```bash
# Command line
python scan.py ext1 ext2 ext3

# From a file
python scan.py --file my-extensions.txt
```

### Output Formats

```bash
# HTML report (recommended)
python scan.py --file extensions.txt --html report.html --open

# JSON output (for automation)
python scan.py cjpalhdlnbpafiamejdnhcphjbkeiagm --json

# Text output (default)
python scan.py cjpalhdlnbpafiamejdnhcphjbkeiagm
```

## Finding Extension IDs

### Method 1: Chrome Web Store URL

The extension ID is the 32-character string at the end of the URL:

```
https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm
                                                        └─────────────────────────────────┘
                                                                    extension ID
```

### Method 2: Chrome Extensions Page

1. Open `chrome://extensions` in Chrome
2. Enable "Developer mode" (top right)
3. Copy the ID from the extension card

### Method 3: Corporate Extension List

If your organization uses Google Workspace or a browser management tool:
- Export installed extensions from the admin console
- Use the extension IDs from your blocklist/allowlist

## Next Steps

- [Understanding Alerts](understanding-alerts.md) - What each alert type means
- [Decision Framework](decision-framework.md) - How to decide BLOCK vs ALLOW
- [Enterprise Use Cases](enterprise-use-cases.md) - Integration patterns
- [API Reference](api-reference.md) - Python library documentation
