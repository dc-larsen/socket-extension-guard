#!/usr/bin/env python3
"""
Extension Guard Demo

Scans a curated set of Chrome extensions and opens an interactive
HTML report in your browser.

Usage:
    python demo.py
"""

import os
import sys
import tempfile
import webbrowser
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from extension_guard import ExtensionGuardClient, generate_html_report


# Sample extensions for demo
# Mix of well-known, risky, and various permission levels
DEMO_EXTENSIONS = [
    # Well-known, popular extensions
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),
    ("gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"),
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass"),

    # Browser tools
    ("fmkadmapgofadopljbjfkapdkoienihi", "React Developer Tools"),
    ("lmhkpmbekcpmknklioeibfkpmmfibljd", "Redux DevTools"),

    # Productivity
    ("aapbdbdomjkkjkaonfhkkikfgjllcleb", "Google Translate"),

    # Socket's own extension
    ("jbcobpbfgkhmjfpjjepkcocalmpkiaop", "Socket Security"),
]


def main():
    print("=" * 60)
    print("  Socket Extension Guard Demo")
    print("=" * 60)
    print()

    # Check for API key
    api_key = os.getenv("SOCKET_API_KEY")
    if not api_key:
        print("ERROR: SOCKET_API_KEY environment variable not set.")
        print()
        print("To get started:")
        print("  1. Get your API key from:")
        print("     https://socket.dev/dashboard/settings/api-tokens")
        print()
        print("  2. Set the environment variable:")
        print("     export SOCKET_API_KEY='your-api-key-here'")
        print()
        print("  3. Run this demo again:")
        print("     python demo.py")
        print()
        sys.exit(1)

    try:
        client = ExtensionGuardClient(api_key)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(f"Scanning {len(DEMO_EXTENSIONS)} extensions...")
    print()

    # Scan each extension
    results = []
    for ext_id, name in DEMO_EXTENSIONS:
        print(f"  Scanning: {name}...", end=" ", flush=True)
        try:
            result = client.scan(ext_id)
            rec = result.recommendation.value.upper()
            alerts = len(result.alerts)
            print(f"{rec} ({alerts} alerts)")
            results.append(result)
        except Exception as e:
            print(f"ERROR: {e}")

    print()
    print("Generating report...")

    # Generate HTML report
    html = generate_html_report(
        results,
        title="Extension Guard Demo Report",
        include_raw=True,
    )

    # Save to temp file and open in browser
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".html",
        delete=False,
        prefix="extension-guard-report-",
    ) as f:
        f.write(html)
        report_path = f.name

    print(f"Report saved to: {report_path}")
    print()
    print("Opening in browser...")

    webbrowser.open(f"file://{report_path}")

    print()
    print("=" * 60)
    print("  Demo Complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  - Review the report in your browser")
    print("  - Try scanning your own extensions:")
    print("    python scan.py <extension_id>")
    print()
    print("  - Scan multiple extensions:")
    print("    python scan.py --file my-extensions.txt")
    print()


if __name__ == "__main__":
    main()
