#!/usr/bin/env python3
"""
Extension Guard Scanner CLI

Scan Chrome extensions for security risks.

Usage:
    python scan.py <extension_id>
    python scan.py <extension_id> --html report.html
    python scan.py <extension_id> --json
    python scan.py --file extensions.txt
    python scan.py "https://chromewebstore.google.com/detail/..."
"""

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from extension_guard import ExtensionGuardClient, generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Scan Chrome extensions for security risks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py cjpalhdlnbpafiamejdnhcphjbkeiagm
  python scan.py "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
  python scan.py --file extensions.txt --html report.html
  python scan.py ext1 ext2 ext3 --json
        """,
    )

    parser.add_argument(
        "extensions",
        nargs="*",
        help="Extension ID(s) or Chrome Web Store URL(s)",
    )

    parser.add_argument(
        "-f", "--file",
        type=Path,
        help="File containing extension IDs (one per line)",
    )

    parser.add_argument(
        "--html",
        type=Path,
        metavar="FILE",
        help="Output HTML report to file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of text",
    )

    parser.add_argument(
        "--open",
        action="store_true",
        help="Open HTML report in browser (requires --html)",
    )

    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Include raw API response in HTML report",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output",
    )

    args = parser.parse_args()

    # Collect extension IDs
    extension_ids = list(args.extensions)

    if args.file:
        if not args.file.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    extension_ids.append(line)

    if not extension_ids:
        parser.print_help()
        sys.exit(1)

    # Initialize client
    try:
        client = ExtensionGuardClient()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Scan extensions
    if not args.quiet and not args.json:
        print(f"Scanning {len(extension_ids)} extension(s)...\n")

    results = client.scan_batch(extension_ids)

    # Output results
    if args.json:
        output = []
        for r in results:
            output.append({
                "id": r.id,
                "name": r.name,
                "version": r.version,
                "purl": r.input_purl,
                "score": {
                    "overall": r.score_overall,
                    "supplyChain": r.score_supply_chain,
                    "vulnerability": r.score_vulnerability,
                },
                "alerts": {
                    "total": len(r.alerts),
                    "critical": len(r.critical_alerts),
                    "high": len(r.high_alerts),
                    "medium": len(r.medium_alerts),
                    "low": len(r.low_alerts),
                },
                "error": r.error,
            })

        print(json.dumps(output if len(output) > 1 else output[0], indent=2))

    elif args.html:
        html = generate_html_report(
            results,
            title="Extension Guard Security Report",
            include_raw=args.include_raw,
        )

        with open(args.html, "w") as f:
            f.write(html)

        if not args.quiet:
            print(f"Report saved to: {args.html}")

        if args.open:
            webbrowser.open(f"file://{args.html.absolute()}")

    else:
        # Text output
        for result in results:
            print_result(result)
            print()


def print_result(result):
    """Print a single result in text format."""
    if result.error:
        print(f"Extension: {result.name or result.input_purl.replace('pkg:chrome/', '')}")
        print(f"Error:     {result.error}")
        return

    print(f"Extension: {result.name}")
    print(f"ID:        {result.input_purl.replace('pkg:chrome/', '')}")
    print(f"Version:   {result.version}")
    print(f"Size:      {result.size_human}")
    print()

    # Scores
    print(f"Scores:")
    print(f"  Overall:       {result.score_overall:.2f}")
    print(f"  Supply Chain:  {result.score_supply_chain:.2f}")
    print(f"  Vulnerability: {result.score_vulnerability:.2f}")
    print()

    # Alert counts
    print(f"Alerts ({len(result.alerts)} total):")
    print(f"  Critical: {len(result.critical_alerts)}")
    print(f"  High:     {len(result.high_alerts)}")
    print(f"  Medium:   {len(result.medium_alerts)}")
    print(f"  Low:      {len(result.low_alerts)}")

    # Show alerts by type
    if result.alerts:
        print()
        print("Alert breakdown:")
        for alert_type, alerts in result.alerts_by_type().items():
            severity = alerts[0].severity.value
            values = [a.display_value for a in alerts if a.display_value]
            if values:
                print(f"  [{severity}] {alert_type}: {', '.join(values[:5])}")
                if len(values) > 5:
                    print(f"           +{len(values) - 5} more")
            else:
                print(f"  [{severity}] {alert_type}")


if __name__ == "__main__":
    main()
