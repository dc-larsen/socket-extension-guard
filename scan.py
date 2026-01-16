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
from extension_guard.models import Recommendation


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
                "recommendation": r.recommendation.value,
                "reason": r.recommendation_reason,
                "alerts": {
                    "total": len(r.alerts),
                    "critical": len(r.critical_alerts),
                    "high": len(r.high_alerts),
                    "medium": len(r.medium_alerts),
                    "low": len(r.low_alerts),
                },
                "highRiskPermissions": r.high_risk_permissions,
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

        # Summary
        if len(results) > 1:
            blocked = sum(1 for r in results if r.recommendation == Recommendation.BLOCK)
            review = sum(1 for r in results if r.recommendation == Recommendation.REVIEW)
            allowed = sum(1 for r in results if r.recommendation == Recommendation.ALLOW)

            print("=" * 50)
            print(f"Summary: {blocked} BLOCK, {review} REVIEW, {allowed} ALLOW")
            print("=" * 50)

    # Exit with error if any extensions should be blocked
    if any(r.recommendation == Recommendation.BLOCK for r in results):
        sys.exit(1)


def print_result(result):
    """Print a single result in text format."""
    rec = result.recommendation
    rec_icon = rec.icon

    # Header
    print(f"Extension: {result.name}")
    print(f"ID:        {result.input_purl.replace('pkg:chrome/', '')}")
    print(f"Version:   {result.version}")
    print(f"Size:      {result.size_human}")
    print()

    # Score
    score = result.score_overall
    if score >= 0.7:
        score_label = "Good"
    elif score >= 0.4:
        score_label = "Moderate Risk"
    else:
        score_label = "High Risk"

    print(f"Score:     {score:.2f}/1.0 ({score_label})")
    print()

    # Recommendation
    print(f"Recommendation: {rec_icon} {rec.value.upper()}")
    print(f"Reason:         {result.recommendation_reason}")
    print()

    # Alert counts
    print(f"Alerts ({len(result.alerts)} total):")
    print(f"  CRITICAL: {len(result.critical_alerts)}")
    print(f"  HIGH:     {len(result.high_alerts)}")
    print(f"  MEDIUM:   {len(result.medium_alerts)}")
    print(f"  LOW:      {len(result.low_alerts)}")

    # High-risk permissions
    if result.high_risk_permissions:
        print()
        print("High-risk permissions:")
        for perm in result.high_risk_permissions:
            print(f"  - {perm}")

    # Show critical/high alerts
    critical_high = result.critical_alerts + result.high_alerts
    if critical_high:
        print()
        print("Critical/High alerts:")
        for alert in critical_high[:10]:
            val = alert.display_value
            if val:
                print(f"  - {alert.type}: {val}")
            else:
                print(f"  - {alert.type}")

        if len(critical_high) > 10:
            print(f"  ... and {len(critical_high) - 10} more")


if __name__ == "__main__":
    main()
