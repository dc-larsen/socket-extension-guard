"""Generate clean HTML reports for extension scan results."""

import html
import json
from datetime import datetime

from .models import ExtensionScanResult, Severity


def generate_html_report(
    results: list[ExtensionScanResult],
    title: str = "Extension Guard Report",
    include_raw: bool = False,
) -> str:
    """Generate an HTML report showing scan results in a table with expandable details."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = "\n".join(_render_row(r, include_raw) for r in results)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
    <style>{CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{html.escape(title)}</h1>
            <p class="meta">Generated {timestamp} &bull; {len(results)} extension(s) scanned</p>
        </header>

        <table class="results-table">
            <thead>
                <tr>
                    <th class="col-expand"></th>
                    <th class="col-name">Extension</th>
                    <th class="col-score">Score</th>
                    <th class="col-alerts">Alerts</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>

        <footer>
            Powered by <a href="https://socket.dev" target="_blank">Socket.dev</a> Extension Guard
        </footer>
    </div>
    <script>{JS}</script>
</body>
</html>'''


def _render_row(result: ExtensionScanResult, include_raw: bool) -> str:
    """Render a table row with expandable details."""
    score = result.score_overall
    score_class = "good" if score >= 0.7 else "moderate" if score >= 0.4 else "poor"

    # Alert counts
    critical = len(result.critical_alerts)
    high = len(result.high_alerts)
    medium = len(result.medium_alerts)
    low = len(result.low_alerts)

    alert_badges = []
    if critical: alert_badges.append(f'<span class="badge critical">{critical} Critical</span>')
    if high: alert_badges.append(f'<span class="badge high">{high} High</span>')
    if medium: alert_badges.append(f'<span class="badge medium">{medium} Medium</span>')
    if low: alert_badges.append(f'<span class="badge low">{low} Low</span>')

    alerts_html = " ".join(alert_badges) if alert_badges else '<span class="badge none">None</span>'

    # Error handling
    if result.error:
        return f'''
        <tr class="row-error">
            <td class="col-expand"></td>
            <td class="col-name">
                <div class="ext-name">{html.escape(result.name or result.input_purl.replace("pkg:chrome/", ""))}</div>
            </td>
            <td class="col-score">—</td>
            <td class="col-alerts"><span class="badge error">Error</span></td>
        </tr>
        <tr class="details-row">
            <td colspan="4">
                <div class="details error-details">{html.escape(result.error)}</div>
            </td>
        </tr>'''

    # Details content
    details = _render_details(result, include_raw)

    ext_id = result.input_purl.replace("pkg:chrome/", "")

    return f'''
    <tr class="data-row" data-expanded="false">
        <td class="col-expand"><button class="expand-btn">▶</button></td>
        <td class="col-name">
            <div class="ext-name">{html.escape(result.name)}</div>
            <div class="ext-meta">
                <code>{html.escape(ext_id)}</code>
                <span>v{html.escape(result.version)}</span>
                <span>{result.size_human}</span>
            </div>
        </td>
        <td class="col-score">
            <div class="score-cell">
                <div class="score-bar"><div class="score-fill {score_class}" style="width:{score*100}%"></div></div>
                <span class="score-value">{score:.2f}</span>
            </div>
        </td>
        <td class="col-alerts">{alerts_html}</td>
    </tr>
    <tr class="details-row">
        <td colspan="4">
            <div class="details">{details}</div>
        </td>
    </tr>'''


def _render_details(result: ExtensionScanResult, include_raw: bool) -> str:
    """Render expanded details for an extension."""
    sections = []

    # Scores breakdown
    sections.append(f'''
    <div class="detail-section">
        <h4>Scores</h4>
        <div class="scores-grid">
            <div class="score-item">
                <span class="score-label">Overall</span>
                <span class="score-num">{result.score_overall:.2f}</span>
            </div>
            <div class="score-item">
                <span class="score-label">Supply Chain</span>
                <span class="score-num">{result.score_supply_chain:.2f}</span>
            </div>
            <div class="score-item">
                <span class="score-label">Vulnerability</span>
                <span class="score-num">{result.score_vulnerability:.2f}</span>
            </div>
        </div>
    </div>''')

    # Alerts by type
    if result.alerts:
        by_type = result.alerts_by_type()
        alert_sections = []

        # Sort by severity (most severe first)
        sorted_types = sorted(
            by_type.items(),
            key=lambda x: -max(a.severity.weight for a in x[1])
        )

        for alert_type, alerts in sorted_types:
            severity = alerts[0].severity
            sev_class = severity.value

            values = [a.display_value for a in alerts if a.display_value]
            values_html = ""
            if values:
                items = [f"<li><code>{html.escape(v)}</code></li>" for v in values[:15]]
                if len(values) > 15:
                    items.append(f"<li class='more'>+{len(values)-15} more</li>")
                values_html = f"<ul class='alert-values'>{''.join(items)}</ul>"

            alert_sections.append(f'''
            <div class="alert-group">
                <div class="alert-header">
                    <span class="alert-type sev-{sev_class}">{html.escape(alert_type)}</span>
                    <span class="alert-count">{len(alerts)}</span>
                </div>
                {values_html}
            </div>''')

        sections.append(f'''
        <div class="detail-section">
            <h4>Alerts ({len(result.alerts)})</h4>
            <div class="alerts-list">{''.join(alert_sections)}</div>
        </div>''')
    else:
        sections.append('''
        <div class="detail-section">
            <h4>Alerts</h4>
            <p class="no-alerts">No alerts detected</p>
        </div>''')

    # Raw JSON
    if include_raw and result.raw:
        raw_json = json.dumps(result.raw, indent=2)
        sections.append(f'''
        <div class="detail-section">
            <details class="raw-section">
                <summary>Raw API Response</summary>
                <pre><code>{html.escape(raw_json)}</code></pre>
            </details>
        </div>''')

    return "".join(sections)


CSS = '''
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: #0f0f14;
    color: #e4e4e7;
    line-height: 1.5;
}

.container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem;
}

header {
    margin-bottom: 2rem;
}

h1 {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
}

.meta {
    color: #71717a;
    font-size: 0.875rem;
}

/* Table */
.results-table {
    width: 100%;
    border-collapse: collapse;
    background: #18181b;
    border-radius: 12px;
    overflow: hidden;
}

thead {
    background: #1f1f26;
}

th {
    text-align: left;
    padding: 0.875rem 1rem;
    font-weight: 500;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #71717a;
    border-bottom: 1px solid #27272a;
}

.col-expand { width: 40px; }
.col-name { width: 40%; }
.col-score { width: 140px; }
.col-alerts { }

/* Data rows */
.data-row {
    cursor: pointer;
    transition: background 0.15s;
}

.data-row:hover {
    background: #1f1f26;
}

.data-row td {
    padding: 1rem;
    border-bottom: 1px solid #27272a;
    vertical-align: middle;
}

.expand-btn {
    background: none;
    border: none;
    color: #52525b;
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.25rem;
    transition: transform 0.2s, color 0.15s;
}

.data-row:hover .expand-btn {
    color: #a1a1aa;
}

.data-row[data-expanded="true"] .expand-btn {
    transform: rotate(90deg);
    color: #8b5cf6;
}

.ext-name {
    font-weight: 500;
    margin-bottom: 0.25rem;
}

.ext-meta {
    display: flex;
    gap: 0.75rem;
    font-size: 0.75rem;
    color: #71717a;
}

.ext-meta code {
    font-family: 'JetBrains Mono', monospace;
    background: #27272a;
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    font-size: 0.7rem;
}

/* Score */
.score-cell {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.score-bar {
    flex: 1;
    height: 6px;
    background: #27272a;
    border-radius: 3px;
    overflow: hidden;
}

.score-fill {
    height: 100%;
    border-radius: 3px;
}

.score-fill.good { background: #22c55e; }
.score-fill.moderate { background: #eab308; }
.score-fill.poor { background: #ef4444; }

.score-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.875rem;
    font-weight: 500;
    min-width: 2.5rem;
}

/* Badges */
.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
    margin-right: 0.375rem;
}

.badge.critical { background: rgba(239,68,68,0.15); color: #ef4444; }
.badge.high { background: rgba(249,115,22,0.15); color: #f97316; }
.badge.medium { background: rgba(234,179,8,0.15); color: #eab308; }
.badge.low { background: rgba(34,197,94,0.15); color: #22c55e; }
.badge.none { background: #27272a; color: #71717a; }
.badge.error { background: rgba(239,68,68,0.15); color: #ef4444; }

/* Details row */
.details-row {
    display: none;
}

.details-row.visible {
    display: table-row;
}

.details-row td {
    padding: 0;
    background: #131316;
    border-bottom: 1px solid #27272a;
}

.details {
    padding: 1.5rem;
    display: grid;
    gap: 1.5rem;
}

.error-details {
    color: #ef4444;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.875rem;
}

.detail-section h4 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #71717a;
    margin-bottom: 0.75rem;
}

/* Scores grid */
.scores-grid {
    display: flex;
    gap: 2rem;
}

.score-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.score-label {
    font-size: 0.8125rem;
    color: #a1a1aa;
}

.score-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.25rem;
    font-weight: 500;
}

/* Alerts list */
.alerts-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.alert-group {
    background: #1a1a1f;
    border: 1px solid #27272a;
    border-radius: 8px;
    padding: 0.875rem;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.alert-type {
    font-size: 0.8125rem;
    font-weight: 500;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
}

.sev-critical { background: #ef4444; color: white; }
.sev-high { background: #f97316; color: white; }
.sev-middle { background: #eab308; color: #0f0f14; }
.sev-low { background: #22c55e; color: white; }
.sev-unknown { background: #52525b; color: white; }

.alert-count {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #71717a;
}

.alert-values {
    list-style: none;
    display: flex;
    flex-wrap: wrap;
    gap: 0.375rem;
}

.alert-values li {
    font-size: 0.75rem;
}

.alert-values code {
    font-family: 'JetBrains Mono', monospace;
    background: #27272a;
    padding: 0.125rem 0.375rem;
    border-radius: 3px;
    font-size: 0.7rem;
}

.alert-values .more {
    color: #71717a;
    font-style: italic;
}

.no-alerts {
    color: #71717a;
    font-size: 0.875rem;
}

/* Raw section */
.raw-section summary {
    cursor: pointer;
    color: #71717a;
    font-size: 0.8125rem;
}

.raw-section pre {
    margin-top: 0.75rem;
    background: #0f0f14;
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 0.75rem;
}

.raw-section code {
    font-family: 'JetBrains Mono', monospace;
    color: #a1a1aa;
}

/* Footer */
footer {
    margin-top: 2rem;
    text-align: center;
    color: #52525b;
    font-size: 0.8125rem;
}

footer a {
    color: #8b5cf6;
    text-decoration: none;
}

footer a:hover {
    text-decoration: underline;
}

/* Error row */
.row-error td {
    padding: 1rem;
    border-bottom: none;
}

/* Responsive */
@media (max-width: 640px) {
    .container { padding: 1rem; }
    .col-score { display: none; }
    .scores-grid { flex-direction: column; gap: 0.5rem; }
}
'''

JS = '''
document.querySelectorAll('.data-row').forEach(row => {
    row.addEventListener('click', () => {
        const expanded = row.dataset.expanded === 'true';
        row.dataset.expanded = !expanded;

        const detailsRow = row.nextElementSibling;
        if (detailsRow && detailsRow.classList.contains('details-row')) {
            detailsRow.classList.toggle('visible', !expanded);
        }
    });
});
'''
