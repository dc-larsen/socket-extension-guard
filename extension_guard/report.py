"""Generate beautiful HTML reports for extension scan results."""

import html
from datetime import datetime
from typing import Optional

from .models import ExtensionScanResult, Recommendation, Severity, ALERT_DESCRIPTIONS


def generate_html_report(
    results: list[ExtensionScanResult],
    title: str = "Extension Guard Security Report",
    include_raw: bool = False,
) -> str:
    """
    Generate a beautiful HTML report for extension scan results.

    Args:
        results: List of scan results to include
        title: Report title
        include_raw: Whether to include raw JSON data

    Returns:
        Complete HTML document as string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Calculate summary stats
    total = len(results)
    blocked = sum(1 for r in results if r.recommendation == Recommendation.BLOCK)
    review = sum(1 for r in results if r.recommendation == Recommendation.REVIEW)
    allowed = sum(1 for r in results if r.recommendation == Recommendation.ALLOW)
    errors = sum(1 for r in results if r.error)

    total_critical = sum(len(r.critical_alerts) for r in results)
    total_high = sum(len(r.high_alerts) for r in results)

    # Sort results: blocked first, then review, then allow
    sorted_results = sorted(
        results,
        key=lambda r: (
            0 if r.recommendation == Recommendation.BLOCK else
            1 if r.recommendation == Recommendation.REVIEW else 2,
            -len(r.critical_alerts),
            -len(r.high_alerts),
        )
    )

    extension_cards = "\n".join(
        _render_extension_card(r, include_raw) for r in sorted_results
    )

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
{CSS_STYLES}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-content">
                <div class="logo">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M2 17L12 22L22 17" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M2 12L12 17L22 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>Socket Extension Guard</span>
                </div>
                <h1>{html.escape(title)}</h1>
                <p class="timestamp">Generated: {timestamp}</p>
            </div>
        </header>

        <section class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="stat-value">{total}</div>
                    <div class="stat-label">Extensions Scanned</div>
                </div>
                <div class="stat-card stat-block">
                    <div class="stat-value">{blocked}</div>
                    <div class="stat-label">Block</div>
                </div>
                <div class="stat-card stat-review">
                    <div class="stat-value">{review}</div>
                    <div class="stat-label">Review</div>
                </div>
                <div class="stat-card stat-allow">
                    <div class="stat-value">{allowed}</div>
                    <div class="stat-label">Allow</div>
                </div>
                <div class="stat-card stat-critical">
                    <div class="stat-value">{total_critical}</div>
                    <div class="stat-label">Critical Alerts</div>
                </div>
                <div class="stat-card stat-high">
                    <div class="stat-value">{total_high}</div>
                    <div class="stat-label">High Alerts</div>
                </div>
            </div>
            {f'<p class="error-note">⚠️ {errors} extension(s) had scan errors</p>' if errors else ''}
        </section>

        <section class="results">
            <h2>Scan Results</h2>
            <div class="filter-bar">
                <button class="filter-btn active" data-filter="all">All ({total})</button>
                <button class="filter-btn filter-block" data-filter="block">Block ({blocked})</button>
                <button class="filter-btn filter-review" data-filter="review">Review ({review})</button>
                <button class="filter-btn filter-allow" data-filter="allow">Allow ({allowed})</button>
            </div>
            <div class="extensions-list">
                {extension_cards}
            </div>
        </section>

        <footer class="footer">
            <p>
                Powered by <a href="https://socket.dev" target="_blank">Socket.dev</a> Extension Guard
                &bull;
                <a href="https://docs.socket.dev/docs/language-support#extension-scanning" target="_blank">Documentation</a>
            </p>
        </footer>
    </div>

    <script>
{JS_SCRIPT}
    </script>
</body>
</html>'''


def _render_extension_card(result: ExtensionScanResult, include_raw: bool) -> str:
    """Render a single extension card."""
    rec = result.recommendation
    rec_class = rec.value.lower()

    # Score bar color
    score = result.score_overall
    if score >= 0.7:
        score_class = "score-good"
    elif score >= 0.4:
        score_class = "score-moderate"
    else:
        score_class = "score-poor"

    # Alert summary
    alerts_summary = _render_alerts_summary(result)

    # Permission badges
    perms_html = ""
    if result.high_risk_permissions:
        perms_html = '<div class="permissions">'
        for perm in result.high_risk_permissions[:6]:
            perms_html += f'<span class="perm-badge">{html.escape(perm)}</span>'
        if len(result.high_risk_permissions) > 6:
            perms_html += f'<span class="perm-badge perm-more">+{len(result.high_risk_permissions) - 6} more</span>'
        perms_html += '</div>'

    # Error state
    if result.error:
        return f'''
        <div class="extension-card rec-{rec_class}" data-recommendation="{rec_class}">
            <div class="card-header">
                <div class="ext-info">
                    <h3 class="ext-name">{html.escape(result.name)}</h3>
                    <span class="ext-id">{html.escape(result.input_purl.replace("pkg:chrome/", ""))}</span>
                </div>
                <div class="recommendation rec-review">
                    <span class="rec-icon">⚠️</span>
                    <span class="rec-text">Error</span>
                </div>
            </div>
            <div class="card-body">
                <p class="error-message">{html.escape(result.error)}</p>
            </div>
        </div>'''

    # Details section
    details_html = _render_alert_details(result)

    raw_html = ""
    if include_raw:
        import json
        raw_json = json.dumps(result.raw, indent=2)
        raw_html = f'''
        <details class="raw-data">
            <summary>Raw API Response</summary>
            <pre><code>{html.escape(raw_json)}</code></pre>
        </details>'''

    return f'''
    <div class="extension-card rec-{rec_class}" data-recommendation="{rec_class}">
        <div class="card-header">
            <div class="ext-info">
                <h3 class="ext-name">{html.escape(result.name)}</h3>
                <div class="ext-meta">
                    <span class="ext-version">v{html.escape(result.version)}</span>
                    <span class="ext-size">{result.size_human}</span>
                    <span class="ext-id">{html.escape(result.input_purl.replace("pkg:chrome/", ""))}</span>
                </div>
            </div>
            <div class="recommendation rec-{rec_class}">
                <span class="rec-icon">{rec.icon}</span>
                <span class="rec-text">{rec.value.upper()}</span>
            </div>
        </div>

        <div class="card-body">
            <div class="score-section">
                <div class="score-bar-container">
                    <div class="score-bar {score_class}" style="width: {score * 100}%"></div>
                </div>
                <div class="score-labels">
                    <span>Security Score: <strong>{score:.2f}</strong></span>
                    <span class="score-detail">Supply Chain: {result.score_supply_chain:.2f}</span>
                    <span class="score-detail">Vulnerabilities: {result.score_vulnerability:.2f}</span>
                </div>
            </div>

            <p class="recommendation-reason">{html.escape(result.recommendation_reason)}</p>

            {perms_html}

            {alerts_summary}

            <details class="alert-details">
                <summary>View All Alerts ({len(result.alerts)})</summary>
                {details_html}
            </details>

            {raw_html}
        </div>
    </div>'''


def _render_alerts_summary(result: ExtensionScanResult) -> str:
    """Render alert count badges."""
    counts = [
        ("Critical", len(result.critical_alerts), "critical"),
        ("High", len(result.high_alerts), "high"),
        ("Medium", len(result.medium_alerts), "medium"),
        ("Low", len(result.low_alerts), "low"),
    ]

    badges = []
    for label, count, cls in counts:
        if count > 0:
            badges.append(f'<span class="alert-badge alert-{cls}">{count} {label}</span>')

    if not badges:
        return '<div class="alerts-summary"><span class="alert-badge alert-none">No alerts</span></div>'

    return f'<div class="alerts-summary">{" ".join(badges)}</div>'


def _render_alert_details(result: ExtensionScanResult) -> str:
    """Render detailed alert list."""
    if not result.alerts:
        return '<p class="no-alerts">No security alerts detected.</p>'

    # Group by type
    by_type = result.alerts_by_type()

    sections = []
    for alert_type, alerts in sorted(by_type.items(), key=lambda x: -max(a.severity.weight for a in x[1])):
        desc = ALERT_DESCRIPTIONS.get(alert_type, {})
        title = desc.get("title", alert_type)
        severity = alerts[0].severity

        values = []
        for a in alerts[:10]:
            val = a.display_value
            if val:
                values.append(f'<li><code>{html.escape(val)}</code></li>')

        if len(alerts) > 10:
            values.append(f'<li class="more">+{len(alerts) - 10} more</li>')

        values_html = f'<ul class="alert-values">{" ".join(values)}</ul>' if values else ''

        sections.append(f'''
        <div class="alert-type-section">
            <div class="alert-type-header">
                <span class="alert-type-badge sev-{severity.value}">{html.escape(title)}</span>
                <span class="alert-count">{len(alerts)}</span>
            </div>
            <p class="alert-description">{html.escape(desc.get("description", ""))}</p>
            {values_html}
        </div>''')

    return "\n".join(sections)


CSS_STYLES = '''
:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #12121a;
    --bg-card: #1a1a24;
    --bg-hover: #22222e;
    --text-primary: #f4f4f5;
    --text-secondary: #a1a1aa;
    --text-muted: #71717a;
    --border: #27272a;
    --accent: #8b5cf6;
    --accent-hover: #a78bfa;

    --red: #ef4444;
    --red-bg: rgba(239, 68, 68, 0.1);
    --orange: #f97316;
    --orange-bg: rgba(249, 115, 22, 0.1);
    --yellow: #eab308;
    --yellow-bg: rgba(234, 179, 8, 0.1);
    --green: #22c55e;
    --green-bg: rgba(34, 197, 94, 0.1);
    --blue: #3b82f6;
    --blue-bg: rgba(59, 130, 246, 0.1);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

/* Header */
.header {
    margin-bottom: 3rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
}

.header-content {
    text-align: center;
}

.logo {
    display: inline-flex;
    align-items: center;
    gap: 0.75rem;
    color: var(--accent);
    font-weight: 600;
    font-size: 1.125rem;
    margin-bottom: 1rem;
}

.logo svg {
    color: var(--accent);
}

h1 {
    font-size: 2.5rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.timestamp {
    color: var(--text-muted);
    font-size: 0.875rem;
}

/* Summary Section */
.summary {
    margin-bottom: 3rem;
}

.summary h2 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
}

.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
}

.stat-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
}

.stat-value {
    font-size: 2.5rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 0.25rem;
}

.stat-label {
    font-size: 0.875rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

.stat-block .stat-value { color: var(--red); }
.stat-review .stat-value { color: var(--yellow); }
.stat-allow .stat-value { color: var(--green); }
.stat-critical .stat-value { color: var(--red); }
.stat-high .stat-value { color: var(--orange); }

.error-note {
    margin-top: 1rem;
    padding: 0.75rem 1rem;
    background: var(--yellow-bg);
    border: 1px solid var(--yellow);
    border-radius: 8px;
    color: var(--yellow);
    font-size: 0.875rem;
}

/* Filter Bar */
.filter-bar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.filter-btn {
    padding: 0.5rem 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
}

.filter-btn:hover {
    background: var(--bg-hover);
    border-color: var(--text-muted);
}

.filter-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
}

.filter-block.active { background: var(--red); border-color: var(--red); }
.filter-review.active { background: var(--yellow); border-color: var(--yellow); color: var(--bg-primary); }
.filter-allow.active { background: var(--green); border-color: var(--green); }

/* Extension Cards */
.extensions-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.extension-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
    transition: border-color 0.2s;
}

.extension-card:hover {
    border-color: var(--text-muted);
}

.extension-card.rec-block {
    border-left: 4px solid var(--red);
}

.extension-card.rec-review {
    border-left: 4px solid var(--yellow);
}

.extension-card.rec-allow {
    border-left: 4px solid var(--green);
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 1.25rem 1.5rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
}

.ext-info {
    flex: 1;
    min-width: 0;
}

.ext-name {
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
    word-break: break-word;
}

.ext-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    font-size: 0.8125rem;
    color: var(--text-muted);
}

.ext-meta span {
    display: inline-flex;
    align-items: center;
}

.ext-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    background: var(--bg-card);
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
}

.recommendation {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.875rem;
    white-space: nowrap;
}

.rec-block {
    background: var(--red-bg);
    color: var(--red);
}

.rec-review {
    background: var(--yellow-bg);
    color: var(--yellow);
}

.rec-allow {
    background: var(--green-bg);
    color: var(--green);
}

.card-body {
    padding: 1.5rem;
}

/* Score Bar */
.score-section {
    margin-bottom: 1rem;
}

.score-bar-container {
    height: 8px;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 0.5rem;
}

.score-bar {
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease-out;
}

.score-good { background: linear-gradient(90deg, var(--green), #4ade80); }
.score-moderate { background: linear-gradient(90deg, var(--yellow), #facc15); }
.score-poor { background: linear-gradient(90deg, var(--red), var(--orange)); }

.score-labels {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.score-detail {
    color: var(--text-muted);
}

.recommendation-reason {
    color: var(--text-secondary);
    margin-bottom: 1rem;
    font-size: 0.9375rem;
}

/* Permissions */
.permissions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.perm-badge {
    display: inline-flex;
    padding: 0.25rem 0.75rem;
    background: var(--orange-bg);
    border: 1px solid var(--orange);
    border-radius: 100px;
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--orange);
    font-family: 'JetBrains Mono', monospace;
}

.perm-more {
    background: var(--bg-secondary);
    border-color: var(--border);
    color: var(--text-muted);
}

/* Alerts Summary */
.alerts-summary {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.alert-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.8125rem;
    font-weight: 500;
}

.alert-critical { background: var(--red-bg); color: var(--red); }
.alert-high { background: var(--orange-bg); color: var(--orange); }
.alert-medium { background: var(--yellow-bg); color: var(--yellow); }
.alert-low { background: var(--green-bg); color: var(--green); }
.alert-none { background: var(--bg-secondary); color: var(--text-muted); }

/* Alert Details */
.alert-details {
    margin-top: 1rem;
}

.alert-details summary {
    cursor: pointer;
    color: var(--accent);
    font-weight: 500;
    padding: 0.5rem 0;
    user-select: none;
}

.alert-details summary:hover {
    color: var(--accent-hover);
}

.alert-type-section {
    padding: 1rem;
    margin: 0.75rem 0;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border);
}

.alert-type-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.alert-type-badge {
    padding: 0.25rem 0.625rem;
    border-radius: 4px;
    font-size: 0.8125rem;
    font-weight: 600;
}

.sev-critical { background: var(--red); color: white; }
.sev-high { background: var(--orange); color: white; }
.sev-middle { background: var(--yellow); color: var(--bg-primary); }
.sev-low { background: var(--green); color: white; }

.alert-count {
    font-size: 0.875rem;
    color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
}

.alert-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
}

.alert-values {
    list-style: none;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.alert-values li {
    font-size: 0.8125rem;
}

.alert-values code {
    background: var(--bg-card);
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-primary);
}

.alert-values .more {
    color: var(--text-muted);
    font-style: italic;
}

/* Raw Data */
.raw-data {
    margin-top: 1rem;
}

.raw-data summary {
    cursor: pointer;
    color: var(--text-muted);
    font-size: 0.8125rem;
}

.raw-data pre {
    margin-top: 0.5rem;
    padding: 1rem;
    background: var(--bg-primary);
    border-radius: 8px;
    overflow-x: auto;
    font-size: 0.75rem;
}

.raw-data code {
    font-family: 'JetBrains Mono', monospace;
    color: var(--text-secondary);
}

/* Error Message */
.error-message {
    color: var(--red);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.875rem;
    padding: 1rem;
    background: var(--red-bg);
    border-radius: 8px;
}

/* Footer */
.footer {
    margin-top: 4rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-muted);
    font-size: 0.875rem;
}

.footer a {
    color: var(--accent);
    text-decoration: none;
}

.footer a:hover {
    text-decoration: underline;
}

/* Responsive */
@media (max-width: 768px) {
    .container {
        padding: 1rem;
    }

    h1 {
        font-size: 1.75rem;
    }

    .card-header {
        flex-direction: column;
        gap: 1rem;
    }

    .recommendation {
        align-self: flex-start;
    }

    .score-labels {
        flex-direction: column;
        gap: 0.25rem;
    }
}

/* Animation */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.extension-card {
    animation: fadeIn 0.3s ease-out;
}

.extension-card:nth-child(2) { animation-delay: 0.05s; }
.extension-card:nth-child(3) { animation-delay: 0.1s; }
.extension-card:nth-child(4) { animation-delay: 0.15s; }
.extension-card:nth-child(5) { animation-delay: 0.2s; }

/* Hidden state for filtering */
.extension-card.hidden {
    display: none;
}
'''

JS_SCRIPT = '''
document.addEventListener('DOMContentLoaded', function() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const cards = document.querySelectorAll('.extension-card');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const filter = this.dataset.filter;

            // Update active button
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');

            // Filter cards
            cards.forEach(card => {
                if (filter === 'all') {
                    card.classList.remove('hidden');
                } else {
                    const rec = card.dataset.recommendation;
                    card.classList.toggle('hidden', rec !== filter);
                }
            });
        });
    });

    // Auto-expand details for blocked extensions
    cards.forEach(card => {
        if (card.dataset.recommendation === 'block') {
            const details = card.querySelector('.alert-details');
            if (details) {
                details.open = true;
            }
        }
    });
});
'''
