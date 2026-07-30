"""
Modern Interactive HTML Report Generator for SecretScanner.
Creates a self-contained, responsive dashboard with filtering, search,
collapsible code context windows, and risk indicator badges.
"""

from __future__ import annotations

import html
from pathlib import Path
from secret_scanner.models import RiskLevel, ScanReport



def generate_html_report(report: ScanReport, output_path: Path | str) -> Path:
    """
    Generate report.html file from ScanReport object.
    
    Args:
        report: ScanReport instance.
        output_path: Destination file path for HTML report.

    Returns:
        Path object to the created HTML file.
    """
    out_file = Path(output_path)
    stats = report.stats
    findings = report.findings

    # Pre-render finding cards HTML
    finding_cards_html = []
    for idx, f in enumerate(findings):
        risk_val = f.risk_level.value
        risk_class = f.risk_level.value.lower()
        
        # Format context lines
        before_lines = "\n".join(html.escape(l) for l in f.context.lines_before)
        matched_line = html.escape(f.context.line_content)
        after_lines = "\n".join(html.escape(l) for l in f.context.lines_after)
        has_context = bool(f.context.lines_before or f.context.lines_after)
        context_label = "Surrounding Code Context" if has_context else "Matched Line"
        code_block_lines = []
        if before_lines:
            code_block_lines.append(before_lines)
        code_block_lines.append(f'<mark class="highlight-line">{f.line_number:4d} | {matched_line}</mark>')
        if after_lines:
            code_block_lines.append(after_lines)
        code_block_content = "\n".join(code_block_lines)

        commit_info = ""
        if f.commit_hash:
            commit_info = f"""
            <div class="meta-tag">
                <span>Commit:</span> <code>{html.escape(f.commit_hash)}</code> 
                {f'| <span>Author:</span> {html.escape(f.author)}' if f.author else ''}
                {f'| <span>Date:</span> {html.escape(f.date)}' if f.date else ''}
            </div>
            """

        card_html = f"""
        <div class="finding-card risk-{risk_class}" data-risk="{risk_val}" data-search="{html.escape((f.finding_type + ' ' + f.file_path + ' ' + f.description).lower())}">
            <div class="card-header" onclick="toggleCard({idx})">
                <div class="header-left">
                    <span class="badge badge-{risk_class}">{risk_val.upper()}</span>
                    <span class="finding-title">{html.escape(f.finding_type)}</span>
                </div>
                <div class="header-right">
                    <span class="file-path">{html.escape(f.file_path)}:{f.line_number}</span>
                    <span class="toggle-icon" id="icon-{idx}">▼</span>
                </div>
            </div>
            
            <div class="card-body" id="body-{idx}">
                <p class="description"><strong>Description:</strong> {html.escape(f.description)}</p>
                {commit_info}
                <div class="matched-box">
                    <span>Matched Secret Preview:</span> <code>{html.escape(f.matched_string)}</code>
                </div>

                <div class="recommendation-box">
                    <strong>Recommendation:</strong> {html.escape(f.recommendation)}
                </div>

                <div class="context-container">
                    <div class="context-header">{context_label} (Line {f.line_number})</div>
                    <pre class="code-block"><code>{code_block_content}</code></pre>
                </div>
            </div>
        </div>
        """
        finding_cards_html.append(card_html)

    findings_body = "\n".join(finding_cards_html) if finding_cards_html else "<div class='no-findings'>✨ No security issues or secrets detected!</div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretScanner Audit Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --critical-color: #ef4444;
            --high-color: #f97316;
            --medium-color: #eab308;
            --low-color: #06b6d4;
            --info-color: #64748b;
            --accent-glow: rgba(59, 130, 246, 0.15);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }}

        .header h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header .meta {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .stat-card .val {{
            font-size: 1.6rem;
            font-weight: 700;
            margin-top: 4px;
        }}

        .stat-card .lbl {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .controls {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            background: var(--card-bg);
            padding: 16px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }}

        .search-box {{
            flex: 1;
            min-width: 250px;
        }}

        .search-box input {{
            width: 100%;
            padding: 10px 14px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background: #0f172a;
            color: var(--text-main);
            font-size: 0.95rem;
        }}

        .filter-badges {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 6px 14px;
            border-radius: 20px;
            border: 1px solid var(--border-color);
            background: #0f172a;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.2s ease;
        }}

        .filter-btn.active, .filter-btn:hover {{
            background: #3b82f6;
            color: #ffffff;
            border-color: #3b82f6;
        }}

        .finding-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s ease;
        }}

        .finding-card.risk-critical {{ border-left: 4px solid var(--critical-color); }}
        .finding-card.risk-high {{ border-left: 4px solid var(--high-color); }}
        .finding-card.risk-medium {{ border-left: 4px solid var(--medium-color); }}
        .finding-card.risk-low {{ border-left: 4px solid var(--low-color); }}
        .finding-card.risk-info {{ border-left: 4px solid var(--info-color); }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            cursor: pointer;
            background: rgba(255, 255, 255, 0.02);
        }}

        .card-header:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}

        .header-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}

        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical-color); border: 1px solid var(--critical-color); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium-color); border: 1px solid var(--medium-color); }}
        .badge-low {{ background: rgba(6, 182, 212, 0.2); color: var(--low-color); border: 1px solid var(--low-color); }}
        .badge-info {{ background: rgba(100, 116, 139, 0.2); color: var(--info-color); border: 1px solid var(--info-color); }}

        .finding-title {{
            font-weight: 600;
            font-size: 1.05rem;
        }}

        .file-path {{
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .toggle-icon {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-left: 12px;
            transition: transform 0.2s ease;
        }}

        .card-body {{
            padding: 18px;
            border-top: 1px solid var(--border-color);
            display: block;
        }}

        .description {{
            margin-bottom: 12px;
            color: #cbd5e1;
        }}

        .meta-tag {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 12px;
            background: #0f172a;
            padding: 6px 12px;
            border-radius: 6px;
        }}

        .matched-box, .recommendation-box {{
            background: #0f172a;
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-size: 0.9rem;
        }}

        .matched-box code {{
            color: #f43f5e;
            font-weight: 600;
        }}

        .recommendation-box {{
            border-left: 3px solid #3b82f6;
        }}

        .context-container {{
            margin-top: 16px;
        }}

        .context-header {{
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .code-block {{
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            overflow-x: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            color: #a7f3d0;
            white-space: pre;
        }}

        .highlight-line {{
            background-color: rgba(239, 68, 68, 0.25);
            color: #fecdd3;
            display: block;
            font-weight: 700;
            padding: 2px 4px;
            border-radius: 3px;
        }}

        .no-findings {{
            text-align: center;
            padding: 48px;
            background: var(--card-bg);
            border-radius: 10px;
            color: #34d399;
            font-size: 1.3rem;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>SecretScanner Security Audit</h1>
                <div class="meta">Target: <code>{html.escape(report.scanned_path)}</code></div>
            </div>
            <div class="meta">Generated: {html.escape(report.scan_timestamp)}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="lbl">Files Scanned</div>
                <div class="val">{stats.files_scanned}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Lines Scanned</div>
                <div class="val">{stats.lines_scanned:,}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Elapsed Time</div>
                <div class="val">{stats.elapsed_time_seconds:.2f}s</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Total Secrets</div>
                <div class="val" style="color: var(--critical-color);">{stats.total_findings}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Critical / High</div>
                <div class="val" style="color: var(--high-color);">{stats.critical_count + stats.high_count}</div>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by file, type, or description..." onkeyup="filterFindings()">
            </div>
            <div class="filter-badges">
                <button class="filter-btn active" onclick="setRiskFilter('ALL', this)">All ({stats.total_findings})</button>
                <button class="filter-btn" onclick="setRiskFilter('Critical', this)">Critical ({stats.critical_count})</button>
                <button class="filter-btn" onclick="setRiskFilter('High', this)">High ({stats.high_count})</button>
                <button class="filter-btn" onclick="setRiskFilter('Medium', this)">Medium ({stats.medium_count})</button>
                <button class="filter-btn" onclick="setRiskFilter('Low', this)">Low ({stats.low_count})</button>
            </div>
        </div>

        <div id="findingsContainer">
            {findings_body}
        </div>
    </div>

    <script>
        let currentRisk = 'ALL';

        function toggleCard(idx) {{
            const body = document.getElementById(`body-${{idx}}`);
            const icon = document.getElementById(`icon-${{idx}}`);
            if (body.style.display === 'none') {{
                body.style.display = 'block';
                icon.style.transform = 'rotate(0deg)';
            }} else {{
                body.style.display = 'none';
                icon.style.transform = 'rotate(-90deg)';
            }}
        }}

        function setRiskFilter(risk, btn) {{
            currentRisk = risk;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterFindings();
        }}

        function filterFindings() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');

            cards.forEach(card => {{
                const cardRisk = card.getAttribute('data-risk');
                const searchData = card.getAttribute('data-search');

                const matchesRisk = (currentRisk === 'ALL' || cardRisk === currentRisk);
                const matchesSearch = (!query || searchData.includes(query));

                if (matchesRisk && matchesSearch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return out_file
