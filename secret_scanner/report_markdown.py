"""
Markdown Report Generator for SecretScanner.
Outputs structured GitHub-Flavored Markdown report (`report.md`).
"""

from __future__ import annotations

from pathlib import Path
from secret_scanner.models import ScanReport



def generate_markdown_report(report: ScanReport, output_path: Path | str) -> Path:
    """
    Generate report.md file from ScanReport object.
    
    Args:
        report: ScanReport data model.
        output_path: Path where report.md should be saved.

    Returns:
        Path object pointing to created Markdown file.
    """
    out_file = Path(output_path)
    stats = report.stats
    findings = report.findings

    lines = [
        f"# SecretScanner Security Audit Report",
        f"",
        f"- **Scanned Directory**: `{report.scanned_path}`",
        f"- **Timestamp**: `{report.scan_timestamp}`",
        f"",
        f"## 📊 Executive Summary",
        f"",
        f"| Metric | Value |",
        f"| :--- | :--- |",
        f"| **Scanned Files** | `{stats.files_scanned}` |",
        f"| **Scanned Lines** | `{stats.lines_scanned:,}` |",
        f"| **Elapsed Time** | `{stats.elapsed_time_seconds:.2f}s` |",
        f"| **Total Findings** | `{stats.total_findings}` |",
        f"| **Critical** | `{stats.critical_count}` |",
        f"| **High** | `{stats.high_count}` |",
        f"| **Medium** | `{stats.medium_count}` |",
        f"| **Low** | `{stats.low_count}` |",
        f"| **Info** | `{stats.info_count}` |",
        f"",
    ]

    if not findings:
        lines.append("✨ **No security issues or secrets detected.**")
    else:
        lines.extend([
            f"## 🔍 Findings Summary Table",
            f"",
            f"| Risk | Type | File Path | Line | Secret Preview |",
            f"| :--- | :--- | :--- | :---: | :--- |",
        ])

        for f in findings:
            preview = f.matched_string.replace("|", "\\|")
            lines.append(
                f"| **{f.risk_level.value}** | {f.finding_type} | `{f.file_path}` | `{f.line_number}` | `{preview}` |"
            )

        lines.extend([
            f"",
            f"## 🛠️ Detailed Audit Breakdown & Remediation",
            f"",
        ])

        for idx, f in enumerate(findings, start=1):
            lines.extend([
                f"### {idx}. [{f.risk_level.value}] {f.finding_type}",
                f"",
                f"- **File**: `{f.file_path}` (Line {f.line_number})",
                f"- **Description**: {f.description}",
                f"- **Matched Value**: `{f.matched_string}`",
            ])

            if f.commit_hash:
                lines.append(f"- **Git Commit**: `{f.commit_hash}` by {f.author} ({f.date})")

            lines.extend([
                f"- **Recommendation**: {f.recommendation}",
                f"",
                f"```",
                f"Line {f.line_number}: {f.context.line_content}",
                f"```",
                f"",
            ])

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return out_file
