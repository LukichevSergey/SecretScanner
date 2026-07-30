"""
Console output formatter and text report generator (`report.txt`) for SecretScanner.
"""

from __future__ import annotations

from pathlib import Path
from secret_scanner.models import ScanReport
from secret_scanner.utils import format_duration



def print_console_summary(report: ScanReport) -> None:
    """
    Print rich summary statistics dashboard to terminal stdout.
    
    Args:
        report: ScanReport data object.
    """
    stats = report.stats
    findings = report.findings

    print("\n" + "=" * 70)
    print("\033[1;36m       SECRET SCANNER AUDIT RESULTS SUMMARY\033[0m")
    print("=" * 70)
    print(f" Target Directory   : {report.scanned_path}")
    print(f" Execution Time     : {format_duration(stats.elapsed_time_seconds)}")
    print(f" Files Scanned     : {stats.files_scanned:,}")
    print(f" Lines Scanned     : {stats.lines_scanned:,}")
    print("-" * 70)
    print(f" Total Secrets      : \033[1;31m{stats.total_findings}\033[0m")
    print(f" Suspicious Lines  : {stats.suspicious_lines}")
    print(f"   ├─ Critical      : \033[1;31m{stats.critical_count}\033[0m")
    print(f"   ├─ High          : \033[0;31m{stats.high_count}\033[0m")
    print(f"   ├─ Medium        : \033[0;33m{stats.medium_count}\033[0m")
    print(f"   ├─ Low           : \033[0;36m{stats.low_count}\033[0m")
    print(f"   └─ Info          : \033[0;37m{stats.info_count}\033[0m")
    print("=" * 70)

    if findings:
        print("\n\033[1;33mTop Detected Security Risks:\033[0m\n")
        # Display top 10 most critical findings in console preview
        sorted_findings = sorted(findings, key=lambda f: f.risk_level.severity_score, reverse=True)
        for idx, f in enumerate(sorted_findings[:10], start=1):
            color = f.risk_level.color_code
            print(f"{idx:2d}. [{color}{f.risk_level.value:8s}\033[0m] {f.finding_type}")
            print(f"    File: {f.file_path}:{f.line_number}")
            print(f"    Match: {f.matched_string}")
            print(f"    Recommendation: {f.recommendation}\n")

        if len(findings) > 10:
            print(f"... and {len(findings) - 10} additional findings detailed in generated reports.\n")

    print("\033[1;32mReports generated:\033[0m report.html, report.json, report.md, report.txt\n")


def generate_text_report(report: ScanReport, output_path: Path | str) -> Path:
    """
    Generate plain text report (`report.txt`) for command-line archiving.
    
    Args:
        report: ScanReport instance.
        output_path: Path to output text file.

    Returns:
        Path to generated text file.
    """
    out_file = Path(output_path)
    stats = report.stats
    findings = report.findings

    lines = [
        "=" * 70,
        "SECRET SCANNER AUDIT REPORT",
        "=" * 70,
        f"Target Directory : {report.scanned_path}",
        f"Scan Timestamp   : {report.scan_timestamp}",
        f"Execution Time   : {format_duration(stats.elapsed_time_seconds)}",
        f"Files Scanned   : {stats.files_scanned}",
        f"Lines Scanned   : {stats.lines_scanned}",
        "-" * 70,
        f"Total Findings   : {stats.total_findings}",
        f"Critical         : {stats.critical_count}",
        f"High             : {stats.high_count}",
        f"Medium           : {stats.medium_count}",
        f"Low              : {stats.low_count}",
        f"Info             : {stats.info_count}",
        "=" * 70,
        "",
    ]

    for idx, f in enumerate(findings, start=1):
        lines.extend([
            f"Finding #{idx}: [{f.risk_level.value}] {f.finding_type}",
            f"File: {f.file_path}:{f.line_number}",
            f"Description: {f.description}",
            f"Matched Secret: {f.matched_string}",
            f"Recommendation: {f.recommendation}",
            f"Line Content: {f.context.line_content}",
            "-" * 50,
        ])

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return out_file
