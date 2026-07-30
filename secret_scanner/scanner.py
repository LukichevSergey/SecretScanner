"""
Core Scanner Orchestrator module.
Coordinates file scanner, git history scanner, statistics collection,
and report generation across output formats.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import Optional


from secret_scanner.config import ScannerConfig
from secret_scanner.file_scanner import scan_files
from secret_scanner.git_scanner import scan_git_history
from secret_scanner.models import ScanReport, ScanStats
from secret_scanner.report_console import generate_text_report, print_console_summary
from secret_scanner.report_html import generate_html_report
from secret_scanner.report_json import generate_json_report
from secret_scanner.report_markdown import generate_markdown_report


class SecretScannerEngine:
    """Core Engine orchestrating secret scanning workflow across files and git history."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def run(self, output_dir: Optional[Path | str] = None) -> ScanReport:
        """
        Execute full audit scan and generate reports.
        
        Args:
            output_dir: Optional custom directory path to store generated report files.
                        Defaults to project path or current working directory.

        Returns:
            ScanReport instance containing complete results.
        """
        start_time = time.perf_counter()
        
        # 1. Execute filesystem scan
        file_findings, total_files, total_lines = scan_files(self.config)

        # 2. Execute git history scan if enabled
        git_findings = []
        if self.config.enable_git:
            git_findings = scan_git_history(self.config)

        # 3. Consolidate findings and eliminate exact duplicates
        combined_findings = file_findings + git_findings
        unique_findings = []
        seen_keys = set()
        for f in combined_findings:
            key = (f.file_path, f.line_number, f.finding_type, f.matched_string)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        # Sort findings by severity
        sorted_findings = sorted(
            unique_findings,
            key=lambda x: x.risk_level.severity_score,
            reverse=True,
        )

        elapsed = time.perf_counter() - start_time

        # 4. Build Statistics
        stats = ScanStats(
            files_scanned=total_files,
            lines_scanned=total_lines,
            elapsed_time_seconds=elapsed,
        )
        stats.update_with_findings(sorted_findings)

        # 5. Resolve the output directory before building the report so the
        #    actual write location (including the cwd fallback) is recorded.
        out_path = Path(output_dir) if output_dir else self.config.project_path
        if not out_path.is_dir():
            out_path = Path.cwd()

        # 6. Build Report Object
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = ScanReport(
            stats=stats,
            findings=sorted_findings,
            scanned_path=str(self.config.project_path),
            scan_timestamp=timestamp_str,
            output_dir=str(out_path),
        )

        # 7. Generate output reports conditionally
        if self.config.generate_json:
            generate_json_report(report, out_path / "report.json")
        if self.config.generate_html:
            generate_html_report(report, out_path / "report.html")
        if self.config.generate_markdown:
            generate_markdown_report(report, out_path / "report.md")
        if self.config.generate_text:
            generate_text_report(report, out_path / "report.txt")


        # 8. Output summary to console
        print_console_summary(report)

        return report
