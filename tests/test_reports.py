"""
Unit tests for JSON, HTML, Markdown, and Text report generators.
"""

import tempfile
import unittest
from pathlib import Path

from secret_scanner.models import Finding, MatchContext, RiskLevel, ScanReport, ScanStats
from secret_scanner.report_html import generate_html_report
from secret_scanner.report_json import generate_json_report
from secret_scanner.report_markdown import generate_markdown_report
from secret_scanner.report_console import generate_text_report


class TestReports(unittest.TestCase):

    def setUp(self):
        self.finding = Finding(
            finding_type="OpenAI API Key",
            risk_level=RiskLevel.CRITICAL,
            description="Detected OpenAI key.",
            file_path="Config/Secrets.swift",
            line_number=10,
            matched_string="sk-proj-****1234",
            recommendation="Store in Keychain.",
            context=MatchContext(
                lines_before=["let x = 1"],
                line_content='let key = "sk-proj-1234"',
                line_number=10,
                lines_after=["let y = 2"],
            ),
            rule_id="API-001",
        )
        self.stats = ScanStats(files_scanned=5, lines_scanned=100)
        self.stats.update_with_findings([self.finding])
        self.report = ScanReport(
            stats=self.stats,
            findings=[self.finding],
            scanned_path="/tmp/test_proj",
            scan_timestamp="2026-07-30 20:00:00",
        )

    def test_json_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            generate_json_report(self.report, out_file)
            self.assertTrue(out_file.exists())
            self.assertIn("scanned_path", out_file.read_text())

    def test_html_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.html"
            generate_html_report(self.report, out_file)
            self.assertTrue(out_file.exists())
            self.assertIn("SecretScanner Security Audit", out_file.read_text())

    def test_markdown_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.md"
            generate_markdown_report(self.report, out_file)
            self.assertTrue(out_file.exists())
            self.assertIn("## 📊 Executive Summary", out_file.read_text())

    def test_text_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.txt"
            generate_text_report(self.report, out_file)
            self.assertTrue(out_file.exists())
            self.assertIn("SECRET SCANNER AUDIT REPORT", out_file.read_text())


if __name__ == "__main__":
    unittest.main()
