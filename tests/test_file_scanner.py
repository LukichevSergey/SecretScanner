"""
Unit tests for file scanner and context extraction.
"""

import tempfile
import unittest
from pathlib import Path
from secret_scanner.config import default_config
from secret_scanner.file_scanner import scan_single_file
from secret_scanner.utils import extract_context


class TestFileScanner(unittest.TestCase):

    def test_extract_context(self):
        lines = [f"Line {i}" for i in range(1, 50)]
        context = extract_context(lines, line_idx=24, context_size=5)

        self.assertEqual(context.line_number, 25)
        self.assertEqual(context.line_content, "Line 25")
        self.assertEqual(len(context.lines_before), 5)
        self.assertEqual(len(context.lines_after), 5)
        self.assertEqual(context.lines_before[0], "Line 20")
        self.assertEqual(context.lines_after[-1], "Line 30")

    def test_scan_single_file_with_secret(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            swift_file = tmppath / "Secrets.swift"
            swift_file.write_text(
                'import Foundation\n\nstruct Secrets {\n    static let apiKey = "AIzaSyA1234567890abcdefghijklmnopqrst12"\n}\n'
            )


            config = default_config(tmppath)
            findings, files_scanned, lines_scanned = scan_single_file(str(swift_file), config)

            self.assertEqual(files_scanned, 1)
            self.assertGreater(lines_scanned, 0)
            self.assertTrue(any(f.rule_id == "API-003" for f in findings))


if __name__ == "__main__":
    unittest.main()
