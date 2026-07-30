"""
Unit tests for Desktop GUI module.
"""

import json
import tempfile
import unittest
from pathlib import Path

from secret_scanner.gui import SecretScannerGUI


class TestGUI(unittest.TestCase):
    """GUI tests run against an isolated settings file, never the user's real one."""

    def _make_app(self, settings_path):
        try:
            return SecretScannerGUI(settings_path=settings_path)
        except Exception as err:
            self.skipTest(f"GUI testing skipped in headless environment: {err}")

    def test_gui_instantiation_uses_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            app = self._make_app(Path(tmpdir) / "settings.json")
            self.assertIsNotNone(app)
            self.assertEqual(app.entropy_threshold_var.get(), 4.5)
            self.assertTrue(app.enable_git_var.get())
            self.assertEqual(app.disabled_rule_ids, set())
            app.destroy()

    def test_settings_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = Path(tmpdir) / "settings.json"

            app = self._make_app(settings)
            app.project_path_var.set("/tmp/example-project")
            app.brief_report_var.set(True)
            app.enable_git_var.set(False)
            app.disabled_rule_ids = {"API-001"}
            app.custom_keywords = ["mapkit"]
            app.custom_rules = [
                {"id": "CUSTOM-1", "name": "Internal ID", "pattern": r"INT-\d{6}", "risk": "Medium"}
            ]
            app._save_settings()
            app.destroy()

            self.assertTrue(settings.exists())
            stored = json.loads(settings.read_text())
            self.assertEqual(stored["project_path"], "/tmp/example-project")

            reopened = self._make_app(settings)
            self.assertEqual(reopened.project_path_var.get(), "/tmp/example-project")
            self.assertTrue(reopened.brief_report_var.get())
            self.assertFalse(reopened.enable_git_var.get())
            self.assertEqual(reopened.disabled_rule_ids, {"API-001"})
            self.assertEqual(reopened.custom_keywords, ["mapkit"])
            self.assertEqual(len(reopened.custom_rules), 1)
            reopened.destroy()

    def test_invalid_custom_regex_is_dropped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            app = self._make_app(Path(tmpdir) / "settings.json")
            app.custom_rules = [
                {"id": "CUSTOM-1", "name": "Broken", "pattern": "([unclosed", "risk": "High"},
                {"id": "CUSTOM-2", "name": "Valid", "pattern": r"INT-\d{6}", "risk": "High"},
            ]
            built = app._build_custom_rule_objects()
            self.assertEqual([r.id for r in built], ["CUSTOM-2"])
            app.destroy()


if __name__ == "__main__":
    unittest.main()
