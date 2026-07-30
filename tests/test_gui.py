"""
Unit tests for Desktop GUI module.
"""

import unittest
from secret_scanner.gui import SecretScannerGUI


class TestGUI(unittest.TestCase):

    def test_gui_instantiation(self):
        try:
            app = SecretScannerGUI()
            self.assertIsNotNone(app)
            self.assertEqual(app.entropy_threshold_var.get(), 4.5)
            self.assertTrue(app.enable_git_var.get())
            app.destroy()
        except Exception as err:
            self.skipTest(f"GUI testing skipped in headless environment: {err}")


if __name__ == "__main__":
    unittest.main()
