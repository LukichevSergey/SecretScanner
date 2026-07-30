"""
Unit tests for pattern detection rules.
"""

import re
import unittest
from secret_scanner.patterns import get_all_rules


class TestPatterns(unittest.TestCase):

    def setUp(self):
        self.rules = {rule.id: rule for rule in get_all_rules()}

    def test_openai_api_key_rule(self):
        rule = self.rules["API-001"]
        regex = re.compile(rule.pattern)
        sample = "let key = \"sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCD\""
        self.assertTrue(regex.search(sample))

    def test_aws_key_rule(self):
        rule = self.rules["API-004"]
        regex = re.compile(rule.pattern)
        sample = "AKIAIOSFODNN7EXAMPLE"
        self.assertTrue(regex.search(sample))

    def test_swift_variable_rule(self):
        rule = self.rules["SWIFT-001"]
        regex = re.compile(rule.pattern)
        sample = 'let password = "SuperSecretPassword123!"'
        match = regex.search(sample)
        self.assertIsNotNone(match)
        if match:
            self.assertEqual(match.group(1), "SuperSecretPassword123!")

    def test_jwt_rule(self):
        rule = self.rules["AUTH-001"]
        regex = re.compile(rule.pattern)
        sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertTrue(regex.search(sample))


if __name__ == "__main__":
    unittest.main()
