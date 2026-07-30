"""
Unit tests for pattern detection rules.
"""

import re
import unittest

from secret_scanner.config import default_config
from secret_scanner.patterns import (
    build_custom_keyword_rule,
    get_all_rules,
    resolve_active_rules,
)


def _any_rule_matches(line, rules=None):
    """True if at least one rule fires on the line (file_patterns ignored)."""
    for rule in rules if rules is not None else get_all_rules():
        if re.search(rule.pattern, line):
            return True
    return False


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

    def test_all_rules_compile_and_ids_are_unique(self):
        ids = [rule.id for rule in get_all_rules()]
        self.assertEqual(len(ids), len(set(ids)))
        for rule in get_all_rules():
            re.compile(rule.pattern)

    def test_prefixed_uuid_api_key_is_detected(self):
        """A UUID-shaped key behind a prefixed name slips past both name and entropy checks."""
        line = 'static let MAPKIT_API_KEY = "00000000-1111-2222-3333-444444444444"'
        self.assertTrue(_any_rule_matches(line))

    def test_non_secret_uuid_constant_is_ignored(self):
        line = 'static let moscowCity = "00000000-1111-2222-3333-555555555555"'
        self.assertFalse(_any_rule_matches(line))

    def test_secret_word_inside_longer_word_is_ignored(self):
        self.assertFalse(_any_rule_matches('let tokenizer = "whitespace"'))
        self.assertFalse(_any_rule_matches('let keyPath = "user.profile.name"'))

    def test_placeholder_and_interpolated_values_are_ignored(self):
        self.assertFalse(_any_rule_matches('let apiKey = "YOUR_API_KEY_HERE"'))
        self.assertFalse(_any_rule_matches('apiKey = "${API_KEY}"'))

    def test_android_and_kotlin_assignments_are_detected(self):
        self.assertTrue(_any_rule_matches('const val API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstu"'))
        self.assertTrue(_any_rule_matches('storePassword=MyR3leaseP@ss'))
        self.assertTrue(
            _any_rule_matches(
                '<string name="google_api_key">AIzaSyD1234567890abcdefghijklmnopqrstu</string>'
            )
        )


class TestRuleResolution(unittest.TestCase):

    def setUp(self):
        self.config = default_config("/tmp")

    def test_disabled_rule_is_excluded(self):
        self.config.disabled_rule_ids = {"API-001"}
        ids = {rule.id for rule in resolve_active_rules(self.config)}
        self.assertNotIn("API-001", ids)
        self.assertIn("API-004", ids)

    def test_custom_keyword_rule_matches_project_specific_name(self):
        rule = build_custom_keyword_rule(["widgetly"])
        self.assertIsNotNone(rule)
        self.assertTrue(re.search(rule.pattern, 'let widgetlyToken = "abc123def456"'))
        self.assertFalse(re.search(rule.pattern, 'let unrelated = "abc123def456"'))

    def test_custom_keyword_rule_is_added_to_active_rules(self):
        self.config.custom_keywords = {"mapkit"}
        ids = {rule.id for rule in resolve_active_rules(self.config)}
        self.assertIn("CUSTOM-KEYWORDS", ids)

    def test_empty_keywords_produce_no_rule(self):
        self.assertIsNone(build_custom_keyword_rule([]))
        self.assertIsNone(build_custom_keyword_rule(["  "]))


if __name__ == "__main__":
    unittest.main()
