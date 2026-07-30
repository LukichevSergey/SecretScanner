"""
Unit tests for Shannon entropy calculator.
"""

import unittest
from secret_scanner.entropy import (
    calculate_shannon_entropy,
    extract_high_entropy_candidates,
    is_false_positive_entropy,
)


class TestEntropy(unittest.TestCase):

    def test_shannon_entropy_calculation(self):
        # Zero entropy string
        self.assertEqual(calculate_shannon_entropy("aaaaaaaaaa"), 0.0)

        # High entropy string
        high_entropy_str = "8xK9#mP$2vL!qZ7wN5rT"
        self.assertGreater(calculate_shannon_entropy(high_entropy_str), 4.0)

    def test_false_positives(self):
        # UUID should be ignored
        self.assertTrue(is_false_positive_entropy("123e4567-e89b-12d3-a456-426614174000"))

        # URL should be ignored
        self.assertTrue(is_false_positive_entropy("https://github.com/apple/swift/blob/main/README.md"))

        # High entropy string should NOT be ignored
        self.assertFalse(is_false_positive_entropy("dK9#mP$2vL!qZ7wN5rT1xY3zA6bC8dE0f"))

    def test_candidate_extraction(self):
        line = 'let secretKey = "dK9#mP$2vL!qZ7wN5rT1xY3zA6bC8dE0f"'
        candidates = extract_high_entropy_candidates(line, min_length=20, entropy_threshold=4.0)
        self.assertTrue(len(candidates) >= 1)
        self.assertIn("dK9#mP$2vL!qZ7wN5rT1xY3zA6bC8dE0f", [c[0] for c in candidates])


if __name__ == "__main__":
    unittest.main()
