"""
Test suite for the ngram function.

Covers basic functionality, large inputs, and edge cases.
"""

import unittest
from ngram import ngram


class TestNgramBasic(unittest.TestCase):
    """Test basic n-gram generation functionality."""

    def test_trigrams(self):
        """Test basic trigram generation."""
        result = ngram("castle", 3)
        expected = ["cas", "ast", "stl", "tle"]
        self.assertEqual(result, expected)

    def test_bigrams(self):
        """Test bigram generation."""
        result = ngram("test", 2)
        expected = ["te", "es", "st"]
        self.assertEqual(result, expected)

    def test_fourgrams(self):
        """Test 4-gram generation."""
        result = ngram("alphabet", 4)
        expected = ["alph", "lpha", "phab", "habe", "abet"]
        self.assertEqual(result, expected)


class TestNgramLargeInputs(unittest.TestCase):
    """Test with large text inputs."""

    def test_long_string(self):
        """Test with a long string (1000 characters)."""
        text = "a" * 1000
        result = ngram(text, 3)
        self.assertEqual(len(result), 998)

    def test_repeated_pattern(self):
        """Test with repeated pattern."""
        text = "abc" * 100
        result = ngram(text, 5)
        self.assertEqual(len(result), 296)
        self.assertEqual(len(result[0]), 5)


class TestNgramEdgeCases(unittest.TestCase):
    """Test edge cases."""

    def test_empty_string(self):
        """Test with empty string."""
        result = ngram("", 3)
        self.assertEqual(result, [])

    def test_window_larger_than_text(self):
        """Test when window is larger than text."""
        result = ngram("ok", 3)
        self.assertEqual(result, [])

    def test_window_equals_text_length(self):
        """Test when window equals text length."""
        result = ngram("abc", 3)
        self.assertEqual(result, ["abc"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
