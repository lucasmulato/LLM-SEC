import unittest
from unittest.mock import patch

from core.vector_guard import MAX_TEXT_LENGTH, VectorGuard


class TestVectorGuard(unittest.TestCase):
    def setUp(self):
        self.guard = VectorGuard()

    def test_empty_and_whitespace(self):
        for content in ("", " ", "\t\r\n", " \t\n" * 100, "\u2003"):
            with self.subTest(content=content):
                result = self.guard.inspect_document(content)
                self.assertTrue(result.is_safe)
                self.assertEqual(result.flags, [])
                self.assertEqual(result.risk_score, 0.0)

    def test_clean_fixture(self):
        result = self.guard.inspect_document("Local reference material with distinct ordinary words.")
        self.assertTrue(result.is_safe)
        self.assertEqual(result.flags, [])
        self.assertEqual(result.risk_score, 0.0)

    def test_each_signature_is_unsafe(self):
        for content in ("Ignore Previous Instructions", "SYSTEM OVERRIDE", "[INST]", "priority: high", "base64:"):
            with self.subTest(content=content):
                result = self.guard.inspect_document(content)
                self.assertFalse(result.is_safe)
                self.assertEqual(len(result.flags), 1)
                self.assertTrue(result.flags[0].startswith("INJECTION_RISK:"))
                self.assertEqual(result.risk_score, 0.4)

    def test_hidden_characters_are_unsafe(self):
        for char in ("\u200b", "\u200c", "\u200d", "\ufeff"):
            with self.subTest(char=char):
                result = self.guard.inspect_document("local" + char + "fixture")
                self.assertFalse(result.is_safe)
                self.assertEqual(result.flags, ["STEGANOGRAPHY: 1 hidden chars found"])
                self.assertEqual(result.risk_score, 0.5)

    def test_repetition_alone_is_unsafe(self):
        result = self.guard.inspect_document("fixture " * 20)
        self.assertFalse(result.is_safe)
        self.assertEqual(len(result.flags), 1)
        self.assertTrue(result.flags[0].startswith("LOW_ENTROPY:"))
        self.assertEqual(result.risk_score, 0.2)

    def test_flags_and_verdict_agree_and_score_is_bounded(self):
        fixtures = (
            "", "ordinary fixture", "ignore previous instructions",
            "fixture " * 20, "\u200b",
            "ignore previous instructions system override [inst] priority: high base64: \u200b"
        )
        for content in fixtures:
            with self.subTest(content=content):
                result = self.guard.inspect_document(content)
                self.assertEqual(result.is_safe, not result.flags)
                self.assertGreaterEqual(result.risk_score, 0.0)
                self.assertLessEqual(result.risk_score, 1.0)
        self.assertEqual(self.guard.inspect_document(fixtures[-1]).risk_score, 1.0)

    def test_input_validation_before_regex(self):
        with patch("core.vector_guard.re.search") as search:
            for content in (None, 123, b"fixture", [], {}):
                with self.subTest(content=content), self.assertRaises(TypeError):
                    self.guard.inspect_document(content)
            with self.assertRaises(ValueError):
                self.guard.inspect_document("a" * (MAX_TEXT_LENGTH + 1))
            search.assert_not_called()

    def test_maximum_length_allowed(self):
        self.assertEqual(MAX_TEXT_LENGTH, 100000)
        for content in ("a" * MAX_TEXT_LENGTH, " " * MAX_TEXT_LENGTH):
            result = self.guard.inspect_document(content)
            self.assertTrue(result.is_safe)
            self.assertEqual(result.flags, [])
