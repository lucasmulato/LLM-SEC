import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from core.health import production_health_check
from core.scanner_pii import MAX_TEXT_LENGTH, PIIScanner
from core.vector_guard import VectorHealth


class TestPIIScanner(unittest.IsolatedAsyncioTestCase):
    async def test_default_masking(self):
        scanner = PIIScanner(model_name=None)
        result = await scanner.scan("fixture@example.test 123-45-6789 sk-" + "a" * 32)
        self.assertEqual(result["count"], 3)
        self.assertTrue(result["is_leaky"])
        self.assertEqual({item["type"] for item in result["detections"]}, {"EMAIL", "SSN", "API_KEY"})
        self.assertTrue(all(item["value"] == "[REDACTED]" for item in result["detections"]))
        self.assertEqual(result["stages"], {
            "regex": "complete", "ner": "disabled", "semantic": "not_implemented"
        })
        self.assertFalse(result["complete"])

    async def test_explicit_raw_values(self):
        scanner = PIIScanner(model_name=None)
        values = ["fixture@example.test", "123-45-6789", "sk-" + "a" * 32]
        result = await scanner.scan(" ".join(values), include_values=True)
        self.assertEqual([item["value"] for item in result["detections"]], values)
        masked = await scanner.scan(values[0])
        self.assertEqual(masked["detections"][0]["value"], "[REDACTED]")

    async def test_clean_and_empty_text(self):
        for text in ("", " \t\n", "ordinary local fixture"):
            with self.subTest(text=text):
                result = await PIIScanner(model_name=None).scan(text)
                self.assertEqual(result["detections"], [])
                self.assertEqual(result["count"], 0)
                self.assertFalse(result["is_leaky"])
                self.assertFalse(result["complete"])

    async def test_regex_only_does_not_import_spacy(self):
        with patch("builtins.__import__", wraps=__import__) as importer:
            scanner = PIIScanner(model_name=None)
        self.assertFalse(any(call.args[0].startswith("spacy") for call in importer.call_args_list))
        self.assertEqual((await scanner.scan(""))["stages"]["ner"], "disabled")

    async def test_missing_dependency_status(self):
        output = io.StringIO()
        with patch.dict("sys.modules", {"spacy": None}), redirect_stdout(output):
            scanner = PIIScanner()
            result = await scanner.scan("fixture@example.test")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(result["stages"]["ner"], "unavailable")
        self.assertTrue(result["is_leaky"])
        self.assertFalse(result["complete"])

    async def test_missing_model_status(self):
        spacy = Mock()
        spacy.load.side_effect = OSError("missing fixture model")
        output = io.StringIO()
        with patch.dict("sys.modules", {"spacy": spacy}), redirect_stdout(output):
            scanner = PIIScanner(model_name="missing_fixture")
            result = await scanner.scan("fixture@example.test")
        spacy.load.assert_called_once_with("missing_fixture")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(result["stages"]["ner"], "unavailable")
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["complete"])

    async def test_mock_ner_masking_and_status(self):
        entities = [
            SimpleNamespace(label_="PERSON", text="Fixture Person"),
            SimpleNamespace(label_="ORG", text="Fixture Company"),
            SimpleNamespace(label_="GPE", text="Fixture Town"),
            SimpleNamespace(label_="DATE", text="Monday")
        ]
        nlp = Mock(return_value=SimpleNamespace(ents=entities))
        spacy = Mock()
        spacy.load.return_value = nlp
        with patch.dict("sys.modules", {"spacy": spacy}):
            scanner = PIIScanner("fixture_model")
        result = await scanner.scan("local fixture")
        self.assertEqual(result["count"], 3)
        self.assertTrue(result["is_leaky"])
        self.assertEqual(result["stages"]["ner"], "complete")
        self.assertFalse(result["complete"])
        self.assertTrue(all(item["value"] == "[REDACTED]" for item in result["detections"]))
        self.assertTrue(all(item["stage"] == "NER" for item in result["detections"]))
        raw = await scanner.scan("local fixture", include_values=True)
        self.assertEqual([item["value"] for item in raw["detections"]], [ent.text for ent in entities[:3]])

    async def test_input_validation_before_processing(self):
        scanner = PIIScanner(model_name=None)
        with patch.object(scanner, "_scan") as process:
            for text in (None, 123, b"fixture", [], {}):
                with self.subTest(text=text), self.assertRaises(TypeError):
                    await scanner.scan(text)
            with self.assertRaises(ValueError):
                await scanner.scan("a" * (MAX_TEXT_LENGTH + 1))
            for option in ("true", 1, None):
                with self.subTest(option=option), self.assertRaises(TypeError):
                    await scanner.scan("fixture", include_values=option)
            process.assert_not_called()

    async def test_maximum_length_allowed(self):
        result = await PIIScanner(model_name=None).scan("a" * MAX_TEXT_LENGTH)
        self.assertEqual(MAX_TEXT_LENGTH, 100000)
        self.assertEqual(result["count"], 0)


class TestHealth(unittest.IsolatedAsyncioTestCase):
    async def test_health_without_optional_dependency(self):
        output = io.StringIO()
        with patch.dict("sys.modules", {"spacy": None}), redirect_stdout(output):
            self.assertTrue(await production_health_check())
        self.assertIn("NER disabled", output.getvalue())
        self.assertIn("semantic checks not implemented", output.getvalue())
        self.assertTrue(output.getvalue().isascii())

    async def test_health_rejects_missing_pii_detection(self):
        result = {
            "is_leaky": False, "count": 0, "detections": [],
            "stages": {"regex": "complete"}
        }
        with patch("core.health.PIIScanner") as scanner, redirect_stdout(io.StringIO()):
            scanner.return_value.scan = AsyncMock(return_value=result)
            self.assertFalse(await production_health_check())
            scanner.assert_called_once_with(model_name=None)

    async def test_health_rejects_inconsistent_count(self):
        result = {
            "is_leaky": True, "count": 2,
            "detections": [{"type": "EMAIL", "value": "[REDACTED]"}],
            "stages": {"regex": "complete"}
        }
        with patch("core.health.PIIScanner") as scanner, redirect_stdout(io.StringIO()):
            scanner.return_value.scan = AsyncMock(return_value=result)
            self.assertFalse(await production_health_check())

    async def test_health_rejects_invalid_vector_verdicts(self):
        for health in (VectorHealth(True, 0.0, []), VectorHealth(False, 0.4, []), VectorHealth(True, 0.4, ["fixture"])):
            with self.subTest(health=health):
                with patch("core.health.VectorGuard") as guard, redirect_stdout(io.StringIO()):
                    guard.return_value.inspect_document.return_value = health
                    self.assertFalse(await production_health_check())

    async def test_health_handles_failure_without_exception_values(self):
        output = io.StringIO()
        with patch("core.health.PIIScanner", side_effect=RuntimeError("private fixture")), redirect_stdout(output):
            self.assertFalse(await production_health_check())
        self.assertNotIn("private fixture", output.getvalue())
