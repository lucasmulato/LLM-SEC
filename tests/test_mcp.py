import asyncio
import importlib
import importlib.util
import json
import unittest
from unittest.mock import AsyncMock, Mock, patch

from core.scanner_pii import MAX_TEXT_LENGTH, PIIScanner


@unittest.skipUnless(importlib.util.find_spec("fastmcp") is not None, "optional fastmcp dependency is not installed")
class TestMCP(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(PIIScanner, "__init__", return_value=None) as constructor:
            with patch("builtins.__import__", wraps=__import__) as importer:
                cls.server = importlib.import_module("mcp_server.server")
                cls.server = importlib.reload(cls.server)
        cls.import_constructor_calls = constructor.call_count
        cls.imported_modules = [call.args[0] for call in importer.call_args_list]

    def setUp(self):
        self.server.get_scanner.cache_clear()
        self.addCleanup(self.server.get_scanner.cache_clear)
        lock = patch.object(self.server, "_scan_lock", asyncio.Lock())
        lock.start()
        self.addCleanup(lock.stop)
        tool = self.server.scan_text_for_pii
        self.scan = getattr(tool, "fn", tool)

    async def test_registry_only_scan_text_for_pii(self):
        get_tools = getattr(self.server.mcp, "get_tools", None)
        if get_tools is None:
            self.skipTest("FastMCP does not expose get_tools")
        tools = await get_tools()
        self.assertEqual(set(tools), {"scan_text_for_pii"})
        self.assertIs(getattr(tools["scan_text_for_pii"], "fn", tools["scan_text_for_pii"]), self.scan)

    async def test_masked_output(self):
        values = ["fixture@example.test", "123-45-6789", "sk-" + "a" * 32]
        scanner = PIIScanner(model_name=None)
        with patch.object(self.server, "get_scanner", return_value=scanner):
            result = await self.scan(" ".join(values))
        self.assertEqual(result["count"], 3)
        self.assertTrue(result["is_leaky"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["stages"], {
            "regex": "complete", "ner": "disabled", "semantic": "not_implemented"
        })
        self.assertEqual({item["type"] for item in result["detections"]}, {"EMAIL", "SSN", "API_KEY"})
        self.assertTrue(all(item["value"] == "[REDACTED]" for item in result["detections"]))
        for value in values:
            self.assertNotIn(value, json.dumps(result))

    async def test_lazy_cached_scanner(self):
        self.assertEqual(self.import_constructor_calls, 0)
        self.assertFalse(any(name == "spacy" or name.startswith("spacy.") for name in self.imported_modules))
        scanner = Mock(scan=AsyncMock(return_value={"count": 0}))
        with patch.object(self.server, "PIIScanner", return_value=scanner) as constructor:
            constructor.assert_not_called()
            self.assertEqual(self.server.get_scanner.cache_info().currsize, 0)
            self.assertEqual(await self.scan("first fixture"), {"count": 0})
            self.assertEqual(await self.scan("second fixture"), {"count": 0})
            constructor.assert_called_once_with()
            self.assertEqual(self.server.get_scanner.cache_info().currsize, 1)
        self.assertEqual(scanner.scan.await_count, 2)
        scanner.scan.assert_any_await("first fixture", include_values=False)
        scanner.scan.assert_any_await("second fixture", include_values=False)

    async def test_invalid_input_before_scanner(self):
        with patch.object(self.server, "get_scanner") as get_scanner:
            for text in (None, 123, b"fixture", [], {}):
                with self.subTest(text=text), self.assertRaisesRegex(TypeError, "text must be a string"):
                    await self.scan(text)
            with self.assertRaisesRegex(ValueError, f"text must not exceed {MAX_TEXT_LENGTH} characters"):
                await self.scan(" " * (MAX_TEXT_LENGTH + 1))
            get_scanner.assert_not_called()

    async def test_maximum_and_empty_input(self):
        scanner = PIIScanner(model_name=None)
        with patch.object(self.server, "get_scanner", return_value=scanner):
            for text in ("", " " * MAX_TEXT_LENGTH):
                with self.subTest(length=len(text)):
                    result = await self.scan(text)
                    self.assertEqual(result["count"], 0)
                    self.assertEqual(result["detections"], [])
                    self.assertFalse(result["is_leaky"])
                    self.assertFalse(result["complete"])

    async def test_no_attack_import(self):
        forbidden = {"core.attack_engine", "core.engine", "core.injection", "core.crescendo", "payloads"}
        for name in self.imported_modules:
            self.assertFalse(any(name == module or name.startswith(module + ".") for module in forbidden), name)
        scanner = PIIScanner(model_name=None)
        with patch.object(self.server, "get_scanner", return_value=scanner):
            with patch("builtins.__import__", wraps=__import__) as importer:
                await self.scan("ordinary local fixture")
        for call in importer.call_args_list:
            name = call.args[0]
            self.assertFalse(any(name == module or name.startswith(module + ".") for module in forbidden), name)
