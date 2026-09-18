import importlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPTIONAL_DEPENDENCIES = {"pydantic", "langgraph", "langchain", "spacy", "redis", "fastmcp", "typer", "rich", "yaml", "aiohttp"}
SOURCE_ROOTS = ("core", "mcp_server", "llmsec")


def iter_module_names():
    for root in SOURCE_ROOTS:
        for path in sorted((ROOT / root).glob("*.py")):
            if path.name != "__main__.py":
                yield f"{root}.{path.stem}"


class TestRepositoryImports(unittest.TestCase):
    def test_every_module_imports_or_declares_optional_dependency(self):
        for name in iter_module_names():
            with self.subTest(module=name):
                try:
                    importlib.import_module(name)
                except ModuleNotFoundError as error:
                    top_level = (error.name or "").split(".")[0]
                    if top_level in OPTIONAL_DEPENDENCIES:
                        self.skipTest(f"optional dependency not installed: {top_level}")
                    self.fail(f"missing required dependency {error.name!r}")
                except SyntaxError as error:
                    self.fail(f"syntax error: {error}")


OPTIONAL_DEPENDENCIES = {
    "pydantic", "langgraph", "langchain", "spacy", "redis",
    "fastmcp", "rich", "typer", "yaml", "aiohttp", "cryptography",
}


if __name__ == "__main__":
    unittest.main()
