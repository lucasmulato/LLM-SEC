import asyncio
from functools import lru_cache
from typing import Any

from fastmcp import FastMCP

from core.scanner_pii import MAX_TEXT_LENGTH, PIIScanner


mcp = FastMCP(
    "LLM-SEC Local Scanner",
    instructions=(
        "Defensive local PII scanning over stdio only. Authorization relies on "
        "the trusted local OS client launching this process. Results are masked. "
        "No models are downloaded: missing local NER models mean degraded "
        "regex-only scanning; inspect stages and complete before using results."
    ),
)
_scan_lock = asyncio.Lock()


@lru_cache(maxsize=1)
def get_scanner() -> PIIScanner:
    return PIIScanner()


@mcp.tool()
async def scan_text_for_pii(text: str) -> dict[str, Any]:
    """Scan text locally for PII, returning masked findings and stage coverage."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"text must not exceed {MAX_TEXT_LENGTH} characters")
    async with _scan_lock:
        task = asyncio.create_task(get_scanner().scan(text, include_values=False))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                task.exception()
            raise


def main() -> None:
    mcp.run(transport='stdio')


if __name__ == "__main__":
    main()
