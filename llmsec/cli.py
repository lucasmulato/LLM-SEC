import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from core.scanner_pii import MAX_TEXT_LENGTH, PIIScanner
from core.vector_guard import VectorGuard
from llmsec import __version__


def _read_input(args: argparse.Namespace) -> str:
    if args.text is not None and args.file is not None:
        raise ValueError("provide text or --file, not both")
    if args.file is not None:
        if not args.file.is_file():
            raise ValueError("--file must reference a regular UTF-8 file")
        with args.file.open(encoding="utf-8") as stream:
            content = stream.read(MAX_TEXT_LENGTH + 1)
    elif args.text is not None:
        content = args.text
    else:
        raise ValueError("provide text or --file")
    if len(content) > MAX_TEXT_LENGTH:
        raise ValueError(f"input must not exceed {MAX_TEXT_LENGTH} characters")
    return content


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llmsec", description="LLM-SEC local defensive scanner")
    parser.add_argument("--version", action="version", version=f"LLM-SEC {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Regex and optional local NER PII detection")
    inspect = commands.add_parser("inspect-document", help="Heuristic text inspection, not vector DB analysis")
    for command in (scan, inspect):
        command.add_argument("text", nargs="?")
        command.add_argument("--file", "-f", type=Path)
        command.add_argument("--json", action="store_true", dest="output_json")
    scan.add_argument("--regex-only", action="store_true", help="Do not load any NER model")
    scan.add_argument("--include-values", action="store_true", help="Explicitly expose sensitive finding values")
    commands.add_parser("health", help="Check regex and document heuristic functionality only")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "health":
        from core.health import production_health_check

        if not asyncio.run(production_health_check()):
            raise SystemExit(1)
        return
    try:
        content = _read_input(args)
    except (OSError, UnicodeError):
        parser.exit(2, "llmsec: unable to read input as a regular UTF-8 file\n")
    except ValueError as error:
        parser.exit(2, f"llmsec: {error}\n")
    try:
        if args.command == "scan":
            scanner = PIIScanner(model_name=None if args.regex_only else "en_core_web_sm")
            result = asyncio.run(scanner.scan(content, include_values=args.include_values))
            if args.output_json:
                print(json.dumps(result, ensure_ascii=True))
            else:
                print(f"LLM-SEC: {result['count']} potential PII finding(s)")
                print("Coverage: " + ", ".join(f"{key}={value}" for key, value in result["stages"].items()))
                print("Incomplete coverage; no findings does not establish absence of sensitive data.")
                for detection in result["detections"]:
                    print(json.dumps(detection, ensure_ascii=True))
        else:
            report = asdict(VectorGuard().inspect_document(content))
            report["assessment"] = "heuristic_only"
            report["limitation"] = "is_safe means no configured flags, not proof of safety"
            print(json.dumps(report, ensure_ascii=True, indent=None if args.output_json else 2))
    except Exception:
        print("llmsec: scan failed; no assessment is available", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
