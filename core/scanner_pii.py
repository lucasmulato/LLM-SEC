import asyncio
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

MAX_TEXT_LENGTH = 100000


@dataclass
class PIIDetected:
    type: str
    value: str
    stage: str


class PIIScanner:
    def __init__(self, model_name: Optional[str] = "en_core_web_sm"):
        self.regex_patterns = {
            "EMAIL": r"(?<![a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "API_KEY": r"sk-[a-zA-Z0-9]{32,}"
        }
        self.nlp = None
        self.ner_status = "disabled" if model_name is None else "unavailable"
        if model_name is not None:
            try:
                import spacy

                self.nlp = spacy.load(model_name)
            except (ImportError, OSError):
                self.nlp = None

    async def scan(self, text: str, include_values: bool = False) -> Dict[str, Any]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > MAX_TEXT_LENGTH:
            raise ValueError(f"text must not exceed {MAX_TEXT_LENGTH} characters")
        if not isinstance(include_values, bool):
            raise TypeError("include_values must be a boolean")
        return await asyncio.to_thread(self._scan, text, include_values)

    def _scan(self, text: str, include_values: bool) -> Dict[str, Any]:
        results = []
        for label, pattern in self.regex_patterns.items():
            for match in re.finditer(pattern, text):
                value = match.group() if include_values else "[REDACTED]"
                results.append(vars(PIIDetected(label, value, "REGEX")))

        ner_status = self.ner_status
        if self.nlp is not None:
            doc = self.nlp(text)
            for ent in doc.ents:
                if ent.label_ in ["PERSON", "ORG", "GPE"]:
                    value = ent.text if include_values else "[REDACTED]"
                    results.append(vars(PIIDetected(ent.label_, value, "NER")))
            ner_status = "complete"

        return {
            "detections": results,
            "count": len(results),
            "is_leaky": bool(results),
            "stages": {
                "regex": "complete",
                "ner": ner_status,
                "semantic": "not_implemented"
            },
            "complete": False
        }
