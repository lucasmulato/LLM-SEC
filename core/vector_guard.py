"""Document Vector Health Guard using deterministic WAD-18 normative metrics."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Union

from core.kernel import NormativeValue

MAX_TEXT_LENGTH = 100000

# Strict WAD-18 Normative Weights (Axiom 1 & 2)
INJECTION_WEIGHT = NormativeValue.from_str("0.4")
STEGANOGRAPHY_WEIGHT = NormativeValue.from_str("0.5")
LOW_ENTROPY_WEIGHT = NormativeValue.from_str("0.2")
MAX_RISK_BOUND = NormativeValue.from_str("1.0")


class NormativeFloat(float):
    """Float representation backed by exact deterministic WAD-18 NormativeValue."""
    _norm: NormativeValue

    def __new__(cls, val: Union[NormativeValue, float, int]):
        if isinstance(val, NormativeValue):
            norm = val
        elif isinstance(val, (int, float)) and not isinstance(val, bool):
            norm = NormativeValue.from_float(float(val))
        else:
            norm = NormativeValue.from_str(str(val))
        obj = super().__new__(cls, norm.to_float())
        obj._norm = norm
        return obj

    @property
    def normative(self) -> NormativeValue:
        return self._norm

    def __copy__(self) -> NormativeFloat:
        return self

    def __deepcopy__(self, memo: object) -> NormativeFloat:
        return self

    def __reduce__(self) -> tuple[type, tuple[NormativeValue]]:
        return (NormativeFloat, (self._norm,))


@dataclass(slots=True)
class VectorHealth:
    """Strict typed schema for document inspection results using WAD-18 normative metrics."""
    is_safe: bool
    risk_score: NormativeFloat
    flags: List[str]

    def __post_init__(self) -> None:
        if not isinstance(self.is_safe, bool):
            raise TypeError("VectorHealth.is_safe must be a bool")
        if not isinstance(self.risk_score, NormativeFloat):
            object.__setattr__(self, "risk_score", NormativeFloat(self.risk_score))
        if not isinstance(self.flags, list):
            raise TypeError("VectorHealth.flags must be a list of strings")


class VectorGuard:
    def __init__(self) -> None:
        # Patterns that indicate attempts to hijack the vector search
        self.injection_signatures = [
            r"ignore previous instructions",
            r"system override",
            r"\[inst\]",  # Common instruction tokens
            r"priority: high",
            r"base64:"    # Obfuscation indicator
        ]
        # Detect "Invisible Text" (common in poisoning) e.g., zero-width spaces
        self.steganography_chars = set(['\u200b', '\u200c', '\u200d', '\ufeff'])

    def inspect_document(self, content: str) -> VectorHealth:
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        if len(content) > MAX_TEXT_LENGTH:
            raise ValueError(f"content must not exceed {MAX_TEXT_LENGTH} characters")

        flags: List[str] = []
        score = NormativeValue.zero()

        # 1. Check for Command Injection signatures
        for pattern in self.injection_signatures:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append(f"INJECTION_RISK: {pattern}")
                score = score + INJECTION_WEIGHT

        # 2. Check for Steganography (Invisible characters)
        steg_count = sum(1 for char in content if char in self.steganography_chars)
        if steg_count > 0:
            flags.append(f"STEGANOGRAPHY: {steg_count} hidden chars found")
            score = score + STEGANOGRAPHY_WEIGHT

        # 3. Density Check (High repetition often messes up embeddings)
        words = content.split()
        if words:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.1:  # Less than 10% unique words
                flags.append("LOW_ENTROPY: Repetitive content (DoS risk)")
                score = score + LOW_ENTROPY_WEIGHT

        bounded_score = score if score < MAX_RISK_BOUND else MAX_RISK_BOUND

        return VectorHealth(
            is_safe=not bool(flags),
            risk_score=NormativeFloat(bounded_score),
            flags=flags
        )
