"""Utility Guardian: Deterministic WAD-18 utility preservation gate.

Prevents security patches and containment barriers from degrading application utility
below normative performance thresholds (Axioms 1 & 2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Final, Optional, Sequence, Tuple

from core.kernel import NormativeValue

DEFAULT_MIN_UTILITY: Final[NormativeValue] = NormativeValue.from_str("0.85")


@dataclass(frozen=True, slots=True)
class UtilityMetric:
    """Normative utility evaluation result."""
    metric_id: str
    utility_score: NormativeValue
    threshold: NormativeValue
    is_admissible: bool
    evaluation_details: str

    def __post_init__(self) -> None:
        if not isinstance(self.utility_score, NormativeValue):
            raise TypeError("utility_score must be a NormativeValue")
        if not isinstance(self.threshold, NormativeValue):
            raise TypeError("threshold must be a NormativeValue")
        if not isinstance(self.is_admissible, bool):
            raise TypeError("is_admissible must be a bool")


class UtilityGuardian:
    """Enforces that security rules and patches do not compromise system utility."""

    def __init__(self, min_threshold: NormativeValue = DEFAULT_MIN_UTILITY) -> None:
        self.min_threshold = min_threshold

    def evaluate_patch(
        self,
        patch_code: str,
        benchmark_results: Optional[Sequence[Tuple[str, bool]]] = None,
        custom_score: Optional[NormativeValue] = None
    ) -> UtilityMetric:
        """Evaluate patch utility deterministically against benchmark suite."""
        if not isinstance(patch_code, str):
            raise TypeError("patch_code must be a str")

        if custom_score is not None:
            score = custom_score
        elif benchmark_results:
            passed = sum(1 for _, ok in benchmark_results if ok)
            total = len(benchmark_results)
            score = NormativeValue.from_fraction(passed, total)
        else:
            # Baseline heuristic: ensure non-empty valid patch
            score = NormativeValue.one() if bool(patch_code.strip()) else NormativeValue.zero()

        is_admissible = score >= self.min_threshold
        details = (
            f"Utility score {score.to_decimal_str(4)} >= threshold {self.min_threshold.to_decimal_str(4)}"
            if is_admissible
            else f"Utility regression detected: {score.to_decimal_str(4)} < {self.min_threshold.to_decimal_str(4)}"
        )

        return UtilityMetric(
            metric_id="UTILITY_BENCHMARK_V1",
            utility_score=score,
            threshold=self.min_threshold,
            is_admissible=is_admissible,
            evaluation_details=details
        )

    def check_patch(self, patch_code: str) -> bool:
        """Boolean gate checking if patch meets minimum utility requirement."""
        return self.evaluate_patch(patch_code).is_admissible
