"""Composable synchronous firewall pipeline with structured layer results."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from time import perf_counter

from .layers.classifier import classify
from .layers.output_guard import guard_output
from .layers.similarity import SimilarityIndex, default_index


@dataclass(frozen=True)
class Inspection:
    layer: str
    verdict: str
    score: float
    reason: str
    latency_ms: float


class Firewall:
    def __init__(self, rules_path: str | Path | None = None,
                 similarity_index: SimilarityIndex | None = None, threshold: float | None = None) -> None:
        configured_path = rules_path or os.getenv("SENTINELLOOP_RULES_PATH")
        self.exact_rules: tuple[str, ...] = ()
        if configured_path:
            path = Path(configured_path)
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self.exact_rules = tuple(rule["exact"] for rule in data.get("rules", []))
        self.similarity_index = similarity_index or default_index()
        self.similarity_threshold = threshold if threshold is not None else float(
            os.getenv("SENTINELLOOP_SIMILARITY_THRESHOLD", "0.55"))

    def inspect_input(self, text: str) -> Inspection:
        started = perf_counter()
        blocked, rule_score, rule_reason = classify(text, self.exact_rules)
        similarity, nearest = self.similarity_index.score(text)
        similar = similarity >= self.similarity_threshold
        verdict = "block" if blocked or similar else "allow"
        layer = "L1" if blocked else ("L2" if similar else "L1+L2")
        score = max(rule_score, similarity)
        reason = rule_reason if blocked else (
            f"similar to training attack {nearest} (cosine={similarity:.3f})" if similar else
            f"no rule matched; nearest training attack {nearest or 'none'} (cosine={similarity:.3f})")
        return Inspection(layer, verdict, score, reason,
                          (perf_counter() - started) * 1000)

    def inspect_output(self, text: str) -> tuple[str, Inspection]:
        started = perf_counter()
        filtered, blocked, reason = guard_output(text)
        return filtered, Inspection("L5", "block" if blocked else "allow", float(blocked), reason,
                                   (perf_counter() - started) * 1000)

    def inspect_untrusted(self, text: str) -> Inspection:
        return self.inspect_input(text)

    @staticmethod
    def as_log(inspection: Inspection) -> dict[str, str | float]:
        return asdict(inspection)
