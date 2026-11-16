"""Composable synchronous firewall pipeline with structured layer results."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from time import perf_counter

from .layers.classifier import classify
from .layers.output_guard import guard_output


@dataclass(frozen=True)
class Inspection:
    layer: str
    verdict: str
    score: float
    reason: str
    latency_ms: float


class Firewall:
    def __init__(self, rules_path: str | Path | None = None) -> None:
        configured_path = rules_path or os.getenv("SENTINELLOOP_RULES_PATH")
        self.exact_rules: tuple[str, ...] = ()
        if configured_path:
            path = Path(configured_path)
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self.exact_rules = tuple(rule["exact"] for rule in data.get("rules", []))

    def inspect_input(self, text: str) -> Inspection:
        started = perf_counter()
        blocked, score, reason = classify(text, self.exact_rules)
        return Inspection("L0+L1", "block" if blocked else "allow", score, reason,
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
