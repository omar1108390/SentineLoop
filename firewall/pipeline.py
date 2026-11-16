"""Composable synchronous firewall pipeline with structured layer results."""

from dataclasses import asdict, dataclass
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
    def inspect_input(self, text: str) -> Inspection:
        started = perf_counter()
        blocked, score, reason = classify(text)
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
