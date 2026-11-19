"""The SentinelLoop firewall: layered, explainable inspection.

====  ===================  ========================================================
ID    Layer                What it does
====  ===================  ========================================================
L0    normalizer           decodes/strips disguises (base64, zero-width, leetspeak...)
L1a   rules                transparent regex signatures of known techniques
L1b   classifier           logistic-regression model trained on attack examples
L2    similarity           TF-IDF nearest-neighbour search over known attacks
L3    quarantine           dual-LLM: untrusted documents become data only
L4    tool_policy          allowlist + provenance + approval for every tool call
L5    output_guard         redacts secrets, system prompt and exfiltration links
====  ===================  ========================================================

L0-L2 are *detectors*: they score text and can be wrong. L3-L5 are
*architectural* controls: they limit what a successful injection can do. Every
inspection returns an :class:`Inspection` whose ``details`` explain each layer.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import perf_counter

from .layers.ml_classifier import InjectionModel, default_model
from .layers.normalizer import normalize_report
from .layers.output_guard import guard_output_report
from .layers.rules import match_rules
from .layers.similarity import SimilarityIndex, default_index

DETECTORS = ("rules", "classifier", "similarity")

LAYER_INFO = {
    "normalizer": ("L0", "Normalizer"),
    "rules": ("L1a", "Signature rules"),
    "classifier": ("L1b", "ML classifier"),
    "similarity": ("L2", "Similarity search"),
    "quarantine": ("L3", "Quarantine"),
    "tool_policy": ("L4", "Tool policy"),
    "output_guard": ("L5", "Output guard"),
}


@dataclass(frozen=True)
class LayerResult:
    layer: str
    verdict: str  # block | allow | info | off
    score: float
    threshold: float | None
    reason: str


@dataclass(frozen=True)
class Inspection:
    layer: str
    verdict: str
    score: float
    reason: str
    latency_ms: float
    details: tuple[LayerResult, ...] = field(default=())
    stage: str = "input"


class Firewall:
    def __init__(
        self,
        rules_path: str | Path | None = None,
        similarity_index: SimilarityIndex | None = None,
        threshold: float | None = None,
        injection_model: InjectionModel | None = None,
        detectors: tuple[str, ...] | frozenset[str] | set[str] = DETECTORS,
    ) -> None:
        configured_path = rules_path or os.getenv("SENTINELLOOP_RULES_PATH")
        self.exact_rules: tuple[str, ...] = ()
        if configured_path:
            path = Path(configured_path)
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self.exact_rules = tuple(rule["exact"] for rule in data.get("rules", []))
        self.similarity_index = similarity_index or default_index()
        self.injection_model = injection_model or default_model()
        # Priority: explicit argument > environment variable > value tuned on the
        # validation split and stored with the model > 0.65.
        tuned = (self.injection_model.model or {}).get("similarity_threshold", 0.65)
        self.similarity_threshold = (
            threshold
            if threshold is not None
            else float(os.getenv("SENTINELLOOP_SIMILARITY_THRESHOLD", tuned))
        )
        unknown = set(detectors) - set(DETECTORS)
        if unknown:
            raise ValueError(f"unknown detectors: {', '.join(sorted(unknown))}")
        self.detectors = frozenset(detectors)

    def inspect_input(self, text: str, stage: str = "input") -> Inspection:
        """Run L0-L2 on one piece of text (a user message or a retrieved document)."""
        started = perf_counter()
        details: list[LayerResult] = []
        _, notes = normalize_report(text)
        details.append(
            LayerResult(
                "normalizer",
                "info",
                0.0,
                None,
                "; ".join(notes) if notes else "no hidden or encoded content found",
            )
        )
        hits: list[LayerResult] = []

        if "rules" in self.detectors:
            matches = match_rules(text, self.exact_rules, stage)
            if matches:
                first = matches[0]
                result = LayerResult(
                    "rules",
                    "block",
                    0.99 if first.rule.id == "credential-theft" else 0.95,
                    None,
                    f"rule '{first.rule.id}' ({first.rule.category}): {first.rule.explanation} "
                    f'Matched: "{first.excerpt}"',
                )
                hits.append(result)
            else:
                result = LayerResult("rules", "allow", 0.0, None, "no signature rule matched")
        else:
            result = LayerResult("rules", "off", 0.0, None, "layer disabled")
        details.append(result)

        if "classifier" in self.detectors and self.injection_model.available:
            score = self.injection_model.score(text)
            threshold = self.injection_model.threshold
            words = ", ".join(f'"{name}"' for name, _ in self.injection_model.top_features(text))
            verdict = "block" if score >= threshold else "allow"
            result = LayerResult(
                "classifier",
                verdict,
                score,
                threshold,
                f"injection probability {score:.2f} (threshold {threshold:.2f})"
                + (f"; strongest attack words: {words}" if words else ""),
            )
            if verdict == "block":
                hits.append(result)
        else:
            reason = "layer disabled" if "classifier" not in self.detectors else "no model file"
            result = LayerResult("classifier", "off", 0.0, None, reason)
        details.append(result)

        if "similarity" in self.detectors:
            similarity, nearest = self.similarity_index.score(text)
            verdict = "block" if similarity >= self.similarity_threshold else "allow"
            result = LayerResult(
                "similarity",
                verdict,
                similarity,
                self.similarity_threshold,
                f"closest known attack: {nearest or 'none'} (cosine similarity {similarity:.2f}, "
                f"threshold {self.similarity_threshold:.2f})",
            )
            if verdict == "block":
                hits.append(result)
        else:
            result = LayerResult("similarity", "off", 0.0, None, "layer disabled")
        details.append(result)

        latency = (perf_counter() - started) * 1000
        if hits:
            first = hits[0]
            return Inspection(
                first.layer,
                "block",
                max(hit.score for hit in hits),
                first.reason,
                latency,
                tuple(details),
                stage,
            )
        scores = [item.score for item in details if item.verdict == "allow"]
        return Inspection(
            "detectors",
            "allow",
            max(scores, default=0.0),
            "no detector flagged this text",
            latency,
            tuple(details),
            stage,
        )

    def inspect_untrusted(self, text: str) -> Inspection:
        return self.inspect_input(text, stage="document")

    def inspect_output(self, text: str) -> tuple[str, Inspection]:
        started = perf_counter()
        filtered, findings = guard_output_report(text)
        blocked = bool(findings)
        reason = (
            "; ".join(findings)
            if findings
            else "no secret, canary, system prompt or exfiltration link detected"
        )
        return filtered, Inspection(
            "output_guard",
            "block" if blocked else "allow",
            float(blocked),
            reason,
            (perf_counter() - started) * 1000,
            (LayerResult("output_guard", "block" if blocked else "allow", float(blocked), None, reason),),
            "output",
        )

    @staticmethod
    def as_log(inspection: Inspection) -> dict:
        return asdict(inspection)
