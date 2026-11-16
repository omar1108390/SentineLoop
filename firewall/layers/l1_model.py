"""Inference for compact JSON-exported injection classifier weights."""

import json
import math
import re
from functools import lru_cache
from pathlib import Path

from .normalizer import normalize

TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")


def _features(text: str, use_bigrams: bool) -> set[str]:
    tokens = TOKEN_RE.findall(normalize(text).casefold())
    features = set(tokens)
    if use_bigrams:
        features.update(f"{left} {right}" for left, right in zip(tokens, tokens[1:]))
    return features


class InjectionModel:
    def __init__(self, model_path: Path | None = None) -> None:
        path = model_path or Path(__file__).resolve().parents[1] / "models" / "injection_classifier.json"
        self.model = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        self.weights = dict(zip(self.model["features"], self.model["weights"])) if self.model else {}

    @property
    def available(self) -> bool:
        return self.model is not None

    @property
    def threshold(self) -> float:
        return float(self.model.get("threshold", 0.5)) if self.model else 1.1

    def score(self, text: str) -> float:
        if not self.model:
            return 0.0
        value = float(self.model["intercept"])
        for feature in _features(text, self.model.get("bigrams", True)):
            value += self.weights.get(feature, 0.0)
        if value >= 0:
            return 1.0 / (1.0 + math.exp(-value))
        exp_value = math.exp(value)
        return exp_value / (1.0 + exp_value)


@lru_cache(maxsize=1)
def default_model() -> InjectionModel:
    return InjectionModel()
