"""L1b ML classifier: logistic regression over word and character n-grams.

The model is trained by ``hardening/training/train_classifier.py`` (training split,
its mutations and a synthetic attack set; never validation/holdout data) and
exported as plain JSON (feature -> weight), so inference needs no ML library.

Features, computed on the *normalized* text:

* words and word pairs ("ignore", "previous instructions"): learn attack vocabulary;
* character 3-5-grams inside words (" ign", "stru", "ompt "): make the model
  robust to misspellings and new word forms it never saw ("instrucions").

The same :func:`features` function is used for training and inference, so the
two can never disagree. Each hardening round retrains the model on newly found
bypasses and writes a new versioned file.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path

from .normalizer import normalize

TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "injection_classifier.json"


def features(text: str, bigrams: bool = True, char_range: tuple[int, int] | None = (3, 5)) -> set[str]:
    return set(_features_cached(text, bigrams, tuple(char_range) if char_range else None))


@lru_cache(maxsize=8192)
def _features_cached(text: str, bigrams: bool, char_range: tuple[int, int] | None) -> frozenset[str]:
    normalized = normalize(text).casefold()
    tokens = TOKEN_RE.findall(normalized)
    found = set(tokens)
    if bigrams:
        found.update(f"{left} {right}" for left, right in zip(tokens, tokens[1:]))
    if char_range:
        low, high = char_range
        for word in set(tokens):
            padded = f" {word} "
            for size in range(low, high + 1):
                found.update("c:" + padded[i : i + size] for i in range(max(1, len(padded) - size + 1)))
    return frozenset(found)


class InjectionModel:
    def __init__(self, model_path: Path | str | None = None) -> None:
        path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.path = path
        self.model = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        self.weights = dict(zip(self.model["features"], self.model["weights"])) if self.model else {}

    @classmethod
    def from_dict(cls, model: dict) -> "InjectionModel":
        instance = cls.__new__(cls)
        instance.path = None
        instance.model = model
        instance.weights = dict(zip(model["features"], model["weights"]))
        return instance

    @property
    def available(self) -> bool:
        return self.model is not None

    @property
    def threshold(self) -> float:
        return float(self.model.get("threshold", 0.5)) if self.model else 1.1

    @property
    def version(self) -> str:
        return str(self.model.get("version", "v0")) if self.model else "missing"

    def _features(self, text: str) -> set[str]:
        char_range = self.model.get("char_ngrams")
        return features(text, self.model.get("bigrams", True), tuple(char_range) if char_range else None)

    def score(self, text: str) -> float:
        if not self.model:
            return 0.0
        value = float(self.model["intercept"])
        for feature in self._features(text):
            value += self.weights.get(feature, 0.0)
        if value >= 0:
            return 1.0 / (1.0 + math.exp(-value))
        exp_value = math.exp(value)
        return exp_value / (1.0 + exp_value)

    def top_features(self, text: str, limit: int = 4) -> list[tuple[str, float]]:
        """The *words* that pushed the score up the most (for explanations)."""
        if not self.model:
            return []
        present = [
            (feature, self.weights[feature])
            for feature in self._features(text)
            if not feature.startswith("c:") and self.weights.get(feature, 0.0) > 0
        ]
        return sorted(present, key=lambda item: item[1], reverse=True)[:limit]


@lru_cache(maxsize=8)
def load_model(model_path: str = "") -> InjectionModel:
    return InjectionModel(model_path or None)


def default_model() -> InjectionModel:
    return load_model("")
