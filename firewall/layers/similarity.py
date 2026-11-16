"""L2 lexical TF-IDF similarity index built from training attacks only."""

import json
import math
import os
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .normalizer import normalize


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]{2,}", normalize(text))


class SimilarityIndex:
    def __init__(self, examples: list[dict[str, str]]) -> None:
        self.examples = examples
        self.term_counts = [Counter(_tokens(row["prompt"])) for row in examples]
        document_frequency: Counter[str] = Counter()
        for terms in self.term_counts:
            document_frequency.update(terms.keys())
        count = max(1, len(examples))
        self.idf = {term: math.log((count + 1) / (frequency + 1)) + 1
                    for term, frequency in document_frequency.items()}
        self.vectors = [self._vector(terms) for terms in self.term_counts]

    @classmethod
    def from_file(cls, path: Path) -> "SimilarityIndex":
        rows = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else []
        return cls([row for row in rows if isinstance(row, dict) and row.get("prompt")])

    def _vector(self, terms: Counter[str]) -> dict[str, float]:
        return {term: (1 + math.log(frequency)) * self.idf.get(term, 0.0)
                for term, frequency in terms.items() if term in self.idf}

    @staticmethod
    def _cosine(first: dict[str, float], second: dict[str, float]) -> float:
        if not first or not second:
            return 0.0
        dot = sum(value * second.get(term, 0.0) for term, value in first.items())
        first_norm = math.sqrt(sum(value * value for value in first.values()))
        second_norm = math.sqrt(sum(value * value for value in second.values()))
        return dot / (first_norm * second_norm) if first_norm and second_norm else 0.0

    def score(self, text: str) -> tuple[float, str]:
        if not self.examples:
            return 0.0, ""
        vector = self._vector(Counter(_tokens(text)))
        best_score, best_id = 0.0, ""
        for row, example in zip(self.vectors, self.examples):
            score = self._cosine(vector, row)
            if score > best_score:
                best_score, best_id = score, example.get("id", "")
        return best_score, best_id


@lru_cache(maxsize=1)
def default_index() -> SimilarityIndex:
    configured = os.getenv("SENTINELLOOP_ATTACK_INDEX")
    if configured:
        return SimilarityIndex.from_file(Path(configured))
    train_path = Path(__file__).resolve().parents[2] / "evaluation" / "train" / "attacks.json"
    return SimilarityIndex.from_file(train_path)
