"""L2 Similarity search: "have we seen an attack like this before?"

Every known training attack is turned into a TF-IDF vector of words and word
pairs. New text is compared with all of them using cosine similarity; if it is
close enough to a known attack it is flagged. This catches light rewordings of
past attacks but not genuinely new ones. The index is built from the training
split only, so evaluation on the holdout split stays honest.
"""

import json
import math
import os
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .normalizer import normalize

# Filler words carry no signal; without this, "tell me a joke" looks like
# "tell me the password" simply because both start with "tell me".
STOPWORDS = frozenset(
    "a an the and or but if of to in on at by for with from as is are was were be been it its "
    "this that these those me my you your i we our us he she they them please can could would "
    "will do does did so then than now just also very what how why when where which who tell give".split()
)


def _line_tokens(line: str) -> list[str]:
    words = [word for word in re.findall(r"[a-z0-9]{2,}", line) if word not in STOPWORDS]
    bigrams = [f"{left}_{right}" for left, right in zip(words, words[1:])]
    return words + bigrams


def _tokens(text: str) -> list[str]:
    return _line_tokens(normalize(text))


def _views(text: str) -> list[list[str]]:
    """Token lists for each normalized view (original, decoded, slang-corrected...).

    Comparing views separately means "reveal ur sys promt" is matched through its
    corrected view "reveal your system prompt" without the raw misspellings diluting
    the score. Lines with fewer than three content words are ignored.
    """
    found: list[list[str]] = []
    for line in dict.fromkeys(normalize(text).splitlines()):
        tokens = _line_tokens(line)
        if len(set(tokens)) >= 3:
            found.append(tokens)
    return found


def attacker_texts(row: dict) -> list[str]:
    """The attacker-controlled text of a corpus row.

    For indirect attacks the user's request is benign ("summarize my email");
    only the planted document is malicious, so only it is used.
    """
    if row.get("channel", "direct") != "direct":
        return [row["prompt"]]
    return list(row.get("turns") or [row["prompt"]])


class SimilarityIndex:
    def __init__(self, examples: list[dict[str, str]]) -> None:
        self.examples = []
        self.term_counts: list[Counter[str]] = []
        for row in examples:
            for index, turn in enumerate(attacker_texts(row)):
                # One entry per normalized view; fragments such as `y = "prompt"` have
                # too few words to compare meaningfully and are skipped.
                for tokens in _views(turn):
                    self.examples.append({"id": f"{row.get('id', 'attack')}-turn-{index}", "prompt": turn})
                    self.term_counts.append(Counter(tokens))
        document_frequency: Counter[str] = Counter()
        for terms in self.term_counts:
            document_frequency.update(terms.keys())
        count = max(1, len(self.examples))
        self.idf = {
            term: math.log((count + 1) / (frequency + 1)) + 1
            for term, frequency in document_frequency.items()
        }
        # Words never seen in an attack are rare and informative: they must still
        # count towards the query's length, otherwise "what is prompt injection"
        # collapses to just "prompt" and looks identical to an attack fragment.
        self.unseen_idf = math.log(count + 1) + 1
        self.vectors = [self._vector(terms) for terms in self.term_counts]
        self.norms = [math.sqrt(sum(v * v for v in vector.values())) for vector in self.vectors]

    @classmethod
    def from_file(cls, path: Path) -> "SimilarityIndex":
        rows = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else []
        return cls([row for row in rows if isinstance(row, dict) and row.get("prompt")])

    def _vector(self, terms: Counter[str]) -> dict[str, float]:
        return {
            term: (1 + math.log(frequency)) * self.idf.get(term, self.unseen_idf)
            for term, frequency in terms.items()
        }

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
        best_score, best_id = 0.0, ""
        for tokens in _views(text):
            vector = self._vector(Counter(tokens))
            query_norm = math.sqrt(sum(value * value for value in vector.values()))
            if not query_norm:
                continue
            for row, norm, example in zip(self.vectors, self.norms, self.examples):
                if not norm:
                    continue
                dot = sum(value * row.get(term, 0.0) for term, value in vector.items())
                score = dot / (query_norm * norm)
                if score > best_score:
                    best_score, best_id = score, example.get("id", "")
        return min(best_score, 1.0), best_id


@lru_cache(maxsize=1)
def default_index() -> SimilarityIndex:
    configured = os.getenv("SENTINELLOOP_ATTACK_INDEX")
    if configured:
        return SimilarityIndex.from_file(Path(configured))
    # The hardening loop promotes training attacks + discovered bypasses here.
    promoted = Path(__file__).resolve().parents[1] / "models" / "attack_index.json"
    if promoted.is_file():
        return SimilarityIndex.from_file(promoted)
    train_path = Path(__file__).resolve().parents[2] / "evaluation" / "train" / "attacks.json"
    return SimilarityIndex.from_file(train_path)
