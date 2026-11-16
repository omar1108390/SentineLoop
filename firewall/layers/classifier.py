"""Small transparent rule classifier; intentionally not presented as a model."""

import re

from .normalizer import normalize

PATTERNS = (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"reveal\s+(your\s+|the\s+)?(secret|system prompt|canary)",
    r"(send|email)\s+(it|the secret|the information)\s+to\s+",
    r"new instruction\s*[:：]",
    r"unrestricted assistant",
)


def classify(text: str) -> tuple[bool, float, str]:
    normalized = normalize(text)
    for pattern in PATTERNS:
        if re.search(pattern, normalized):
            return True, 0.95, f"matched injection rule: {pattern}"
    return False, 0.0, "no injection rule matched"
