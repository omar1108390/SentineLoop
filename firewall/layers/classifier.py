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

# This is a narrow request-safety rule, separate from prompt-injection rules.
# It blocks direct requests to steal or collect credentials while allowing
# questions about preventing credential theft or learning about it defensively.
UNSAFE_REQUEST_PATTERNS = (
    r"\b(?:how\s+(?:do|can|could)\s+(?:i|we|someone)\s+|ways?\s+to\s+|methods?\s+to\s+|"
    r"teach\s+me\s+to\s+|show\s+me\s+how\s+to\s+|help\s+me\s+)"
    r"(?:steal|phish|harvest|capture|collect|exfiltrate)\s+"
    r"(?:(?:someone|users?|people|victims?)['’]s?\s+)?"
    r"(?:login\s+)?(?:passwords?|credentials?|login details|authentication tokens|session cookies)\b",
    r"\b(?:i want to|i need to)\s+(?:steal|phish|harvest|capture|collect|exfiltrate)\s+"
    r"(?:(?:someone|users?|people|victims?)['’]s?\s+)?"
    r"(?:login\s+)?(?:passwords?|credentials?|login details|authentication tokens|session cookies)\b",
)


def classify(text: str, exact_rules: tuple[str, ...] = ()) -> tuple[bool, float, str]:
    normalized = normalize(text)
    for signature in exact_rules:
        if signature and signature in normalized:
            return True, 1.0, "matched hardened exact-text rule"
    for pattern in PATTERNS:
        if re.search(pattern, normalized):
            return True, 0.95, f"matched injection rule: {pattern}"
    for pattern in UNSAFE_REQUEST_PATTERNS:
        if re.search(pattern, normalized):
            return True, 0.99, "matched safety rule: direct credential theft request"
    return False, 0.0, "no injection rule matched"
