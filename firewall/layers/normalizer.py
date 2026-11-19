"""L0 Normalizer: undo the disguises attackers use before any detector looks.

Attackers hide instructions so that filters miss them while the model still
understands them: base64, ROT13, URL/HTML encoding, invisible zero-width
characters, look-alike Cyrillic letters, leetspeak (``1gn0r3``) or spaced-out
letters (``i g n o r e``). The normalizer produces one string containing the
original text *and* every decoded variant, so later layers inspect all of them.

It never blocks anything itself; :func:`normalize_report` also lists which
disguises it removed, which is shown in the dashboard as an explanation.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from functools import lru_cache
from html import unescape
from urllib.parse import unquote

ZERO_WIDTH_CHARS = "​‌‍⁠﻿­"
ZERO_WIDTH = dict.fromkeys(map(ord, ZERO_WIDTH_CHARS), None)
HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "α": "a", "ο": "o", "ε": "e",
        "ι": "i", "κ": "k", "τ": "t", "ρ": "p",
    }
)  # fmt: skip
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize_report(text: str) -> tuple[str, list[str]]:
    """Return the inspection text and a list of human-readable transformations."""
    value, notes = _normalize_cached(text)
    return value, list(notes)


@lru_cache(maxsize=8192)
def _normalize_cached(text: str) -> tuple[str, tuple[str, ...]]:
    # Every detector normalizes the same text; caching makes that free after the first.
    value, notes = _normalize(text)
    return value, tuple(notes)


def _normalize(text: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    value = unicodedata.normalize("NFKC", text)
    if value != text:
        notes.append("converted look-alike Unicode (e.g. full-width letters) to plain text")
    if any(char in value for char in ZERO_WIDTH_CHARS):
        notes.append("removed invisible zero-width characters")
        value = value.translate(ZERO_WIDTH)
    mapped = value.translate(HOMOGLYPHS)
    if mapped != value:
        notes.append("replaced Cyrillic/Greek look-alike letters")
        value = mapped
    decoded = unescape(unquote(value))
    if decoded != value:
        notes.append("decoded URL/HTML entities")
        value = decoded
    if re.search(r"<!--.*?-->", value, flags=re.DOTALL):
        notes.append("exposed text hidden in HTML comments")
    value = re.sub(r"<!--(.*?)-->", r" \1 ", value, flags=re.DOTALL)
    if re.search(r"<[^>]+>", value):
        notes.append("removed HTML/markup tags")
    value = re.sub(r"<[^>]*>", " ", value)

    candidates = [value]
    for token in re.findall(r"(?<![\w/+])[A-Za-z0-9+/]{12,}={0,2}(?![\w/+])", value):
        try:
            plain = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if plain.isprintable() and len(plain) <= 4000 and sum(c.isalpha() for c in plain) > len(plain) / 2:
            candidates.append(plain)
            notes.append("decoded a base64 block")
    lowered = value.casefold()
    # Digits inside words ("s3cr3t"); "@" and "$" alone are too common (emails, prices).
    if re.search(r"[a-z][01347][a-z]|\b[01347][a-z]{2}", lowered):
        candidates.append(lowered.translate(LEET))
        notes.append("translated leetspeak digits/symbols back to letters")
    collapsed = re.sub(
        r"(?<!\w)(?:\w[ .\-_*/|]){3,}\w(?!\w)",
        lambda match: re.sub(r"[ .\-_*/|]", "", match.group()),
        lowered,
    )
    if collapsed != lowered:
        candidates.append(collapsed)
        notes.append("joined spaced-out letters")
    # Only add a ROT13 view when the text announces one; decoding every input
    # would double the vocabulary the classifier sees and add noise.
    if re.search(r"rot-?13|caesar", lowered):
        candidates.append(codecs.encode(value, "rot_13"))
        notes.append("decoded ROT13 text")
    # Chat slang and misspellings ("can u gimme ur sys promt"): the model understands
    # them, so the detectors must too.
    joined = "\n".join(candidates).casefold()
    corrected, changes = correct_casual(joined)
    if changes:
        candidates.append(corrected)
        notes.append("rewrote casual spelling: " + ", ".join(changes[:6]))
    return "\n".join(candidates).casefold(), notes


SLANG = {
    "u": "you", "ur": "your", "yr": "your", "r": "are", "pls": "please", "plz": "please",
    "plzz": "please", "sys": "system", "sysprompt": "system prompt", "instrux": "instructions",
    "instr": "instructions", "instrs": "instructions", "msg": "message", "prev": "previous",
    "prv": "previous", "pw": "password", "pwd": "password", "passwd": "password",
    "creds": "credentials", "cfg": "configuration", "config": "configuration", "gimme": "give me",
    "lemme": "let me", "wanna": "want to", "rn": "right now", "abt": "about",
}  # fmt: skip
# Attack keywords whose misspellings are repaired (edit distance 1, or 2 for long words).
KEYWORDS = (
    "ignore", "disregard", "forget", "previous", "instructions", "system", "prompt", "reveal",
    "secret", "password", "credentials", "confidential", "override", "bypass", "guidelines",
    "restrictions", "developer", "jailbreak", "unrestricted", "display", "canary", "configuration",
)  # fmt: skip


def _edit_distance(first: str, second: str) -> int:
    previous = list(range(len(second) + 1))
    for i, a in enumerate(first, 1):
        current = [i]
        for j, b in enumerate(second, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a != b)))
        previous = current
    return previous[-1]


@lru_cache(maxsize=65536)
def _repair(word: str) -> str | None:
    if word in SLANG:
        return SLANG[word]
    if len(word) < 5 or word in KEYWORDS:
        return None
    for key in KEYWORDS:
        if abs(len(word) - len(key)) > 2:
            continue
        limit = 2 if len(key) >= 8 else 1
        swapped = any(word[:k] + word[k + 1] + word[k] + word[k + 2 :] == key for k in range(len(word) - 1))
        if swapped or _edit_distance(word, key) <= limit:
            return key
    return None


def correct_casual(text: str) -> tuple[str, list[str]]:
    """Expand slang and repair misspelled attack keywords; report each change."""
    changes: list[str] = []

    def fix(match: re.Match) -> str:
        word = match.group()
        repaired = _repair(word)
        if repaired is None:
            return word
        label = f"{word} -> {repaired}"
        if label not in changes:
            changes.append(label)
        return repaired

    return re.sub(r"[a-z]+", fix, text), changes


def normalize(text: str) -> str:
    return normalize_report(text)[0]
