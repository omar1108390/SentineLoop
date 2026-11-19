"""L3 Quarantine: the "dual-LLM" pattern for untrusted documents.

Detectors guess whether text is malicious. Quarantine does not guess: it changes
the *architecture* so that untrusted text can never act as an instruction.

In a real system a second, tool-less model reads the document and returns only
structured data; the privileged model that can call tools never sees the raw
text. In the sandbox the privileged agent simply never interprets quarantined
documents as instructions, and this function plays the tool-less reader: it
returns a data-only rendering with imperative sentences aimed at the assistant
replaced by ``[instruction removed]``.

Limitation: quarantine stops hijacking, but it cannot make a misleading
document truthful. A phishing email is still summarised as a phishing email.
"""

from __future__ import annotations

import re

from .normalizer import normalize_report

INSTRUCTION_HINTS = re.compile(
    r"\b(?:ignore|disregard|forget|override|assistant|ai\b|you must|you should|reply|respond|"
    r"say|send|forward|email|add|create|schedule|include|render|embed|reveal|print|output|"
    r"repeat|show|tell|system|instructions?|decode|execute|follow)\b",
    re.IGNORECASE,
)


def quarantine(text: str) -> str:
    _, notes = normalize_report(text)
    visible = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    visible = re.sub(r"<[^>]+>", " ", visible)
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", visible) if part.strip()]
    kept: list[str] = []
    removed = 0
    for sentence in sentences:
        if INSTRUCTION_HINTS.search(sentence):
            removed += 1
            continue
        kept.append(sentence)
    summary = " ".join(kept) if kept else "(no plain data content)"
    if removed:
        summary += f" [{removed} instruction{'s' if removed != 1 else ''} removed]"
    if notes:
        summary += " [hidden content stripped]"
    return summary
