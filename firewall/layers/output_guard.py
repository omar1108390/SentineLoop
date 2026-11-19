"""L5 Output guard: check the model's answer before the user (or a browser) sees it.

Even if an injection gets past every input check, the damage usually shows up
in the output: a leaked secret, the hidden system prompt, or a markdown image
whose URL smuggles data to an attacker's server the moment it is rendered.
The guard redacts those and reports what it removed. It cannot undo a tool call
that already ran; that is the tool policy's job.
"""

from __future__ import annotations

import re

from target_app.agent import CANARY_TOKEN, FAKE_SECRET, SYSTEM_PROMPT, SYSTEM_PROMPT_MARKER

from .normalizer import normalize

TRUSTED_LINK_DOMAIN = "example.test"
OUTSIDE_IMAGE = re.compile(
    r"!\[[^\]]*\]\((?:https?://)(?![\w.-]*" + re.escape(TRUSTED_LINK_DOMAIN) + r"\b)[^)]*\)",
    re.IGNORECASE,
)


def guard_output_report(text: str) -> tuple[str, list[str]]:
    findings: list[str] = []
    filtered = text
    if SYSTEM_PROMPT in filtered or SYSTEM_PROMPT_MARKER.casefold() in filtered.casefold():
        filtered = filtered.replace(SYSTEM_PROMPT, "[REDACTED SYSTEM PROMPT]")
        filtered = re.sub(re.escape(SYSTEM_PROMPT_MARKER), "[REDACTED]", filtered, flags=re.I)
        findings.append("system prompt text redacted")
    if CANARY_TOKEN in filtered:
        filtered = filtered.replace(CANARY_TOKEN, "[REDACTED]")
        findings.append("canary token redacted")
    if FAKE_SECRET in filtered:
        filtered = filtered.replace(FAKE_SECRET, "[REDACTED]")
        findings.append("secret redacted")
    if OUTSIDE_IMAGE.search(filtered):
        filtered = OUTSIDE_IMAGE.sub("[external image removed]", filtered)
        findings.append("markdown image to an outside domain removed (possible data exfiltration)")
    # Attackers ask for the secret base64-encoded or with spaces between letters.
    # Run the L0 normalizer on the answer to catch those disguises too.
    normalized = _alnum(normalize(filtered))
    if any(_alnum(token) in normalized for token in (FAKE_SECRET, CANARY_TOKEN)):
        filtered = "[Response withheld by SentinelLoop: it contained an encoded secret.]"
        findings.append("encoded secret detected after normalization; response withheld")
    return filtered, findings


def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def guard_output(text: str) -> tuple[str, bool, str]:
    """Backwards-compatible summary: (filtered_text, blocked, reason)."""
    filtered, findings = guard_output_report(text)
    if findings:
        return filtered, True, "; ".join(findings)
    return text, False, "no secret, canary, system prompt or exfiltration link detected"
