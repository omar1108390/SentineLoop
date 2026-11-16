"""Layer 5: redact demo secrets and canaries if they appear in output."""

from target_app.agent import CANARY_TOKEN, FAKE_SECRET


def guard_output(text: str) -> tuple[str, bool, str]:
    leaked = CANARY_TOKEN in text or FAKE_SECRET in text
    if leaked:
        filtered = text.replace(CANARY_TOKEN, "[REDACTED]").replace(FAKE_SECRET, "[REDACTED]")
        return filtered, True, "sandbox secret or canary redacted"
    return text, False, "no canary or sandbox secret detected"
