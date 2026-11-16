"""Layer 5: redact the sandbox canary if it appears in output."""

from target_app.agent import CANARY_TOKEN


def guard_output(text: str) -> tuple[str, bool, str]:
    if CANARY_TOKEN in text:
        return text.replace(CANARY_TOKEN, "[REDACTED]"), True, "canary token redacted"
    return text, False, "no canary detected"
