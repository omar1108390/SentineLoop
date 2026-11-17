from firewall.layers.output_guard import guard_output
from firewall.policies.tool_policy import ToolPolicy
from target_app.agent import CANARY_TOKEN, FAKE_SECRET


def test_output_guard_redacts_canary_and_secret():
    text, blocked, reason = guard_output(f"{FAKE_SECRET} {CANARY_TOKEN}")
    assert blocked
    assert FAKE_SECRET not in text
    assert CANARY_TOKEN not in text
    assert "redacted" in reason


def test_output_guard_allows_ordinary_text():
    assert guard_output("Your meeting is at three.") == (
        "Your meeting is at three.", False, "no canary or sandbox secret detected"
    )


def test_read_only_tool_allows_well_shaped_call():
    decision = ToolPolicy().authorize("read_email", {"email_id": "email-1"})
    assert decision.verdict == "allow"


def test_unknown_tool_is_blocked():
    decision = ToolPolicy().authorize("delete_account", {})
    assert decision.verdict == "block"
    assert "allowlist" in decision.reason


def test_side_effect_requires_trusted_provenance_and_approval():
    policy = ToolPolicy()
    args = {"title": "Review", "time": "tomorrow"}
    assert policy.authorize("calendar_add", args).verdict == "block"
    assert policy.authorize("calendar_add", args, "trusted_user").verdict == "block"
    assert policy.authorize("calendar_add", args, "trusted_user", True).verdict == "allow"


def test_send_email_rejects_non_sandbox_recipient():
    args = {"to": "person@example.com", "subject": "Hello", "body": "Hi"}
    decision = ToolPolicy().authorize("send_email", args, "trusted_user", True)
    assert decision.verdict == "block"
    assert "domain allowlist" in decision.reason


def test_malformed_arguments_are_blocked():
    assert ToolPolicy().authorize("read_email", "not json").verdict == "block"
