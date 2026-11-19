"""L4 Tool policy: decide whether a tool call may run.

Detection can fail, so SentinelLoop also limits what a hijacked assistant is
*able* to do. Every tool call is checked for:

* **allowlist** - only known sandbox tools exist;
* **argument shape** - exact argument names, short strings, sandbox IDs only;
* **destination** - email may only go to the organisation's own domain;
* **provenance** - a side-effect tool (send email, add event) only runs when the
  *user* asked for it, never because a retrieved document said so;
* **approval** - side effects also need explicit approval from the user.

Provenance is tracked by the agent: it knows whether an instruction came from
the user's message or from an email/file/web page (simple taint tracking).
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    verdict: str
    reason: str
    tool_name: str


class ToolPolicy:
    """Validate tool names, argument shapes, provenance, and approval state."""

    def __init__(self, policy_path: Path | None = None) -> None:
        path = policy_path or Path(__file__).with_name("tool_policy.json")
        self.config = json.loads(path.read_text(encoding="utf-8-sig"))
        self.read_only = set(self.config["read_only_tools"])
        self.approval_required = set(self.config["approval_required_tools"])
        self.domains = set(self.config["email_domain_allowlist"])
        self.max_length = int(self.config["max_string_length"])

    def authorize(
        self,
        tool_name: str,
        arguments: dict[str, Any] | str,
        provenance: str = "untrusted",
        approval_granted: bool = False,
    ) -> PolicyDecision:
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                return PolicyDecision("block", "tool arguments are not valid JSON", tool_name)
        if not isinstance(arguments, dict):
            return PolicyDecision("block", "tool arguments must be a JSON object", tool_name)
        allowed_names = self.read_only | self.approval_required
        if tool_name not in allowed_names:
            return PolicyDecision("block", "tool is not in the sandbox allowlist", tool_name)
        if any(not isinstance(value, str) or len(value) > self.max_length for value in arguments.values()):
            return PolicyDecision("block", "tool arguments must be short strings", tool_name)
        required = {
            "read_email": {"email_id"},
            "search_files": {"query"},
            "calendar_view": set(),
            "browse": {"url"},
            "calendar_add": {"title", "time"},
            "send_email": {"to", "subject", "body"},
        }[tool_name]
        if set(arguments) != required:
            return PolicyDecision(
                "block",
                f"expected exactly these arguments: {', '.join(sorted(required))}",
                tool_name,
            )
        if tool_name == "read_email" and not arguments["email_id"].startswith("email-"):
            return PolicyDecision("block", "email_id is outside the fake sandbox namespace", tool_name)
        if tool_name == "send_email":
            recipient = arguments["to"].rsplit("@", 1)
            if len(recipient) != 2 or recipient[1].lower() not in self.domains:
                return PolicyDecision(
                    "block", "recipient is outside the fake email domain allowlist", tool_name
                )
        if tool_name in self.approval_required:
            if provenance != "trusted_user":
                return PolicyDecision(
                    "block", "side-effect tool was requested from untrusted provenance", tool_name
                )
            if not approval_granted:
                return PolicyDecision("block", "explicit trusted user approval is required", tool_name)
        return PolicyDecision("allow", "tool name and arguments satisfy sandbox policy", tool_name)
