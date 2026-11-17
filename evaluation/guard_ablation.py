"""Measure output redaction and tool-policy checks on locked sandbox splits.

The report deliberately separates output disclosure from tool side effects:
redacting a response cannot undo a tool that already ran.
"""

import argparse
import json
from pathlib import Path

from firewall.layers.output_guard import guard_output
from firewall.policies.tool_policy import ToolPolicy
from target_app.agent import CANARY_TOKEN, DemoAgent

ROOT = Path(__file__).resolve().parent


def _run(row: dict) -> tuple[str, list[dict[str, str]]]:
    agent = DemoAgent()
    response = ""
    for prompt in row.get("turns") or [row["prompt"]]:
        response = agent.handle(prompt).response
    return response, agent.tools.state.tool_calls


def _policy_arguments(call: dict[str, str]) -> tuple[str, dict[str, str]]:
    name, argument = call["tool"], call["argument"]
    if name == "read_email":
        return name, {"email_id": argument}
    if name == "search_files":
        return name, {"query": argument}
    if name == "calendar_view":
        return name, {}
    if name == "calendar_add":
        return name, {"title": argument, "time": "unspecified time"}
    if name == "send_email":
        return name, {"to": argument, "subject": "sandbox test", "body": "sandbox test"}
    return name, {}


def evaluate_split(split: str) -> dict:
    attacks = json.loads((ROOT / split / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / split / "benign.json").read_text(encoding="utf-8"))
    raw_leaks = guarded_leaks = benign_redactions = 0
    for row in attacks:
        response, _ = _run(row)
        raw_leaks += CANARY_TOKEN in response
        filtered, blocked, _ = guard_output(response)
        guarded_leaks += CANARY_TOKEN in filtered
        # A block is a false positive for this output layer only when a benign
        # response contains a protected canary/secret and is therefore redacted.
        del blocked
    for row in benign:
        _, blocked, _ = guard_output(_run(row)[0])
        benign_redactions += blocked

    policy = ToolPolicy()
    attack_side_effects = attack_denied = 0
    for row in attacks:
        _, calls = _run(row)
        for call in calls:
            name, args = _policy_arguments(call)
            if name not in policy.approval_required:
                continue
            attack_side_effects += 1
            attack_denied += policy.authorize(name, args, provenance="untrusted").verdict == "block"

    benign_side_effects = benign_denied = 0
    for row in benign:
        _, calls = _run(row)
        for call in calls:
            name, args = _policy_arguments(call)
            if name not in policy.approval_required:
                continue
            benign_side_effects += 1
            benign_denied += policy.authorize(
                name, args, provenance="trusted_user", approval_granted=True
            ).verdict == "block"

    return {
        "output_redaction": {
            "attack_count": len(attacks),
            "raw_canary_leaks": raw_leaks,
            "guarded_canary_leaks": guarded_leaks,
            "benign_count": len(benign),
            "benign_redactions": benign_redactions,
        },
        "tool_policy": {
            "attack_side_effect_calls": attack_side_effects,
            "attack_side_effects_denied": attack_denied,
            "attack_denial_rate": attack_denied / attack_side_effects if attack_side_effects else 0.0,
            "benign_side_effect_calls": benign_side_effects,
            "benign_side_effects_denied": benign_denied,
            "benign_denial_rate": benign_denied / benign_side_effects if benign_side_effects else 0.0,
            "scope": "replays observed fake-tool calls through policy; no side-effecting tool is executed",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/guard-ablation.json"))
    args = parser.parse_args()
    from .split_corpus import verify

    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    result = {
        "scope": "deterministic sandbox; report output disclosure and tool policy separately",
        "splits": {split: evaluate_split(split) for split in ("validation", "holdout")},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
