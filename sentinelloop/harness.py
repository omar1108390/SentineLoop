"""Run one scenario against the sandbox agent with a chosen set of defenses.

This is the single place where the target, the firewall layers and the judge
are wired together. The fuzzer, the search algorithms, the hardening loop, the
evaluation scripts and the dashboard's Attack Lab all call :func:`run_scenario`,
so every number in the project is produced the same way.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any

from firewall import DETECTORS, Firewall, Inspection
from firewall.layers.quarantine import quarantine as quarantine_document
from firewall.policies.tool_policy import ToolPolicy
from target_app.agent import DemoAgent
from target_app.interpreter import all_goals
from target_app.judge import ObjectiveJudge
from target_app.tools import FakeTools, SandboxState

from .corpus import Attack

BLOCK_MESSAGE = "Request blocked by SentinelLoop: this message looks like a prompt injection."


@dataclass(frozen=True)
class Defenses:
    """Which layers are switched on. Detectors run on user input and/or documents."""

    detectors: frozenset[str] = field(default_factory=lambda: frozenset(DETECTORS))
    input_filter: bool = True
    content_filter: bool = True
    quarantine: bool = True
    tool_policy: bool = True
    output_guard: bool = True

    def describe(self) -> dict[str, Any]:
        value = asdict(self)
        value["detectors"] = sorted(self.detectors)
        return value

    @classmethod
    def from_layers(cls, layers: list[str] | set[str] | tuple[str, ...]) -> "Defenses":
        """Build from a flat list such as ``["rules", "classifier", "output_guard"]``."""
        chosen = set(layers)
        detectors = frozenset(chosen & set(DETECTORS))
        return cls(
            detectors=detectors,
            input_filter=bool(detectors),
            content_filter=bool(detectors),
            quarantine="quarantine" in chosen,
            tool_policy="tool_policy" in chosen,
            output_guard="output_guard" in chosen,
        )

    def layers(self) -> list[str]:
        names = sorted(self.detectors, key=DETECTORS.index)
        for name in ("quarantine", "tool_policy", "output_guard"):
            if getattr(self, name):
                names.append(name)
        return names


NO_DEFENSE = Defenses(frozenset(), False, False, False, False, False)
PROFILES: dict[str, Defenses] = {
    "none": NO_DEFENSE,
    "keyword": Defenses(frozenset({"rules"}), True, True, False, False, False),
    "detectors": Defenses(frozenset(DETECTORS), True, True, False, False, False),
    "full": Defenses(),
}
PROFILE_DESCRIPTIONS = {
    "none": "No protection: the vulnerable assistant on its own.",
    "keyword": "Only the signature rules, like a simple keyword blocklist.",
    "detectors": "All detectors (rules + ML classifier + similarity) on input and documents.",
    "full": "Detectors plus architectural controls: quarantine, tool policy and output guard.",
}


def _inspection(item: Inspection | None) -> dict[str, Any] | None:
    if item is None:
        return None
    value = asdict(item)
    value["details"] = [dict(detail) for detail in value["details"]]
    return value


def make_firewall(defenses: Defenses, firewall: Firewall | None = None) -> Firewall | None:
    if not (defenses.input_filter or defenses.content_filter or defenses.output_guard):
        return None
    if firewall is None:
        return Firewall(detectors=defenses.detectors)
    if firewall.detectors == defenses.detectors:
        return firewall
    clone = Firewall(
        similarity_index=firewall.similarity_index,
        threshold=firewall.similarity_threshold,
        injection_model=firewall.injection_model,
        detectors=defenses.detectors,
    )
    clone.exact_rules = firewall.exact_rules
    return clone


def run_scenario(
    attack: Attack,
    defenses: Defenses | str = "full",
    firewall: Firewall | None = None,
    policy: ToolPolicy | None = None,
) -> dict[str, Any]:
    """Plant the attack (if indirect), send the user turns, judge the outcome."""
    if isinstance(defenses, str):
        defenses = PROFILES[defenses]
    started = perf_counter()
    firewall = make_firewall(defenses, firewall)
    policy = policy or (ToolPolicy() if defenses.tool_policy else None)
    judge = ObjectiveJudge()

    state = SandboxState()
    if attack.indirect:
        meta = {"title": attack.title} if attack.title else {}
        state.plant(attack.channel, attack.prompt, **meta)
    agent = DemoAgent(FakeTools(state))

    transcript: list[dict[str, Any]] = []
    stopped_by: list[str] = []
    outcome = None
    for turn in attack.user_turns():
        entry: dict[str, Any] = {"user": turn, "input_check": None, "documents": []}
        calls_before = len(state.tool_calls)
        blocked_before = len(state.blocked_tool_calls)
        if firewall is not None and defenses.input_filter:
            check = firewall.inspect_input(turn)
            entry["input_check"] = _inspection(check)
            if check.verdict == "block":
                stopped_by.append(check.layer)
                entry.update(response=BLOCK_MESSAGE, raw_response="", output_check=None,
                             tool_calls=[], blocked_tool_calls=[], refused=False)  # fmt: skip
                transcript.append(entry)
                outcome = judge.evaluate(BLOCK_MESSAGE, state, blocked=True)
                break

        document_checks: list[Inspection] = []

        def content_guard(text: str) -> bool:
            check = firewall.inspect_untrusted(text)
            document_checks.append(check)
            return check.verdict != "block"

        def tool_gate(tool: str, args: dict[str, str], provenance: str) -> tuple[bool, str]:
            decision = policy.authorize(
                tool, args, provenance=provenance, approval_granted=provenance == "trusted_user"
            )
            return decision.verdict == "allow", decision.reason

        result = agent.handle(
            turn,
            content_guard=content_guard if firewall is not None and defenses.content_filter else None,
            quarantine=quarantine_document if defenses.quarantine else None,
            tool_gate=tool_gate if policy is not None else None,
        )
        checks = iter(document_checks)
        planted = {doc["id"]: doc for doc in state.emails + state.files + state.web_pages}
        for document in result.documents:
            record = dict(document)
            if firewall is not None and defenses.content_filter:
                check = next(checks, None)
                record["check"] = _inspection(check)
                if check is not None and check.verdict == "block":
                    stopped_by.append(check.layer)
            if document["status"] == "quarantined":
                source = planted.get(document["id"], {}).get("body", "")
                neutralised = len(all_goals(source))
                record["neutralised_instructions"] = neutralised
                if neutralised:
                    stopped_by.append("quarantine")
            entry["documents"].append(record)

        response = result.response
        output_check = None
        if firewall is not None and defenses.output_guard:
            response, output_check = firewall.inspect_output(response)
            if output_check.verdict == "block":
                stopped_by.append("output_guard")
        new_blocked = state.blocked_tool_calls[blocked_before:]
        if new_blocked:
            stopped_by.append("tool_policy")
        entry.update(
            response=response,
            raw_response=result.response,
            output_check=_inspection(output_check),
            tool_calls=state.tool_calls[calls_before:],
            blocked_tool_calls=new_blocked,
            refused=result.refused,
            task=result.task,
        )
        transcript.append(entry)
        outcome = judge.evaluate(response, state, refused=result.refused, hijacked_by=result.hijacked_by)
        if outcome.label == "breach":
            break

    if outcome is None:  # pragma: no cover - every attack has at least one turn
        outcome = judge.evaluate("", state)
    return {
        "id": attack.id,
        "family": attack.family,
        "technique": attack.technique,
        "channel": attack.channel,
        "parent": attack.parent,
        "prompt": attack.prompt,
        "turns": list(attack.user_turns()),
        "outcome": outcome.label,
        "reason": outcome.reason,
        "signals": list(outcome.signals),
        "stopped_by": list(dict.fromkeys(stopped_by)),
        "defenses": defenses.layers(),
        "transcript": transcript,
        "tool_calls": list(state.tool_calls),
        "latency_ms": round((perf_counter() - started) * 1000, 4),
    }


def default_profile() -> str:
    value = os.getenv("SENTINELLOOP_DEFENSE_PROFILE", "full")
    return value if value in PROFILES else "full"
