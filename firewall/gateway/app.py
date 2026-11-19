"""SentinelLoop gateway: OpenAI-compatible firewall proxy, learning lab API and dashboard.

Endpoints (interactive docs at ``/docs``):

* ``POST /v1/chat/completions`` - OpenAI-compatible chat, protected by every layer.
  Responses carry an extra ``sentinelloop`` object explaining each decision.
* ``POST /v1/inspect``           - run the detectors on a text and explain the verdict.
* ``GET  /v1/lab/scenarios``     - the attack catalogue (families, examples).
* ``POST /v1/lab/run``           - run one attack against chosen defense profiles.
* ``POST /v1/fuzzer/quick``      - synchronous fuzzing of a seed or the whole corpus.
* ``POST /v1/fuzzer/runs``       - queue a background run (needs Redis + RQ worker).
* ``POST /v1/files/analyze``     - scan an uploaded document for hidden instructions.
* ``GET  /v1/events``, ``/v1/metrics``, ``/health``, ``/v1/models``.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from collections import Counter, deque
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from firewall import DETECTORS, LAYER_INFO, Firewall, Inspection
from firewall.gateway.event_store import default_store
from firewall.gateway.file_analysis import MAX_FILE_BYTES, analyze_bytes
from firewall.policies.tool_policy import ToolPolicy
from fuzzer.mutators import mutate
from sentinelloop import __version__
from sentinelloop.corpus import CHANNEL_LABELS, DEFAULT_REQUESTS, FAMILIES, Attack, load_seed_rows
from sentinelloop.harness import (
    PROFILE_DESCRIPTIONS,
    PROFILES,
    Defenses,
    default_profile,
    run_scenario,
)
from target_app.agent import SYSTEM_PROMPT


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = {"event": record.getMessage(), "timestamp": time.time()}
        for name in ("request_id", "layer", "verdict", "score", "latency_ms", "reason", "stage"):
            if hasattr(record, name):
                fields[name] = getattr(record, name)
        return json.dumps(fields, ensure_ascii=False)


logger = logging.getLogger("sentinelloop.gateway")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

ROOT = Path(__file__).resolve().parents[2]
events: deque[dict[str, Any]] = deque(maxlen=500)
app = FastAPI(
    title="SentinelLoop Gateway",
    version=__version__,
    description="Prompt-injection firewall, learning lab and red-team API (sandbox only).",
)
tool_policy = ToolPolicy()
_store = None


def event_store():
    global _store
    if _store is None:
        _store = default_store()
    return _store


# --------------------------------------------------------------------------- models
class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    messages: list[dict[str, Any]] = Field(min_length=1)
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False


class InspectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    detectors: list[str] | None = None


class LabRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000, description="attacker-controlled text")
    channel: Literal["direct", "email", "file", "web"] = "direct"
    turns: list[str] = Field(default_factory=list, max_length=6)
    title: str = Field(default="", max_length=120)
    profiles: list[str] = Field(default_factory=lambda: ["none", "full"], max_length=4)
    layers: list[str] | None = Field(default=None, description="custom set of enabled layers")


class QuickFuzzRequest(BaseModel):
    prompt: str | None = Field(default=None, max_length=4000)
    channel: Literal["direct", "email", "file", "web"] = "direct"
    family: str = Field(default="custom", max_length=32)
    profile: str = "full"


class FuzzerRunRequest(BaseModel):
    include_mutations: bool = True
    use_firewall: bool = True
    prompt: str | None = Field(default=None, max_length=4000)
    family: str = Field(default="custom", max_length=32)


# --------------------------------------------------------------------------- events
def _log_event(
    request_id: str, inspection: dict[str, Any] | Inspection, source: str, excerpt: str = ""
) -> dict[str, Any]:
    data = inspection if isinstance(inspection, dict) else Firewall.as_log(inspection)
    event = {
        "request_id": request_id,
        "layer": data["layer"],
        "verdict": data["verdict"],
        "score": float(data.get("score", 0.0)),
        "latency_ms": float(data.get("latency_ms", 0.0)),
        "reason": data["reason"],
        "stage": data.get("stage", "input"),
        "source": source,
        "excerpt": excerpt[:160],
        "timestamp": time.time(),
    }
    events.appendleft(event)
    try:
        event_store().append_event(event)
    except Exception:
        logger.exception("event_store_write_failed")
    logger.info(
        "firewall_decision",
        extra={key: value for key, value in event.items() if key not in {"timestamp", "excerpt"}},
    )
    return event


def _log_run(request_id: str, result: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """Persist every decision recorded in a harness transcript."""
    logged = []
    for turn in result["transcript"]:
        if turn.get("input_check"):
            logged.append(_log_event(request_id, turn["input_check"], source, turn["user"]))
        for document in turn.get("documents", []):
            if document.get("check"):
                logged.append(
                    _log_event(
                        request_id, document["check"], source, f"[{document['channel']}] {document['label']}"
                    )
                )
            if document.get("neutralised_instructions"):
                logged.append(
                    _log_event(
                        request_id,
                        {"layer": "quarantine", "verdict": "block", "score": 1.0, "stage": "document",
                         "reason": f"{document['neutralised_instructions']} instruction(s) in an "
                         "untrusted document were neutralised (treated as data only)"},  # fmt: skip
                        source,
                        f"[{document['channel']}] {document['label']}",
                    )
                )
        for call in turn.get("blocked_tool_calls", []):
            logged.append(
                _log_event(
                    request_id,
                    {"layer": "tool_policy", "verdict": "block", "score": 1.0, "stage": "tool",
                     "reason": f"{call['tool']} blocked: {call['reason']}"},  # fmt: skip
                    source,
                    f"{call['tool']} requested by {call['origin']}",
                )
            )
        if turn.get("output_check"):
            logged.append(_log_event(request_id, turn["output_check"], source, turn.get("raw_response", "")))
    return logged


# --------------------------------------------------------------------------- helpers
def _text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return ""


def _completion(model: str, text: str, finish_reason: str = "stop") -> dict[str, Any]:
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _stream_completion(result: dict[str, Any]) -> StreamingResponse:
    choice = result["choices"][0]
    content = choice.get("message", {}).get("content") or ""
    base = {
        "id": result.get("id", "chatcmpl-" + uuid.uuid4().hex),
        "object": "chat.completion.chunk",
        "created": result.get("created", int(time.time())),
        "model": result.get("model", "sentinelloop-sandbox"),
    }

    def stream():
        first = {**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]}
        yield "data: " + json.dumps(first, ensure_ascii=False) + "\n\n"
        if content:
            token = {**base, "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]}
            yield "data: " + json.dumps(token, ensure_ascii=False) + "\n\n"
        final = {
            **base,
            "choices": [{"index": 0, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}],
        }
        yield "data: " + json.dumps(final, ensure_ascii=False) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _upstream_request(payload: dict[str, Any], base_url: str, api_key: str | None) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    # Some edges (e.g. Groq's Cloudflare) reject urllib's default signature with 403/1010.
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SentinelLoop/0.2 (OpenAI-compatible client)",
    }
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    request = urllib.request.Request(url, json.dumps(payload).encode("utf-8"), headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:1000]
        raise HTTPException(status_code=502, detail=f"Upstream returned {error.code}: {detail}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {error}") from error


def _profile(name: str) -> Defenses:
    if name not in PROFILES:
        raise HTTPException(
            status_code=422, detail=f"unknown profile '{name}'; use one of {sorted(PROFILES)}"
        )
    return PROFILES[name]


def _layers(layers: list[str]) -> Defenses:
    known = set(DETECTORS) | {"quarantine", "tool_policy", "output_guard"}
    unknown = set(layers) - known
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown layers: {', '.join(sorted(unknown))}")
    return Defenses.from_layers(layers)


# --------------------------------------------------------------------------- pages
@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> str:
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "version": __version__,
        "backend": "upstream" if os.getenv("SENTINELLOOP_UPSTREAM_URL") else "sandbox",
        "defense_profile": default_profile(),
    }


@app.get("/v1/models")
def models() -> dict[str, Any]:
    upstream = os.getenv("SENTINELLOOP_UPSTREAM_URL")
    model = os.getenv("SENTINELLOOP_MODEL", "sentinelloop-sandbox") if upstream else "sentinelloop-sandbox"
    return {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "sentinelloop"}]}


# --------------------------------------------------------------------------- learning lab
@app.get("/v1/layers")
def layers() -> dict[str, Any]:
    """The defense layers and the named profiles that combine them."""
    return {
        "layers": [{"id": key, "code": code, "name": name} for key, (code, name) in LAYER_INFO.items()],
        "profiles": {
            name: {"description": PROFILE_DESCRIPTIONS[name], "layers": PROFILES[name].layers()}
            for name in PROFILES
        },
    }


@app.post("/v1/inspect")
def inspect_text(request: InspectRequest) -> dict[str, Any]:
    detectors = request.detectors if request.detectors is not None else list(DETECTORS)
    unknown = set(detectors) - set(DETECTORS)
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown detectors: {', '.join(sorted(unknown))}")
    firewall = Firewall(detectors=detectors)
    result = firewall.inspect_input(request.text)
    data = Firewall.as_log(result)
    data["details"] = [
        {**detail, "code": LAYER_INFO[detail["layer"]][0], "name": LAYER_INFO[detail["layer"]][1]}
        for detail in data["details"]
    ]
    _log_event(uuid.uuid4().hex, result, "inspect", request.text)
    return data


@app.get("/v1/lab/scenarios")
def lab_scenarios() -> dict[str, Any]:
    rows = load_seed_rows()
    return {
        "families": FAMILIES,
        "channels": CHANNEL_LABELS,
        "default_requests": DEFAULT_REQUESTS,
        "scenarios": [
            {
                "id": row["id"],
                "family": row["family"],
                "channel": row.get("channel", "direct"),
                "goal": row.get("goal", ""),
                "prompt": row["prompt"],
                "turns": row.get("turns", []),
                "title": row.get("title", ""),
            }
            for row in rows
        ],
    }


@app.post("/v1/lab/run")
def lab_run(request: LabRequest) -> dict[str, Any]:
    attack = Attack(
        request.prompt,
        "custom",
        turns=tuple(turn for turn in request.turns if turn.strip()),
        channel=request.channel,
        title=request.title,
    )
    configs: dict[str, Defenses] = {name: _profile(name) for name in request.profiles}
    if request.layers is not None:
        configs["custom"] = _layers(request.layers)
    request_id = uuid.uuid4().hex
    results = {}
    for name, defenses in configs.items():
        result = run_scenario(attack, defenses)
        result["profile"] = name
        if name != "none":
            _log_run(request_id, result, f"lab:{name}")
        results[name] = result
    return {"request_id": request_id, "user_turns": list(attack.user_turns()), "results": results}


@app.post("/v1/fuzzer/quick")
def quick_fuzz(request: QuickFuzzRequest) -> dict[str, Any]:
    """Run synchronously in-process: the sandbox is deterministic and fast (no Redis needed)."""
    defenses = _profile(request.profile)
    if request.prompt:
        seed = Attack(request.prompt, request.family, channel=request.channel, id="custom")
        attacks = [seed, *mutate(seed)]
    else:
        from fuzzer.runner import load_attacks

        attacks = load_attacks(True)
    started = time.perf_counter()
    results = [run_scenario(attack, defenses) for attack in attacks]
    families: dict[str, Counter] = {}
    for row in results:
        families.setdefault(row["family"], Counter())["attempts"] += 1
        families[row["family"]]["breaches"] += row["outcome"] == "breach"
    breaches = sum(row["outcome"] == "breach" for row in results)
    stopped = Counter(layer for row in results for layer in row["stopped_by"])
    attempts = [
        {
            "technique": row["technique"],
            "family": row["family"],
            "channel": row["channel"],
            "prompt": row["prompt"],
            "outcome": row["outcome"],
            "signals": row["signals"],
            "stopped_by": row["stopped_by"],
        }
        for row in results
    ]
    return {
        "profile": request.profile,
        "attempts": len(results),
        "breaches": breaches,
        "asr": breaches / len(results) if results else 0.0,
        "stopped_by": dict(stopped),
        "by_family": {
            family: {"attempts": counts["attempts"], "breaches": counts["breaches"],
                     "asr": counts["breaches"] / counts["attempts"]}  # fmt: skip
            for family, counts in sorted(families.items())
        },
        "results": (
            attempts if request.prompt else [row for row in attempts if row["outcome"] == "breach"][:50]
        ),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
    }


# --------------------------------------------------------------------------- queued fuzzer
def _job_queue():
    try:
        from redis import Redis
        from rq import Queue
    except ImportError as error:
        raise HTTPException(
            status_code=503, detail="Install the jobs extra to enable queued fuzzer runs"
        ) from error
    redis_url = os.getenv("SENTINELLOOP_REDIS_URL", "redis://localhost:6379/0")
    try:
        connection = Redis.from_url(redis_url, socket_connect_timeout=2)
        connection.ping()
    except Exception as error:
        raise HTTPException(status_code=503, detail="Fuzzer job queue is unavailable") from error
    return Queue("fuzzer", connection=connection, default_timeout=3600)


@app.post("/v1/fuzzer/runs", status_code=202)
def submit_fuzzer_run(request: FuzzerRunRequest) -> dict[str, str]:
    queue = _job_queue()
    job = queue.enqueue(
        "fuzzer.jobs.run_fuzzer_job",
        include_mutations=request.include_mutations,
        use_firewall=request.use_firewall,
        seed_prompt=request.prompt,
        family=request.family,
        job_timeout=3600,
    )
    return {"job_id": job.id, "status": "queued"}


@app.get("/v1/fuzzer/runs/{job_id}")
def fuzzer_run_status(job_id: str) -> dict[str, Any]:
    queue = _job_queue()
    try:
        job = queue.fetch_job(job_id)
    except Exception as error:
        raise HTTPException(status_code=503, detail="Could not read job status") from error
    if job is None:
        raise HTTPException(status_code=404, detail="Fuzzer job not found")
    return {
        "job_id": job.id,
        "status": job.get_status(refresh=True),
        "result": job.result if job.is_finished else None,
        "error": "Fuzzer job failed; see worker logs" if job.is_failed else None,
    }


# --------------------------------------------------------------------------- monitoring
@app.get("/v1/events")
def recent_events(limit: int = 100) -> dict[str, Any]:
    try:
        selected = event_store().recent_events(limit)
    except Exception:
        logger.exception("event_store_read_failed")
        selected = list(events)[: max(1, min(limit, 500))]
    latencies = sorted(float(event["latency_ms"]) for event in selected)
    p95_index = max(0, int(0.95 * len(latencies) + 0.999) - 1)
    requests = {event["request_id"] for event in selected}
    blocked_requests = {event["request_id"] for event in selected if event["verdict"] == "block"}
    return {
        "events": selected,
        "metrics": {
            "inspections": len(selected),
            "requests": len(requests),
            "blocked_requests": len(blocked_requests),
            "blocked": sum(event["verdict"] == "block" for event in selected),
            "allowed": sum(event["verdict"] == "allow" for event in selected),
            "by_layer": dict(Counter(event["layer"] for event in selected if event["verdict"] == "block")),
            "p95_latency_ms": latencies[p95_index] if latencies else 0.0,
        },
    }


def _artifacts_dir() -> Path:
    return Path(os.getenv("SENTINELLOOP_ARTIFACTS_DIR", str(ROOT / "artifacts")))


def _read_artifact(name: str) -> dict[str, Any]:
    path = _artifacts_dir() / name
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


@app.get("/v1/metrics")
def benchmark_metrics() -> dict[str, Any]:
    """Pre-computed benchmark results (run `python -m sentinelloop benchmark` to refresh)."""
    fuzz = {}
    for name in PROFILES:
        data = _read_artifact(f"fuzz/{name}-summary.json")
        if data:
            fuzz[name] = {"overall": data.get("overall", {}), "by_family": data.get("summary", {})}
    hardening = _read_artifact("hardening/report.json")
    rounds = [
        {
            "version": row["version"],
            "training_bypasses": row.get("training_attack", {}).get("breaches"),
            "classifier_threshold": row.get("classifier_threshold"),
            "known_attacks": row.get("known_attacks_in_index"),
            "holdout_detectors_asr": row["holdout"]["detectors"]["asr"],
            "holdout_full_asr": row["holdout"]["full"]["asr"],
            "holdout_fpr": row["holdout"]["benign"]["fpr"],
            "validation_detectors_asr": row["validation"]["detectors"]["asr"],
        }
        for row in hardening.get("rounds", [])
    ]
    profiles = _read_artifact("evaluation/profiles.json").get("splits", {})
    profile_table = {
        split: {
            name: {
                "asr": values["attacks"]["asr"],
                "breaches": values["attacks"]["breaches"],
                "attempts": values["attacks"]["attempts"],
                "fpr": values["benign"]["fpr"],
                "utility": values["benign"]["utility"],
            }
            for name, values in rows.items()
        }
        for split, rows in profiles.items()
    }
    ablation = {
        name: {key: row[key] for key in ("asr", "fpr", "utility", "breaches", "attempts", "layers")}
        for name, row in _read_artifact("evaluation/ablation.json").get("configurations", {}).items()
    }
    grid = _read_artifact("search/map-elites-detectors.json")
    stats = _read_artifact("evaluation/stats.json").get("comparisons", {})
    path = _artifacts_dir() / "evaluation" / "profiles.json"
    return {
        "available": bool(fuzz or profiles),
        "generated_at": path.stat().st_mtime if path.is_file() else None,
        "fuzz": fuzz,
        "profiles": profile_table,
        "hardening": rounds,
        "ablation": ablation,
        "layers": _read_artifact("evaluation/layers.json").get("splits", {}),
        "map_elites": {
            "profile": grid.get("profile"),
            "dimensions": grid.get("dimensions", {}),
            "coverage": grid.get("coverage"),
            "possible_cells": grid.get("possible_cells"),
            "cells": [
                {key: cell.get(key) for key in ("family", "technique", "fitness", "outcome", "prompt")}
                for cell in grid.get("archive", [])
            ],
        },
        "stats": {
            name: {
                key: row.get(key)
                for key in ("baseline_asr", "baseline_asr_ci95", "firewall_asr", "asr_reduction",
                            "asr_reduction_ci95", "paired_attempts", "seed_clusters")  # fmt: skip
            }
            for name, row in stats.items()
        },
    }


# --------------------------------------------------------------------------- documents
@app.post("/v1/files/analyze")
async def analyze_uploaded_file(request: Request, filename: str = "uploaded-file") -> dict[str, Any]:
    """Scan an upload in memory for hidden prompt injections; never saved or executed."""
    content = await request.body()
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB analysis limit")
    try:
        result = analyze_bytes(filename, request.headers.get("content-type", ""), content)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    scan = result["prompt_injection"]
    _log_event(
        uuid.uuid4().hex,
        {"layer": scan.get("layer") or "detectors", "verdict": scan["status"] if scan["status"] in {"block", "allow"} else "allow",
         "score": scan.get("score") or 0.0, "stage": "document", "reason": scan["reason"]},  # fmt: skip
        "file",
        result["filename"],
    )
    return result


# --------------------------------------------------------------------------- chat
def _sandbox_document(request: ChatRequest) -> dict[str, str] | None:
    extension = (request.model_extra or {}).get("sentinelloop") or {}
    document = extension.get("document") if isinstance(extension, dict) else None
    if not isinstance(document, dict) or not str(document.get("content", "")).strip():
        return None
    channel = document.get("channel", "email")
    if channel not in {"email", "file", "web"}:
        raise HTTPException(status_code=422, detail="document.channel must be email, file or web")
    return {
        "channel": channel,
        "content": str(document["content"])[:8000],
        "title": str(document.get("title", ""))[:120],
    }


@app.post("/v1/chat/completions", response_model=None)
def chat_completions(request: ChatRequest) -> dict[str, Any] | StreamingResponse:
    upstream = os.getenv("SENTINELLOOP_UPSTREAM_URL")
    configured_model = (
        os.getenv("SENTINELLOOP_MODEL", "sentinelloop-sandbox") if upstream else "sentinelloop-sandbox"
    )
    model = request.model or configured_model
    request_id = uuid.uuid4().hex
    messages = [dict(message) for message in request.messages]
    if upstream:
        result = _upstream_chat(request, messages, model, request_id, upstream)
        return _stream_completion(result) if request.stream else result

    # Sandbox backend: the whole conversation runs through the shared harness.
    turns = tuple(
        _text_content(message.get("content")) for message in messages if message.get("role") == "user"
    )
    if not turns:
        turns = ("Hello",)
    document = _sandbox_document(request)
    if document:
        attack = Attack(
            document["content"], "chat", turns=turns, channel=document["channel"], title=document["title"]
        )
    else:
        attack = Attack(turns[-1], "chat", turns=turns)
    profile = default_profile()
    run = run_scenario(attack, profile)
    trace = _log_run(request_id, run, "chat")
    final = run["transcript"][-1]
    blocked = any(
        (turn.get("input_check") or {}).get("verdict") == "block"
        or (turn.get("output_check") or {}).get("verdict") == "block"
        for turn in run["transcript"]
    )
    result = _completion(model, final["response"], "content_filter" if blocked else "stop")
    result["sentinelloop"] = {
        "request_id": request_id,
        "profile": profile,
        "decision": "blocked" if blocked else ("protected" if run["stopped_by"] else "allowed"),
        "stopped_by": run["stopped_by"],
        "judge": {"outcome": run["outcome"], "reason": run["reason"], "signals": run["signals"]},
        "trace": trace,
        "transcript": run["transcript"],
    }
    return _stream_completion(result) if request.stream else result


def _upstream_chat(
    request: ChatRequest, messages: list[dict[str, Any]], model: str, request_id: str, upstream: str
) -> dict[str, Any]:
    firewall = Firewall()
    trace = []
    # User messages are direct input; tool/function results are retrieved (untrusted) content.
    for message in messages:
        role = message.get("role")
        if role not in {"user", "tool", "function"}:
            continue
        text = _text_content(message.get("content"))
        check = firewall.inspect_input(text, stage="input" if role == "user" else "document")
        trace.append(_log_event(request_id, check, "chat", text))
        if check.verdict == "block":
            result = _completion(
                model,
                "Request blocked by SentinelLoop: this message looks like a prompt injection.",
                "content_filter",
            )
            result["sentinelloop"] = {"request_id": request_id, "decision": "blocked", "trace": trace}
            return result

    payload = request.model_dump(exclude_none=True)
    payload.pop("sentinelloop", None)
    payload["model"] = model
    payload["stream"] = False  # buffer so the full answer passes the output guard first
    if os.getenv("SENTINELLOOP_UPSTREAM_PERSONA", "").lower() == "sandbox":
        # Give the hosted model the sandbox system prompt (fake secret + canary) so
        # real-model injections can be measured with the same output guard.
        payload["messages"] = [{"role": "system", "content": SYSTEM_PROMPT}, *messages]
    result = _upstream_request(payload, upstream, os.getenv("SENTINELLOOP_API_KEY"))
    try:
        response_message = result["choices"][0]["message"]
        answer = _text_content(response_message.get("content"))
    except (KeyError, IndexError, TypeError) as error:
        raise HTTPException(status_code=502, detail="Upstream returned an invalid chat completion") from error
    filtered, output_check = firewall.inspect_output(answer)
    trace.append(_log_event(request_id, output_check, "chat", answer))
    response_message["content"] = filtered
    decision = "redacted" if output_check.verdict == "block" else "allowed"
    if response_message.get("tool_calls") or response_message.get("function_call"):
        calls = response_message.get("tool_calls", [])
        if response_message.get("function_call"):
            calls = [{"function": response_message["function_call"]}]
        reasons = []
        for call in calls:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            decision_ = tool_policy.authorize(function.get("name", ""), function.get("arguments", "{}"))
            reasons.append(
                decision_.reason if decision_.verdict == "block"
                else "policy allows this read-only call, but no tool executor is connected"
            )  # fmt: skip
            trace.append(
                _log_event(
                    request_id,
                    {"layer": "tool_policy", "verdict": decision_.verdict, "score": float(decision_.verdict == "block"),
                     "stage": "tool", "reason": decision_.reason},  # fmt: skip
                    "chat",
                    function.get("name", ""),
                )
            )
        response_message.pop("tool_calls", None)
        response_message.pop("function_call", None)
        response_message["content"] = "Tool call withheld by SentinelLoop: " + "; ".join(reasons)
        result["choices"][0]["finish_reason"] = "content_filter"
        decision = "tool-call-withheld"
    elif output_check.verdict == "block":
        result["choices"][0]["finish_reason"] = "content_filter"
    result["sentinelloop"] = {"request_id": request_id, "decision": decision, "trace": trace}
    return result
