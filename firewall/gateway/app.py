"""OpenAI-compatible gateway with firewall inspection and a sandbox default backend."""

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from firewall import Firewall, Inspection
from firewall.policies.tool_policy import ToolPolicy
from firewall.gateway.event_store import default_store
from target_app.agent import DemoAgent


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = {"event": record.getMessage(), "timestamp": time.time()}
        for name in ("request_id", "layer", "verdict", "score", "latency_ms", "reason"):
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
events: deque[dict[str, Any]] = deque(maxlen=500)
app = FastAPI(title="SentinelLoop Firewall Gateway", version="0.1.0")
tool_policy = ToolPolicy()
event_store = default_store()


class FuzzerRunRequest(BaseModel):
    include_mutations: bool = True
    use_firewall: bool = True


class ChatRequest(BaseModel):
    model: str = "sentinelloop-sandbox"
    messages: list[dict[str, Any]] = Field(min_length=1)
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False


def _log_inspection(request_id: str, result: Inspection) -> None:
    event = {"request_id": request_id, "layer": result.layer, "verdict": result.verdict,
             "score": result.score, "latency_ms": result.latency_ms, "reason": result.reason,
             "timestamp": time.time()}
    events.appendleft(event)
    try:
        event_store.append_event(event)
    except Exception:
        logger.exception("event_store_write_failed")
    logger.info("firewall_decision", extra={key: value for key, value in event.items() if key != "timestamp"})


def _text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return ""


def _completion(model: str, text: str, finish_reason: str = "stop") -> dict[str, Any]:
    return {"id": "chatcmpl-" + uuid.uuid4().hex, "object": "chat.completion",
            "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def _stream_completion(result: dict[str, Any]) -> StreamingResponse:
    choice = result["choices"][0]
    message = choice.get("message", {})
    content = message.get("content") or ""
    finish_reason = choice.get("finish_reason", "stop")
    base = {"id": result.get("id", "chatcmpl-" + uuid.uuid4().hex),
            "object": "chat.completion.chunk", "created": result.get("created", int(time.time())),
            "model": result.get("model", "sentinelloop-sandbox")}

    def events():
        first = {**base, "choices": [{"index": 0, "delta": {"role": "assistant"},
                                      "finish_reason": None}]}
        yield "data: " + json.dumps(first, ensure_ascii=False) + "\n\n"
        if content:
            token = {**base, "choices": [{"index": 0, "delta": {"content": content},
                                           "finish_reason": None}]}
            yield "data: " + json.dumps(token, ensure_ascii=False) + "\n\n"
        final = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}]}
        yield "data: " + json.dumps(final, ensure_ascii=False) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _upstream_request(payload: dict[str, Any], base_url: str, api_key: str | None) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
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


def _job_queue():
    try:
        from redis import Redis
        from rq import Queue
    except ImportError as error:
        raise HTTPException(status_code=503, detail="Install the jobs extra to enable queued fuzzer runs") from error
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
    return {"job_id": job.id, "status": job.get_status(refresh=True),
            "result": job.result if job.is_finished else None,
            "error": "Fuzzer job failed; see worker logs" if job.is_failed else None}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "backend": "upstream" if os.getenv("SENTINELLOOP_UPSTREAM_URL") else "sandbox"}


@app.get("/v1/models")
def models() -> dict[str, Any]:
    model = os.getenv("SENTINELLOOP_MODEL", "sentinelloop-sandbox")
    return {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "sentinelloop"}]}


@app.get("/v1/events")
def recent_events(limit: int = 100) -> dict[str, Any]:
    try:
        selected = event_store.recent_events(limit)
    except Exception:
        logger.exception("event_store_read_failed")
        selected = list(events)[:max(1, min(limit, 500))]
    latencies = sorted(float(event["latency_ms"]) for event in selected)
    p95_index = max(0, int(0.95 * len(latencies) + 0.999) - 1)
    return {"events": selected, "metrics": {
        "inspections": len(selected),
        "blocked": sum(event["verdict"] == "block" for event in selected),
        "allowed": sum(event["verdict"] == "allow" for event in selected),
        "p95_latency_ms": latencies[p95_index] if latencies else 0.0,
    }}


@app.get("/v1/metrics")
def benchmark_metrics() -> dict[str, Any]:
    artifacts = Path(os.getenv("SENTINELLOOP_ARTIFACTS_DIR", str(Path.cwd() / "artifacts")))

    def read_report(name: str) -> dict[str, Any]:
        path = artifacts / name
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    baseline = read_report("baseline.json")
    protected = read_report("firewall.json")
    hardening = read_report("closed_loop/report.json")
    utility_report = read_report("utility-report.json")
    genetic_baseline = read_report("genetic-baseline.json")
    genetic_firewall = read_report("genetic-firewall.json")
    map_baseline = read_report("map-elites-baseline.json")
    map_firewall = read_report("map-elites-firewall.json")
    family_rows = []
    families = set(baseline.get("summary", {})) | set(protected.get("summary", {}))
    for family in sorted(families):
        family_rows.append({"family": family,
                            "baseline_asr": baseline.get("summary", {}).get(family, {}).get("asr", 0.0),
                            "firewall_asr": protected.get("summary", {}).get(family, {}).get("asr", 0.0)})

    layer_counts: dict[tuple[str, str], dict[str, int]] = {}
    for attempt in protected.get("attempts", []):
        try:
            layers = json.loads(attempt.get("input_layers", "[]"))
        except (TypeError, json.JSONDecodeError):
            layers = []
        for check in layers:
            layer = check.get("layer", "unknown") if isinstance(check, dict) else check
            key = (attempt.get("family", "unknown"), layer)
            cell = layer_counts.setdefault(key, {"attempts": 0, "blocked": 0})
            cell["attempts"] += 1
            verdict = check.get("verdict", attempt.get("input_verdict")) if isinstance(check, dict) else attempt.get("input_verdict")
            cell["blocked"] += int(verdict == "block")
    heatmap = [{"family": family, "layer": layer, **counts}
               for (family, layer), counts in sorted(layer_counts.items())]

    breaches = [attempt for attempt in baseline.get("attempts", []) if attempt.get("outcome") == "breach"]
    top_breaches = [{"family": row.get("family", "unknown"), "prompt": row.get("prompt", ""),
                     "reason": row.get("reason", "")}
                    for row in breaches[:5]]
    baseline_holdout = hardening.get("baseline_holdout_overall", {})
    versions = ([{"version": "baseline", "asr": baseline_holdout.get("asr", 0.0),
                 "fpr": 0.0, "new_rules": 0}] +
                [{"version": row.get("version"), "asr": row.get("holdout", {}).get("asr", 0.0),
                 "fpr": row.get("holdout", {}).get("fpr", 0.0),
                 "new_rules": row.get("hardening_rules_added", 0)}
                for row in hardening.get("rounds", [])])
    return {"family_asr": family_rows, "versions": versions, "layer_heatmap": heatmap,
            "top_breaches": top_breaches,
            "genetic_history": {"baseline": genetic_baseline.get("history", []),
                                "firewall": genetic_firewall.get("history", [])},
            "map_elites_history": {"baseline": map_baseline.get("history", []),
                                   "firewall": map_firewall.get("history", [])},
            "map_elites_archive": {
                "dimensions": map_baseline.get("dimensions", map_firewall.get("dimensions", {})),
                "baseline": map_baseline.get("archive", []),
                "firewall": map_firewall.get("archive", []),
            },
            "baseline_holdout": baseline_holdout,
            "utility": {key: utility_report.get(key, default) for key, default in {
                "task_count": 0, "baseline_success_count": 0, "baseline_success_rate": 0.0,
                "firewall_success_count": 0, "firewall_success_rate": 0.0,
                "benign_block_count": 0, "benign_block_rate": 0.0,
                "baseline_successes_preserved": 0, "utility_retention": 0.0,
            }.items()}}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    page = Path(__file__).with_name("dashboard.html")
    return page.read_text(encoding="utf-8")


@app.post("/v1/chat/completions", response_model=None)
def chat_completions(request: ChatRequest) -> dict[str, Any] | StreamingResponse:
    request_id = uuid.uuid4().hex
    firewall = Firewall()
    messages = [dict(message) for message in request.messages]
    untrusted = [message for message in messages if message.get("role") == "user"]
    checks = [firewall.inspect_input(_text_content(message.get("content"))) for message in untrusted]
    for check in checks:
        _log_inspection(request_id, check)
    blocked = next((check for check in checks if check.verdict == "block"), None)
    if blocked:
        result = _completion(request.model, "Request blocked by SentinelLoop firewall.", "content_filter")
        return _stream_completion(result) if request.stream else result

    upstream = os.getenv("SENTINELLOOP_UPSTREAM_URL")
    if upstream:
        payload = request.model_dump(exclude_none=True)
        if request.stream:
            # Buffer upstream output so the full answer passes the output guard before any SSE data is sent.
            payload["stream"] = False
        result = _upstream_request(payload, upstream, os.getenv("SENTINELLOOP_API_KEY"))
        try:
            answer = result["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as error:
            raise HTTPException(status_code=502, detail="Upstream returned an invalid chat completion") from error
        filtered, output_check = firewall.inspect_output(answer)
        _log_inspection(request_id, output_check)
        response_message = result["choices"][0]["message"]
        response_message["content"] = filtered
        # Do not return tool calls to clients without an explicit authorization policy.
        if response_message.get("tool_calls") or response_message.get("function_call"):
            calls = response_message.get("tool_calls", [])
            if response_message.get("function_call"):
                calls = [{"function": response_message["function_call"]}]
            policy_reasons = []
            for call in calls:
                function = call.get("function", {}) if isinstance(call, dict) else {}
                decision = tool_policy.authorize(function.get("name", ""), function.get("arguments", "{}"))
                policy_reasons.append(decision.reason if decision.verdict == "block"
                                      else "policy allows read-only call; execution is not configured")
                _log_inspection(request_id, Inspection("L4", decision.verdict,
                                0.0 if decision.verdict == "allow" else 1.0,
                                decision.reason, 0.0))
            response_message.pop("tool_calls", None)
            response_message.pop("function_call", None)
            reason = "; ".join(policy_reasons) or "tool execution is not configured"
            response_message["content"] = "Tool call blocked: " + reason
            _log_inspection(request_id, Inspection("L5", "block", 1.0,
                            "gateway does not forward model-generated tool calls", 0.0))
            result["choices"][0]["finish_reason"] = "content_filter"
        elif output_check.verdict == "block":
            result["choices"][0]["finish_reason"] = "content_filter"
        return _stream_completion(result) if request.stream else result

    guard = lambda text: _inspect_untrusted(firewall, request_id, text)
    agent = DemoAgent()
    response = ""
    output_check = None
    for message in untrusted:
        turn_text = _text_content(message.get("content"))
        response = agent.handle(turn_text, content_guard=guard).response
        response, output_check = firewall.inspect_output(response)
        _log_inspection(request_id, output_check)
        if output_check.verdict == "block":
            break
    if not untrusted:
        response = "I can summarize sandbox email, search fake files, or update the sandbox calendar."
    finish_reason = "content_filter" if output_check and output_check.verdict == "block" else "stop"
    result = _completion(request.model, response, finish_reason)
    return _stream_completion(result) if request.stream else result


def _inspect_untrusted(firewall: Firewall, request_id: str, text: str) -> bool:
    result = firewall.inspect_untrusted(text)
    _log_inspection(request_id, result)
    return result.verdict != "block"
