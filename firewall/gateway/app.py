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
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from firewall import Firewall, Inspection
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "backend": "upstream" if os.getenv("SENTINELLOOP_UPSTREAM_URL") else "sandbox"}


@app.get("/v1/models")
def models() -> dict[str, Any]:
    model = os.getenv("SENTINELLOOP_MODEL", "sentinelloop-sandbox")
    return {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "sentinelloop"}]}


@app.get("/v1/events")
def recent_events(limit: int = 100) -> dict[str, Any]:
    selected = list(events)[:max(1, min(limit, 500))]
    latencies = sorted(float(event["latency_ms"]) for event in selected)
    p95_index = max(0, int(0.95 * len(latencies) + 0.999) - 1)
    return {"events": selected, "metrics": {
        "inspections": len(selected),
        "blocked": sum(event["verdict"] == "block" for event in selected),
        "allowed": sum(event["verdict"] == "allow" for event in selected),
        "p95_latency_ms": latencies[p95_index] if latencies else 0.0,
    }}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    page = Path(__file__).with_name("dashboard.html")
    return page.read_text(encoding="utf-8")


@app.post("/v1/chat/completions")
def chat_completions(request: ChatRequest) -> dict[str, Any]:
    if request.stream:
        raise HTTPException(status_code=501, detail="Streaming is not supported yet")
    request_id = uuid.uuid4().hex
    firewall = Firewall()
    messages = [dict(message) for message in request.messages]
    untrusted = [message for message in messages if message.get("role") == "user"]
    checks = [firewall.inspect_input(_text_content(message.get("content"))) for message in untrusted]
    for check in checks:
        _log_inspection(request_id, check)
    blocked = next((check for check in checks if check.verdict == "block"), None)
    if blocked:
        return _completion(request.model, "Request blocked by SentinelLoop firewall.", "content_filter")

    upstream = os.getenv("SENTINELLOOP_UPSTREAM_URL")
    if upstream:
        payload = request.model_dump(exclude_none=True)
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
            response_message.pop("tool_calls", None)
            response_message.pop("function_call", None)
            response_message["content"] = "Tool call blocked: no tool execution policy is configured."
            _log_inspection(request_id, Inspection("L5", "block", 1.0,
                            "upstream requested a tool call; execution is disabled", 0.0))
            result["choices"][0]["finish_reason"] = "content_filter"
        elif output_check.verdict == "block":
            result["choices"][0]["finish_reason"] = "content_filter"
        return result

    guard = lambda text: _inspect_untrusted(firewall, request_id, text)
    user_text = "\n".join(_text_content(message.get("content")) for message in untrusted)
    agent = DemoAgent()
    response = agent.handle(user_text, content_guard=guard).response
    filtered, output_check = firewall.inspect_output(response)
    _log_inspection(request_id, output_check)
    finish_reason = "content_filter" if output_check.verdict == "block" else "stop"
    return _completion(request.model, filtered, finish_reason)


def _inspect_untrusted(firewall: Firewall, request_id: str, text: str) -> bool:
    result = firewall.inspect_untrusted(text)
    _log_inspection(request_id, result)
    return result.verdict != "block"
