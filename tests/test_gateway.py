import json

from firewall.gateway import app as gateway


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"choices":[]}'


def test_upstream_request_sets_client_signature_and_forwards_model(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr(gateway.urllib.request, "urlopen", fake_urlopen)
    payload = {"model": "openai/gpt-oss-120b", "messages": [{"role": "user", "content": "hi"}]}
    result = gateway._upstream_request(payload, "https://api.groq.com/openai/v1/", "test-token")

    assert result == {"choices": []}
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert captured["headers"]["User-agent"] == "SentinelLoop/0.1 (OpenAI-compatible client)"
    assert captured["headers"]["Authorization"] == "Bearer test-token"
    assert captured["body"] == payload
    assert captured["timeout"] == 60
