import asyncio
import json
import httpx2
from openai import AsyncOpenAI
from typesafe_sdk import AsyncTypeSafeClient

from atomicroot.integration.providers import OpenAIModel, JevClassifier, CRITERIA, OPTIONS


def test_actual_typesafe_async_sdk_serialization_and_decoding(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "offline-placeholder")
    calls = []
    def respond(request):
        calls.append(str(request.url))
        if request.url.path == "/v1/models":
            return httpx2.Response(200, json={"models": [{"name": "jev-1.13.0", "description": "fixture", "release_date": "2026-09-01"}]})
        assert str(request.url) == "https://api.typesafe.ai/v1/systemone"
        body = json.loads(request.content)
        assert body["model"] == "jev-1.13.0"
        assert list(body["questions"]["confidentiality"]["criteria"]) == list(OPTIONS)
        return httpx2.Response(200, json={"model": "jev-1.13.0", "answers": {"confidentiality": {
            "type": "choice", "choice": "UNKNOWN", "confidence": .9, "probabilities": {"PUBLIC": .05, "SENSITIVE": .05, "UNKNOWN": .9}}},
            "usage": {"input_tokens": 100, "output_tokens": 3}})
    def factory(**kwargs): return AsyncTypeSafeClient(**kwargs, transport=httpx2.MockTransport(respond))
    provider = JevClassifier(client_factory=factory)
    assert "jev-1.13.0" in asyncio.run(provider.available_models())["models"]
    result = asyncio.run(provider.classify({"untrusted_document": "offline test"}, CRITERIA))
    assert result["candidate_label"] == "UNKNOWN" and result["usage"]["input_tokens"] == 100
    assert len(calls) == 2


def test_actual_openai_async_sdk_request_and_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "offline-placeholder")
    def respond(request):
        assert str(request.url) == "https://api.openai.com/v1/chat/completions"
        body = json.loads(request.content)
        assert body["response_format"] == {"type": "json_object"} and body["store"] is False
        return httpx2.Response(200, json={"id": "fixture", "object": "chat.completion", "created": 1, "model": "configured-model-version",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": '{"kind":"done","summary":"observed"}'}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})
    def factory(**kwargs): return AsyncOpenAI(**kwargs, http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(respond)))
    result = asyncio.run(OpenAIModel("configured-model", client_factory=factory).generate([
        {"role": "system", "content": "Return JSON"}, {"role": "user", "content": "offline fixture"}]))
    assert result["output"]["kind"] == "done" and result["actual_model"] == "configured-model-version"
