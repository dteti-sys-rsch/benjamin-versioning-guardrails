"""Offline local-provider checks; no real Ollama calls in the default suite."""
import asyncio
import json

import httpx2
import pytest

from atomicroot.integration.providers import (
    OllamaModel, Limits, DisabledClassifier, OLLAMA_CONTEXT,
    model_configuration, live_model, discover_models,
)
from atomicroot.integration.pilot import PilotHost
from atomicroot.integration.inference import ModelBridge


MESSAGES = [{"role": "user", "content": "Return a synthetic JSON object"}]


def response(**changes):
    return {"model": "qwen3:8b", "done": True, "done_reason": "stop",
            "message": {"role": "assistant", "content": '{"kind":"done","summary":"synthetic"}'},
            "prompt_eval_count": 100, "eval_count": 12, **changes}


def factory(respond):
    def create(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return httpx2.AsyncClient(**kwargs, transport=httpx2.MockTransport(respond))
    return create


def test_local_request_has_exact_model_caps_json_no_secrets_or_cloud(monkeypatch):
    for name in ("OPENAI_API_KEY", "GROQ_API_KEY", "OLLAMA_API_KEY"):
        monkeypatch.setenv(name, "SECRET_SENTINEL")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://evil.invalid")
    def respond(request):
        assert str(request.url) == "http://localhost:11434/api/chat"
        assert "authorization" not in request.headers
        assert b"SECRET_SENTINEL" not in request.content
        body = json.loads(request.content)
        assert body == {"model": "qwen3:8b", "messages": MESSAGES, "stream": False,
                        "format": "json", "think": False,
                        "options": {"num_predict": 512, "num_ctx": OLLAMA_CONTEXT, "temperature": 0}}
        return httpx2.Response(200, json=response())
    model = OllamaModel(limits=Limits(max_output_tokens=512), client_factory=factory(respond))
    output = asyncio.run(model.generate(MESSAGES))
    assert output == {"output": {"kind": "done", "summary": "synthetic"}, "actual_model": "qwen3:8b",
                      "usage": {"input_tokens": 100, "output_tokens": 12}}


@pytest.mark.parametrize("change", [
    {"model": "unapproved:8b"}, {"done": False}, {"done_reason": "length"},
    {"message": {"role": "assistant", "content": "not JSON"}},
    {"message": {"role": "assistant", "content": "[]"}},
    {"message": {"role": "assistant", "content": "{}", "tool_calls": [{"name": "shell"}]}},
    {"prompt_eval_count": -1}, {"eval_count": True}, {"eval_count": None},
])
def test_invalid_or_incomplete_local_output_is_not_accepted(change):
    model = OllamaModel(client_factory=factory(lambda _: httpx2.Response(200, json=response(**change))))
    with pytest.raises(ValueError): asyncio.run(model.generate(MESSAGES))


@pytest.mark.parametrize("status", [302, 404, 503])
def test_redirect_missing_model_and_server_error_have_no_retry_or_pull(status):
    calls = []
    def respond(request):
        calls.append(str(request.url))
        return httpx2.Response(status, headers={"Location": "https://evil.invalid"}, json={"error": "fixture"})
    model = OllamaModel(client_factory=factory(respond))
    with pytest.raises(httpx2.HTTPStatusError): asyncio.run(model.generate(MESSAGES))
    assert calls == ["http://localhost:11434/api/chat"]


def test_local_factory_default_override_and_cloud_tags_rejected(monkeypatch):
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    config = model_configuration("ollama")
    assert config["model"] == "qwen3:8b" and config["key_environment"] is None
    assert isinstance(live_model("ollama"), OllamaModel)
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3:4b")
    assert live_model("ollama").model == "qwen3:4b"
    assert live_model("ollama", "qwen3:8b").model == "qwen3:8b"
    for tag in ("qwen3", "qwen3:latest", "qwen3:8b-cloud", "https://host/model", "qwen3:8 b"):
        with pytest.raises(ValueError): model_configuration("ollama", tag)


def test_local_model_discovery_uses_only_loopback_metadata(monkeypatch):
    actual_client = httpx2.AsyncClient
    def respond(request):
        assert str(request.url) == "http://localhost:11434/api/tags"
        assert request.method == "GET" and not request.content and "authorization" not in request.headers
        return httpx2.Response(200, json={"models": [{"name": "qwen3:8b"}]})
    monkeypatch.setattr(httpx2, "AsyncClient", lambda **kwargs: actual_client(
        **kwargs, transport=httpx2.MockTransport(respond)))
    assert asyncio.run(discover_models("ollama")) == ["qwen3:8b"]


def test_missing_ollama_scope_blocks_before_any_local_inference(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    calls = []
    def respond(request):
        calls.append(True)
        return httpx2.Response(200, json=response())
    model = OllamaModel(client_factory=factory(respond))
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    host.contract["inference_egress"] = []
    proposal = host.runtime.contracts.propose(host.contract, host.principals["reader"])
    host.runtime.broker.decide(proposal["review_id"], True, host.approver)
    host.runtime.contracts.activate(proposal["proposal_id"], proposal["review_id"], host.approver)
    try:
        with pytest.raises(ValueError, match="egress blocked"):
            bridge.worker("op", "run", messages=MESSAGES, sources=[], context_resource="reader-context",
                          principal=host.principals["reader"], task="pilot", purpose="research")
        assert not calls and not host.runtime.store.inspect_outbox()
    finally: host.runtime.store.close()


def test_local_worker_dispatch_requires_committed_intent_and_reuses_receipt(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    calls = []
    def respond(request):
        calls.append(True)
        intents = [o for o in host.runtime.store.inspect_outbox() if json.loads(o["payload"])["tool"] == "model_inference"]
        assert len(intents) == 1 and intents[0]["status"] == "RELEASING"
        assert json.loads(request.content)["messages"] == MESSAGES
        return httpx2.Response(200, json=response())
    model = OllamaModel(client_factory=factory(respond))
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    proposal = host.runtime.contracts.propose(host.contract, host.principals["reader"])
    host.runtime.broker.decide(proposal["review_id"], True, host.approver)
    host.runtime.contracts.activate(proposal["proposal_id"], proposal["review_id"], host.approver)
    try:
        args = dict(messages=MESSAGES, sources=[], context_resource="reader-context",
                    principal=host.principals["reader"], task="pilot", purpose="research")
        first = bridge.worker("op", "run", **args)
        second = bridge.worker("op", "run", **args)
        assert first == second == {"kind": "done", "summary": "synthetic"}
        assert calls == [True]
        assert host.runtime.store.inspect_outbox()[0]["status"] == "RELEASED"
    finally: host.runtime.store.close()


def test_local_cli_needs_bootstrap_authorization_but_not_key(tmp_path, monkeypatch):
    import phase35_cli
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.setattr("sys.argv", ["phase35_cli.py", "--directory", str(tmp_path),
                                    "--provider", "ollama", "--model-mode", "live"])
    with pytest.raises(SystemExit) as exc: phase35_cli.main()
    assert exc.value.code == 2
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["missing"] == ["--authorize-model-usage (initial prompt provider scope)"]
    assert not status["live_validated"] and not (tmp_path / "ledger.sqlite").exists()


def test_local_cli_fake_workflow_and_live_binding_change_preserve_state(tmp_path, monkeypatch):
    import phase35_cli
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    command = ["phase35_cli.py", "--directory", str(tmp_path), "--provider", "ollama",
               "--fixture-approve", "--quiet-progress"]
    monkeypatch.setattr("sys.argv", command)
    with pytest.raises(SystemExit) as exc: phase35_cli.main()
    assert exc.value.code == 0
    status = (tmp_path / "status.json").read_bytes()
    report = json.loads(status)
    assert report["workflow_status"] == "DONE" and report["LLM"] == "OFFLINE VERIFIED"
    assert len([o for o in report["observations"] if o["status"] == "COMMITTED"]) == 3
    checkpoint = (tmp_path / "graph.sqlite").read_bytes()
    monkeypatch.setattr("sys.argv", command + ["--model-mode", "live", "--authorize-model-usage"])
    with pytest.raises(SystemExit) as blocked: phase35_cli.main()
    assert blocked.value.code == 2
    assert json.loads((tmp_path / "status-blocked.json").read_text())["error"] == "RUN_CONFIGURATION_CHANGED"
    assert (tmp_path / "status.json").read_bytes() == status
    assert (tmp_path / "graph.sqlite").read_bytes() == checkpoint
