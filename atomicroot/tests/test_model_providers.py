"""Provider selection must preserve host identity, immutable egress and memo."""
import asyncio
import json
from dataclasses import replace

import httpx2
import pytest
from openai import AsyncOpenAI

from atomicroot.integration.providers import (
    GroqModel, NineRouterModel, RouterRoute, Limits, DisabledClassifier,
    model_configuration, live_model, discover_models, router_endpoint,
)
from atomicroot.integration.pilot import PilotHost
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.workflow import AgentWorkflow


MESSAGES = [{"role": "system", "content": "Return JSON"}, {"role": "user", "content": "Synthetic fixture"}]


def response(model, content='{"kind":"done","summary":"fixture"}', finish="stop"):
    return {"id": "fixture", "object": "chat.completion", "created": 1, "model": model,
            "choices": [{"index": 0, "finish_reason": finish,
                         "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}}


def sdk_factory(respond):
    def factory(**kwargs):
        assert kwargs["max_retries"] == 0
        return AsyncOpenAI(**kwargs, http_client=httpx2.AsyncClient(
            transport=httpx2.MockTransport(respond), follow_redirects=False, trust_env=False))
    return factory


def test_groq_actual_sdk_endpoint_parameters_model_usage(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "offline-placeholder")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://evil.invalid/v1")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    def respond(request):
        assert str(request.url) == "https://api.groq.com/openai/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer offline-placeholder"
        data = json.loads(request.content)
        assert data["model"] == "openai/gpt-oss-120b"
        assert data["messages"] == MESSAGES
        assert data["response_format"] == {"type": "json_object"}
        assert data["max_completion_tokens"] == 512
        assert "tools" not in data and "store" not in data
        return httpx2.Response(200, json=response(data["model"]))
    result = asyncio.run(GroqModel(limits=Limits(max_output_tokens=512),
                                  client_factory=sdk_factory(respond)).generate(MESSAGES))
    assert result == {"output": {"kind": "done", "summary": "fixture"},
                      "actual_model": "openai/gpt-oss-120b", "usage": {"input_tokens": 100, "output_tokens": 10}}


@pytest.mark.parametrize("model,content,finish", [
    ("different-model", '{}', "stop"),
    ("openai/gpt-oss-120b", 'not json', "stop"),
    ("openai/gpt-oss-120b", '[]', "stop"),
    ("openai/gpt-oss-120b", '{}', "length"),
])
def test_groq_invalid_response_not_accepted(monkeypatch, model, content, finish):
    monkeypatch.setenv("GROQ_API_KEY", "offline-placeholder")
    provider = GroqModel("openai/gpt-oss-120b", client_factory=sdk_factory(
        lambda _: httpx2.Response(200, json=response(model, content, finish))))
    with pytest.raises(ValueError): asyncio.run(provider.generate(MESSAGES))


def test_groq_429_has_no_hidden_retry_and_missing_key_no_call(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    calls = []
    def respond(_):
        calls.append(True)
        return httpx2.Response(429, json={"error": {"message": "rate limited", "type": "rate_limit"}})
    provider = GroqModel("openai/gpt-oss-120b", client_factory=sdk_factory(respond))
    with pytest.raises(ValueError, match="GROQ_API_KEY"): asyncio.run(provider.generate(MESSAGES))
    assert calls == []
    monkeypatch.setenv("GROQ_API_KEY", "offline-placeholder")
    from openai import RateLimitError
    with pytest.raises(RateLimitError): asyncio.run(provider.generate(MESSAGES))
    assert len(calls) == 1


def route():
    return RouterRoute("http://localhost:20128/v1", "ag/gemini-3.8-flash", "antigravity", "gemini-3.8-flash", "route-v1")


def test_router_sdk_pinned_destination_compression_off_actual_model(monkeypatch):
    monkeypatch.setenv("NINEROUTER_API_KEY", "offline-placeholder")
    def respond(request):
        assert str(request.url) == "http://localhost:20128/v1/chat/completions"
        assert request.headers["X-9Router-Token-Saver"] == "off"
        data = json.loads(request.content)
        assert data["model"] == route().model and data["messages"] == MESSAGES
        assert data["max_tokens"] == 1600
        return httpx2.Response(200, json=response(route().response_model))
    provider = NineRouterModel(route(), trusted_route=True, client_factory=sdk_factory(respond))
    assert asyncio.run(provider.generate(MESSAGES))["actual_model"] == route().response_model
    other = NineRouterModel(route(), trusted_route=True, client_factory=sdk_factory(
        lambda _: httpx2.Response(200, json=response("unapproved-fallback"))))
    with pytest.raises(ValueError, match="model mismatch"): asyncio.run(other.generate(MESSAGES))


@pytest.mark.parametrize("url", ["https://remote.example/v1", "http://localhost.evil:20128/v1",
    "http://user:password@localhost:20128/v1", "http://localhost:20128/v1?route=other",
    "http://localhost:20128/v1/other", "http://localhost/v1"])
def test_router_rejects_remote_or_ambiguous_endpoint(url):
    with pytest.raises(ValueError): router_endpoint(url)


def test_router_binding_changes_scope_and_requires_host_trust():
    initial = route()
    for change in ({"model": "ag/gemini-3.7-flash"}, {"revision": "route-v2"},
                   {"endpoint": "http://127.0.0.1:20128/v1"}, {"upstream_provider": "other"},
                   {"response_model": "different"}):
        assert replace(initial, **change).provider != initial.provider
    with pytest.raises(ValueError, match="trusted"): NineRouterModel(initial)
    with pytest.raises(ValueError): replace(initial, model="premium-combo")


def test_configuration_selects_provider_without_cross_credentials(monkeypatch):
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.setenv("OPENAI_MODEL", "openai-configured")
    assert model_configuration("groq")["model"] == "openai/gpt-oss-120b"
    assert model_configuration("groq")["key_environment"] == "GROQ_API_KEY"
    assert live_model("groq", "openai/gpt-oss-20b").model == "openai/gpt-oss-20b"
    assert live_model("openai").model == "openai-configured"
    with pytest.raises(ValueError): model_configuration("unknown")


@pytest.mark.parametrize("provider", ["groq", route().provider])
def test_selected_provider_same_graph_review_and_guarded_tools(tmp_path, provider):
    host = PilotHost(tmp_path, model_provider=provider)
    model = host.fake_model()
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    flow = AgentWorkflow(host.runtime, bridge, tmp_path / "graph.sqlite", task="pilot", principals=host.principals,
                         approver=host.approver, context_resources={r: r + "-context" for r in host.principals}, host=host.contract)
    try:
        first = flow.start("run", "Read both synthetic papers and simulate sending Alice a summary")
        assert "__interrupt__" in first and not host.runtime.store.inspect_outbox()
        assert "openai" not in host.contract["allowed_recipients"]
        host.runtime.broker.decide(first["__interrupt__"][0].value["review_id"], True, host.approver)
        result = flow.resume("run")
        assert result["status"] == "DONE", result
        assert len([o for o in result["observations"] if o["status"] == "COMMITTED"]) == 3
        inference = [json.loads(o["payload"]) for o in host.runtime.store.inspect_outbox()
                     if json.loads(o["payload"])["tool"] == "model_inference"]
        assert inference and all(o["args"]["to"] == provider for o in inference)
    finally:
        flow.close()
        host.runtime.store.close()


def test_missing_provider_scope_and_changed_provider_cannot_dispatch(tmp_path):
    host = PilotHost(tmp_path, model_provider="groq")
    model = host.fake_model()
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    # A valid contract can delegate Groq while omitting its inference scope.
    host.contract["inference_egress"] = [r for r in host.contract["inference_egress"] if r["provider"] != "groq"]
    p = host.runtime.contracts.propose(host.contract, host.principals["reader"])
    host.runtime.broker.decide(p["review_id"], True, host.approver)
    host.runtime.contracts.activate(p["proposal_id"], p["review_id"], host.approver)
    try:
        with pytest.raises(ValueError, match="egress blocked"):
            bridge.worker("op", "run", messages=MESSAGES, sources=[], context_resource="reader-context",
                          principal=host.principals["reader"], task="pilot", purpose="research")
        assert not model.calls and not host.runtime.store.inspect_outbox()
        model.provider = "openai"
        with pytest.raises(ValueError, match="context changed"):
            bridge.worker("op", "run", messages=MESSAGES, sources=[], context_resource="reader-context",
                          principal=host.principals["reader"], task="pilot", purpose="research")
        assert not model.calls
    finally: host.runtime.store.close()


def test_model_listing_is_metadata_only_no_redirect_or_environment_proxy(monkeypatch):
    monkeypatch.setenv("NINEROUTER_BASE_URL", "http://localhost:20128/v1")
    monkeypatch.delenv("NINEROUTER_API_KEY", raising=False)
    actual_client = httpx2.AsyncClient
    def respond(request):
        assert str(request.url) == "http://localhost:20128/v1/models"
        assert request.method == "GET" and not request.content
        assert "authorization" not in request.headers
        return httpx2.Response(200, json={"data": [{"id": "ag/gemini-3.8-flash"}]})
    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return actual_client(**kwargs, transport=httpx2.MockTransport(respond))
    monkeypatch.setattr(httpx2, "AsyncClient", factory)
    assert asyncio.run(discover_models("9router")) == ["ag/gemini-3.8-flash"]
    with pytest.raises(ValueError): asyncio.run(discover_models("9router", timeout=-1))


def test_cli_groq_default_and_missing_key_records_no_live_success(tmp_path, monkeypatch, capsys):
    import phase35_cli
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.setattr("sys.argv", ["phase35_cli.py", "--directory", str(tmp_path), "--provider", "groq",
                                    "--model-mode", "live", "--authorize-model-usage"])
    with pytest.raises(SystemExit) as exc: phase35_cli.main()
    assert exc.value.code == 2
    report = json.loads((tmp_path / "status.json").read_text())
    assert report["missing"] == ["GROQ_API_KEY"] and not report["live_validated"]
    assert report["model_configuration"]["model"] == "openai/gpt-oss-120b"
    assert not (tmp_path / "ledger.sqlite").exists()


def test_cli_router_incomplete_configuration_is_blocked_before_ledger(tmp_path, monkeypatch, capsys):
    import phase35_cli
    for name in ("NINEROUTER_MODEL", "NINEROUTER_UPSTREAM_PROVIDER", "NINEROUTER_RESPONSE_MODEL", "NINEROUTER_ROUTE_REVISION"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.argv", ["phase35_cli.py", "--directory", str(tmp_path), "--provider", "9router", "--model-mode", "live"])
    with pytest.raises(SystemExit) as exc: phase35_cli.main()
    assert exc.value.code == 2
    report = json.loads((tmp_path / "status.json").read_text())
    assert report["configuration"] == "INVALID_OR_MISSING" and not report["live_validated"]
    assert not (tmp_path / "ledger.sqlite").exists()


def test_cli_router_requires_attestation_and_keeps_key_out_of_reports(tmp_path, monkeypatch, capsys):
    import phase35_cli
    for name, value in {"NINEROUTER_BASE_URL": route().endpoint, "NINEROUTER_MODEL": route().model,
                        "NINEROUTER_UPSTREAM_PROVIDER": route().upstream_provider,
                        "NINEROUTER_RESPONSE_MODEL": route().response_model,
                        "NINEROUTER_ROUTE_REVISION": route().revision,
                        "NINEROUTER_API_KEY": "offline-secret-not-a-real-key"}.items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr("sys.argv", ["phase35_cli.py", "--directory", str(tmp_path), "--provider", "9router",
                                    "--model-mode", "live", "--authorize-model-usage"])
    with pytest.raises(SystemExit) as exc: phase35_cli.main()
    assert exc.value.code == 2
    text = (tmp_path / "status.json").read_text()
    assert "--trust-router-route" in text and "offline-secret-not-a-real-key" not in text
    assert "offline-secret-not-a-real-key" not in capsys.readouterr().out
    assert not (tmp_path / "ledger.sqlite").exists()
