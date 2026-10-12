"""Regression for the observed local worker model_inference loop."""
import json

import httpx2
import pytest

from atomicroot.integration.pilot import PilotHost
from atomicroot.integration.providers import OllamaModel, DisabledClassifier
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.workflow import AgentWorkflow
from atomicroot.integration.prompts import worker_messages, worker_response_schema
from atomicroot.framework.storage import dumps
from atomicroot.tests.test_ollama_provider import response, factory


def activate(host, contract=None):
    p = host.runtime.contracts.propose(contract or host.contract, host.principals["reader"])
    host.runtime.broker.decide(p["review_id"], True, host.approver)
    host.runtime.contracts.activate(p["proposal_id"], p["review_id"], host.approver)


def action_tools(schema):
    return {v["properties"]["tool"]["const"] for v in schema["oneOf"] if "tool" in v["properties"]}


@pytest.mark.parametrize("scenario,expected", [("literature", {"read_document", "send_email"}),
                                              ("budget", {"transfer_funds"})])
def test_generation_choices_use_worker_capability_not_whole_task_contract(tmp_path, scenario, expected):
    host = PilotHost(tmp_path, scenario, model_provider="ollama")
    try:
        messages = worker_messages("reader", "Synthetic goal", host.contract, [], [], {"spent": 0, "reserved": 0})
        data = json.loads(messages[-1]["content"])
        assert "model_inference" in data["approved_contract"]["allowed_tools"]
        assert set(data["available_actions"]) == expected
        grammar = worker_response_schema(host.contract)
        assert action_tools(grammar) == expected
        assert {b["properties"]["kind"]["const"] for b in grammar["oneOf"]} == {"action", "done", "contract"}
        assert "never return them as a worker action" in messages[0]["content"]
    finally: host.runtime.store.close()


def test_native_schema_is_bound_to_context_and_changed_schema_cannot_reuse_operation(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    calls = []
    def respond(request):
        body = json.loads(request.content)
        schema = body["format"]
        assert action_tools(schema) == {"read_document", "send_email"}
        assert list(schema["oneOf"][0]["properties"]) == ["kind", "tool", "args"]
        with host.runtime.store.snapshot() as snap:
            doc = snap.read("document:reader-context")[1]
            assert json.loads(doc["content"])["response_schema"] == schema
        calls.append(True)
        return httpx2.Response(200, json=response())
    model = OllamaModel(client_factory=factory(respond))
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    activate(host)
    args = dict(messages=[{"role": "user", "content": "Synthetic test"}], sources=[],
                context_resource="reader-context", principal=host.principals["reader"], task="pilot", purpose="research")
    try:
        bridge.worker("op", "run", **args)
        revision = {**host.contract, "allowed_tools": ["model_inference", "read_document"]}
        activate(host, revision)
        with pytest.raises(ValueError, match="context changed"): bridge.worker("op", "run", **args)
        assert calls == [True]
    finally: host.runtime.store.close()


def test_forged_generation_schema_rejected_before_inference(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    calls = []
    model = OllamaModel(client_factory=factory(lambda request: calls.append(True)))
    bridge = ModelBridge(host.runtime, model, DisabledClassifier(), bootstrap_authorized=True)
    activate(host)
    try:
        context = {"messages": [{"role": "user", "content": "Synthetic test"}], "sources": [],
                   "provider": "ollama", "model": "qwen3:8b", "prompt_version": "worker-v3",
                   "response_schema": {"type": "object", "properties": {"tool": {"const": "shell"}}}}
        doc = host.runtime.storage.ingest("reader-context", dumps(context), host.owner)
        request = bridge.tools.stage({"tool": "model_inference", "args": {"resource": "reader-context",
             "digest": doc["digest"], "to": "ollama"}}, principal=host.principals["reader"], task="pilot",
             purpose="research", operation="forged", host_inference=True)
        result = bridge.tools.execute(request, host.principals["reader"])
        assert result.status == "EVALUATION_ERROR" and result.detail["reason"] == "untrusted worker response schema"
        assert not calls and not host.runtime.store.inspect_outbox()
    finally: host.runtime.store.close()


def test_model_can_ignore_schema_but_host_still_blocks_original_bad_action(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    scripted = host.fake_model().responder
    def respond(request):
        data = json.loads(request.content)
        if type(data["format"]) is str:
            output = scripted(data["messages"])
        else:
            assert "model_inference" not in action_tools(data["format"])
            # A faulty/malicious daemon can violate the requested grammar.
            # GuardedTools must reject it independently, with no nested call.
            output = {"kind": "action", "tool": "model_inference", "args": {"model": "qwen3:8b", "prompt": "summarize"}}
        return httpx2.Response(200, json=response(message={"role": "assistant", "content": json.dumps(output)}))
    bridge = ModelBridge(host.runtime, OllamaModel(client_factory=factory(respond)), DisabledClassifier(), bootstrap_authorized=True)
    flow = AgentWorkflow(host.runtime, bridge, tmp_path / "graph.sqlite", task="pilot", principals=host.principals,
        approver=host.approver, context_resources={r:r+"-context" for r in host.principals}, host=host.contract,
        host_validator=host.validate_proposal, scope_limits=host.scope_limits)
    try:
        first = flow.start("run", "Synthetic literature goal")
        host.runtime.broker.decide(first["__interrupt__"][0].value["review_id"], True, host.approver)
        result = flow.resume("run")
        assert result["status"] == "STEP_LIMIT"
        assert all(o["status"] == "REJECTED" and "host-managed" in o["detail"]["reason"] for o in result["observations"])
        assert len(result["observations"]) == 6
        assert all(json.loads(o["payload"])["tool"] == "model_inference" for o in host.runtime.store.inspect_outbox())
        assert len(bridge.memo.attempts()) == 7  # author + six host-managed worker calls, no nested inference
    finally:
        flow.close()
        host.runtime.store.close()


def test_budget_revision_still_works_with_native_schema(tmp_path):
    host = PilotHost(tmp_path, "budget", model_provider="ollama")
    scripted = host.fake_model().responder
    def respond(request):
        data = json.loads(request.content)
        if type(data["format"]) is dict: assert action_tools(data["format"]) == {"transfer_funds"}
        output = scripted(data["messages"])
        return httpx2.Response(200, json=response(message={"role": "assistant", "content": json.dumps(output)}))
    bridge = ModelBridge(host.runtime, OllamaModel(client_factory=factory(respond)), DisabledClassifier(), bootstrap_authorized=True)
    flow = AgentWorkflow(host.runtime, bridge, tmp_path / "graph.sqlite", task="pilot", principals=host.principals,
        approver=host.approver, context_resources={r:r+"-context" for r in host.principals}, host=host.contract,
        host_validator=host.validate_proposal, scope_limits=host.scope_limits, max_steps=8)
    try:
        result = flow.start("run", "Two synthetic payments of 400")
        reviews = 0
        while "__interrupt__" in result:
            reviews += 1
            host.runtime.broker.decide(result["__interrupt__"][0].value["review_id"], True, host.approver)
            result = flow.resume("run")
        assert reviews == 2 and result["status"] == "DONE"
        with host.runtime.store.snapshot() as snap: assert snap.read("budget:pilot")[1] == 800
    finally:
        flow.close()
        host.runtime.store.close()


def test_literature_native_schema_and_two_source_context_fit_existing_size_bound(tmp_path):
    host = PilotHost(tmp_path, model_provider="ollama")
    scripted = host.fake_model().responder
    def respond(request):
        data = json.loads(request.content)
        output = scripted(data["messages"])
        return httpx2.Response(200, json=response(message={"role": "assistant", "content": json.dumps(output)}))
    bridge = ModelBridge(host.runtime, OllamaModel(client_factory=factory(respond)), DisabledClassifier(), bootstrap_authorized=True)
    flow = AgentWorkflow(host.runtime, bridge, tmp_path / "graph.sqlite", task="pilot", principals=host.principals,
        approver=host.approver, context_resources={r:r+"-context" for r in host.principals}, host=host.contract,
        host_validator=host.validate_proposal, scope_limits=host.scope_limits, max_steps=8)
    try:
        result = flow.start("run", "Read both synthetic sources, summarize and simulate emailing Alice")
        host.runtime.broker.decide(result["__interrupt__"][0].value["review_id"], True, host.approver)
        result = flow.resume("run")
        assert result["status"] == "DONE"
        assert [o["detail"]["tool"] for o in result["observations"]] == ["read_document", "read_document", "send_email"]
        with host.runtime.store.snapshot() as snap:
            for role in host.principals:
                assert len(snap.read("document:"+role+"-context")[1]["content"].encode("utf-8")) <= 8192
    finally:
        flow.close()
        host.runtime.store.close()
