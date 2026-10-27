"""Regression for live-style workers that keep proposing an already delivered read."""
import json
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import TaskSpec
from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.providers import FakeModel, DisabledClassifier, Limits
from atomicroot.tests.test_phase36_tasks import ConfigSystem, rule
from atomicroot.tests.test_phase37_executor import read_response, done, send, model_spec
from phase36_cli import load, init_fixture, local_identities


def test_stubborn_model_readers_stop_on_receipts_and_writer_uses_source_content(tmp_path):
    runtime = FrameworkRuntime(str(tmp_path / "ledger.sqlite"))
    init_fixture(runtime, load("examples/phase37/trusted-model-fixture.json"))
    user, approver = local_identities(runtime)
    spec = load("examples/phase37/literature-fake-model.json")
    preview = runtime.tasks.propose(spec, user)
    runtime.broker.decide(preview["review_id"], True, approver)
    runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
    refs = {r["resource"]: r for r in spec["resources"]}
    def respond(messages):
        view = json.loads(messages[-1]["content"])
        if view["node"] in {"read-a", "read-b"}:
            # Exactly the observed Qwen failure: never proposes done itself.
            return read_response(refs["journal-a" if view["node"] == "read-a" else "journal-b"])
        texts = [ob["content"] for ob in view["observations"] if ob.get("tool") == "read_document"]
        assert len(texts) == 2
        assert all(ob["instruction_trust"] == "UNTRUSTED" for ob in view["observations"] if "content" in ob)
        assert "journal-a" not in [r["resource"] for r in view["node_progress"]["remaining"] if r["kind"] == "read"]
        if view["step"] == 0: return {"kind": "output", "output": "summary", "content": " | ".join(texts)}
        if view["step"] == 1: return {"kind": "action", "tool": "send_email", "args": {"to": "alice@corp.id", "body": " | ".join(texts)}}
        return done()
    model = FakeModel(respond, provider="ollama"); model.execution_binding = "stubborn-read-regression-v1"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    f = ConfigWorkflow(runtime, tmp_path / "graph.sqlite", task="literature-a", caller=user,
        bridge=ModelBridge(runtime, model, DisabledClassifier(), llm_limits=limits))
    try:
        result = f.start("stubborn")
        assert result["status"] == "SATISFIED", result
        assert len(model.calls) == 4
        assert all(len(dumps(m).encode()) < 8192 for m in model.calls)
        rows = runtime.store.inspect_outbox()
        assert len([r for r in rows if json.loads(r["payload"])["tool"] == "read_document"]) == 2
        assert result["nodes"]["read-a"]["reason"] == result["nodes"]["read-b"]["reason"] == "required_reads_delivered"
        assert result["nodes"]["summary"]["reason"] == "registered_acceptance_satisfied"
        email = next(json.loads(r["receipt"])["result"] for r in rows if json.loads(r["payload"])["tool"] == "send_email")
        assert "bind authorization to versions" in email["body"] and "check freshness atomically" in email["body"]
    finally: f.close(); runtime.store.close()


def test_repeated_read_in_mixed_node_has_bounded_feedback_without_new_effect(tmp_path):
    s = ConfigSystem(tmp_path / "ledger.sqlite")
    spec = model_spec(s); s.activate(spec)
    model = FakeModel(lambda messages: read_response(s.refs[0]), provider="ollama")
    model.execution_binding = "repeat-mixed-node-v1"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    f = ConfigWorkflow(s.runtime, tmp_path / "graph.sqlite", task="t", caller=s.user,
        bridge=ModelBridge(s.runtime, model, DisabledClassifier(), llm_limits=limits))
    try:
        result = f.start("repeat")
        assert result["status"] == "RETRY_EXHAUSTED", result
        assert result["nodes"]["a"]["reason"] == "repeated_read_without_progress"
        assert len(model.calls) == 4  # One delivered read, at most three repeat proposals.
        rows = s.runtime.store.inspect_outbox()
        assert len([r for r in rows if json.loads(r["payload"])["tool"] == "read_document"]) == 1
        last_view = json.loads(model.calls[-1][-1]["content"])
        assert len([ob for ob in last_view["observations"] if ob.get("content")]) == 1
    finally: f.close(); s.runtime.store.close()


def test_repeat_with_new_content_version_follows_authorization_not_cached_feedback(tmp_path):
    s = ConfigSystem(tmp_path / "ledger.sqlite")
    # Mixed scope keeps the node open, so an explicit second read is proposed.
    s.spec["workflow"]["nodes"] = [{"id": "a", "agent": "reader1", "depends_on": []}]
    s.activate()
    original_content = "Synthetic source d1"
    changed = False
    def change(node, observation):
        nonlocal changed
        if observation["status"] == "COMMITTED" and not changed:
            changed = True
            s.runtime.storage.ingest("d1", original_content, s.owner)  # Same digest, new version and UNKNOWN label.
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user,
        worker=ScriptedWorker({"a": [read_response(s.refs[0]), read_response(s.refs[0]), done()]}), after_effect=change)
    try:
        result = f.start("changed")
        assert result["status"] in {"REFUSED", "FAILED"}
        assert not any(ob["status"] == "ALREADY_OBSERVED" for ob in result["nodes"]["a"]["observations"])
        assert len(s.runtime.store.inspect_outbox()) == 1
        with s.runtime.store.snapshot() as snap: assert snap.read("document:d1")[1]["version"] == 2
    finally: f.close(); s.runtime.store.close()


def test_pure_read_node_waits_for_verified_delivery_before_completing(tmp_path):
    s = ConfigSystem(tmp_path / "ledger.sqlite")
    s.spec.update(resources=[s.refs[0]], scope=[rule("read_document", "d1")],
        agents=[{"id": "reader1", "role": "Source reader", "scope": [rule("read_document", "d1")]}],
        workflow={"nodes": [{"id": "a", "agent": "reader1", "depends_on": []}]}, outputs=[], acceptance=[{"kind": "read", "resource": "d1"}])
    s.activate()
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user,
        worker=ScriptedWorker({"a": [read_response(s.refs[0])] * 6}))
    receiver, lost = s.runtime.receiver, False
    class LostAck:
        def deliver(self, task, operation, payload):
            nonlocal lost
            result = receiver.deliver(task, operation, payload)
            if not lost: lost = True; raise TimeoutError("lost read acknowledgment")
            return result
    f.tools.receiver = LostAck()
    try:
        waiting = f.start("ack")
        assert waiting["status"] == "DELIVERY_UNKNOWN" and waiting["nodes"]["a"]["phase"] == "DELIVERY_WAIT"
        assert not f.completion("ack")["satisfied"]
        finished = f.resume("ack")
        assert finished["status"] == "SATISFIED" and finished["nodes"]["a"]["reason"] == "registered_acceptance_satisfied"
        assert len(s.runtime.store.inspect_outbox()) == 1
    finally: f.close(); s.runtime.store.close()


def test_structured_schema_omits_published_output_and_rejects_expanded_grammar(tmp_path):
    from atomicroot.integration.prompts import config_response_schema, config_schema_matches
    s = ConfigSystem(tmp_path / "ledger.sqlite")
    spec = model_spec(s); spec["outputs"] = [{"id": "summary", "kind": "summary"}]
    spec["acceptance"] = [{"kind": "output", "output": "summary"}, {"kind": "read", "resource": "d1"}]
    s.activate(spec)
    schemas = []
    class Structured(FakeModel):
        structured_worker_output = True
        async def generate(self, messages, *, response_schema=None):
            schemas.append(response_schema)
            # Repeat output if the generation grammar still offers it.
            has_output = any(c["properties"]["kind"] == {"const": "output"} for c in response_schema["oneOf"])
            output = {"kind": "output", "output": "summary", "content": "Actual fake-model response"} if has_output else done()
            self.calls.append(messages)
            return {"output": output, "actual_model": self.model, "usage": None}
    model = Structured(lambda m: done(), provider="ollama"); model.execution_binding = "schema-progress-v1"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user,
                       bridge=ModelBridge(s.runtime, model, DisabledClassifier(), llm_limits=limits))
    try:
        assert f.start("output")["status"] == "INCOMPLETE"  # Done still cannot invent the missing read.
        assert len(model.calls) == 2
        assert any(c["properties"]["kind"] == {"const": "output"} for c in schemas[0]["oneOf"])
        assert not any(c["properties"]["kind"] == {"const": "output"} for c in schemas[1]["oneOf"])
        agent = spec["agents"][0]
        assert config_schema_matches(schemas[1], agent, spec["outputs"])
        forged = config_response_schema(agent, spec["outputs"])
        forged["oneOf"].append({"type": "object", "properties": {"kind": {"const": "admin"}}})
        assert not config_schema_matches(forged, agent, spec["outputs"])
    finally: f.close(); s.runtime.store.close()
