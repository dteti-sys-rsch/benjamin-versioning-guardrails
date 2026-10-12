import json
import sqlite3
from copy import deepcopy

import pytest

from atomicroot.integration.pilot import PilotHost
from atomicroot.integration.providers import DisabledClassifier, FakeClassifier
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.workflow import AgentWorkflow
from atomicroot.integration.progress import Progress
from atomicroot.integration.prompts import worker_messages


def workflow(host, *, progress=None, model=None, classifier=None):
    bridge = ModelBridge(host.runtime, model or host.fake_model(), classifier or DisabledClassifier(),
                         bootstrap_authorized=True, progress=progress)
    flow = AgentWorkflow(host.runtime, bridge, host.directory / "graph.sqlite", task="pilot", principals=host.principals,
        approver=host.approver, context_resources={r: r + "-context" for r in host.principals}, host=host.contract,
        host_validator=host.validate_proposal, scope_limits=host.scope_limits, max_steps=8)
    return flow, bridge


def approve(host, flow, result):
    host.runtime.broker.decide(result["__interrupt__"][0].value["review_id"], True, host.approver)
    return flow.resume("run")


@pytest.mark.parametrize("scenario", ["literature", "injection", "sensitive", "unknown"])
def test_document_profiles_remove_financial_and_disabled_classifier_scope(tmp_path, scenario):
    h = PilotHost(tmp_path, scenario, model_provider="groq")
    try:
        c = h.contract
        assert c["budget_limit"] == 0
        assert set(c["allowed_tools"]) == {"read_document", "send_email", "model_inference"}
        assert set(c["allowed_recipients"]) == {"alice@corp.id", "groq"}
        assert c["classification_restrictions"] is False
        assert {r["provider"] for r in c["inference_egress"]} == {"groq"}
        assert len(c["inference_egress"]) == 4
        h.validate_proposal(c)
        prompt = worker_messages("reader", "Review", c, [], [], {"spent": 0, "reserved": 0})[0]["content"]
        assert "transfer_funds" not in prompt and "deploy" not in prompt
    finally: h.runtime.store.close()


def test_budget_profile_has_only_payments_context_and_reviewed_increase(tmp_path):
    h = PilotHost(tmp_path, "budget", model_provider="groq")
    flow, bridge = workflow(h)
    try:
        assert not h.documents
        assert set(h.contract["allowed_resources"]) == {"reader-context", "executor-context"}
        assert set(h.contract["allowed_tools"]) == {"model_inference", "transfer_funds"}
        assert set(h.contract["allowed_recipients"]) == {"groq", "account"}
        assert h.contract["purpose"] == "payments"
        assert all(r["labels"] == ["UNKNOWN"] for r in h.contract["inference_egress"])
        initial = flow.start("run", "Two synthetic payments of 400")
        assert initial["__interrupt__"][0].value["preview"]["proposal"]["budget_limit"] == 500
        revision = approve(h, flow, initial)
        assert revision["__interrupt__"][0].value["preview"]["proposal"]["budget_limit"] == 800
        with h.runtime.store.snapshot() as s: assert s.read("budget:pilot")[1] == 400
        result = approve(h, flow, revision)
        assert result["status"] == "DONE"
        with h.runtime.store.snapshot() as s: assert s.read("budget:pilot")[1] == 800
        assert len([o for o in result["observations"] if o["status"] == "COMMITTED"]) == 2
    finally:
        flow.close()
        h.runtime.store.close()


def test_classifier_scope_enabled_only_for_actual_pilot_target(tmp_path):
    h = PilotHost(tmp_path, model_provider="groq", classification_enabled=True)
    flow, bridge = workflow(h, classifier=FakeClassifier())
    try:
        assert "classify_document" in h.contract["allowed_tools"]
        assert h.contract["classification_restrictions"] is True
        rules = [r for r in h.contract["inference_egress"] if r["provider"] == "typesafe"]
        assert rules == [{"provider": "typesafe", "resource": "paper", "purpose": "research", "labels": ["PUBLIC"]}]
        result = approve(h, flow, flow.start("run", "Read and summarize"))
        doc = h.documents["paper"]
        c = bridge.classify("classification", "run", resource="paper", digest=doc["digest"], version=doc["version"],
                           principal=h.principals["reader"], task="pilot", purpose="research")
        assert c["status"] == "COMMITTED" and c["detail"]["delivery"] == "RELEASED"
        other = h.documents["paper-2"]
        rejected = bridge.classify("other", "run", resource="paper-2", digest=other["digest"], version=other["version"],
                                  principal=h.principals["reader"], task="pilot", purpose="research")
        assert rejected["status"] == "DENY"
        assert len(bridge.receiver.classifier.calls) == 1
    finally:
        flow.close()
        h.runtime.store.close()


@pytest.mark.parametrize("change", [
    {"budget_limit": 1000}, {"allowed_tools": ["transfer_funds"]},
    {"allowed_resources": ["other-resource"]}, {"allowed_recipients": ["evil@example.org"]},
    {"allowed_agents": ["attacker"]}, {"purpose": "other"}, {"task_id": "other-task"},
    {"unknown_release": "ESCALATE"}, {"classification_restrictions": True},
    {"inference_egress": [{"provider": "evil", "resource": "paper", "purpose": "research", "labels": ["SENSITIVE"]}]},
])
def test_host_scope_rejects_expanded_proposal_before_human_review(tmp_path, change):
    h = PilotHost(tmp_path, model_provider="groq")
    model = h.fake_model()
    model.responder = lambda _: {"kind": "contract", "proposal": {**deepcopy(h.contract), **change}, "unsupported": []}
    flow, bridge = workflow(h, model=model)
    try:
        result = flow.start("run", "Read both sources and summarize to Alice")
        assert result["status"] == "NEEDS_CLARIFICATION"
        assert "__interrupt__" not in result and not h.runtime.store.inspect_outbox()
        with h.runtime.store.snapshot() as s: assert s.read("contract3:pilot")[1] is None
        assert len(model.calls) == 3  # original + bounded repairs, no approval bypass
    finally:
        flow.close()
        h.runtime.store.close()


def test_scope_validation_accepts_rule_order_and_rejects_label_widening(tmp_path):
    h = PilotHost(tmp_path)
    try:
        p = deepcopy(h.contract)
        p["inference_egress"].reverse()
        for r in p["inference_egress"]: r["labels"].reverse()
        h.validate_proposal(p)
        p["inference_egress"][0]["labels"].append("SENSITIVE")
        with pytest.raises(ValueError): h.validate_proposal(p)
    finally: h.runtime.store.close()


def test_progress_records_real_flow_without_prompt_payload_or_secrets(tmp_path, capsys):
    h = PilotHost(tmp_path, model_provider="groq")
    log = Progress(tmp_path / "progress.jsonl")
    model = h.fake_model()
    original = model.responder
    def respond(messages):
        o = original(messages)
        if o.get("tool") == "send_email": o["args"]["body"] = "PRIVATE_BODY_SENTINEL"
        return o
    model.responder = respond
    flow, bridge = workflow(h, model=model, progress=log)
    try:
        result = approve(h, flow, flow.start("run", "PRIVATE_GOAL_SENTINEL"))
        assert result["status"] == "DONE"
        raw = (tmp_path / "progress.jsonl").read_text()
        rows = [json.loads(line) for line in raw.splitlines()]
        events = [r["event"] for r in rows]
        assert {"AUTHOR", "CONTRACT_VALIDATION", "CONTRACT_REVIEW", "CONTRACT_ACTIVE", "WORKER",
                "ACTION", "AUTHORIZATION", "COMMIT", "DELIVERY", "INFERENCE_CALL", "INFERENCE_RETURNED"} <= set(events)
        assert events.index("CONTRACT_ACTIVE") < events.index("ACTION")
        assert events.count("INFERENCE_CALL") == len(model.calls)
        assert "PRIVATE_BODY_SENTINEL" not in raw and "PRIVATE_GOAL_SENTINEL" not in raw
        assert "PRIVATE_BODY_SENTINEL" not in capsys.readouterr().out
        assert [r["sequence"] for r in rows] == list(range(1, len(rows) + 1))
        quiet = Progress(tmp_path / "progress.jsonl", quiet=True)
        quiet("WORKFLOW", status="DONE")
        assert not capsys.readouterr().out
    finally:
        flow.close()
        h.runtime.store.close()


def test_broken_progress_sink_does_not_change_authorization_or_effect(tmp_path):
    h = PilotHost(tmp_path)
    def broken(*args, **kwargs): raise OSError("failed local log sink")
    flow, bridge = workflow(h, progress=broken)
    try:
        result = approve(h, flow, flow.start("run", "Summarize both sources"))
        assert result["status"] == "DONE"
        assert len([o for o in result["observations"] if o["status"] == "COMMITTED"]) == 3
    finally:
        flow.close()
        h.runtime.store.close()


@pytest.mark.parametrize("change", [
    {"allowed_tools": ["model_inference", "transfer_funds", "send_email"]},
    {"budget_limit": 1000},
])
def test_worker_revision_cannot_expand_host_scope_or_reset_spend(tmp_path, change):
    h = PilotHost(tmp_path, "budget")
    model = h.fake_model()
    original = model.responder
    def respond(messages):
        output = original(messages)
        if "approved_contract" in json.loads(messages[-1]["content"]) and output.get("kind") == "contract":
            output["proposal"].update(change)
        return output
    model.responder = respond
    flow, _ = workflow(h, model=model)
    try:
        result = approve(h, flow, flow.start("run", "Two synthetic payments of 400"))
        assert "__interrupt__" not in result and result["status"] == "STEP_LIMIT"
        assert any(o["status"] == "REJECTED" for o in result["observations"])
        with h.runtime.store.snapshot() as snap:
            assert snap.read("contract3:pilot")[1]["budget_limit"] == 500
            assert snap.read("budget:pilot")[1] == 400
            assert "send_email" not in snap.read("contract3:pilot")[1]["allowed_tools"]
        assert len([o for o in h.runtime.store.inspect_outbox() if json.loads(o["payload"])["tool"] == "transfer_funds"]) == 1
    finally:
        flow.close()
        h.runtime.store.close()


def test_cli_blocks_legacy_binding_without_changing_ledger_or_checkpoint(tmp_path, monkeypatch):
    import phase35_cli
    command = ["phase35_cli.py", "--directory", str(tmp_path), "--scenario", "budget",
               "--fixture-approve", "--quiet-progress"]
    monkeypatch.setattr("sys.argv", command)
    with pytest.raises(SystemExit) as first: phase35_cli.main()
    assert first.value.code == 0
    status = (tmp_path / "status.json").read_bytes()
    checkpoint = (tmp_path / "graph.sqlite").read_bytes()
    with sqlite3.connect(tmp_path / "ledger.sqlite") as conn:
        current = json.loads(conn.execute("SELECT data FROM inference_jobs WHERE id='cli-config'").fetchone()[0])
        legacy = {k: current[k] for k in ("scenario", "model", "model_mode")}
        conn.execute("UPDATE inference_jobs SET data=? WHERE id='cli-config'", (json.dumps(legacy),))
        conn.commit()
        before = list(conn.iterdump())
    def no_graph(*args, **kwargs): raise AssertionError("changed binding must stop before workflow/model calls")
    monkeypatch.setattr(phase35_cli, "AgentWorkflow", no_graph)
    monkeypatch.setattr("sys.argv", command + ["--recover"])
    with pytest.raises(SystemExit) as blocked: phase35_cli.main()
    assert blocked.value.code == 2
    assert json.loads((tmp_path / "status-blocked.json").read_text())["error"] == "RUN_CONFIGURATION_CHANGED"
    assert (tmp_path / "status.json").read_bytes() == status
    assert (tmp_path / "graph.sqlite").read_bytes() == checkpoint
    with sqlite3.connect(tmp_path / "ledger.sqlite") as conn: assert list(conn.iterdump()) == before
