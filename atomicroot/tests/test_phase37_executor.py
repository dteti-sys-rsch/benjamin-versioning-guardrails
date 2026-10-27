"""Executor A tests: controlled schedules and ledger evidence, entirely offline."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from pathlib import Path
import json

import pytest
from fastapi.testclient import TestClient

from atomicroot.tests.test_phase36_tasks import ConfigSystem, rule
from atomicroot.framework.app import FrameworkRuntime, create_phase3_app
from atomicroot.framework.identity import Principal
from atomicroot.framework.runtime import envelope
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import TaskSpec, task_schema
from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.providers import FakeModel, FakeClassifier, DisabledClassifier, Limits
from atomicroot.integration.guarded import GuardedTools
from atomicroot.integration.progress import Progress


@pytest.fixture
def system(tmp_path):
    system = ConfigSystem(tmp_path / "ledger.sqlite")
    yield system
    system.runtime.store.close()


def read_response(ref): return {"kind": "action", "tool": "read_document", "args": {"resource": ref["resource"], "digest": ref["digest"]}}
def done(): return {"kind": "done", "summary": "finished"}
def send(): return {"kind": "action", "tool": "send_email", "args": {"to": "alice@corp.id", "body": "Synthetic summary"}}


def literature_worker(s):
    return ScriptedWorker({"a": [read_response(s.refs[0]), done()], "b": [read_response(s.refs[1]), done()],
        "join": [{"kind": "output", "output": "summary", "content": "Synthetic summary"}, send(), done()]})


def flow(s, path, worker=None, **kw):
    return ConfigWorkflow(s.runtime, path, task=s.spec["task_id"], caller=s.user, worker=worker or literature_worker(s), **kw)


def test_two_configs_three_agents_overlap_join_and_evidence(system, tmp_path):
    s = system; s.activate()
    gate = Barrier(2)
    order = []; reached = set()
    def hook(stage, node):
        if stage == "worker_ready" and node in {"a", "b"} and node not in reached:
            reached.add(node); gate.wait(timeout=5)
        if stage == "worker_ready" and node == "join":
            assert {"a", "b"} <= reached
        order.append((stage, node))
    f = flow(s, tmp_path / "graph.sqlite", hook=hook)
    try:
        result = f.start("run")
        assert result["status"] == "SATISFIED", result
        assert all(d["phase"] == "DONE" for d in result["nodes"].values())
        assert len(result["nodes"]["a"]["observations"]) == len(result["nodes"]["b"]["observations"]) == 1
        evidence = result["completion"]
        assert evidence["quality"] == "NOT_EVALUATED" and all(e["evidence"] for e in evidence["criteria"])
        with s.runtime.store.snapshot() as snap: assert snap.read("exposure:t")[1] == ["PUBLIC"]
        history = f.status("run")["history"]
        receipts = s.runtime.store.inspect_outbox()
        assert len(receipts) == 3
        assert f.recover("run")["status"] == "SATISFIED"
        with pytest.raises(ValueError): f.start("run")
        assert f.status("run")["history"] == history
        assert s.runtime.store.inspect_outbox() == receipts
        assert f.status("run")["invocations"][-1]["status"] == "INVOCATION_FAILED"
    finally: f.close()
    payment = deepcopy(s.spec)
    payment.update(task_id="payments", purpose="payments", resources=[], budget_limit=600, outputs=[],
        scope=[rule("transfer_funds", destination="account-1", purpose="payments", amount=300), rule("transfer_funds", destination="account-2", purpose="payments", amount=300)],
        acceptance=[{"kind": "receipt", "tool": "transfer_funds", "destination": "account-1"}, {"kind": "receipt", "tool": "transfer_funds", "destination": "account-2"}])
    payment["agents"][0]["scope"] = [payment["scope"][0]]; payment["agents"][1]["scope"] = [payment["scope"][1]]; payment["agents"][2]["scope"] = []
    s.activate(payment)
    worker = ScriptedWorker({"a": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-1", "amount": 200}}, done()],
        "b": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-2", "amount": 200}}, done()], "join": [done()]})
    f = ConfigWorkflow(s.runtime, tmp_path / "graph.sqlite", task="payments", caller=s.user, worker=worker)
    try:
        assert f.start("second")["status"] == "SATISFIED"
        with s.runtime.store.snapshot() as snap: assert snap.read("budget:payments")[1] == 400
    finally: f.close()


def test_done_and_forged_evidence_are_not_completion(system, tmp_path):
    s = system; s.activate()
    f = flow(s, tmp_path / "g.sqlite", ScriptedWorker({n: [done()] for n in ("a", "b", "join")}))
    try:
        result = f.start("empty")
        assert result["status"] == "INCOMPLETE"
        assert not any(e["satisfied"] for e in result["completion"]["criteria"])
    finally: f.close()


@pytest.mark.parametrize("response", [send(), {"kind": "action", "tool": "send_email", "args": {"to": "alice@corp.id", "body": "x"}, "grant": "forged"}])
def test_hidden_scope_and_worker_grant_cannot_bypass(system, tmp_path, response):
    s = system; s.activate()
    f = flow(s, tmp_path / "g.sqlite", ScriptedWorker({"a": [response] * 4, "b": [done()], "join": [done()]}))
    try:
        result = f.start("blocked")
        assert result["status"] in {"REFUSED", "UNSUPPORTED"}
        assert not s.runtime.store.inspect_outbox()
    finally: f.close()


def test_commit_before_ack_recovery_dedupes_and_keeps_exposure(system, tmp_path):
    s = system; s.activate()
    failed = Event()
    def crash(node, observation):
        if node == "a" and observation["status"] == "COMMITTED" and not failed.is_set():
            failed.set(); raise RuntimeError("simulated crash before checkpoint acknowledgment")
    f = flow(s, tmp_path / "g.sqlite", after_effect=crash)
    try:
        with pytest.raises(RuntimeError): f.start("recover")
        rows = s.runtime.store.inspect_outbox()
        assert len(rows) == 2
        with s.runtime.store.snapshot() as snap: exposure = snap.read("exposure:t")
    finally: f.close()
    f = flow(s, tmp_path / "g.sqlite")
    try:
        assert f.recover("recover")["status"] == "SATISFIED"
        assert len(s.runtime.store.inspect_outbox()) == 3
        with s.runtime.store.snapshot() as snap:
            assert snap.read("exposure:t") == exposure
            assert snap._conn.execute("SELECT count(*) FROM receiver_receipts WHERE task='t'").fetchone()[0] == 3
    finally: f.close()


def test_concurrent_invocations_cannot_overwrite_checkpoint(system, tmp_path):
    s = system; s.activate()
    arrived, release = Event(), Event()
    def hook(stage, node):
        if stage == "worker_ready" and node == "a": arrived.set(); assert release.wait(5)
    f = flow(s, tmp_path / "g.sqlite", hook=hook)
    g = flow(s, tmp_path / "g.sqlite")
    try:
        with ThreadPoolExecutor(2) as pool:
            future = pool.submit(f.start, "same")
            assert arrived.wait(5)
            with pytest.raises(ValueError, match="active"): g.recover("same")
            release.set()
            assert future.result(timeout=10)["status"] == "SATISFIED"
        assert g.status("same")["status"] == "SATISFIED"
    finally: release.set(); f.close(); g.close()


def test_changed_config_or_driver_rejected_without_reset(system, tmp_path):
    s = system; s.activate()
    f = flow(s, tmp_path / "g.sqlite")
    try: assert f.start("bound")["status"] == "SATISFIED"
    finally: f.close()
    before = s.runtime.store.inspect_outbox()
    changed = flow(s, tmp_path / "g.sqlite", ScriptedWorker({"a": [done()]}))
    try:
        with pytest.raises(ValueError, match="binding"): changed.recover("bound")
        assert changed.status("bound")["status"] == "SATISFIED"
    finally: changed.close()
    revised = deepcopy(s.spec); revised["objective"] = "Reviewed new objective"; s.activate(revised)
    f = flow(s, tmp_path / "g.sqlite")
    try:
        with pytest.raises(ValueError, match="binding"): f.recover("bound")
        assert s.runtime.store.inspect_outbox() == before
        with s.runtime.store.snapshot() as snap: assert snap.read("exposure:t")[1] == ["PUBLIC"]
    finally: f.close()


def review_system(s):
    ref = s.refs[0]
    s.runtime.labels.set_label("d1", ref["digest"], ref["version"], "UNKNOWN", ["research"], s.owner)
    s.spec["unknown_release"] = "ESCALATE"
    s.activate()


@pytest.mark.parametrize("decision", ["approve", "reject", "pause", "stale"])
def test_review_broker_pause_reject_stale_restart(system, tmp_path, decision):
    s = system; review_system(s)
    f = flow(s, tmp_path / "g.sqlite")
    try:
        result = f.start("review")
        assert result["status"] == "REVIEW_WAIT" and result.get("__interrupt__")
        review_id = result["nodes"]["join"]["review"]
        before = s.runtime.store.inspect_outbox()
        assert len(before) == 2
        if decision == "pause":
            assert f.resume("review").get("__interrupt__")
            assert s.runtime.store.inspect_outbox() == before
        elif decision == "stale":
            s.runtime.catalog.set_destination({"destination": "alice@corp.id", "kind": "recipient", "purposes": ["research"],
                "endpoint": None, "models": [], "labels": []}, s.admin)
            with pytest.raises(ValueError, match="stale"): s.runtime.broker.decide(review_id, True, s.approver)
            updated = f.resume("review")
            assert updated.get("__interrupt__") and updated["nodes"]["join"]["review"] != review_id
            assert s.runtime.store.inspect_outbox() == before
        else:
            s.runtime.broker.decide(review_id, decision == "approve", s.approver)
            f.close(); f = flow(s, tmp_path / "g.sqlite")
            result = f.resume("review")
            assert result["status"] == ("SATISFIED" if decision == "approve" else "REVIEW_REJECTED")
            assert len(s.runtime.store.inspect_outbox()) == (3 if decision == "approve" else 2)
    finally: f.close()


def test_model_context_is_bound_and_no_author_call(system, tmp_path):
    s = system
    ctxrule = rule("model_inference", "ctx", "ollama")
    s.runtime.catalog.set_destination({"destination": "ollama", "kind": "provider", "purposes": ["research"],
        "endpoint": "http://localhost:11434/api", "models": ["offline-script-v1"], "labels": ["PUBLIC", "UNKNOWN"]}, s.admin)
    s.spec["resources"].append({**s.refs[2], "binding": "host_context"})
    s.spec["scope"].extend([ctxrule, rule("model_inference", "d1", "ollama")])
    s.spec["provider"] = {"destination": "ollama", "model": "offline-script-v1"}
    # One worker performs a read with a context that changes on its next decision.
    s.spec["agents"] = [{"id": "reader1", "role": "Researcher", "scope": s.spec["scope"]}]
    s.spec["workflow"]["nodes"] = [{"id": "a", "agent": "reader1", "depends_on": []}]
    s.spec["acceptance"] = [{"kind": "read", "resource": "d1"}, {"kind": "receipt", "tool": "send_email", "destination": "alice@corp.id"}]
    s.spec["outputs"] = []
    rights = deepcopy(s.rights)
    if ctxrule not in rights["scope"]: rights["scope"].append(ctxrule)
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    s.activate()
    responses = [read_response(s.refs[0]), send()]
    model = FakeModel(lambda messages: responses[json.loads(messages[-1]["content"])["step"]], provider="ollama")
    model.execution_binding = "test-fixture-v1"
    limits = Limits(**TaskSpec.parse(s.spec).data["limits"]["inference"])
    bridge = ModelBridge(s.runtime, model, DisabledClassifier(), llm_limits=limits)
    errors = []
    original = bridge.worker
    def monitored(*args, **kw):
        try: return original(*args, **kw)
        except Exception as exc: errors.append(str(exc)); raise
    bridge.worker = monitored
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user, bridge=bridge)
    try:
        result = f.start("model")
        assert result["status"] == "SATISFIED", errors
        assert len(model.calls) == 2
        assert all("delegation" in json.loads(m[-1]["content"]) for m in model.calls)
        assert len(s.runtime.store.inspect_outbox()) == 4
        with s.runtime.store.snapshot() as snap: assert snap.read("document:ctx")[1]["version"] == 3
        assert f.recover("model")["status"] == "SATISFIED" and len(model.calls) == 2
        # A worker cannot use an approved context identity with bytes absent from a trusted job.
        with s.runtime.store.snapshot() as snap: doc = snap.read("document:ctx")[1]
        request, principal = s.request("reader1", "model_inference", {"resource": "ctx", "digest": doc["digest"], "to": "ollama"}, op="forged-context")
        assert s.runtime.authority.authorize(request, principal)["decision"] == "EVALUATION_ERROR"
        assert len(model.calls) == 2
    finally: f.close()


def test_api_user_only_and_no_worker_driver_in_body(system, tmp_path):
    s = system; s.activate()
    worker = literature_worker(s)
    factory = lambda task, caller: ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task=task, caller=caller, worker=worker)
    identity = [s.user]
    client = TestClient(create_phase3_app(s.runtime, lambda request: identity[0], executor_factory=factory))
    assert client.post("/tasks/t/runs/api/start", json={"worker": "evil"}).status_code == 422
    assert client.post("/tasks/t/runs/api/start", json={}).json()["status"] == "SATISFIED"
    identity[0] = s.runtime.tasks.principal("t", "reader1", s.user)
    assert client.post("/tasks/t/runs/evil/start", json={}).status_code == 403


def test_parallel_progress_sequence_is_redacted(tmp_path):
    progress = Progress(tmp_path / "p.jsonl", quiet=True)
    with ThreadPoolExecutor(4) as pool: list(pool.map(lambda n: progress("WORKER", step=n, status="READY"), range(100)))
    rows = [json.loads(row) for row in (tmp_path / "p.jsonl").read_text().splitlines()]
    assert [r["sequence"] for r in rows] == list(range(1, 101))
    assert [r["session_elapsed_ms"] for r in rows] == sorted(r["session_elapsed_ms"] for r in rows)
    assert all(r["since_previous_ms"] >= 0 for r in rows)
    with pytest.raises(ValueError): progress("WORKER", body="secret")


def test_phase35_fresh_start_failure_preserves_previous_success(tmp_path, monkeypatch):
    import phase35_cli
    command = ["phase35_cli.py", "--directory", str(tmp_path), "--scenario", "literature", "--fixture-approve", "--quiet-progress"]
    monkeypatch.setattr("sys.argv", command)
    with pytest.raises(SystemExit) as first: phase35_cli.main()
    assert first.value.code == 0
    status, transcript = (tmp_path / "status.json").read_bytes(), (tmp_path / "transcript.json").read_bytes()
    with pytest.raises(SystemExit) as second: phase35_cli.main()
    assert second.value.code == 1
    assert (tmp_path / "status.json").read_bytes() == status
    assert (tmp_path / "transcript.json").read_bytes() == transcript
    monkeypatch.setattr("sys.argv", command + ["--provider", "ollama", "--model", "qwen3:latest"])
    with pytest.raises(SystemExit) as third: phase35_cli.main()
    assert third.value.code == 2
    assert (tmp_path / "status.json").read_bytes() == status and (tmp_path / "transcript.json").read_bytes() == transcript
    assert len(list((tmp_path / "invocations").glob("*.json"))) == 3


@pytest.mark.parametrize("scenario", ["exfil", "budget"])
def test_executor_two_initial_allow_stale_no_second_effect_separate_connections(system, tmp_path, monkeypatch, scenario):
    s = system
    if scenario == "exfil":
        ref = s.refs[0]; s.runtime.labels.set_label("d1", ref["digest"], ref["version"], "SENSITIVE", ["research"], s.owner)
        spec = deepcopy(s.spec)
        spec.update(resources=[ref], scope=[rule("read_document", "d1"), rule("send_email", destination="alice@corp.id")], outputs=[],
                    acceptance=[{"kind": "read", "resource": "d1"}, {"kind": "receipt", "tool": "send_email", "destination": "alice@corp.id"}])
        responses = {"a": [read_response(ref), done()], "b": [send(), done()], "join": [done()]}
    else:
        spec = deepcopy(s.spec)
        spec.update(task_id="payments", purpose="payments", resources=[], budget_limit=500, outputs=[],
                    scope=[rule("transfer_funds", destination="account-1", purpose="payments", amount=300), rule("transfer_funds", destination="account-2", purpose="payments", amount=300)],
                    acceptance=[{"kind": "receipt", "tool": "transfer_funds", "destination": "account-1"}, {"kind": "receipt", "tool": "transfer_funds", "destination": "account-2"}])
        responses = {"a": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-1", "amount": 300}}, done()],
                     "b": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-2", "amount": 300}}, done()], "join": [done()]}
    spec["agents"][0]["scope"] = [spec["scope"][0]]; spec["agents"][1]["scope"] = [spec["scope"][1]]; spec["agents"][2]["scope"] = []
    s.activate(spec)
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task=spec["task_id"], caller=s.user, worker=ScriptedWorker(responses))
    second = FrameworkRuntime(s.path, signing_key=s.runtime.authority._sk, clock=s.clock)
    gate, first_committed = Barrier(2), Event()
    sequence, auths, commits = [], [], []
    first_op = f.operation({"run": "race"}, "a", 0, "action")
    second_op = f.operation({"run": "race"}, "b", 0, "action")
    class Schedule:
        def checkpoint(self, stage, op):
            sequence.append((stage, op))
            if stage == "before_cas" and op in {first_op, second_op}:
                gate.wait(timeout=5)
                if op == second_op: assert first_committed.wait(5)
            if stage == "after_commit" and op == first_op: first_committed.set()
    schedule = Schedule()
    with s.runtime.store.snapshot() as snap:
        initial_keys = [prefix + spec["task_id"] for prefix in ("budget:", "reserved:", "exposure:", "contract3:", "policyset:")]
        initial_keys += [prefix + ref["resource"] for ref in spec["resources"] for prefix in ("document:", "label:")]
        initial_state = {key: snap.read(key) for key in initial_keys}
    for runtime in (s.runtime, second):
        runtime.authority.harness = runtime.gateway.harness = schedule
        original_auth, original_commit = runtime.authority.authorize, runtime.gateway.commit
        def auth(*args, _fn=original_auth, **kw):
            result = _fn(*args, **kw); auths.append((args[0]["operation_id"], result.get("decision"))); return result
        def commit(*args, _fn=original_commit, **kw):
            result = _fn(*args, **kw); commits.append((kw["action_id"], result["status"])); return result
        monkeypatch.setattr(runtime.authority, "authorize", auth); monkeypatch.setattr(runtime.gateway, "commit", commit)
    tools1, tools2 = GuardedTools(s.runtime), GuardedTools(second)
    def execute(request, principal, **kw): return (tools1 if request["operation_id"] == first_op else tools2).execute(request, principal, **kw)
    monkeypatch.setattr(f.tools, "execute", execute)
    try:
        result = f.start("race")
        assert result["status"] == "REFUSED"
        assert (first_op, "ALLOW") in auths and (second_op, "ALLOW") in auths and (second_op, "DENY") in auths
        assert (second_op, "STALE_TICKET") in commits
        rows = s.runtime.store.inspect_outbox()
        assert len(rows) == 1 and rows[0]["operation"] == first_op and rows[0]["status"] == "RELEASED"
        assert ("after_commit", first_op) in sequence
        (tmp_path / "schedule.json").write_text(dumps({"scenario": scenario, "task_spec": spec,
            "initial_state": initial_state, "steps": sequence, "authorization_results": auths, "commit_results": commits}), encoding="utf-8")
        with s.runtime.store.snapshot() as snap:
            if scenario == "budget": assert snap.read("budget:payments")[1] == 300 and snap.read("reserved:payments")[1] == 0
            else: assert snap.read("exposure:t")[1] == ["SENSITIVE"]
    finally: f.close(); second.store.close()


def test_delivery_unknown_resume_reconciles_stable_operation(system, tmp_path):
    s = system; s.activate()
    f = flow(s, tmp_path / "g.sqlite")
    receiver = s.runtime.receiver
    ambiguous = Event()
    class LostAck:
        def deliver(self, task, operation, payload):
            receipt = receiver.deliver(task, operation, payload)
            if payload["tool"] == "send_email" and not ambiguous.is_set():
                ambiguous.set(); raise TimeoutError("lost acknowledgment")
            return receipt
    f.tools.receiver = LostAck(); f.tools.max_dispatch = 1
    try:
        result = f.start("lost")
        assert result["status"] == "DELIVERY_UNKNOWN" and result.get("__interrupt__")
        assert not f.completion("lost")["satisfied"]
        op = result["nodes"]["join"]["pending"]["operation_id"]
        resumed = f.resume("lost")
        assert resumed["status"] == "SATISFIED", (resumed["nodes"]["join"]["phase"], s.runtime.store.inspect_outbox()[-1]["attempts"], f.graph.get_state(f.config("lost")).interrupts)
        rows = s.runtime.store.inspect_outbox()
        assert len(rows) == 3 and any(r["operation"] == op and r["attempts"] == 2 for r in rows)
        with s.runtime.store.snapshot() as snap: assert snap._conn.execute("SELECT count(*) FROM receiver_receipts WHERE task='t'").fetchone()[0] == 3
    finally: f.close()


def model_spec(s, *, classifier=False):
    spec = deepcopy(s.spec)
    inference = [rule("model_inference", "ctx", "ollama"), rule("model_inference", "d1", "ollama")]
    spec.update(resources=[s.refs[0], {**s.refs[2], "binding": "host_context"}],
        scope=[rule("read_document", "d1"), rule("send_email", destination="alice@corp.id"), *inference], outputs=[],
        acceptance=[{"kind": "read", "resource": "d1"}, {"kind": "receipt", "tool": "send_email", "destination": "alice@corp.id"}],
        provider={"destination": "ollama", "model": "offline-script-v1"})
    s.runtime.catalog.set_destination({"destination": "ollama", "kind": "provider", "purposes": ["research"],
        "endpoint": "http://localhost:11434/api", "models": ["offline-script-v1"], "labels": ["PUBLIC", "UNKNOWN", "SENSITIVE"]}, s.admin)
    if classifier:
        spec["scope"].append(rule("classify_document", "d1", "typesafe"))
        spec["classifier"] = {"mode": "jev", "destination": "typesafe", "model": "jev-1.13.0", "resources": ["d1"], "before_nodes": ["a"]}
        s.runtime.catalog.set_destination({"destination": "typesafe", "kind": "provider", "purposes": ["research"],
            "endpoint": "https://api.typesafe.ai", "models": ["jev-1.13.0"], "labels": ["PUBLIC", "UNKNOWN"]}, s.admin)
    spec["agents"] = [{"id": "reader1", "role": "Configurable research worker", "scope": spec["scope"]}]
    spec["workflow"]["nodes"] = [{"id": "a", "agent": "reader1", "depends_on": []}]
    rights = deepcopy(s.rights); rights["scope"] = spec["scope"]
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    return spec


@pytest.mark.parametrize("candidate", ["PUBLIC", "SENSITIVE", "ERROR", "ERROR_PUBLIC", "STALE"])
def test_classifier_timing_false_public_failure_and_stale_do_not_open_release(system, tmp_path, candidate):
    s = system; ref = s.refs[0]
    if candidate in {"PUBLIC", "ERROR"}: s.runtime.labels.set_label("d1", ref["digest"], ref["version"], "UNKNOWN", ["research"], s.owner)
    spec = model_spec(s, classifier=True); s.activate(spec)
    order = []
    def before():
        order.append("classifier")
        if candidate == "STALE": s.runtime.storage.ingest("d1", "Changed synthetic version", s.owner)
    label = "SENSITIVE" if candidate == "STALE" else "ERROR" if candidate == "ERROR_PUBLIC" else candidate
    response = RuntimeError("classifier failure") if label == "ERROR" else {"outcome": "SUCCESS", "candidate_label": label, "confidence": 1.,
        "probabilities": {"PUBLIC": float(label == "PUBLIC"), "SENSITIVE": float(label == "SENSITIVE"), "UNKNOWN": 0.}, "reason": "test fixture"}
    classifier = FakeClassifier(response, before_response=before); classifier.execution_binding = "classifier-fixture-" + candidate
    responses = [read_response(ref), send(), done()]
    def respond(messages):
        order.append("model")
        return responses[json.loads(messages[-1]["content"])["step"]]
    model = FakeModel(respond, provider="ollama"); model.execution_binding = "classifier-workflow-model-v1"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    bridge = ModelBridge(s.runtime, model, classifier, llm_limits=limits, jev_limits=limits)
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user, bridge=bridge)
    try:
        result = f.start("classification")
        assert result["status"] == "SATISFIED" if candidate == "ERROR_PUBLIC" else result["status"] in {"REFUSED", "FAILED"}, result
        assert order[0] == "classifier" and len(classifier.calls) == 1
        assert any(json.loads(r["payload"])["tool"] == "send_email" for r in s.runtime.store.inspect_outbox()) == (candidate == "ERROR_PUBLIC")
        with s.runtime.store.snapshot() as snap:
            official = snap.read("label:d1")[1]
            proposals = [json.loads(r[0]) for r in snap._conn.execute("SELECT data FROM classification_proposals")]
            if candidate in {"PUBLIC", "ERROR"}: assert official["label"] == "UNKNOWN"
            elif candidate == "ERROR_PUBLIC": assert official["label"] == "PUBLIC" and not official.get("restrictions")
            elif candidate == "SENSITIVE": assert official["label"] == "PUBLIC" and official["restrictions"][0]["label"] == "SENSITIVE"
            else: assert proposals[0]["status"] == "STALE" and official["label"] == "UNKNOWN"
    finally: f.close()


def test_model_and_classifier_without_current_scope_make_zero_calls(system, tmp_path):
    s = system
    spec = model_spec(s, classifier=True); s.activate(spec)
    model = FakeModel(lambda m: done(), provider="ollama"); model.execution_binding = "blocked-model"
    classifier = FakeClassifier(); classifier.execution_binding = "blocked-classifier"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    bridge = ModelBridge(s.runtime, model, classifier, llm_limits=limits, jev_limits=limits)
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user, bridge=bridge)
    # Official admin update removes both inference rights after activation.
    rights = deepcopy(s.rights); rights["scope"] = [rule("read_document", "d1"), rule("send_email", destination="alice@corp.id")]
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    try:
        assert f.start("blocked")["status"] == "FAILED"
        assert model.calls == classifier.calls == []
        assert not s.runtime.store.inspect_outbox()
    finally: f.close()


@pytest.mark.parametrize("failure", ["missing", "solver", "identity"])
def test_executor_security_failure_no_effect(system, tmp_path, monkeypatch, failure):
    s = system; s.activate()
    f = flow(s, tmp_path / "g.sqlite", ScriptedWorker({"a": [read_response(s.refs[0])], "b": [done()], "join": [done()]}))
    if failure == "missing":
        # Trusted corruption fixture; missing fact must fail closed, not default to zero.
        with s.runtime.store.transaction() as conn: conn.execute("DELETE FROM conflict_keys WHERE key='budget:t'")
    elif failure == "solver":
        def fail(*args, **kwargs): raise RuntimeError("solver unavailable")
        monkeypatch.setattr("atomicroot.framework.runtime.solve", fail)
    else:
        f.principals["reader1"] = Principal("forged-subject", frozenset({"worker"}), frozenset({"t"}))
    try:
        result = f.start("failure")
        assert result["status"] in {"FAILED", "REFUSED"}, result
        assert not s.runtime.store.inspect_outbox()
    finally: f.close()


@pytest.mark.parametrize("case", ["timeout", "steps", "unsupported"])
def test_explicit_terminal_bounds(system, tmp_path, case):
    s = system
    s.spec["limits"]["max_steps"] = 1; s.activate()
    class Worker:
        binding = {"mode": "test-offline", "case": case}
        def __call__(self, view):
            if case == "timeout": raise TimeoutError("test deadline")
            if case == "unsupported": return {"kind": "action", "tool": "unregistered", "args": {}}
            return read_response(s.refs[0 if view["node"] == "a" else 1])
    f = flow(s, tmp_path / "g.sqlite", Worker())
    try:
        status = f.start("bounds")["status"]
        assert status == ("TIMEOUT" if case == "timeout" else "RETRY_EXHAUSTED")
    finally: f.close()


@pytest.mark.parametrize("mode", ["scripted", "fake"])
def test_real_examples_cli_execution_and_history(tmp_path, monkeypatch, mode):
    import phase36_cli, phase37_cli
    from nacl.signing import SigningKey
    directory = tmp_path / mode; directory.mkdir()
    key = SigningKey.generate(); (directory / "signing.key").write_bytes(bytes(key))
    runtime = FrameworkRuntime(str(directory / "ledger.sqlite"), signing_key=key)
    try:
        fixture = "examples/phase37/trusted-model-fixture.json" if mode == "fake" else "examples/phase36/trusted-fixture.json"
        phase36_cli.init_fixture(runtime, phase36_cli.load(fixture))
        user, approver = phase36_cli.local_identities(runtime)
        spec = phase36_cli.load("examples/phase37/literature-fake-model.json" if mode == "fake" else "examples/phase36/literature.json")
        preview = runtime.tasks.propose(spec, user)
        runtime.broker.decide(preview["review_id"], True, approver)
        runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
        payment_preview = runtime.tasks.propose(phase36_cli.load("examples/phase36/payments.json"), user)
        runtime.broker.decide(payment_preview["review_id"], True, approver)
        runtime.contracts.activate(payment_preview["proposal_id"], payment_preview["review_id"], approver)
        if mode == "fake":
            with pytest.raises(PermissionError): phase37_cli.build_workflow(runtime, directory / "g.sqlite", "literature-a", user, mode="live")
    finally: runtime.store.close()
    argv = ["phase37_cli.py", "--directory", str(directory), "--task", "literature-a", "--worker-mode", mode,
            "--responses", "examples/phase37/literature-responses.json", "--quiet-progress"]
    monkeypatch.setattr("sys.argv", argv + ["start"])
    assert phase37_cli.main() == 0
    monkeypatch.setattr("sys.argv", argv + ["recover"])
    assert phase37_cli.main() == 0
    monkeypatch.setattr("sys.argv", argv + ["start"])
    assert phase37_cli.main() == 1
    monkeypatch.setattr("sys.argv", ["phase37_cli.py", "--directory", str(directory), "--task", "literature-a", "status"])
    assert phase37_cli.main() == 0
    with __import__("sqlite3").connect(directory / "ledger.sqlite") as conn:
        assert conn.execute("SELECT status FROM execution_runs").fetchone()[0] == "SATISFIED"
        assert conn.execute("SELECT count(*) FROM execution_history").fetchone()[0] == 1
        from collections import Counter
        intents = Counter(json.loads(r[0])["tool"] for r in conn.execute("SELECT payload FROM outbox"))
        assert intents == ({"read_document": 2, "send_email": 1, "model_inference": 4} if mode == "fake" else {"read_document": 2, "send_email": 1})
    monkeypatch.setattr("sys.argv", ["phase37_cli.py", "--directory", str(directory), "--task", "payments-a", "--responses", "examples/phase37/payments-responses.json", "start"])
    assert phase37_cli.main() == 0
    with __import__("sqlite3").connect(directory / "ledger.sqlite") as conn:
        assert conn.execute("SELECT status FROM execution_runs WHERE task='payments-a'").fetchone()[0] == "SATISFIED"


def test_config_ollama_schema_binding_stays_guarded(system, tmp_path):
    s = system; spec = model_spec(s); s.activate(spec)
    class StructuredFake(FakeModel):
        structured_worker_output = True
        async def generate(self, messages, *, response_schema=None):
            assert response_schema and not any(c["properties"]["kind"].get("const") == "contract" for c in response_schema["oneOf"])
            return await super().generate(messages)
    model = StructuredFake(lambda m: done(), provider="ollama"); model.execution_binding = "structured-fake-v1"
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user,
                       bridge=ModelBridge(s.runtime, model, DisabledClassifier(), llm_limits=limits))
    try:
        assert f.start("structured")["status"] == "INCOMPLETE"
        assert len(model.calls) == 1
    finally: f.close()


@pytest.mark.parametrize("lost_ack", [True, False])
def test_inference_unknown_recovery_and_persisted_retry_bound(system, tmp_path, lost_ack):
    s = system; spec = model_spec(s); s.activate(spec)
    model = FakeModel(lambda m: done() if lost_ack else RuntimeError("ambiguous model response"), provider="ollama")
    model.execution_binding = {"mode": "test-inference-unknown", "lost_ack": lost_ack}
    limits = Limits(**TaskSpec.parse(spec).data["limits"]["inference"])
    bridge = ModelBridge(s.runtime, model, DisabledClassifier(), llm_limits=limits)
    if lost_ack:
        receiver, lost = bridge.receiver, Event()
        class Receiver:
            async def adeliver(self, task, operation, payload):
                receipt = await receiver.adeliver(task, operation, payload)
                if not lost.is_set(): lost.set(); raise TimeoutError("lost inference receipt")
                return receipt
        bridge.tools.receiver = Receiver()
    f = ConfigWorkflow(s.runtime, tmp_path / "g.sqlite", task="t", caller=s.user, bridge=bridge)
    try:
        result = f.start("inference-unknown")
        assert result["status"] == "DELIVERY_UNKNOWN" and result.get("__interrupt__")
        resumed = f.resume("inference-unknown")
        if lost_ack:
            assert resumed["status"] == "INCOMPLETE" and not resumed.get("__interrupt__")
            assert len(model.calls) == 1
            assert s.runtime.store.inspect_outbox()[0]["status"] == "RELEASED"
        else:
            assert resumed.get("__interrupt__")
            terminal = f.resume("inference-unknown")
            assert terminal["status"] == "DELIVERY_UNKNOWN" and not terminal.get("__interrupt__")
            assert s.runtime.store.inspect_outbox()[0]["attempts"] == 3
            assert len(model.calls) == 1  # Persisted per-call caps prevent repeated provider charges.
            f.recover("inference-unknown")
            assert s.runtime.store.inspect_outbox()[0]["attempts"] == 3
    finally: f.close()


def test_mid_run_official_revision_cannot_rebind_staged_action(system, tmp_path):
    s = system
    s.spec["workflow"]["nodes"] = [{"id": "a", "agent": "reader1", "depends_on": []}]
    s.activate()
    revised = Event()
    def hook(stage, node):
        if stage == "before_effect" and not revised.is_set():
            revised.set()
            next_spec = deepcopy(s.spec); next_spec["objective"] = "Officially revised objective"
            s.activate(next_spec)
    f = flow(s, tmp_path / "g.sqlite", ScriptedWorker({"a": [read_response(s.refs[0]), done()]}), hook=hook)
    try:
        assert f.start("revision")["status"] == "FAILED"
        assert not s.runtime.store.inspect_outbox()
        with s.runtime.store.snapshot() as snap: assert snap.read("exposure:t")[1] == []
    finally: f.close()


def test_concurrent_output_conflict_preserves_immutable_evidence(system, tmp_path):
    s = system; s.activate()
    worker = ScriptedWorker({"a": [{"kind": "output", "output": "summary", "content": "First proposal"}],
                             "b": [{"kind": "output", "output": "summary", "content": "Second proposal"}]})
    f = flow(s, tmp_path / "g.sqlite", worker)
    try:
        result = f.start("output-conflict")
        assert result["status"] == "UNSUPPORTED"
        assert any(d.get("reason") == "output_binding_conflict" for d in result["nodes"].values())
        with s.runtime.store.snapshot() as snap: assert snap._conn.execute("SELECT count(*) FROM execution_outputs").fetchone()[0] == 1
        assert not s.runtime.store.inspect_outbox()
    finally: f.close()
