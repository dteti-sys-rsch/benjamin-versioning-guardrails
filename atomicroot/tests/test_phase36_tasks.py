"""Phase 3.6 mechanism tests use trusted identity/catalog fixtures, no network."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from threading import Event
from pathlib import Path
import json

import pytest
from fastapi.testclient import TestClient

from atomicroot.framework.app import FrameworkRuntime, create_phase3_app
from atomicroot.framework.identity import Principal
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import TaskSpec
from atomicroot.framework.runtime import envelope
from atomicroot.tests.phase3_support import custom_policy, Clock


def rule(tool, resource=None, destination=None, purpose="research", amount=0):
    return {"tool": tool, "resource": resource, "destination": destination, "purpose": purpose, "max_amount": amount}


class ConfigSystem:
    def __init__(self, path):
        self.path = str(path)
        self.clock = Clock()
        self.runtime = FrameworkRuntime(self.path, clock=self.clock)
        self.admin = Principal("admin", frozenset({"admin"}))
        self.user = Principal("user", frozenset({"user"}), frozenset({"t", "payments"}))
        self.approver = Principal("approver", frozenset({"approver"}), self.user.tasks)
        self.owner = Principal("owner", frozenset({"owner"}), resources=frozenset({"d1", "d2", "ctx"}))
        self.refs = []
        for name in ("d1", "d2", "ctx"):
            ref = self.runtime.storage.ingest(name, "Synthetic source " + name, self.owner)
            self.runtime.labels.set_label(name, ref["digest"], ref["version"], "PUBLIC", ["research", "payments"], self.owner)
            self.refs.append(ref)
        for dest in ("alice@corp.id", "bob@corp.id", "account-1", "account-2"):
            self.runtime.catalog.set_destination({"destination": dest, "kind": "recipient", "purposes": ["research", "payments"],
                "endpoint": None, "models": [], "labels": []}, self.admin)
        self.scope = [rule("read_document", "d1"), rule("read_document", "d2"), rule("send_email", destination="alice@corp.id"),
            rule("deploy", "d1", "alice@corp.id"), rule("deploy", "d2", "bob@corp.id")]
        self.rights = {"scope": self.scope, "budget_limit": 1000, "max_agents": 4,
            "limits": {"max_steps": 64, "max_in_flight": 4, "max_calls": 12, "max_tokens": 200000,
                       "max_output_tokens": 1600, "max_retries": 2, "timeout": 120}}
        self.runtime.catalog.set_entitlement("t", "user", self.rights, self.admin)
        payment_rights = deepcopy(self.rights)
        payment_rights["scope"] = [rule("transfer_funds", destination="account-1", purpose="payments", amount=500),
                                  rule("transfer_funds", destination="account-2", purpose="payments", amount=500)]
        self.runtime.catalog.set_entitlement("payments", "user", payment_rights, self.admin)
        self.spec = {"schema_version": 1, "task_id": "t", "objective": "Read sources and send a simulated summary", "purpose": "research",
            "resources": self.refs[:2], "scope": self.scope, "budget_limit": 0,
            "agents": [{"id": "reader1", "role": "Reader A", "scope": [self.scope[0], self.scope[3]]},
                       {"id": "reader2", "role": "Reader B", "scope": [self.scope[1], self.scope[4]]},
                       {"id": "sender", "role": "Writer", "scope": [self.scope[2]]}],
            "policies": [], "workflow": {"nodes": [{"id": "a", "agent": "reader1", "depends_on": []},
                {"id": "b", "agent": "reader2", "depends_on": []}, {"id": "join", "agent": "sender", "depends_on": ["a", "b"]}]},
            "outputs": [{"id": "summary", "kind": "summary"}], "acceptance": [{"kind": "read", "resource": "d1"},
                {"kind": "read", "resource": "d2"}, {"kind": "receipt", "tool": "send_email", "destination": "alice@corp.id"},
                {"kind": "output", "output": "summary"}], "provider": None, "classifier": {"mode": "disabled"},
            "limits": {"max_steps": 8, "max_in_flight": 3, "inference": {"max_tokens": 200000}}, "unknown_release": "DENY"}

    def activate(self, spec=None):
        preview = self.runtime.tasks.propose(spec or self.spec, self.user)
        self.runtime.broker.decide(preview["review_id"], True, self.approver)
        self.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], self.approver)
        return preview

    def request(self, agent="sender", tool="send_email", args=None, op="op", task="t", purpose="research"):
        principal = self.runtime.tasks.principal(task, agent, self.user)
        return {"task_id": task, "agent_id": principal.subject, "operation_id": op, "tool": tool, "purpose": purpose,
                "args": args or {"to": "alice@corp.id", "body": "Synthetic summary"}}, principal

    def auth(self, *args, **kwargs):
        request, principal = self.request(*args, **kwargs)
        return self.runtime.authority.authorize(request, principal), principal


@pytest.fixture
def system(tmp_path):
    s = ConfigSystem(tmp_path / "phase36.sqlite")
    yield s
    s.runtime.store.close()


def test_two_specs_three_agents_and_correlated_scope(system):
    s = system
    s.activate()
    assert len(s.runtime.tasks.status("t", s.user)["resolved"]["agents"]) == 3
    good, principal = s.auth()
    assert good["decision"] == "ALLOW", good
    for agent, tool, args in [("reader1", "send_email", {"to": "alice@corp.id", "body": "forbidden"}),
        ("reader1", "read_document", {"resource": "d2", "digest": s.refs[1]["digest"]}),
        ("reader1", "deploy", {"resource": "d1", "digest": s.refs[0]["digest"], "to": "bob@corp.id"})]:
        auth, _ = s.auth(agent, tool, args, op="bad-" + tool)
        assert auth["decision"] == "DENY", auth
        assert "ticket" not in auth
    assert not s.runtime.store.inspect_outbox()
    payment = deepcopy(s.spec)
    payment.update(task_id="payments", purpose="payments", objective="Two bounded simulated transfers", resources=[], budget_limit=600,
        scope=[rule("transfer_funds", destination="account-1", purpose="payments", amount=500),
               rule("transfer_funds", destination="account-2", purpose="payments", amount=500)],
        policies=[custom_policy({"op": "le", "left": {"op": "amount"}, "right": {"op": "const", "value": 300}}, tools=["transfer_funds"], name="per_payment_cap")],
        outputs=[], acceptance=[{"kind": "receipt", "tool": "transfer_funds", "destination": "account-1"}])
    payment["agents"][0]["scope"] = [payment["scope"][0]]
    payment["agents"][1]["scope"] = [payment["scope"][1]]
    payment["agents"][2]["scope"] = []
    s.activate(payment)
    auth, p = s.auth("reader1", "transfer_funds", {"to": "account-1", "amount": 250}, task="payments", purpose="payments")
    assert auth["decision"] == "ALLOW", auth
    denied, _ = s.auth("reader1", "transfer_funds", {"to": "account-1", "amount": 400}, op="over", task="payments", purpose="payments")
    assert denied["decision"] == "DENY" and denied["policy"] == "per_payment_cap"
    assert s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], p)["status"] == "COMMITTED"


@pytest.mark.parametrize("mutation", ["unknown", "duplicate", "missing", "digest", "operator", "scope", "agent_scope", "negative", "bool", "cycle", "provider", "limits", "acceptance"])
def test_invalid_input_fails_without_active_contract_or_effect(system, mutation):
    s = system
    spec = deepcopy(s.spec)
    if mutation == "unknown": spec["set_fact"] = {}
    elif mutation == "duplicate": spec["agents"].append(spec["agents"][0])
    elif mutation == "missing": spec["resources"][0]["resource"] = "missing"
    elif mutation == "digest": spec["resources"][0]["digest"] = "sha256:" + "0" * 64
    elif mutation == "operator": spec["policies"] = [custom_policy({"op": "eval", "code": "True"})]
    elif mutation == "scope":
        spec["scope"][3]["destination"] = "bob@corp.id"
        spec["agents"][0]["scope"][1]["destination"] = "bob@corp.id"
    elif mutation == "agent_scope": spec["agents"][0]["scope"].append(rule("transfer_funds", destination="account-1", amount=10))
    elif mutation == "negative": spec["budget_limit"] = -1
    elif mutation == "bool": spec["budget_limit"] = True
    elif mutation == "cycle": spec["workflow"]["nodes"][0]["depends_on"] = ["join"]
    elif mutation == "provider": spec["provider"] = {"destination": "evil", "model": "arbitrary", "endpoint": "http://evil"}
    elif mutation == "limits": spec["limits"]["inference"]["max_calls"] = 13
    else: spec["acceptance"] = [{"kind": "arbitrary_code"}]
    assert s.runtime.tasks.validate(spec, s.user)["valid"] is False
    assert s.runtime.store.get_state("contract3:t") is None
    assert not s.runtime.store.inspect_outbox()


def test_review_reject_pause_and_stale_no_activation(system):
    s = system
    preview = s.runtime.tasks.propose(s.spec, s.user)
    with pytest.raises(ValueError): s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)
    assert s.runtime.broker.status(preview["review_id"], s.approver)["effective_status"] == "PENDING"
    s.runtime.broker.decide(preview["review_id"], False, s.approver)
    with pytest.raises(ValueError): s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)
    preview = s.runtime.tasks.propose(s.spec, s.user)
    s.runtime.broker.decide(preview["review_id"], True, s.approver)
    rights = deepcopy(s.rights)
    rights["scope"].append(rule("send_email", destination="bob@corp.id"))  # membership phantom
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    with pytest.raises(ValueError, match="stale"): s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)
    assert s.runtime.store.get_state("contract3:t") is None
    assert not s.runtime.store.inspect_outbox()


@pytest.mark.parametrize("change", ["entitlement", "label", "destination", "delegation"])
def test_relevant_change_stales_ticket(system, change):
    s = system
    s.activate()
    args = {"resource": "d1", "digest": s.refs[0]["digest"]}
    auth, p = s.auth("reader1", "read_document", args)
    assert auth["decision"] == "ALLOW", auth
    if change == "entitlement": s.runtime.catalog.set_entitlement("t", "user", s.rights, s.admin)
    elif change == "label": s.runtime.labels.set_label("d1", s.refs[0]["digest"], 1, "SENSITIVE", ["research"], s.owner)
    elif change == "destination":
        auth, p = s.auth(op="send")
        s.runtime.catalog.set_destination({"destination": "alice@corp.id", "kind": "recipient", "purposes": ["payments"],
            "endpoint": None, "models": [], "labels": []}, s.admin)
    else:
        spec = deepcopy(s.spec)
        spec["agents"][0]["scope"].remove(spec["scope"][0])
        spec["agents"][1]["scope"].append(spec["scope"][0])
        s.activate(spec)
    result = s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], p)
    assert result["status"] == "STALE_TICKET", result
    assert not s.runtime.store.inspect_outbox()


def test_unrelated_destination_does_not_stale_and_agent_identity_not_body(system):
    s = system
    s.activate()
    auth, p = s.auth()
    s.runtime.catalog.set_destination({"destination": "unrelated@corp.id", "kind": "recipient", "purposes": ["research"],
        "endpoint": None, "models": [], "labels": []}, s.admin)
    assert s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], p)["status"] == "COMMITTED"
    request, _ = s.request(op="forge")
    request["agent_id"] = "sender"
    assert s.runtime.authority.authorize(request, p)["decision"] == "EVALUATION_ERROR"
    with pytest.raises(PermissionError): s.runtime.catalog.set_entitlement("t", "user", s.rights, p)
    contract = deepcopy(s.runtime.store.get_state("contract3:t"))
    del contract["task_binding"]
    with pytest.raises(ValueError, match="binding"): s.runtime.contracts.propose(contract, p)


def test_rollback_preserves_review_and_ledger_and_revision_no_reset(system, monkeypatch):
    s = system
    s.activate()
    auth, p = s.auth("reader1", "read_document", {"resource": "d1", "digest": s.refs[0]["digest"]})
    assert s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], p)["status"] == "COMMITTED"
    preview = s.runtime.tasks.propose(s.spec, s.user)
    s.runtime.broker.decide(preview["review_id"], True, s.approver)
    baseline = list(s.runtime.store._conn.iterdump())
    original = s.runtime.store.audit
    def fail(conn, kind, actor, data):
        if kind == "CONTRACT_ACTIVATED": raise RuntimeError("injected transaction failure")
        return original(conn, kind, actor, data)
    monkeypatch.setattr(s.runtime.store, "audit", fail)
    with pytest.raises(RuntimeError): s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)
    assert baseline == list(s.runtime.store._conn.iterdump())
    monkeypatch.setattr(s.runtime.store, "audit", original)
    s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)
    assert s.runtime.store.get_state("exposure:t") == ["PUBLIC"]
    assert len(s.runtime.store.inspect_outbox()) == 1
    assert s.runtime.broker.status(preview["review_id"], s.approver)["status"] == "CONSUMED"
    with pytest.raises(ValueError): s.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)


def test_concurrent_grant_consumption_separate_connections(system):
    s = system
    preview = s.runtime.tasks.propose(s.spec, s.user)
    s.runtime.broker.decide(preview["review_id"], True, s.approver)
    other = FrameworkRuntime(s.path, clock=s.clock)
    barrier = Barrier(2)
    def run(runtime):
        barrier.wait()
        try: return runtime.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver)["status"]
        except ValueError: return "REJECTED"
    try:
        with ThreadPoolExecutor(2) as pool: result = list(pool.map(run, [s.runtime, other]))
        assert sorted(result) == ["ACTIVE", "REJECTED"]
    finally: other.store.close()


def test_migration_does_not_change_existing_rows_or_grant_legacy_scope(tmp_path):
    from atomicroot.tests.phase3_support import System
    old = System(tmp_path / "legacy.sqlite")
    old.execute()
    old.runtime.store._conn.execute("DROP TABLE resolved_tasks")
    before = list(old.runtime.store._conn.iterdump())
    old.runtime.store.close()
    upgraded = FrameworkRuntime(old.path, signing_key=old.sk, clock=old.clock)
    try:
        upgraded.store._conn.execute("DROP TABLE resolved_tasks")
        assert list(upgraded.store._conn.iterdump()) == before
        assert upgraded.store.get_state("taskmode:t") is None
        assert len(upgraded.store.inspect_outbox()) == 1
    finally: upgraded.store.close()


def test_api_role_separation_schema_and_bad_references(system):
    s = system
    identities = {"user": s.user, "admin": s.admin, "approver": s.approver,
                  "worker": Principal("fake", frozenset({"worker"}), frozenset({"t"}))}
    with TestClient(create_phase3_app(s.runtime, lambda req: identities[req.headers["x-identity"]])) as client:
        headers = {"x-identity": "user"}
        assert client.get("/tasks/schema", headers=headers).status_code == 200
        assert client.post("/tasks/validate", headers=headers, json=s.spec).json()["valid"] is True
        assert client.post("/tasks/proposals", headers={"x-identity": "worker"}, json=s.spec).status_code == 403
        assert client.post("/catalog/entitlements/t/user", headers=headers, json=s.rights).status_code == 403
        preview = client.post("/tasks/proposals", headers=headers, json=s.spec).json()
        assert client.post(f"/contracts/{preview['proposal_id']}/activate", headers=headers, json={"review_id": preview["review_id"]}).status_code == 403
        assert client.get("/tasks/t", headers=headers).json()["status"] == "DRAFT"


def test_task_spec_canonical_copy_and_duplicate_json_key(tmp_path, system):
    from phase36_cli import load
    parsed = TaskSpec.parse(system.spec)
    copy = parsed.data
    copy["agents"].clear()
    assert len(parsed.data["agents"]) == 3
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":2}')
    with pytest.raises(ValueError, match="duplicate JSON key"): load(path)


def test_examples_fixture_and_cli_surface(tmp_path, capsys, monkeypatch):
    from phase36_cli import load, init_fixture, local_identities, main
    examples = Path(__file__).resolve().parents[2] / "examples" / "phase36"
    runtime = FrameworkRuntime(str(tmp_path / "examples.sqlite"))
    try:
        init_fixture(runtime, load(examples / "trusted-fixture.json"))
        user, approver = local_identities(runtime)
        for filename in ("literature.json", "payments.json"):
            spec = load(examples / filename)
            assert runtime.tasks.validate(spec, user)["valid"]
            preview = runtime.tasks.propose(spec, user)
            assert len(preview["preview"]["resolved_task"]["agents"]) == 3
            runtime.broker.decide(preview["review_id"], True, approver)
            runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
            assert runtime.tasks.status(spec["task_id"], user)["status"] == "ACTIVE"
        assert not runtime.store.inspect_outbox()  # Foundation does not run a workflow.
    finally: runtime.store.close()
    directory = str(tmp_path / "cli")
    def command(*parts):
        monkeypatch.setattr("sys.argv", ["phase36_cli.py", "--directory", directory, *parts])
        assert main() == 0
        return json.loads(capsys.readouterr().out)
    command("init-fixture", str(examples / "trusted-fixture.json"))
    assert command("validate", str(examples / "literature.json"))["valid"]
    preview = command("preview", str(examples / "literature.json"))
    assert command("decide", preview["review_id"], "pause")["review"] == "PENDING"
    command("decide", preview["review_id"], "approve")
    assert command("activate", preview["proposal_id"], preview["review_id"])["status"] == "ACTIVE"
    assert command("status", "literature-a")["binding"] == preview["preview"]["proposal"]["task_binding"]


def test_hard_deny_and_solver_error_are_not_opened_by_general_approval(system, monkeypatch):
    from atomicroot.authority.policy_engine import PolicyResult
    s = system
    s.runtime.labels.set_label("d1", s.refs[0]["digest"], 1, "SENSITIVE", ["research"], s.owner)
    preview = s.activate()
    read, p = s.auth("reader1", "read_document", {"resource": "d1", "digest": s.refs[0]["digest"]})
    assert read["decision"] == "ALLOW"
    assert s.runtime.gateway.commit(read["ticket"], read["commit_args"], p)["status"] == "COMMITTED"
    req, sender = s.request(op="sensitive-send")
    denied = s.runtime.authority.authorize(req, sender, grant_id=preview["review_id"])
    assert denied["decision"] == "DENY" and denied["policy"] == "no_exfil_after_sensitive"
    monkeypatch.setattr("atomicroot.framework.runtime.solve", lambda *args: PolicyResult("UNKNOWN", {}, [], "unknown"))
    error = s.runtime.authority.authorize(req, sender, grant_id=preview["review_id"])
    assert error["decision"] == "EVALUATION_ERROR" and "ticket" not in error
    assert len(s.runtime.store.inspect_outbox()) == 1


def test_parent_cannot_be_self_authorized_and_legacy_task_not_adopted(system, tmp_path):
    s = system
    forged_user = Principal("other-user", frozenset({"user"}), s.user.tasks)
    assert s.runtime.tasks.validate(s.spec, forged_user)["valid"] is False
    s.activate()
    with pytest.raises(PermissionError): s.runtime.tasks.propose(s.spec, forged_user)
    with pytest.raises(PermissionError): s.runtime.tasks.principal("t", "sender", forged_user)
    alias = deepcopy(s.spec)
    alias["task_id"] = "task-alias"
    with pytest.raises(PermissionError): s.runtime.tasks.validate(alias, s.user)
    from atomicroot.tests.phase3_support import System
    legacy = System(tmp_path / "legacy2.sqlite")
    try:
        snapshot = list(legacy.runtime.store._conn.iterdump())
        principal = Principal("user", frozenset({"user"}), frozenset({"t"}))
        invalid = legacy.runtime.tasks.validate(s.spec, principal)
        assert invalid["valid"] is False and "legacy" in invalid["unsupported"][0]
        assert snapshot == list(legacy.runtime.store._conn.iterdump())
    finally: legacy.runtime.store.close()


def test_resolver_reads_values_and_versions_from_one_snapshot(system, monkeypatch):
    from atomicroot.authority.policy_engine import StatusReader
    s = system
    arrived, release = Event(), Event()
    key = "entitlement:t:user"
    version_before = s.runtime.store.get_versions([key])[key]
    original = StatusReader.read
    def gated(reader, name):
        value = original(reader, name)
        if name == key:
            arrived.set()
            assert release.wait(10)
        return value
    other = FrameworkRuntime(s.path, clock=s.clock)
    monkeypatch.setattr(StatusReader, "read", gated)
    try:
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(s.runtime.tasks.validate, s.spec, s.user)
            assert arrived.wait(10)
            rights = deepcopy(s.rights)
            rights["scope"] = []
            other.catalog.set_entitlement("t", "user", rights, s.admin)
            release.set()
            resolved = pending.result(10)
        assert resolved["valid"] is True  # Old consistent snapshot, never old values/new versions.
        assert resolved["resolved"]["basis"][key] == version_before
        assert s.runtime.store.get_versions([key])[key] == version_before + 1
    finally:
        release.set()
        other.store.close()


def payment_spec(system, budget=400):
    examples = Path(__file__).resolve().parents[2] / "examples" / "phase36" / "payments.json"
    text = examples.read_text().replace('"payments-a"', '"payments"').replace('"account-a"', '"account-1"').replace('"account-b"', '"account-2"')
    spec = json.loads(text)
    spec["budget_limit"] = budget
    return spec


def test_budget_shared_between_agents_and_revision_preserves_settlement(system):
    s = system
    spec = payment_spec(s)
    s.activate(spec)
    a, pa = s.auth("payer-a", "transfer_funds", {"to": "account-1", "amount": 250}, task="payments", purpose="payments", op="a")
    b, pb = s.auth("payer-b", "transfer_funds", {"to": "account-2", "amount": 250}, task="payments", purpose="payments", op="b")
    assert a["decision"] == b["decision"] == "ALLOW"
    assert s.runtime.gateway.commit(a["ticket"], a["commit_args"], pa)["status"] == "COMMITTED"
    assert s.runtime.gateway.commit(b["ticket"], b["commit_args"], pb)["status"] == "STALE_TICKET"
    assert len(s.runtime.store.inspect_outbox()) == 1
    retry, _ = s.auth("payer-b", "transfer_funds", {"to": "account-2", "amount": 250}, task="payments", purpose="payments", op="b")
    assert retry["decision"] == "DENY" and retry["policy"] == "budget_monotone"
    s.runtime.dispatcher.dispatch_once()
    assert s.runtime.store.get_state("budget:payments") == 250
    s.activate(payment_spec(s, 500))
    assert s.runtime.store.get_state("budget:payments") == 250
    assert s.runtime.store.get_state("reserved:payments") == 0
    assert len(s.runtime.store.inspect_outbox()) == 1


def test_agent_membership_addition_invalidates_old_ticket(system):
    s = system
    s.activate()
    ticket, principal = s.auth()
    assert "agents:t" in ticket["ticket"]["footprint"]
    spec = deepcopy(s.spec)
    spec["agents"].append({"id": "observer", "role": "No protected tools", "scope": []})
    s.activate(spec)
    result = s.runtime.gateway.commit(ticket["ticket"], ticket["commit_args"], principal)
    assert result["status"] == "STALE_TICKET" and "agents:t" in result["stale_keys"]


def test_content_change_stales_proposal_and_requires_new_resolution(system):
    s = system
    preview = s.runtime.tasks.propose(s.spec, s.user)
    s.runtime.storage.ingest("d1", "New synthetic content", s.owner)
    with pytest.raises(ValueError, match="stale"): s.runtime.broker.decide(preview["review_id"], True, s.approver)
    assert s.runtime.tasks.validate(s.spec, s.user)["valid"] is False
    assert s.runtime.tasks.status("t", s.user)["status"] == "DRAFT"


def test_provider_configuration_resolution_does_not_make_network_call(system):
    s = system
    s.runtime.catalog.set_destination({"destination": "ollama", "kind": "provider", "purposes": ["research"],
        "endpoint": "http://localhost:11434/api", "models": ["qwen3:8b"], "labels": ["PUBLIC", "UNKNOWN"]}, s.admin)
    inference = rule("model_inference", "ctx", "ollama")
    spec = deepcopy(s.spec)
    spec["resources"].append(s.refs[2]); spec["scope"].append(inference)
    spec["agents"][2]["scope"].append(inference)
    spec["provider"] = {"destination": "ollama", "model": "qwen3:8b"}
    # Catalog provider alone does not grant egress rights.
    assert s.runtime.tasks.validate(spec, s.user)["valid"] is False
    rights = deepcopy(s.rights)
    rights["scope"].append(inference)
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    assert s.runtime.tasks.validate(spec, s.user)["valid"] is True
    bad_model = deepcopy(spec)
    bad_model["provider"]["model"] = "unregistered"
    assert s.runtime.tasks.validate(bad_model, s.user)["valid"] is False
    assert not s.runtime.store.inspect_outbox()


def test_active_pinned_resource_cannot_silently_follow_new_version(system):
    s = system
    s.activate()
    s.runtime.storage.ingest("d1", "Changed source", s.owner)
    new_ref = s.runtime.store.get_state("document:d1")
    auth, _ = s.auth("reader1", "read_document", {"resource": "d1", "digest": new_ref["digest"]})
    assert auth["decision"] == "DENY"
    assert not s.runtime.store.inspect_outbox()


def test_inference_source_requires_agent_scope_and_current_provider_labels(system):
    s = system
    destination = {"destination": "ollama", "kind": "provider", "purposes": ["research"],
        "endpoint": "http://localhost:11434/api", "models": ["qwen3:8b"], "labels": ["PUBLIC", "UNKNOWN"]}
    s.runtime.catalog.set_destination(destination, s.admin)
    context = {"provider": "ollama", "model": "qwen3:8b", "prompt_version": "worker-v3",
        "messages": [{"role": "user", "content": "Synthetic input"}], "sources": [{"resource": "d1", "digest": s.refs[0]["digest"]}]}
    ref = s.runtime.storage.ingest("ctx", dumps(context), s.owner)
    ctx_scope, source_scope = rule("model_inference", "ctx", "ollama"), rule("model_inference", "d1", "ollama")
    spec = deepcopy(s.spec)
    spec["resources"].append(ref)
    spec["scope"].extend([ctx_scope, source_scope])
    spec["agents"][2]["scope"].append(ctx_scope)
    spec["agents"][0]["scope"].append(source_scope)
    spec["provider"] = {"destination": "ollama", "model": "qwen3:8b"}
    rights = deepcopy(s.rights)
    rights["scope"].extend([ctx_scope, source_scope])
    s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
    s.activate(spec)
    args = {"to": "ollama", "resource": "ctx", "digest": ref["digest"]}
    denied, _ = s.auth("sender", "model_inference", args)
    assert denied["decision"] == "DENY" and denied["policy"] == "source_agent_scope:d1"
    spec["agents"][2]["scope"].append(source_scope)
    s.activate(spec)
    auth, p = s.auth("sender", "model_inference", args)
    assert auth["decision"] == "ALLOW", auth
    destination["labels"] = ["PUBLIC"]
    s.runtime.catalog.set_destination(destination, s.admin)
    assert s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], p)["status"] == "STALE_TICKET"
    denied, _ = s.auth("sender", "model_inference", args)
    assert denied["decision"] == "DENY" and denied["policy"] == "resolved_provider"
    assert not s.runtime.store.inspect_outbox()
