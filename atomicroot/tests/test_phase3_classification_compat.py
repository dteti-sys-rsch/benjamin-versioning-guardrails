"""Conditional Phase 3 compatibility regressions: classifier is never label authority."""
from copy import deepcopy
import json
import threading

import pytest
from fastapi.testclient import TestClient

from atomicroot.framework.app import FrameworkRuntime, create_phase3_app
from atomicroot.framework.identity import Principal
from atomicroot.framework.storage import FrameworkStore
from atomicroot.tests.phase3_support import System


@pytest.fixture
def system(tmp_path):
    s = System(tmp_path / "classification.db", label=None, unknown="ESCALATE")
    s.owner = Principal("owner", frozenset({"owner"}), frozenset({"t"}), frozenset({"d", "d2"}))
    s.classifier = Principal("JEV-fixture", frozenset({"classifier"}), resources=frozenset({"d", "d2"}))
    return s


def begin(s):
    return s.runtime.classification.begin("d", s.document["digest"], s.document["version"],
                                         "fixture-model", "v1", "criteria-v1", "sha256:" + "1" * 64, s.classifier)


def result_for(p, label="SENSITIVE", **updates):
    return {**{k: p[k] for k in ("resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash")},
            "outcome": "SUCCESS", "candidate_label": label, "confidence": 0.99, "probabilities": {label: 1},
            "covered_bytes": p["input_bytes"], "truncated": False, "reason": "offline fixture", **updates}


def record(s, label="SENSITIVE", **updates):
    p = begin(s)
    return s.runtime.classification.record(p["proposal_id"], result_for(p, label, **updates), s.classifier)


def restriction_contract(s):
    s.activate({**s.proposal, "classification_restrictions": True})


def accept(s, p):
    return s.runtime.labels.accept_classification(p["proposal_id"], "t", "research", s.owner)


@pytest.mark.parametrize("official", ["UNKNOWN", "SENSITIVE"])
def test_public_proposal_cannot_release_or_downgrade(system, official):
    s = system
    if official == "SENSITIVE":
        s.runtime.labels.set_label("d", s.document["digest"], 1, "SENSITIVE", ["research"], s.owner)
    before = s.runtime.store.get_state("label:d")
    label_version = s.runtime.store.get_version("label:d")
    s.read()
    p = record(s, "PUBLIC")
    assert p["status"] == "PROPOSED"
    assert accept(s, p)["status"] == "DECLINED"
    assert s.runtime.store.get_state("label:d") == before
    assert s.runtime.store.get_version("label:d") == label_version
    assert s.auth()["decision"] == ("DENY" if official == "SENSITIVE" else "ESCALATE")


@pytest.mark.parametrize("change", ["content", "same_bytes_new_version", "label", "label_reaffirmation"])
def test_old_proposal_stale_after_exact_content_or_label_basis_change(system, change):
    s = system
    restriction_contract(s)
    if change == "label_reaffirmation":
        s.runtime.labels.set_label("d", s.document["digest"], 1, "UNKNOWN", ["research"], s.owner)
    p = record(s)
    if change in {"content", "same_bytes_new_version"}:
        content = "replacement" if change == "content" else s.runtime.store.get_state("document:d")["content"]
        s.runtime.storage.ingest("d", content, s.owner)
    else:
        s.runtime.labels.set_label("d", s.document["digest"], 1, "UNKNOWN", ["research"], s.owner)
    current = s.runtime.store.get_state("label:d")
    version = s.runtime.store.get_version("label:d")
    assert accept(s, p)["status"] == "STALE"
    assert s.runtime.store.get_state("label:d") == current
    assert s.runtime.store.get_version("label:d") == version


def test_inference_old_content_cannot_be_applied_to_new_resource_version(system):
    s = system
    restriction_contract(s)
    p = begin(s)
    s.runtime.storage.ingest("d", "changed while inference ran", s.owner)
    output = s.runtime.classification.record(p["proposal_id"], result_for(p), s.classifier)
    assert accept(s, output)["status"] == "STALE"


def test_restriction_preserves_authority_and_stales_pending_read_and_release(system):
    s = system
    restriction_contract(s)
    s.runtime.labels.set_label("d", s.document["digest"], 1, "PUBLIC", ["research"], s.owner)
    official = s.runtime.store.get_state("label:d")
    s.read()
    read = s.auth(s.request("second-read", "read_document"))
    send = s.auth(s.request("share"))
    assert read["decision"] == send["decision"] == "ALLOW"
    p = record(s)
    accepted = accept(s, p)
    assert accepted["status"] == "ACCEPTED_RESTRICTION"
    label = s.runtime.store.get_state("label:d")
    assert {k: v for k, v in label.items() if k != "restrictions"} == official
    assert accepted["accepted"]["affected_tasks"] == ["t"]
    assert s.commit(read)["status"] == "STALE_TICKET"
    assert s.commit(send)["status"] == "STALE_TICKET"
    assert s.auth(s.request("retry"))["decision"] == "DENY"
    s.runtime.labels.set_label("d", s.document["digest"], 1, "PUBLIC", ["research"], s.owner)
    assert s.runtime.store.get_state("label:d")["restrictions"] == label["restrictions"]
    assert s.auth(s.request("still-sensitive"))["decision"] == "DENY"
    with pytest.raises(ValueError): accept(s, p)


def test_restriction_does_not_clear_sensitive_exposure_or_open_with_generic_consent(system):
    s = system
    restriction_contract(s)
    s.read()
    consent = s.auth()
    assert consent["decision"] == "ESCALATE"
    s.runtime.broker.decide(consent["review_id"], True, s.approver)
    accepted = accept(s, record(s))
    assert accepted["status"] == "ACCEPTED_RESTRICTION"
    assert s.auth(grant_id=consent["review_id"])["decision"] == "DENY"


@pytest.mark.parametrize("outcome", ["TIMEOUT", "ERROR", "MISSING_CONTENT"])
def test_classifier_failure_keeps_valid_official_label(system, outcome):
    s = system
    s.runtime.labels.set_label("d", s.document["digest"], 1, "PUBLIC", ["research"], s.owner)
    before = s.runtime.store.get_state("label:d")
    version = s.runtime.store.get_version("label:d")
    p = record(s, "PUBLIC", outcome=outcome, covered_bytes=0)
    assert p["candidate_label"] == "UNKNOWN" and p["status"] == "ERROR"
    assert accept(s, p)["status"] == "DECLINED"
    assert s.runtime.store.get_state("label:d") == before
    assert s.runtime.store.get_version("label:d") == version


@pytest.mark.parametrize("update", [{"confidence": 0.1}, {"truncated": True}, {"covered_bytes": 0}])
def test_abstention_never_public_and_does_not_invalidate_unrelated_policy(system, update):
    s = system
    read = s.auth(s.request("read", "read_document"))
    p = record(s, "PUBLIC", **update)
    assert p["candidate_label"] == "UNKNOWN" and p["status"] == "ABSTAINED"
    assert s.commit(read)["status"] == "COMMITTED"  # confidence telemetry is not a policy key
    assert s.runtime.store.get_state("label:d")["label"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash"])
def test_cached_response_must_match_exact_binding(system, field):
    p = begin(system)
    result = result_for(p)
    result[field] = 2 if field == "content_version" else "wrong"
    with pytest.raises(ValueError, match="binding"):
        system.runtime.classification.record(p["proposal_id"], result, system.classifier)
    assert system.runtime.classification.status(p["proposal_id"], system.classifier)["status"] == "REQUESTED"


def test_worker_and_classifier_cannot_apply_restriction(system):
    s = system
    restriction_contract(s)
    p = record(s)
    for caller in (s.worker, s.classifier):
        with pytest.raises(PermissionError):
            s.runtime.labels.accept_classification(p["proposal_id"], "t", "research", caller)
    with pytest.raises(PermissionError): s.runtime.classification.begin("d", s.document["digest"], 1, "m", "v", "v", "sha256:" + "1" * 64, s.worker)
    assert s.runtime.store.get_state("label:d")["label"] == "UNKNOWN"


def test_restriction_needs_explicit_approved_contract(system):
    p = record(system)
    with pytest.raises(ValueError, match="contract"):
        accept(system, p)
    assert system.runtime.store.get_state("label:d")["label"] == "UNKNOWN"


@pytest.mark.parametrize("failure", ["proposal", "event"])
def test_atomic_acceptance_rollback_leaves_proposal_label_exposure_unchanged(system, failure):
    s = system
    restriction_contract(s)
    s.read()
    p = record(s)
    store = s.runtime.store
    before = {key: (store.get_version(key), store.get_state(key)) for key in ("label:d", "exposure:t")}
    if failure == "proposal":
        store._conn.execute("CREATE TRIGGER fail_accept BEFORE UPDATE ON classification_proposals WHEN NEW.status='ACCEPTED_RESTRICTION' BEGIN SELECT RAISE(ABORT, 'accept crash'); END")
    else:
        store._conn.execute("CREATE TRIGGER fail_accept BEFORE INSERT ON service_events WHEN NEW.kind='CLASSIFICATION_ACCEPTED_RESTRICTION' BEGIN SELECT RAISE(ABORT, 'event crash'); END")
    with pytest.raises(Exception): accept(s, p)
    assert {key: (store.get_version(key), store.get_state(key)) for key in before} == before
    assert s.runtime.classification.status(p["proposal_id"], s.owner)["status"] == "PROPOSED"
    store._conn.execute("DROP TRIGGER fail_accept")
    assert accept(s, p)["status"] == "ACCEPTED_RESTRICTION"


def test_concurrent_acceptance_separate_connections_one_transition(system):
    s = system
    restriction_contract(s)
    p = record(s)
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    barrier = threading.Barrier(2)
    outcomes = []
    def run(runtime):
        barrier.wait()
        try: outcomes.append(runtime.labels.accept_classification(p["proposal_id"], "t", "research", s.owner)["status"])
        except ValueError: outcomes.append("REJECTED")
    threads = [threading.Thread(target=run, args=(runtime,)) for runtime in (s.runtime, other)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(5)
    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["ACCEPTED_RESTRICTION", "REJECTED"]
    assert len(s.runtime.store.get_state("label:d")["restrictions"]) == 1
    other.store.close()


def provider_contract(s, *, rules=True, labels=None):
    contract = {**s.proposal, "allowed_tools": s.proposal["allowed_tools"] + ["classify_document"],
                "allowed_recipients": s.proposal["allowed_recipients"] + ["provider-1", "provider-2"]}
    if rules:
        contract["inference_egress"] = [{"provider": "provider-1", "resource": "d", "purpose": "research", "labels": labels or ["UNKNOWN"]}]
    s.activate(contract)


def inference(s, op="inference", provider="provider-1", **updates):
    return s.request(op, "classify_document", {"resource": "d", "digest": s.document["digest"], "to": provider}, **updates)


def test_no_provider_scope_means_no_adapter_call_or_outbox(system):
    s = system
    provider_contract(s, rules=False)
    calls = []
    class Spy:
        def deliver(self, *args):
            calls.append(args)
            raise AssertionError("provider must not be called")
    s.runtime.dispatcher.receiver = Spy()
    denial = s.auth(inference(s))
    assert denial["decision"] == "DENY" and denial["policy"] == "provider_scope"
    assert s.runtime.dispatcher.dispatch_once()["status"] == "IDLE"
    assert calls == [] and s.runtime.store.inspect_outbox() == []


def test_unknown_provider_ingestion_requires_prior_scope_not_future_public_prediction(system):
    s = system
    provider_contract(s, labels=["PUBLIC"])
    p = record(s, "PUBLIC")
    assert s.auth(inference(s))["decision"] == "DENY"
    assert accept(s, p)["status"] == "DECLINED"
    provider_contract(s, labels=["UNKNOWN"])
    auth = s.auth(inference(s, "allowed"))
    assert auth["decision"] == "ALLOW"
    assert s.commit(auth)["status"] == "COMMITTED"
    # Only the existing offline receiver simulation is exercised.
    result = s.runtime.dispatcher.dispatch_once()
    assert result["receipt"]["result"]["outcome"] == "OFFLINE_SIMULATION"
    assert s.runtime.store.get_state("label:d")["label"] == "UNKNOWN"


@pytest.mark.parametrize("attack", ["provider", "purpose", "resource", "sensitive"])
def test_provider_resource_purpose_and_data_boundaries(system, attack):
    s = system
    provider_contract(s, labels=["PUBLIC", "SENSITIVE", "UNKNOWN"])
    request = inference(s)
    if attack == "provider": request["args"]["to"] = "provider-2"
    if attack == "purpose": request["purpose"] = "other-purpose"
    if attack == "resource":
        d2 = s.runtime.storage.ingest("d2", "outside", s.owner)
        request["args"].update(resource="d2", digest=d2["digest"])
    if attack == "sensitive": s.runtime.labels.set_label("d", s.document["digest"], 1, "SENSITIVE", ["research"], s.owner)
    assert s.auth(request)["decision"] == "DENY"
    assert s.runtime.store.inspect_outbox() == []


def test_provider_scope_change_and_content_change_stale_prior_intent_ticket(system):
    s = system
    provider_contract(s)
    auth = s.auth(inference(s))
    provider_contract(s, rules=False)
    assert s.commit(auth)["status"] == "STALE_TICKET"
    provider_contract(s)
    next_auth = s.auth(inference(s, "next"))
    s.runtime.storage.ingest("d", "new", s.owner)
    assert s.commit(next_auth)["status"] == "STALE_TICKET"


def test_additive_migration_preserves_all_existing_business_records(system):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    s.read()
    pending = s.auth(s.request("pending-read", "read_document"))
    review = s.auth()
    s.runtime.broker.decide(review["review_id"], True, s.approver)
    consent_ticket = s.auth(grant_id=review["review_id"])
    store = s.runtime.store
    # Reproduce the pre-patch schema without rewriting any business row.
    store._conn.execute("DROP TABLE classification_proposals")
    tables = [row[0] for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    before = {table: store._conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in tables}
    s.restart()
    after = {table: s.runtime.store._conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in tables}
    assert before == after
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM classification_proposals").fetchone()[0] == 0
    assert s.commit(consent_ticket)["status"] == "COMMITTED"
    assert s.commit(pending)["status"] == "COMMITTED"
    assert s.runtime.store.get_state("reserved:t") == 200_000


def test_api_separates_evidence_intake_from_owner_acceptance(system):
    s = system
    restriction_contract(s)
    identities = {"worker": s.worker, "classifier": s.classifier, "owner": s.owner}
    client = TestClient(create_phase3_app(s.runtime, lambda request: identities[request.headers["Authorization"]]))
    body = {"resource": "d", "digest": s.document["digest"], "content_version": 1,
            "model_id": "m", "model_version": "v1", "criteria_version": "v1", "criteria_hash": "sha256:" + "1" * 64}
    assert client.post("/classification/proposals", headers={"Authorization": "worker"}, json=body).status_code == 403
    proposal = client.post("/classification/proposals", headers={"Authorization": "classifier"}, json=body).json()
    path = "/classification/proposals/" + proposal["proposal_id"]
    response = client.post(path + "/result", headers={"Authorization": "classifier"}, json=result_for(proposal))
    assert response.json()["status"] == "PROPOSED"
    assert client.post(path + "/accept", headers={"Authorization": "classifier"}, json={"task_id": "t", "purpose": "research"}).status_code == 403
    assert client.post(path + "/accept", headers={"Authorization": "worker"}, json={"task_id": "t", "purpose": "research"}).status_code == 403
    assert client.post(path + "/accept", headers={"Authorization": "owner"}, json={"task_id": "t", "purpose": "research"}).json()["status"] == "ACCEPTED_RESTRICTION"
    assert client.get(path, headers={"Authorization": "owner"}).json()["status"] == "ACCEPTED_RESTRICTION"
