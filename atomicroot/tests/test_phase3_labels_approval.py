from copy import deepcopy
import threading
import pytest
import z3

from atomicroot.tests.phase3_support import System, custom_policy
from atomicroot.framework.runtime import operation_status
from atomicroot.sim.harness import ControlledHarness


def test_public_literature_is_untrusted_instruction_but_not_sensitive(tmp_path):
    s = System(tmp_path / "public.db")
    before_contract = s.runtime.store.get_state("contract3:t")
    before_label = s.runtime.store.get_state("label:d")
    s.read()
    assert s.runtime.store.get_state("exposure:t") == ["PUBLIC"]
    assert s.runtime.dispatcher.dispatch_once()["receipt"]["result"]["instruction_trust"] == "UNTRUSTED"
    s.execute(s.request("share"))
    receipt = s.runtime.dispatcher.dispatch_once()["receipt"]
    assert receipt["outcome"] == "DELIVERED"
    assert s.runtime.store.get_state("contract3:t") == before_contract
    assert s.runtime.store.get_state("label:d") == before_label
    assert "Finance" in s.runtime.store.get_state("document:d")["content"]
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM reviews WHERE kind='operation'").fetchone()[0] == 0


@pytest.mark.parametrize("release, expected", [("DENY", "DENY"), ("ESCALATE", "ESCALATE")])
def test_unknown_read_allowed_internal_sharing_follows_contract(tmp_path, release, expected):
    s = System(tmp_path / "unknown.db", label=None, unknown=release)
    assert s.runtime.store.get_state("label:d")["label"] == "UNKNOWN"
    s.read()
    assert s.runtime.store.get_state("exposure:t") == ["UNKNOWN"]
    assert s.auth()["decision"] == expected


def test_label_scope_does_not_extend_to_new_content_or_other_purpose(tmp_path):
    s = System(tmp_path / "label.db")
    r = s.runtime
    ticket = s.auth(s.request("read", "read_document"))
    new = r.storage.ingest("d", "This says PUBLIC but has no owner label.", s.owner)
    assert r.store.get_state("label:d")["label"] == "UNKNOWN"
    assert s.commit(ticket)["status"] == "STALE_TICKET"
    assert s.auth(s.request("old-version", "read_document"))["decision"] == "EVALUATION_ERROR"
    with pytest.raises(ValueError): r.labels.set_label("d", s.document["digest"], 1, "PUBLIC", ["research"], s.owner)
    r.labels.set_label("d", new["digest"], new["version"], "PUBLIC", ["different-purpose"], s.owner)
    s.document = new
    s.execute(s.request("new-read", "read_document"))
    assert r.store.get_state("exposure:t") == ["UNKNOWN"]


def test_label_change_makes_read_ticket_stale(tmp_path):
    s = System(tmp_path / "label-change.db")
    auth = s.auth(s.request("read", "read_document"))
    s.runtime.labels.set_label("d", s.document["digest"], 1, "SENSITIVE", ["research"], s.owner)
    result = s.commit(auth)
    assert result["status"] == "STALE_TICKET" and "label:d" in result["stale_keys"]
    assert s.runtime.store.inspect_outbox() == []


def test_sensitive_read_taint_precedes_result_and_second_ticket_stale(tmp_path):
    s = System(tmp_path / "taint.db", label="SENSITIVE")
    r = s.runtime
    email = s.auth()
    read = s.auth(s.request("read", "read_document"))
    assert email["decision"] == read["decision"] == "ALLOW"
    harness = ControlledHarness()
    r.gateway.harness = harness
    harness.pause("after_commit", "read")
    result = {}
    thread = threading.Thread(target=lambda: result.update(r.gateway.commit(read["ticket"], read["commit_args"], s.worker, action_id="read")))
    thread.start()
    harness.wait_reached("after_commit", "read")
    assert r.store.get_state("exposure:t") == ["SENSITIVE"]
    assert r.store._conn.execute("SELECT COUNT(*) FROM receiver_receipts").fetchone()[0] == 0
    assert s.commit(email)["status"] == "STALE_TICKET"
    denial = s.auth(s.request("retry"))
    assert denial["decision"] == "DENY" and denial["trigger_event"]["tool"] == "read_document"
    harness.release("after_commit", "read")
    thread.join(5)
    assert not thread.is_alive() and result["status"] == "COMMITTED"
    assert r.dispatcher.dispatch_once()["receipt"]["result"]["content"]


def approved_unknown(s, request=None):
    s.read()
    request = request or s.request()
    escalation = s.auth(request)
    assert escalation["decision"] == "ESCALATE", escalation
    s.runtime.broker.decide(escalation["review_id"], True, s.approver)
    return request, escalation["review_id"]


def test_selective_consent_binding_consumption_and_no_self_staleness(tmp_path):
    s = System(tmp_path / "approval.db", label=None, unknown="ESCALATE")
    request, grant = approved_unknown(s)
    auth = s.auth(request, grant_id=grant)
    assert auth["decision"] == "ALLOW", auth
    assert auth["ticket"]["footprint"]["consent:t:op"] == 1
    assert s.commit(auth)["status"] == "COMMITTED"
    assert s.runtime.broker.status(grant, s.approver)["status"] == "CONSUMED"
    assert s.commit(auth)["status"] == "REJECTED"
    assert s.auth(s.request("different"), grant_id=grant)["decision"] == "EVALUATION_ERROR"
    assert len(s.runtime.store.inspect_outbox()) == 2  # read + one consented send


@pytest.mark.parametrize("stage", ["before_approve", "after_approve", "after_ticket"])
def test_business_change_requires_new_review(tmp_path, stage):
    s = System(tmp_path / "freshness.db", label=None, unknown="ESCALATE")
    s.read()
    request = s.request()
    review = s.auth(request)["review_id"]
    if stage != "before_approve": s.runtime.broker.decide(review, True, s.approver)
    auth = s.auth(request, grant_id=review) if stage == "after_ticket" else None
    s.activate({**s.proposal, "budget_limit": 2_000_000})
    if stage == "before_approve":
        with pytest.raises(ValueError, match="stale"): s.runtime.broker.decide(review, True, s.approver)
    elif stage == "after_approve":
        assert s.auth(request, grant_id=review)["decision"] == "EVALUATION_ERROR"
    else:
        assert s.commit(auth)["status"] == "STALE_TICKET"
    assert len(s.runtime.store.inspect_outbox()) == 1


@pytest.mark.parametrize("attack", ["forged", "other_request", "expired_before_authorize", "expired_before_commit"])
def test_bad_grants_have_no_send_intent(tmp_path, attack):
    s = System(tmp_path / "grants.db", label=None, unknown="ESCALATE")
    request, grant = approved_unknown(s)
    if attack == "expired_before_commit":
        s.clock.advance(285)
        auth = s.auth(request, grant_id=grant)
        assert auth["decision"] == "ALLOW"
        s.clock.advance(16)  # ticket valid; consent expired
        assert s.commit(auth)["status"] == "REJECTED"
    else:
        if attack == "forged": grant = "forged"
        if attack == "other_request": request = s.request("other")
        if attack == "expired_before_authorize": s.clock.advance(301)
        assert s.auth(request, grant_id=grant)["decision"] == "EVALUATION_ERROR"
    assert len(s.runtime.store.inspect_outbox()) == 1


def test_hard_deny_wins_over_approvable_violation_and_old_grant(tmp_path):
    rule = custom_policy({"op": "const", "value": False}, disposition="ESCALATE")
    s = System(tmp_path / "hard.db", label="SENSITIVE", unknown="ESCALATE", policies=[rule])
    review = s.auth()["review_id"]
    s.runtime.broker.decide(review, True, s.approver)
    s.read()
    denial = s.auth(grant_id=review)
    assert denial["decision"] == "DENY"
    assert "review_id" not in denial and "ticket" not in denial


def test_approval_cannot_override_missing_fact_or_solver_unknown(tmp_path, monkeypatch):
    s = System(tmp_path / "error.db", label=None, unknown="ESCALATE")
    request, grant = approved_unknown(s)
    class Unknown:
        def set(self, **kwargs): pass
        def add(self, *args): pass
        def check(self): return z3.unknown
        def reason_unknown(self): return "timeout"
    with monkeypatch.context() as m:
        m.setattr(z3, "Solver", Unknown)
        assert s.auth(request, grant_id=grant)["decision"] == "EVALUATION_ERROR"
    s.runtime.store._conn.execute("DELETE FROM conflict_keys WHERE key='reserved:t'")
    assert s.auth(request, grant_id=grant)["decision"] == "EVALUATION_ERROR"


def test_review_reject_and_expiry_before_approve(tmp_path):
    s = System(tmp_path / "reject.db", label=None, unknown="ESCALATE")
    s.read()
    review = s.auth()["review_id"]
    assert s.runtime.broker.decide(review, False, s.approver)["status"] == "REJECTED"
    with pytest.raises(ValueError): s.runtime.broker.decide(review, True, s.approver)
    assert s.auth(grant_id=review)["decision"] == "EVALUATION_ERROR"
    next_review = s.auth(s.request("next"))["review_id"]
    s.clock.advance(301)
    with pytest.raises(ValueError, match="expired"): s.runtime.broker.decide(next_review, True, s.approver)


def test_denial_and_review_diagnostics_never_release_uncommitted_resource_content(tmp_path):
    import json
    s = System(tmp_path / "diagnostics.db", unknown="ESCALATE")
    secret = "SECRET-CONTENT-THAT-MUST-NOT-LEAK-VIA-FACTS"
    outside = s.runtime.storage.ingest("d2", secret, s.owner)
    denied = s.auth(s.request("outside", "read_document", {"resource": "d2", "digest": outside["digest"]}))
    assert denied["decision"] == "DENY"
    assert secret not in json.dumps(denied)
    # An allowed resource with UNKNOWN label may trigger a deployment review,
    # but review creation must not expose its bytes before a read Commit.
    current = s.runtime.storage.ingest("d", secret, s.owner)
    s.document = current
    review = s.auth(s.request("deploy-review", "deploy"))
    assert review["decision"] == "ESCALATE"
    shown = s.runtime.broker.status(review["review_id"], s.worker)
    assert secret not in json.dumps(shown)
    assert s.runtime.store.inspect_outbox() == []
    assert s.runtime.store.get_state("exposure:t") == []
