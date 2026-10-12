from copy import deepcopy
import json
import threading
import pytest

from atomicroot.tests.phase3_support import System
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.runtime import operation_status
from atomicroot.framework.outbox import SimulatedReceiver
from atomicroot.authority.ticket import create_ticket
from atomicroot.gateway.gateway import ToolGateway
from atomicroot.sim.harness import ControlledHarness


@pytest.fixture
def system(tmp_path): return System(tmp_path / "outbox.db")


def test_budget_race_both_allow_one_stale_no_dispatch(system):
    s = system
    first = s.auth(s.request("a", "transfer_funds", {"to": "account-1", "amount": 700_000}))
    second = s.auth(s.request("b", "transfer_funds", {"to": "account-1", "amount": 700_000}))
    assert first["decision"] == second["decision"] == "ALLOW"
    assert s.commit(first)["status"] == "COMMITTED"
    assert s.commit(second)["status"] == "STALE_TICKET"
    assert len(s.runtime.store.inspect_outbox()) == 1
    assert s.runtime.store.get_state("reserved:t") == 700_000
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM receiver_receipts").fetchone()[0] == 0
    assert s.auth(s.request("b", "transfer_funds", {"to": "account-1", "amount": 700_000}))["decision"] == "DENY"


def test_commit_is_intent_and_later_policy_change_does_not_revoke_delivery(system):
    s = system
    s.execute()
    s.activate({**s.proposal, "allowed_tools": ["read_document"]})
    assert s.runtime.dispatcher.dispatch_once()["status"] == "RELEASED"
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM receiver_state WHERE key LIKE 'email:%'").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["signature", "tool", "task_id", "agent_id", "nonce", "write_set", "footprint", "not_after"])
def test_tampered_ticket_no_outbox(system, field):
    s = system
    auth = s.auth()
    bad = deepcopy(auth["ticket"])
    if field == "write_set": bad[field] = []
    elif field == "footprint": bad[field] = {}
    else: bad[field] = "forged"
    assert s.runtime.gateway.commit(bad, auth["commit_args"], s.worker)["status"] == "REJECTED"
    assert s.runtime.store.inspect_outbox() == []


def test_expired_ticket_payload_substitution_and_mutable_reference_rejected(system):
    s = system
    auth = s.auth()
    changed = deepcopy(auth["commit_args"])
    changed["payload"]["body"] = "substituted"
    assert s.runtime.gateway.commit(auth["ticket"], changed, s.worker)["status"] == "REJECTED"
    s.clock.advance(31)
    assert s.commit(auth)["status"] == "REJECTED"
    assert s.auth(s.request("ref", args={"to": "alice@corp.id", "body_ref": "mem:x"}))["decision"] == "EVALUATION_ERROR"
    assert s.runtime.store.inspect_outbox() == []


def test_immutable_operation_and_separate_idempotent_status_not_ticket_replay(system):
    s = system
    request = s.request("stable", "transfer_funds")
    auth = s.execute(request)
    assert s.commit(auth)["status"] == "REJECTED"
    retry = s.auth(request)
    assert retry["idempotent_status"] and retry["status"] == "COMMITTED" and "ticket" not in retry
    changed = deepcopy(request)
    changed["args"]["amount"] += 1
    assert s.auth(changed)["decision"] == "EVALUATION_ERROR"
    with pytest.raises(PermissionError): operation_status(s.runtime.store, "t", "stable", "wrong", s.worker)
    assert s.runtime.store.get_state("reserved:t") == 200_000
    assert len(s.runtime.store.inspect_outbox()) == 1


def test_operation_identity_survives_reauthorize_after_stale(system):
    s = system
    request = s.request("stable", "transfer_funds")
    first = s.auth(request)
    s.activate({**s.proposal, "budget_limit": 2_000_000})
    assert s.commit(first)["status"] == "STALE_TICKET"
    second = s.auth(request)
    assert first["ticket"]["ticket_id"] != second["ticket"]["ticket_id"]
    assert first["request_digest"] == second["request_digest"]
    assert s.commit(second)["status"] == "COMMITTED"
    assert len(s.runtime.store.inspect_outbox()) == 1


def test_atomic_failure_at_outbox_insert_rolls_back_all_state_and_grant(tmp_path):
    s = System(tmp_path / "rollback.db", label=None, unknown="ESCALATE")
    s.read()
    request = s.request("pay", "transfer_funds")
    review = s.auth(request)["review_id"]
    s.runtime.broker.decide(review, True, s.approver)
    auth = s.auth(request, grant_id=review)
    store = s.runtime.store
    before = {k: store.get_version(k) for k in auth["ticket"]["write_set"]}
    store._conn.execute("CREATE TRIGGER fail_intent BEFORE INSERT ON outbox WHEN NEW.operation='pay' BEGIN SELECT RAISE(ABORT, 'crash at insert'); END")
    assert s.commit(auth)["status"] == "REJECTED"
    assert store.get_state("reserved:t") == 0
    assert store.get_state("operation:t:pay") is False
    assert s.runtime.broker.status(review, s.approver)["status"] == "APPROVED"
    assert {k: store.get_version(k) for k in before} == before
    assert len(store.get_trace("t")) == 1 and len(store.inspect_outbox()) == 1
    store._conn.execute("DROP TRIGGER fail_intent")
    assert s.commit(auth)["status"] == "COMMITTED"
    assert store.get_state("reserved:t") == 200_000


def test_real_concurrent_replay_separate_connections(system):
    s = system
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    auth = s.auth()
    barrier = threading.Barrier(2)
    results = []
    def run(gateway):
        barrier.wait()
        results.append(gateway.commit(auth["ticket"], auth["commit_args"], s.worker))
    threads = [threading.Thread(target=run, args=(r.gateway,)) for r in (s.runtime, other)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(5)
    assert all(not thread.is_alive() for thread in threads)
    assert sorted(r["status"] for r in results) == ["COMMITTED", "REJECTED"]
    assert len(s.runtime.store.inspect_outbox()) == 1
    other.store.close()

def test_concurrent_authorization_separate_connections_uses_safe_z3_context(system):
    s = system
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    barrier = threading.Barrier(2)
    results = []
    def authorize(runtime, op):
        barrier.wait()
        results.append(runtime.authority.authorize(s.request(op), s.worker))
    threads = [threading.Thread(target=authorize, args=(runtime, op))
               for runtime, op in ((s.runtime, "a"), (other, "b"))]
    for thread in threads: thread.start()
    for thread in threads: thread.join(5)
    assert all(not t.is_alive() for t in threads)
    assert len(results) == 2 and all(r["decision"] == "ALLOW" for r in results), results
    # Both independent operations have the same shared business snapshot.
    assert all(r["ticket"]["footprint"]["contract3:t"] == 1 for r in results)
    other.store.close()


def test_receiver_cannot_report_failure_after_durable_effect(system):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    assert s.runtime.dispatcher.dispatch_once(lose_ack=True)["status"] == "UNKNOWN"
    s.runtime.dispatcher.receiver = SimulatedReceiver(s.runtime.store, definite_failures={("t", "pay")})
    assert s.runtime.dispatcher.dispatch_once()["status"] == "RELEASED"
    assert s.runtime.store.get_state("budget:t") == 200_000


def test_irrelevant_key_does_not_stale_but_reservation_settlement_does(system):
    s = system
    auth = s.auth()
    s.runtime.store.set_state("unrelated:fixture", "change")
    assert s.commit(auth)["status"] == "COMMITTED"
    s.runtime.dispatcher.dispatch_once()
    s.execute(s.request("pay", "transfer_funds"))
    waiting = s.auth(s.request("waiting"))
    assert s.runtime.dispatcher.dispatch_once()["status"] == "RELEASED"
    stale = s.commit(waiting)
    assert stale["status"] == "STALE_TICKET"
    assert {"budget:t", "reserved:t"} <= set(stale["stale_keys"])


def test_concurrent_claim_single_winner_and_receiver_dedupe(system):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    barrier = threading.Barrier(2)
    claims = []
    def claim(dispatcher):
        barrier.wait()
        claims.append(dispatcher.claim())
    threads = [threading.Thread(target=claim, args=(r.dispatcher,)) for r in (s.runtime, other)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(5)
    assert all(not t.is_alive() for t in threads)
    assert sum(c is not None for c in claims) == 1
    winner = next(c for c in claims if c is not None)
    payload = json.loads(winner["payload"])
    first = s.runtime.receiver.deliver("t", "pay", payload)
    assert other.receiver.deliver("t", "pay", payload) == first
    assert s.runtime.dispatcher.finish(winner, first)["status"] == "RELEASED"
    balance = json.loads(s.runtime.store._conn.execute("SELECT value FROM receiver_state WHERE key='account:account-1'").fetchone()[0])
    assert balance["balance"] == 200_000
    other.store.close()


def test_lost_ack_restart_retry_has_one_effect_and_one_settlement(system):
    s = system
    request = s.request("pay", "transfer_funds")
    auth = s.execute(request)
    assert s.runtime.dispatcher.dispatch_once(lose_ack=True)["status"] == "UNKNOWN"
    assert s.runtime.store.get_state("reserved:t") == 200_000
    assert s.runtime.store.get_state("budget:t") == 0
    receipt = s.runtime.store._conn.execute("SELECT receipt FROM receiver_receipts").fetchone()[0]
    s.restart()
    result = s.runtime.dispatcher.dispatch_once()
    assert result["status"] == "RELEASED" and json.loads(receipt) == result["receipt"]
    assert s.runtime.store.get_state("reserved:t") == 0 and s.runtime.store.get_state("budget:t") == 200_000
    status = operation_status(s.runtime.store, "t", "pay", auth["request_digest"], s.worker)
    assert status["attempts"] == 2 and status["delivery"] == "RELEASED"
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM receiver_receipts").fetchone()[0] == 1
    assert s.runtime.dispatcher.dispatch_once()["status"] == "IDLE"


@pytest.mark.parametrize("effect_before_crash", [False, True])
def test_expired_lease_recovery_and_fencing(system, effect_before_crash):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    old_claim = s.runtime.dispatcher.claim()
    if effect_before_crash:
        s.runtime.receiver.deliver("t", "pay", json.loads(old_claim["payload"]))
    s.restart()
    assert s.runtime.dispatcher.claim() is None
    s.clock.advance(31)
    new_claim = s.runtime.dispatcher.claim()
    assert new_claim["attempts"] == 2 and new_claim["lease"] != old_claim["lease"]
    receipt = s.runtime.receiver.deliver("t", "pay", json.loads(new_claim["payload"]))
    assert s.runtime.dispatcher.finish(old_claim, receipt)["status"] == "IGNORED"
    assert s.runtime.dispatcher.finish(new_claim, receipt)["status"] == "RELEASED"
    assert s.runtime.store.get_state("budget:t") == 200_000


def test_unknown_reservation_stays_bound_and_definite_failure_releases(system):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    claim = s.runtime.dispatcher.claim()
    assert s.runtime.dispatcher.finish(claim, error="timeout")["status"] == "UNKNOWN"
    assert s.runtime.store.get_state("reserved:t") == 200_000
    large = s.request("large", "transfer_funds", {"to": "account-1", "amount": 800_001})
    assert s.auth(large)["decision"] == "DENY"
    s.runtime.dispatcher.receiver = SimulatedReceiver(s.runtime.store, definite_failures={("t", "pay")})
    assert s.runtime.dispatcher.dispatch_once()["status"] == "FAILED"
    assert s.runtime.store.get_state("reserved:t") == s.runtime.store.get_state("budget:t") == 0
    assert s.auth(large)["decision"] == "ALLOW"
    assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM receiver_state").fetchone()[0] == 0


def test_settlement_cannot_be_forged_and_rolls_back(system):
    s = system
    s.execute(s.request("pay", "transfer_funds"))
    claim = s.runtime.dispatcher.claim()
    with pytest.raises(ValueError, match="unverified"):
        s.runtime.dispatcher.finish(claim, {"outcome": "FAILED", "absence_proven": True})
    receipt = s.runtime.receiver.deliver("t", "pay", json.loads(claim["payload"]))
    store = s.runtime.store
    store._conn.execute("CREATE TRIGGER fail_settle BEFORE UPDATE OF value ON conflict_keys WHEN NEW.key='budget:t' BEGIN SELECT RAISE(ABORT, 'settle crash'); END")
    with pytest.raises(Exception): s.runtime.dispatcher.finish(claim, receipt)
    assert store.get_state("reserved:t") == 200_000 and store.get_state("budget:t") == 0
    assert store.inspect_outbox()[0]["status"] == "RELEASING"
    store._conn.execute("DROP TRIGGER fail_settle")
    assert s.runtime.dispatcher.finish(claim, receipt)["status"] == "RELEASED"


def test_payload_is_frozen_before_authorization_and_delivery(system):
    s = system
    request = s.request()
    auth = s.auth(request)
    request["args"]["body"] = "mutated caller container"
    assert s.commit(auth)["status"] == "COMMITTED"
    receipt = s.runtime.dispatcher.dispatch_once()["receipt"]
    assert receipt["result"]["body"] == "summary"
    payload = json.loads(s.runtime.store.inspect_outbox()[0]["payload"])
    payload["args"]["body"] = "substitution"
    with pytest.raises(ValueError, match="payload mismatch"): s.runtime.receiver.deliver("t", "op", payload)


def test_dummy_deploy_mutates_simulated_state(system):
    s = system
    s.execute(s.request("deploy", "deploy"))
    receipt = s.runtime.dispatcher.dispatch_once()["receipt"]
    assert receipt["result"]["digest"] == s.document["digest"]
    assert s.runtime.store._conn.execute("SELECT value FROM receiver_state WHERE key='deployment:sandbox'").fetchone()


def test_legacy_gateway_cannot_bypass_phase3_outbox(system):
    s = system
    ticket = create_ticket("t", "W", "send_email", {"to": "any"}, {}, [], s.sk)
    gateway = ToolGateway(s.runtime.store, s.sk.verify_key)
    result = gateway.commit(ticket.to_dict(), {"to": "any"}, caller_agent_id="W")
    assert result["status"] == "REJECTED" and "Phase 3" in result["reason"]
    assert gateway.effect_log.effects == [] and s.runtime.store.inspect_outbox() == []


def test_snapshot_read_during_concurrent_contract_activation(system):
    s = system
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    harness = ControlledHarness()
    s.runtime.authority.harness = harness
    harness.pause("snapshot_authorization", "a")
    result = {}
    thread = threading.Thread(target=lambda: result.update(s.auth(action_id="a")))
    thread.start()
    harness.wait_reached("snapshot_authorization", "a")
    proposal = other.contracts.propose({**s.proposal, "allowed_recipients": ["different"]}, s.worker)
    other.broker.decide(proposal["review_id"], True, s.approver)
    other.contracts.activate(proposal["proposal_id"], proposal["review_id"], s.approver)
    harness.release("snapshot_authorization", "a")
    thread.join(5)
    assert not thread.is_alive() and result["decision"] == "ALLOW", result
    assert result["ticket"]["footprint"]["contract3:t"] == 1
    assert s.commit(result)["status"] == "STALE_TICKET"
    other.store.close()
