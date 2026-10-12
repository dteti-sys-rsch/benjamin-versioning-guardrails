import threading

import pytest
import z3

from atomicroot.authority.authority import PolicyAuthority, TaskContextStore
from atomicroot.authority.policies import budget_monotone, no_exfil_after_sensitive
from atomicroot.authority.policy_engine import (Ref, Const, If, StatusReader,
    dependencies, solve)
from atomicroot.authority.ticket import create_ticket, generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.sim.harness import ControlledHarness
from atomicroot.sim.worker import SimulatedWorker
from atomicroot.store.trace_store import TraceStore


@pytest.fixture
def system():
    store = TraceStore()
    sk, vk = generate_keypair()
    ctx = TaskContextStore()
    authority = PolicyAuthority(store, ctx, sk)
    effects = ToolEffectLog()
    gateway = ToolGateway(store, vk, effects)
    ctx.register_task("t1", {"budget_cap": 100})
    ctx.register_document("d1", "finance")
    return store, ctx, authority, gateway, effects, SimulatedWorker("A", authority, gateway)


def test_expected_budget_boundaries_and_witness(system):
    store, ctx, authority, gateway, effects, worker = system
    for amount, spend, expected in [(50, 0, "ALLOW"), (100, 0, "ALLOW"),
                                    (101, 0, "DENY"), (20, 80, "ALLOW"),
                                    (21, 80, "DENY"), (30, 80, "DENY")]:
        store.set_state("budget:t1", spend)
        request = {"task_id": "t1", "agent_id": "A", "tool": "transfer_funds",
                   "args": {"amount": amount}}
        with store.snapshot() as snap:
            z3_result = budget_monotone.evaluate({}, {"reader": StatusReader(snap)}, request)
        assert z3_result.decision == expected
        assert {"budget:t1", "contract:t1"} <= set(z3_result.footprint)
        if z3_result.decision == "DENY":
            assert z3_result.witness is not None
            assert z3_result.violating_action == {"tool": "transfer_funds", "args": {"amount": amount}}


def test_expected_taint_outcomes_and_witness(system):
    store, ctx, authority, gateway, effects, worker = system
    for tainted, expected in [([], "ALLOW"), (["public"], "ALLOW"),
                              (["internal"], "ALLOW"), (["finance"], "DENY"),
                              (["sensitive"], "DENY")]:
        store.set_state("taint:t1", tainted)
        request = {"task_id": "t1", "agent_id": "A", "tool": "send_email",
                   "args": {"to": "x"}}
        with store.snapshot() as snap:
            z3_result = no_exfil_after_sensitive.evaluate({}, {"reader": StatusReader(snap)}, request)
        assert z3_result.decision == expected
        assert "taint:t1" in z3_result.footprint
        if expected == "DENY":
            assert z3_result.witness is not None
            assert z3_result.trigger_event is None  # trusted setup mutation has no trace event


def test_real_trigger_event_and_budget_evidence(system):
    store, ctx, authority, gateway, effects, worker = system
    assert worker.authorize_and_execute("t1", "read_document", {"doc_id": "d1"})["status"] == "COMMITTED"
    denial = worker.request_authorization("t1", "send_email", {"to": "x"})
    assert denial["decision"] == "DENY"
    assert denial["trigger_event"]["seq"] == 1
    assert denial["trigger_event"]["tool"] == "read_document"
    assert denial["evidence_events"][0]["seq"] == 1
    assert worker.authorize_and_execute("t1", "transfer_funds", {"amount": 80})["status"] == "COMMITTED"
    denial = worker.request_authorization("t1", "transfer_funds", {"amount": 30})
    assert denial["decision"] == "DENY"
    assert denial["trigger_event"]["tool"] == "transfer_funds"
    assert denial["evidence_events"]
    assert denial["witness"]["budget:t1"] == "80"
    assert denial["witness"]["contract:t1"] == "100"
    assert 80 + denial["violating_action"]["args"]["amount"] > 100


def test_static_unused_branch_dynamic_read_and_official_initial_key(system):
    store, ctx, authority, gateway, effects, worker = system
    expr = If(Const(False), Ref("tainted", "task"), Const(True))
    request = {"task_id": "t1", "args": {}}
    assert dependencies(expr, request) == {"taint:t1"}
    with store.snapshot() as snap:
        result = solve("no_exfil_after_sensitive", expr, request, StatusReader(snap), [])
    assert result.decision == "ALLOW"
    assert result.footprint["taint:t1"] == 0
    ticket = worker.request_authorization("t1", "read_document", {"doc_id": "d1"})
    assert {"class:d1", "taint:t1"} <= set(ticket["footprint"])


def test_outside_footprint_and_conservative_abort(system):
    store, ctx, authority, gateway, effects, worker = system
    email = worker.request_authorization("t1", "send_email", {"to": "x"})
    store.set_state("irrelevant:t1", "changed")
    assert worker.execute(email, {"to": "x"})["status"] == "COMMITTED"
    read = worker.request_authorization("t1", "read_document", {"doc_id": "d1"})
    assert "taint:t1" in read["footprint"]
    store.set_state("taint:t1", ["finance"])
    assert worker.execute(read, {"doc_id": "d1"})["status"] == "STALE_TICKET"


def test_small_domain_outside_footprint_cannot_change_decision(system):
    store, ctx, authority, gateway, effects, worker = system
    for taint in ([], ["finance"]):
        store.set_state("taint:t1", taint)
        request = {"task_id": "t1", "agent_id": "A", "tool": "send_email", "args": {"to": "x"}}
        decisions = []
        for irrelevant in (0, 1, 2):
            store.set_state("irrelevant:t1", irrelevant)
            with store.snapshot() as snap:
                result = no_exfil_after_sensitive.evaluate({}, {"reader": StatusReader(snap)}, request)
            assert "irrelevant:t1" not in result.footprint
            decisions.append(result.decision)
        assert len(set(decisions)) == 1


def test_contract_and_class_changes_stale_tickets(system):
    store, ctx, authority, gateway, effects, worker = system
    transfer = worker.request_authorization("t1", "transfer_funds", {"amount": 50})
    ctx.register_task("t1", {"budget_cap": 40})
    assert worker.execute(transfer, {"amount": 50})["status"] == "STALE_TICKET"
    read = worker.request_authorization("t1", "read_document", {"doc_id": "d1"})
    ctx.register_document("d1", "public")
    assert worker.execute(read, {"doc_id": "d1"})["status"] == "STALE_TICKET"


def test_two_applicable_policies_cannot_bypass_either(system):
    store, ctx, authority, gateway, effects, worker = system
    # Trusted service definition fixture classifies this transfer as external.
    authority = PolicyAuthority(store, ctx,
        external_tools=no_exfil_after_sensitive.EXTERNAL_TOOLS | {"transfer_funds"})
    authority.configure_tool_policies("transfer_funds",
                                     ["no_exfil_after_sensitive", "budget_monotone"])
    worker = SimulatedWorker("A", authority, ToolGateway(store, authority.verify_key))
    store.set_state("taint:t1", ["finance"])
    assert worker.request_authorization("t1", "transfer_funds", {"amount": 1})["policy"] == "no_exfil_after_sensitive"
    store.set_state("taint:t1", [])
    assert worker.request_authorization("t1", "transfer_funds", {"amount": 101})["policy"] == "budget_monotone"
    ticket = worker.request_authorization("t1", "transfer_funds", {"amount": 1})
    assert {"taint:t1", "budget:t1", "contract:t1"} <= set(ticket["footprint"])


def test_errors_fail_closed(system):
    store, ctx, authority, gateway, effects, worker = system
    assert worker.request_authorization("t1", "transfer_funds", {"amount": -1})["decision"] == "EVALUATION_ERROR"
    assert worker.request_authorization("t1", "transfer_funds", {"amount": True})["decision"] == "EVALUATION_ERROR"
    assert worker.request_authorization("t1", "read_document", {"doc_id": "unknown"})["decision"] == "EVALUATION_ERROR"
    with store.snapshot() as snap:
        reader = StatusReader(snap)
        assert solve("test", object(), {"task_id": "t1", "args": {}}, reader, []).decision == "EVALUATION_ERROR"
    class UnknownSolver:
        calls = 0
        def set(self, **kwargs): pass
        def add(self, *args): pass
        def push(self): pass
        def check(self):
            self.calls += 1
            return z3.sat if self.calls == 1 else z3.unknown
        def model(self):
            raise AssertionError("model must not be called")
    with store.snapshot() as snap:
        result = solve("test", Const(True), {"task_id": "t1", "args": {}},
                       StatusReader(snap), [], solver_factory=UnknownSolver)
    assert result.decision == "EVALUATION_ERROR"


def test_interleaved_snapshot_is_consistent(tmp_path):
    path = str(tmp_path / "snapshot.db")
    first, second = TraceStore(path), TraceStore(path)
    sk, vk = generate_keypair()
    harness = ControlledHarness()
    authority = PolicyAuthority(first, TaskContextStore(), sk, harness=harness)
    authority.task_ctx.register_task("t1", {"budget_cap": 100})
    worker = SimulatedWorker("A", authority, ToolGateway(first, vk))
    harness.pause("snapshot_authorization", "x")
    result = {}
    thread = threading.Thread(target=lambda: result.update(
        worker.request_authorization("t1", "transfer_funds", {"amount": 50}, action_id="x")))
    thread.start()
    harness.wait_reached("snapshot_authorization", "x")
    second.set_state("budget:t1", 90)
    harness.release("snapshot_authorization", "x")
    thread.join(5)
    assert not thread.is_alive()
    assert result["footprint"]["budget:t1"] == 0
    assert worker.execute(result, {"amount": 50})["status"] == "STALE_TICKET"
    assert [s for _, _, s in harness.steps] == ["snapshot_authorization", "ticket_issued"]


def test_recorded_checkpoint_schedule_can_be_replayed():
    schedule = [("a", "snapshot_authorization"), ("a", "ticket_issued"),
                ("b", "snapshot_authorization"), ("b", "ticket_issued")]
    harness = ControlledHarness(replay=schedule)
    def run(action):
        harness.checkpoint("snapshot_authorization", action)
        harness.checkpoint("ticket_issued", action)
    b = threading.Thread(target=run, args=("b",))
    a = threading.Thread(target=run, args=("a",))
    b.start()
    a.start()
    a.join(5)
    b.join(5)
    assert not a.is_alive() and not b.is_alive()
    assert harness.recorded_schedule() == schedule
