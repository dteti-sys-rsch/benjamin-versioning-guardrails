"""Ticket binding, replay, and real SQLite connection concurrency."""
from datetime import datetime, timedelta, timezone
import threading

import z3
import asyncio
import httpx

from atomicroot.authority.authority import PolicyAuthority, TaskContextStore
from atomicroot.authority.policy_engine import Const, StatusReader, solve
from atomicroot.authority.ticket import create_ticket, generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.sim.harness import ControlledHarness
from atomicroot.sim.worker import SimulatedWorker
from atomicroot.store.trace_store import TraceStore
from atomicroot.api import create_app


def test_ticket_binding_expiry_and_rejected_effects():
    store = TraceStore()
    sk, vk = generate_keypair()
    effects = ToolEffectLog()
    gateway = ToolGateway(store, vk, effects)
    ticket = create_ticket("t1", "A", "send_email", {"to": "x"},
                           {"taint:t1": 0}, [], sk)
    tests = [
        ({**ticket.to_dict(), "signature": "ed25519:bad"}, {"to": "x"}, "A"),
        ({**ticket.to_dict(), "tool": "read_document"}, {"to": "x"}, "A"),
        ({**ticket.to_dict(), "task_id": "t2"}, {"to": "x"}, "A"),
        (ticket.to_dict(), {"to": "y"}, "A"),
        (ticket.to_dict(), {"to": "x"}, "B"),
    ]
    for forged, args, caller in tests:
        assert gateway.commit(forged, args, caller_agent_id=caller)["status"] == "REJECTED"
    expired = create_ticket("t1", "A", "send_email", {"to": "x"}, {}, [], sk)
    expired.not_after = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    expired.sign(sk)
    assert gateway.commit(expired.to_dict(), {"to": "x"}, caller_agent_id="A")["status"] == "REJECTED"
    future = create_ticket("t1", "A", "send_email", {"to": "x"}, {}, [], sk)
    future.not_before = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    future.sign(sk)
    assert gateway.commit(future.to_dict(), {"to": "x"}, caller_agent_id="A")["status"] == "REJECTED"
    assert not effects.effects
    assert store.get_trace() == []


def test_worker_cannot_choose_write_set_or_classification():
    store = TraceStore()
    sk, vk = generate_keypair()
    ctx = TaskContextStore()
    auth = PolicyAuthority(store, ctx, sk)
    ctx.register_task("t1", {"budget_cap": 100})
    ctx.register_document("d1", "finance")
    request = {"task_id": "t1", "agent_id": "A", "tool": "read_document",
               "args": {"doc_id": "d1"}, "write_set": [], "data_class": "public"}
    ticket = auth.authorize(request, caller_agent_id="A")
    assert "taint:t1" in ticket["write_set"]
    bad = {**request, "args": {"doc_id": "d1", "data_class": "public"}}
    assert auth.authorize(bad, caller_agent_id="A")["decision"] == "EVALUATION_ERROR"
    assert auth.authorize(request, caller_agent_id="B")["decision"] == "EVALUATION_ERROR"


def test_concurrent_same_key_with_separate_connections(tmp_path):
    path = str(tmp_path / "cas.db")
    store_a, store_b = TraceStore(path), TraceStore(path)
    sk, vk = generate_keypair()
    harness = ControlledHarness()
    effects = ToolEffectLog()
    auth = PolicyAuthority(store_a, TaskContextStore(), sk)
    auth.task_ctx.register_task("t1", {"budget_cap": 100})
    worker_a = SimulatedWorker("A", auth, ToolGateway(store_a, vk, effects, harness=harness))
    worker_b = SimulatedWorker("B", auth, ToolGateway(store_b, vk, effects, harness=harness))
    ticket_a = worker_a.request_authorization("t1", "transfer_funds", {"amount": 70})
    ticket_b = worker_b.request_authorization("t1", "transfer_funds", {"amount": 70})
    harness.pause("before_cas", "a")
    harness.pause("before_cas", "b")
    results = {}
    threads = [
        threading.Thread(target=lambda: results.update(a=worker_a.execute(ticket_a, {"amount": 70}, action_id="a"))),
        threading.Thread(target=lambda: results.update(b=worker_b.execute(ticket_b, {"amount": 70}, action_id="b"))),
    ]
    for thread in threads:
        thread.start()
    harness.wait_reached("before_cas", "a")
    harness.wait_reached("before_cas", "b")
    harness.release("before_cas", "a")
    harness.release("before_cas", "b")
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert {results["a"]["status"], results["b"]["status"]} == {"COMMITTED", "STALE_TICKET"}
    assert store_a.get_state("budget:t1") == 70
    assert len(store_a.get_trace()) == len(effects.effects) == 1
    assert any(stage == "after_commit" for _, _, stage in harness.steps)


def test_concurrent_replay_empty_write_set_separate_connections(tmp_path):
    path = str(tmp_path / "replay.db")
    store_a, store_b = TraceStore(path), TraceStore(path)
    sk, vk = generate_keypair()
    effects = ToolEffectLog()
    ticket = create_ticket("t1", "A", "send_email", {"to": "x"}, {}, [], sk)
    gateways = [ToolGateway(store_a, vk, effects), ToolGateway(store_b, vk, effects)]
    barrier = threading.Barrier(3)
    results = []
    def run(gateway):
        barrier.wait()
        results.append(gateway.commit(ticket.to_dict(), {"to": "x"}, caller_agent_id="A"))
    threads = [threading.Thread(target=run, args=(gateway,)) for gateway in gateways]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert sorted(r["status"] for r in results) == ["COMMITTED", "REJECTED"]
    assert len(effects.effects) == len(store_a.get_trace()) == 1


def test_unsat_path_does_not_read_model():
    class Solver:
        checks = 0
        def set(self, **kwargs): pass
        def add(self, *args): pass
        def push(self): pass
        def check(self):
            self.checks += 1
            return z3.sat if self.checks == 1 else z3.unsat
        def model(self):
            raise AssertionError("model on UNSAT")
    store = TraceStore()
    with store.snapshot() as snap:
        result = solve("test", Const(True), {"task_id": "t1", "args": {}},
                       StatusReader(snap), [], solver_factory=Solver)
    assert result.decision == "ALLOW"


def test_fastapi_uses_server_bound_identity():
    store = TraceStore()
    sk, vk = generate_keypair()
    auth = PolicyAuthority(store, TaskContextStore(), sk)
    auth.task_ctx.register_task("t1", {"budget_cap": 100})
    gateway = ToolGateway(store, vk)
    app = create_app(auth, gateway, lambda request: "A")

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://test") as client:
            bad = await client.post("/authorize", json={"task_id": "t1", "agent_id": "B",
                                                        "tool": "transfer_funds", "args": {"amount": 1}})
            assert bad.status_code == 422
            good = await client.post("/authorize", json={"task_id": "t1", "agent_id": "A",
                                                         "tool": "transfer_funds", "args": {"amount": 1}})
            assert good.status_code == 200
            committed = await client.post("/commit", json={"ticket": good.json(),
                                                            "args": {"amount": 1}})
            assert committed.json()["status"] == "COMMITTED"
    asyncio.run(scenario())


def test_caller_mutation_after_verification_cannot_change_commit():
    store = TraceStore()
    sk, vk = generate_keypair()
    harness = ControlledHarness()
    effects = ToolEffectLog()
    auth = PolicyAuthority(store, TaskContextStore(), sk)
    auth.task_ctx.register_task("t1", {"budget_cap": 100})
    worker = SimulatedWorker("A", auth, ToolGateway(store, vk, effects, harness=harness))
    args = {"amount": 50}
    ticket = worker.request_authorization("t1", "transfer_funds", args)
    harness.pause("before_cas", "mutable")
    result = {}
    thread = threading.Thread(target=lambda: result.update(
        worker.execute(ticket, args, action_id="mutable")))
    thread.start()
    harness.wait_reached("before_cas", "mutable")
    args["amount"] = 999
    ticket["write_set"].clear()
    harness.release("before_cas", "mutable")
    thread.join(5)
    assert not thread.is_alive()
    assert result["status"] == "COMMITTED"
    assert store.get_state("budget:t1") == 50
    assert effects.effects[0]["args"] == {"amount": 50}


def test_expiry_rechecked_inside_commit_transaction():
    clock_value = [datetime.now(timezone.utc)]
    store = TraceStore(clock=lambda: clock_value[0])
    sk, vk = generate_keypair()
    harness = ControlledHarness()
    effects = ToolEffectLog()
    gateway = ToolGateway(store, vk, effects, harness=harness)
    ticket = create_ticket("t1", "A", "send_email", {"to": "x"}, {}, [], sk)
    harness.pause("before_cas", "expiry")
    result = {}
    thread = threading.Thread(target=lambda: result.update(gateway.commit(
        ticket.to_dict(), {"to": "x"}, caller_agent_id="A", action_id="expiry")))
    thread.start()
    harness.wait_reached("before_cas", "expiry")
    clock_value[0] += timedelta(minutes=1)
    harness.release("before_cas", "expiry")
    thread.join(5)
    assert not thread.is_alive()
    assert result["status"] == "REJECTED"
    assert not effects.effects and not store.get_trace()
