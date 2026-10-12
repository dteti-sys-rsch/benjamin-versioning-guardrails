"""
test_parallel_disjoint — non-overlapping footprints both commit.

Phase 1 criterion: two tasks with independent task-state conflict keys must
both commit without invalidating each other's tickets. Shared policy membership
is read-only during ordinary commits. SQLite WAL has one
physical writer at a time; this tests logical independence of keys.
"""

import pytest
import threading

from atomicroot.store.trace_store import TraceStore
from atomicroot.authority.authority import PolicyAuthority, TaskContextStore
from atomicroot.authority.ticket import generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.sim.worker import SimulatedWorker


@pytest.fixture
def harness():
    store = TraceStore(":memory:")
    sk, vk = generate_keypair()
    task_ctx = TaskContextStore()
    authority = PolicyAuthority(store, task_ctx, signing_key=sk)
    effect_log = ToolEffectLog()
    gateway = ToolGateway(store, vk, effect_log)

    # Separate task state; both read the unchanged tool policy membership.
    task_ctx.register_task("t-alpha", {"budget_cap": 500_000})
    task_ctx.register_task("t-beta", {"budget_cap": 500_000})

    worker_alpha = SimulatedWorker("agent-alpha", authority, gateway)
    worker_beta = SimulatedWorker("agent-beta", authority, gateway)

    return {
        "store": store,
        "authority": authority,
        "gateway": gateway,
        "effect_log": effect_log,
        "worker_alpha": worker_alpha,
        "worker_beta": worker_beta,
    }


class TestDisjointFootprintsParallel:
    """
    Two workers operating on disjoint conflict keys
    (budget:t-alpha vs budget:t-beta) must both commit successfully,
    even when executed concurrently.
    """

    def test_disjoint_both_commit(self, harness):
        h = harness

        # Both request auth — different tasks, different conflict keys.
        ticket_alpha = h["worker_alpha"].request_authorization(
            task_id="t-alpha",
            tool="transfer_funds",
            args={"to_account": "vendor-X", "amount": 300_000},
        )
        ticket_beta = h["worker_beta"].request_authorization(
            task_id="t-beta",
            tool="transfer_funds",
            args={"to_account": "vendor-Y", "amount": 250_000},
        )

        assert "ticket_id" in ticket_alpha
        assert "ticket_id" in ticket_beta

        # Commit both — order does not matter since keys are disjoint.
        result_alpha = h["worker_alpha"].execute(
            ticket_alpha,
            {"to_account": "vendor-X", "amount": 300_000},
        )
        result_beta = h["worker_beta"].execute(
            ticket_beta,
            {"to_account": "vendor-Y", "amount": 250_000},
        )

        assert result_alpha["status"] == "COMMITTED"
        assert result_beta["status"] == "COMMITTED"

        # Both effects fired.
        assert len(h["effect_log"].effects) == 2

    def test_disjoint_concurrent_threads(self, harness):
        """
        Same test but with actual threading to increase confidence
        that the locking does not cause false conflicts.
        """
        h = harness

        ticket_alpha = h["worker_alpha"].request_authorization(
            task_id="t-alpha",
            tool="transfer_funds",
            args={"to_account": "vendor-X", "amount": 100_000},
        )
        ticket_beta = h["worker_beta"].request_authorization(
            task_id="t-beta",
            tool="transfer_funds",
            args={"to_account": "vendor-Y", "amount": 100_000},
        )

        results = {}

        def commit_alpha():
            results["alpha"] = h["worker_alpha"].execute(
                ticket_alpha,
                {"to_account": "vendor-X", "amount": 100_000},
            )

        def commit_beta():
            results["beta"] = h["worker_beta"].execute(
                ticket_beta,
                {"to_account": "vendor-Y", "amount": 100_000},
            )

        t1 = threading.Thread(target=commit_alpha)
        t2 = threading.Thread(target=commit_beta)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert results["alpha"]["status"] == "COMMITTED"
        assert results["beta"]["status"] == "COMMITTED"
