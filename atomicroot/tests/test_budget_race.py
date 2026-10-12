"""
test_budget_race — concurrent double-spend scenario for budget_monotone.

Scenario:
    A task has a budget cap of 1,000,000 IDR.
    Two agents concurrently request transfers of 700,000 IDR each.
    Each individual transfer is under the cap, so both are ALLOWED by the
    policy at evaluation time.  But their combined total (1,400,000) exceeds
    the cap.

Two modes:
- **baseline**: CAS disabled → both commits succeed, budget violated.
- **atomicroot**: CAS enabled → the second commit detects that
  budget:<task_id> was bumped by the first → STALE_TICKET.
"""

import pytest

from atomicroot.store.trace_store import TraceStore
from atomicroot.authority.authority import PolicyAuthority, TaskContextStore
from atomicroot.authority.ticket import generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.sim.worker import SimulatedWorker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def harness():
    store = TraceStore(":memory:")
    sk, vk = generate_keypair()
    task_ctx = TaskContextStore()
    authority = PolicyAuthority(store, task_ctx, signing_key=sk)
    effect_log = ToolEffectLog()
    gateway = ToolGateway(store, vk, effect_log, allow_baseline=True)

    task_id = "t-budget-01"
    task_ctx.register_task(task_id, {"budget_cap": 1_000_000})

    worker_a = SimulatedWorker("agent-A", authority, gateway)
    worker_b = SimulatedWorker("agent-B", authority, gateway)

    return {
        "store": store,
        "authority": authority,
        "task_ctx": task_ctx,
        "gateway": gateway,
        "effect_log": effect_log,
        "worker_a": worker_a,
        "worker_b": worker_b,
        "task_id": task_id,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_budget_scenario(harness, *, skip_freshness_check: bool):
    """
    Execute the concurrent double-spend interleaving.

    Steps:
    1. Agent A requests auth for transfer_funds (700,000).
    2. Agent B requests auth for transfer_funds (700,000).
       Both observe budget:t-budget-01 at version 0, cumulative spend 0.
       Both are individually under the 1,000,000 cap → ALLOW.
    3. Agent A commits → budget version 0 → 1, spend recorded.
    4. The same Commit records the spend in SQLite.
    5. Agent B commits with ticket observing version 0.
    """
    h = harness
    task_id = h["task_id"]

    args_a = {"to_account": "vendor-A", "amount": 700_000}
    args_b = {"to_account": "vendor-B", "amount": 700_000}

    # Step 1 & 2: Both agents request auth concurrently.
    ticket_a = h["worker_a"].request_authorization(
        task_id=task_id, tool="transfer_funds", args=args_a,
    )
    assert "ticket_id" in ticket_a, f"Agent A auth denied: {ticket_a}"

    ticket_b = h["worker_b"].request_authorization(
        task_id=task_id, tool="transfer_funds", args=args_b,
    )
    assert "ticket_id" in ticket_b, f"Agent B auth denied: {ticket_b}"

    # Step 3: Agent A commits.
    result_a = h["worker_a"].execute(
        ticket_a, args_a, skip_freshness_check=skip_freshness_check,
    )
    assert result_a["status"] == "COMMITTED", f"Agent A commit failed: {result_a}"

    # Spend is updated in the same SQLite Commit as the event and version.

    # Step 5: Agent B commits.
    result_b = h["worker_b"].execute(
        ticket_b, args_b, skip_freshness_check=skip_freshness_check,
    )

    return result_a, result_b, h["effect_log"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBudgetRaceBaseline:
    """
    Baseline: CAS disabled → both transfers succeed, budget violated.
    """

    def test_baseline_double_spend_succeeds(self, harness):
        result_a, result_b, effect_log = _run_budget_scenario(
            harness, skip_freshness_check=True,
        )

        assert result_a["status"] == "COMMITTED"
        assert result_b["status"] == "COMMITTED"

        # Both effects fired — 1,400,000 total on a 1,000,000 cap.
        assert len(effect_log.effects) == 2, (
            "Baseline: both transfers should have executed (budget violation)"
        )


class TestBudgetRaceAtomicRoot:
    """
    AtomicRoot: CAS enabled → second transfer rejected.
    """

    def test_atomicroot_blocks_double_spend(self, harness):
        result_a, result_b, effect_log = _run_budget_scenario(
            harness, skip_freshness_check=False,
        )

        assert result_a["status"] == "COMMITTED"
        assert result_b["status"] == "STALE_TICKET"
        assert "budget:t-budget-01" in result_b["stale_keys"]

        # Only one transfer effect fired.
        assert len(effect_log.effects) == 1
        assert effect_log.effects[0]["tool"] == "transfer_funds"

    def test_atomicroot_reauth_after_stale_is_denied(self, harness):
        """
        After the first transfer commits, re-evaluating Agent B's request
        with the *updated* cumulative spend should result in a DENY
        (projected 1,400,000 > cap 1,000,000).
        """
        h = harness
        _result_a, result_b, _ = _run_budget_scenario(
            harness, skip_freshness_check=False,
        )
        assert result_b["status"] == "STALE_TICKET"

        # Agent B re-requests authorisation.
        reauth = h["worker_b"].request_authorization(
            task_id=h["task_id"],
            tool="transfer_funds",
            args={"to_account": "vendor-B", "amount": 700_000},
        )

        # This time the policy should DENY because cumulative is 700k + 700k > 1M.
        assert reauth["decision"] == "DENY"
        assert reauth["policy"] == "budget_monotone"
