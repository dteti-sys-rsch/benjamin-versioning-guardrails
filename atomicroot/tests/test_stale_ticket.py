"""
test_stale_ticket — unit tests for ticket freshness enforcement.

Verifies:
- A ticket whose footprint versions match the Trace Store is accepted.
- A ticket whose footprint versions are stale (because another commit bumped
  a conflict key) is rejected with STALE_TICKET.
- A ticket with a forged/invalid signature is rejected.
- A ticket with mismatched args_hash is rejected.
"""

import pytest

from atomicroot.store.trace_store import TraceStore
from atomicroot.authority.ticket import generate_keypair, create_ticket, args_hash
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def setup():
    """Create a fresh Trace Store, keypair, and Gateway."""
    store = TraceStore(":memory:")
    sk, vk = generate_keypair()
    effect_log = ToolEffectLog()
    gateway = ToolGateway(store, vk, effect_log)
    return store, sk, vk, gateway, effect_log


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFreshTicketAccepted:
    """A ticket with matching footprint versions is COMMITTED."""

    def test_fresh_commit(self, setup):
        store, sk, vk, gateway, effect_log = setup

        # Set up a conflict key at version 3.
        store.set_version("taint:t-01", 3)

        # Create a ticket observing version 3.
        ticket = create_ticket(
            task_id="t-01",
            agent_id="W1",
            tool="send_email",
            args={"to": "alice@corp.id"},
            footprint={"taint:t-01": 3},
            write_set=["taint:t-01"],
            signing_key=sk,
        )

        result = gateway.commit(ticket.to_dict(), {"to": "alice@corp.id"}, caller_agent_id="W1")

        assert result["status"] == "COMMITTED"
        assert result["version_after"]["taint:t-01"] == 4
        assert effect_log.was_executed(ticket.ticket_id)


class TestStaleTicketRejected:
    """A ticket whose footprint no longer matches is STALE_TICKET."""

    def test_stale_after_concurrent_bump(self, setup):
        store, sk, vk, gateway, effect_log = setup

        # Conflict key starts at version 5.
        store.set_version("taint:t-02", 5)

        # Ticket observes version 5.
        ticket = create_ticket(
            task_id="t-02",
            agent_id="W2",
            tool="send_email",
            args={"to": "bob@evil.io"},
            footprint={"taint:t-02": 5},
            write_set=["taint:t-02"],
            signing_key=sk,
        )

        # Another commit bumps the key to version 6 before our ticket is used.
        store.set_version("taint:t-02", 6)

        result = gateway.commit(ticket.to_dict(), {"to": "bob@evil.io"}, caller_agent_id="W2")

        assert result["status"] == "STALE_TICKET"
        assert "taint:t-02" in result["stale_keys"]
        assert not effect_log.was_executed(ticket.ticket_id)


class TestInvalidSignatureRejected:
    """A ticket signed with the wrong key is REJECTED."""

    def test_bad_signature(self, setup):
        store, sk, vk, gateway, effect_log = setup

        # Sign with a different key.
        other_sk, _ = generate_keypair()
        ticket = create_ticket(
            task_id="t-03",
            agent_id="W3",
            tool="read_document",
            args={"doc_id": "d-1"},
            footprint={},
            write_set=[],
            signing_key=other_sk,  # wrong key!
        )

        result = gateway.commit(ticket.to_dict(), {"doc_id": "d-1"}, caller_agent_id="W3")

        assert result["status"] == "REJECTED"
        assert result["reason"] == "invalid_signature"
        assert not effect_log.was_executed(ticket.ticket_id)


class TestArgsHashMismatchRejected:
    """A ticket presented with different args than it was issued for is REJECTED."""

    def test_tampered_args(self, setup):
        store, sk, vk, gateway, effect_log = setup

        ticket = create_ticket(
            task_id="t-04",
            agent_id="W4",
            tool="send_email",
            args={"to": "alice@corp.id"},
            footprint={},
            write_set=[],
            signing_key=sk,
        )

        # Present different args.
        result = gateway.commit(
            ticket.to_dict(),
            {"to": "eve@evil.io"},  # different from signed args
            caller_agent_id="W4",
        )

        assert result["status"] == "REJECTED"
        assert result["reason"] == "args_hash_mismatch"
        assert not effect_log.was_executed(ticket.ticket_id)


class TestConcurrentCAS:
    """
    Two commits on the same conflict key — exactly one succeeds.

    This is the core Trace Store invariant: the CAS (compare-and-swap)
    ensures serialised access even under concurrency.
    """

    def test_two_commits_same_key(self, setup):
        store, sk, vk, gateway, effect_log = setup

        store.set_version("taint:t-05", 0)

        # Both tickets observe version 0.
        ticket_a = create_ticket(
            task_id="t-05", agent_id="W1", tool="read_document",
            args={"doc_id": "a"}, footprint={"taint:t-05": 0},
            write_set=["taint:t-05"], signing_key=sk,
        )
        ticket_b = create_ticket(
            task_id="t-05", agent_id="W2", tool="read_document",
            args={"doc_id": "b"}, footprint={"taint:t-05": 0},
            write_set=["taint:t-05"], signing_key=sk,
        )

        # Commit A first.
        res_a = gateway.commit(ticket_a.to_dict(), {"doc_id": "a"}, caller_agent_id="W1")
        assert res_a["status"] == "COMMITTED"

        # Commit B: same key was bumped by A → stale.
        res_b = gateway.commit(ticket_b.to_dict(), {"doc_id": "b"}, caller_agent_id="W2")
        assert res_b["status"] == "STALE_TICKET"
        assert "taint:t-05" in res_b["stale_keys"]
