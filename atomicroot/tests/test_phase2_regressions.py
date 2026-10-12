"""Security regressions found while auditing the Phase 1 prototype."""
from atomicroot.authority.ticket import create_ticket, generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.store.trace_store import TraceStore


def test_empty_write_set_ticket_is_single_use():
    store = TraceStore()
    sk, vk = generate_keypair()
    effects = ToolEffectLog()
    gateway = ToolGateway(store, vk, effects)
    ticket = create_ticket("t-1", "W1", "send_email", {"to": "a"},
                           {"taint:t-1": 0}, [], sk)
    assert gateway.commit(ticket.to_dict(), {"to": "a"}, caller_agent_id="W1")["status"] == "COMMITTED"
    assert gateway.commit(ticket.to_dict(), {"to": "a"}, caller_agent_id="W1")["status"] == "REJECTED"
    assert len(effects.effects) == 1


def test_signature_is_bound_to_tool_and_task():
    store = TraceStore()
    sk, vk = generate_keypair()
    gateway = ToolGateway(store, vk)
    ticket = create_ticket("t-1", "W1", "send_email", {"to": "a"}, {}, [], sk)
    for field, replacement in [("tool", "read_document"), ("task_id", "t-2")]:
        forged = ticket.to_dict()
        forged[field] = replacement
        assert gateway.commit(forged, {"to": "a"}, caller_agent_id="W1")["status"] == "REJECTED"


def test_store_transaction_rolls_back_on_duplicate_event():
    store = TraceStore()
    event = {"event_id": "duplicate", "task_id": "t", "agent_id": "W",
             "tool": "send_email", "args_hash": "h", "ticket_id": "ticket-1"}
    assert store.commit({"taint:t": 0}, ["taint:t"], event).status == "COMMITTED"
    event2 = {**event, "ticket_id": "ticket-2"}
    try:
        store.commit({"taint:t": 1}, ["taint:t"], event2)
    except Exception:
        pass
    assert store.get_version("taint:t") == 1
    assert len(store.get_trace()) == 1


def test_rollback_after_state_update_leaves_no_partial_commit():
    store = TraceStore()
    store._conn.execute("""CREATE TRIGGER fail_bump BEFORE UPDATE OF version ON conflict_keys
        WHEN NEW.key='budget:t' BEGIN SELECT RAISE(ABORT, 'forced failure'); END""")
    event = {"task_id": "t", "agent_id": "W", "tool": "transfer_funds",
             "args_hash": "h", "ticket_id": "tk", "nonce": "n", "args": {"amount": 10}}
    try:
        store.commit({"budget:t": 0}, ["budget:t"], event)
    except Exception:
        pass
    assert store.get_version("budget:t") == 0
    assert store.get_state("budget:t", 0) == 0
    assert store.get_trace() == []
    store._conn.execute("DROP TRIGGER fail_bump")
    assert store.commit({"budget:t": 0}, ["budget:t"], event).status == "COMMITTED"


def test_nonce_is_unique_even_with_distinct_ticket_ids():
    store = TraceStore()
    event = {"task_id": "t", "agent_id": "W", "tool": "send_email",
             "args_hash": "h", "nonce": "n"}
    assert store.commit({}, [], {**event, "ticket_id": "tk1"}).status == "COMMITTED"
    assert store.commit({}, [], {**event, "ticket_id": "tk2"}).status == "REPLAY"
    assert len(store.get_trace()) == 1
