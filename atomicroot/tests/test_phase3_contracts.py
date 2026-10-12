from copy import deepcopy
import pytest

from atomicroot.framework.dsl import parse_expr
from atomicroot.framework.registry import SOURCES, FACT_REGISTRY
from atomicroot.authority.policy_engine import StatusReader, solve, dependencies
from atomicroot.tests.phase3_support import System, custom_policy


@pytest.fixture
def system(tmp_path): return System(tmp_path / "phase3.db")


def test_contract_preview_activation_and_scope_enforcement(system):
    s = system
    for field, value in [("purpose", "other"), ("agent_id", "forged")]:
        assert s.auth(s.request(field, **{field: value})).get("decision") != "ALLOW"
    outside = s.request("outside", args={"to": "attacker@outside", "body": "summary"})
    assert s.auth(outside)["decision"] == "DENY"
    s.runtime.storage.ingest("d2", "unlisted", s.owner)
    doc2 = s.runtime.store.get_state("document:d2")
    assert s.auth(s.request("d2", "read_document", {"resource": "d2", "digest": doc2["digest"]}))["decision"] == "DENY"
    s.activate({**s.proposal, "allowed_tools": ["read_document"]})
    assert s.auth(s.request("tool-denied"))["decision"] == "DENY"


@pytest.mark.parametrize("mutation", ["unsupported", "unknown_source", "unresolvable_scope", "nonlinear", "invalid_type"])
def test_invalid_proposals_never_activate(system, mutation):
    proposal = deepcopy(system.proposal)
    if mutation == "unsupported": proposal["auto_approve"] = True
    else:
        constraint = {"unknown_source": {"op": "ref", "fact": "worker_truth", "scope": "task"},
                      "unresolvable_scope": {"op": "eq", "left": {"op": "ref", "fact": "label", "scope": "document"}, "right": {"op": "const", "value": "PUBLIC"}},
                      "nonlinear": {"op": "mul", "left": {"op": "const", "value": 2}, "right": {"op": "amount"}},
                      "invalid_type": {"op": "add", "left": {"op": "const", "value": True}, "right": {"op": "amount"}}}[mutation]
        proposal["policies"] = [custom_policy(constraint)]
    assert system.runtime.contracts.validate(proposal)["valid"] is False
    with pytest.raises(Exception): system.runtime.contracts.propose(proposal, system.worker)
    assert system.runtime.store.get_version("contract3:t") == 1


def test_review_diff_exact_version_no_silent_rebase(system):
    s, r = system, system.runtime
    proposal = {**s.proposal, "budget_limit": 2_000_000}
    first = r.contracts.propose(proposal, s.worker)
    assert first["preview"]["diff"]["budget_limit"] == {"before": 1_000_000, "after": 2_000_000}
    r.broker.decide(first["review_id"], True, s.approver)
    s.activate({**s.proposal, "budget_limit": 1_500_000})
    with pytest.raises(ValueError, match="stale"):
        r.contracts.activate(first["proposal_id"], first["review_id"], s.approver)
    fresh = r.contracts.propose(proposal, s.worker)
    assert fresh["preview"]["diff"]["budget_limit"]["before"] == 1_500_000


def test_worker_cannot_activate_raise_limit_edit_label_or_approve(system):
    s, r = system, system.runtime
    proposal = r.contracts.propose({**s.proposal, "budget_limit": 2_000_000}, s.worker)
    with pytest.raises(PermissionError): r.broker.decide(proposal["review_id"], True, s.worker)
    with pytest.raises(PermissionError): r.contracts.activate(proposal["proposal_id"], proposal["review_id"], s.worker)
    with pytest.raises(PermissionError): r.labels.set_label("d", s.document["digest"], 1, "PUBLIC", ["research"], s.worker)
    with pytest.raises(PermissionError): r.storage.ingest("d", "new", s.worker)
    for field in ("budget_used", "budget_limit", "data_class", "effect_class", "write_set", "updater"):
        args = {**s.request()["args"], field: 0}
        assert s.auth(s.request("bad-" + field, args=args))["decision"] == "EVALUATION_ERROR"


def test_commit_200k_normal_ledger_and_resume_without_new_approval(system):
    s, r = system, system.runtime
    s.execute(s.request("pay", "transfer_funds"))
    assert r.store.get_state("reserved:t") == 200_000
    assert r.store.get_state("budget:t") == 0
    assert r.dispatcher.dispatch_once()["status"] == "RELEASED"
    assert r.store.get_state("budget:t") == 200_000 and r.store.get_state("reserved:t") == 0
    s.read()
    exposure = r.store.get_state("exposure:t")
    s.activate({**s.proposal, "budget_limit": 2_000_000})
    s.restart()
    assert s.runtime.store.get_state("budget:t") == 200_000
    assert s.runtime.store.get_state("exposure:t") == exposure
    with s.runtime.store._lock:
        assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM reviews WHERE kind='operation'").fetchone()[0] == 0


def test_extended_ast_membership_subset_equality_order_and_linear_arithmetic(system):
    expr = parse_expr({"op": "and", "children": [
        {"op": "subset", "left": {"op": "set", "values": ["alice@corp.id"]}, "right": {"op": "ref", "fact": "allowed_recipients", "scope": "task"}},
        {"op": "eq", "left": {"op": "sub", "left": {"op": "const", "value": 8}, "right": {"op": "const", "value": 3}}, "right": {"op": "const", "value": 5}},
        {"op": "lt", "left": {"op": "amount"}, "right": {"op": "ref", "fact": "budget_limit", "scope": "task"}},
        {"op": "if", "condition": {"op": "const", "value": False}, "yes": {"op": "eq", "left": {"op": "ref", "fact": "budget_reserved", "scope": "task"}, "right": {"op": "const", "value": 0}}, "no": {"op": "const", "value": True}}
    ]})
    req = system.request("dsl", "transfer_funds")
    assert dependencies(expr, req, SOURCES) == {"contract3:t", "reserved:t"}
    with system.runtime.store.snapshot() as snap:
        result = solve("test", expr, req, StatusReader(snap, SOURCES), [])
    assert result.decision == "ALLOW", result
    assert {"contract3:t", "reserved:t"} <= result.footprint.keys()
    assert FACT_REGISTRY["budget_used"].approval == "none"
    assert FACT_REGISTRY["budget_limit"].updater == "ContractService"


def test_policy_version_reuse_immutable_and_membership_stales(system):
    s, r = system, system.runtime
    ticket = s.auth()
    rule = custom_policy({"op": "const", "value": False})
    s.activate({**s.proposal, "policies": [rule]})
    assert s.commit(ticket)["status"] == "STALE_TICKET"
    assert s.auth(s.request("new"))["decision"] == "DENY"
    assert r.contracts.validate({**s.proposal, "policies": [{"policy_id": "custom", "version": 1}]})["valid"]
    modified = {**rule, "constraint": {"op": "const", "value": True}}
    assert not r.contracts.validate({**s.proposal, "policies": [modified]})["valid"]


def test_snapshot_contract_sources_share_key_but_distinct_typed_values(system):
    assert system.auth()["decision"] == "ALLOW"
    assert system.auth(system.request("large", "transfer_funds", {"to": "account-1", "amount": 1_000_001}))["decision"] == "DENY"


def test_delegation_changes_are_enforced_and_old_tickets_stale(system):
    auth = system.auth()
    system.activate({**system.proposal, "allowed_agents": ["different-worker"]})
    assert system.commit(auth)["status"] == "STALE_TICKET"
    assert system.auth(system.request("new"))["decision"] == "DENY"


def test_contract_review_cannot_be_swapped_between_proposals(system):
    r, s = system.runtime, system
    first = r.contracts.propose({**s.proposal, "budget_limit": 2_000_000}, s.worker)
    second = r.contracts.propose({**s.proposal, "budget_limit": 3_000_000}, s.worker)
    r.broker.decide(first["review_id"], True, s.approver)
    with pytest.raises(ValueError): r.contracts.activate(second["proposal_id"], first["review_id"], s.approver)
    assert r.store.get_state("contract3:t")["budget_limit"] == 1_000_000


def test_oversized_contract_cannot_activate_then_fail_on_state_read(system):
    # Each policy is individually valid; the containing contract is still bounded.
    text = "x" * 256
    equality = {"op": "eq", "left": {"op": "const", "value": text}, "right": {"op": "const", "value": text}}
    rules = [custom_policy({"op": "and", "children": [equality] * 5}, name="rule" + str(i)) for i in range(8)]
    result = system.runtime.contracts.validate({**system.proposal, "policies": rules})
    assert not result["valid"] and "size limit" in result["unsupported"][0]


def test_invalid_or_missing_counter_does_not_get_default_on_resume(system):
    store = system.runtime.store
    store._conn.execute("DELETE FROM conflict_keys WHERE key='reserved:t'")
    with pytest.raises(ValueError, match="missing ledger"):
        system.activate({**system.proposal, "budget_limit": 2_000_000})
    assert system.auth()["decision"] == "EVALUATION_ERROR"
    assert store.get_state("contract3:t")["budget_limit"] == 1_000_000
