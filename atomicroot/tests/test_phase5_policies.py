"""Shared policy kernel, read provenance and guarded simulated update semantics."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json

import pytest

from atomicroot.tests.phase3_support import System, custom_policy
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.framework.policy_catalog import catalog
from atomicroot.framework.dsl import compile_policy
from atomicroot.framework.registry import SOURCES
from atomicroot.authority.policy_engine import dependencies
from atomicroot.integration.guarded import GuardedTools


@pytest.fixture
def system(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    s.proposal["allowed_tools"].append("update_document")
    s.activate(s.proposal)
    yield s
    s.runtime.store.close()


def read(s):
    ob = GuardedTools(s.runtime).execute(s.request("read", "read_document"), s.worker)
    assert ob.detail["delivery"] == "RELEASED"
    return ob.detail["receipt"]


def write_request(s, receipt, op="write", content="Proposed synthetic output"):
    return s.request(op, "update_document", {"resource": "d", "digest": s.document["digest"], "content": content, "read_receipt": receipt["receipt_id"]})


def test_positive_update_provenance_schema_and_atomic_version(system):
    s = system; receipt = read(s)
    assert receipt["read_binding"] == {"task": "t", "agent": "W", "operation": "read", "resource": "d", "digest": s.document["digest"], "version": 1}
    request = write_request(s, receipt)
    auth = s.auth(request)
    assert auth["decision"] == "ALLOW", auth
    assert {"document:d", "label:d", "readbasis:t:write"} <= auth["ticket"]["footprint"].keys()
    assert s.commit(auth)["status"] == "COMMITTED"
    assert s.runtime.store.get_state("document:d")["version"] == 2
    assert s.runtime.store.get_state("label:d")["label"] == "UNKNOWN"
    before = s.runtime.store.get_state("document:d")
    s.runtime.storage.ingest("d", "Later owner mutation", s.owner)
    delivered = s.runtime.dispatcher.dispatch_once()
    assert delivered["receipt"]["result"] == before  # frozen update, no mutable reread
    assert s.runtime.authority.authorize(request, s.worker)["idempotent_status"]
    assert s.commit(auth)["status"] == "REJECTED"


@pytest.mark.parametrize("attack", ["missing", "forged", "wrong_resource", "wrong_agent", "pending", "empty_reads", "negative_type", "oversized"])
def test_missing_forged_or_unreleased_read_is_not_worker_selectable(system, attack):
    s = system; receipt = read(s)
    request = write_request(s, receipt)
    if attack == "missing": request["args"].pop("read_receipt")
    elif attack == "forged": request["args"]["read_receipt"] = "receipt-forged"
    elif attack == "wrong_resource": request["args"]["resource"] = "d2"
    elif attack == "wrong_agent":
        request["agent_id"] = "other"
    elif attack == "pending":
        # A receipt stored by the receiver is insufficient until the verified
        # delivery result is available to this worker through settlement.
        s.execute(s.request("unsettled", "read_document"))
        claim = s.runtime.dispatcher.claim()
        proof = s.runtime.receiver.deliver("t", "unsettled", json.loads(claim["payload"]))
        request["args"]["read_receipt"] = proof["receipt_id"]
    elif attack == "empty_reads": request["args"].update(reads=[])
    elif attack == "negative_type": request["args"]["content"] = -1
    elif attack == "oversized": request["args"]["content"] = "x" * 8193
    result = s.auth(request)
    assert result["decision"] != "ALLOW" and "ticket" not in result
    assert s.runtime.store.get_state("document:d")["version"] == 1


def test_stale_receipt_before_authorize_and_after_allow_requires_new_read(system):
    s = system; receipt = read(s); request = write_request(s, receipt)
    old = s.auth(request); assert old["decision"] == "ALLOW"
    s.runtime.storage.ingest("d", "Changed by owner", s.owner)
    assert s.commit(old)["status"] == "STALE_TICKET"
    renewed = s.auth(request)
    assert renewed["decision"] == "DENY" and renewed["policy"] == "no_write_after_stale_read"
    assert s.runtime.store.get_state("readbasis:t:write")["version"] == 1
    current = s.runtime.store.get_state("document:d")
    substituted = deepcopy(request); substituted["args"]["digest"] = current["digest"]
    assert s.auth({**substituted, "operation_id": "substituted-base"})["decision"] == "DENY"
    new_read = s.request("new-read", "read_document", {"resource": "d", "digest": current["digest"]})
    ob = GuardedTools(s.runtime).execute(new_read, s.worker)
    new = s.request("new-write", "update_document", {"resource": "d", "digest": current["digest"], "content": "", "read_receipt": ob.detail["receipt"]["receipt_id"]})
    assert GuardedTools(s.runtime).execute(new, s.worker).status == "COMMITTED"


def test_write_rollback_and_separate_connection_race(system):
    s = system; receipt = read(s)
    requests = [write_request(s, receipt, op=f"write-{i}") for i in range(2)]
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    auths = [s.auth(requests[0]), other.authority.authorize(requests[1], s.worker)]
    assert all(a["decision"] == "ALLOW" for a in auths)
    s.runtime.store._conn.execute("CREATE TEMP TRIGGER abort_update BEFORE INSERT ON outbox WHEN NEW.operation='write-0' BEGIN SELECT RAISE(ABORT,'fault'); END")
    assert s.commit(auths[0])["status"] == "REJECTED"
    assert s.runtime.store.get_state("document:d")["version"] == 1
    s.runtime.store._conn.execute("DROP TRIGGER abort_update")
    barrier = Barrier(2)
    def commit(runtime, auth):
        barrier.wait(3)
        return runtime.gateway.commit(auth["ticket"], auth["commit_args"], s.worker)["status"]
    try:
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(commit, r, a) for r, a in zip((s.runtime, other), auths)]
            assert sorted(f.result(5) for f in futures) == ["COMMITTED", "STALE_TICKET"]
    finally: other.store.close()


def test_output_cannot_lose_sensitive_shared_exposure(system):
    s = system
    s.runtime.labels.set_label("d", s.document["digest"], 1, "SENSITIVE", ["research"], s.owner)
    receipt = read(s)
    assert GuardedTools(s.runtime).execute(write_request(s, receipt), s.worker).status == "COMMITTED"
    label = s.runtime.store.get_state("label:d")
    assert label["label"] == "SENSITIVE" and label["conservative_sensitive"]
    document = s.runtime.store.get_state("document:d")
    s.runtime.labels.set_label("d", document["digest"], document["version"], "PUBLIC", ["research"], s.owner)
    assert s.runtime.store.get_state("label:d")["conservative_sensitive"] is True


def test_dsl_extension_parameters_composition_and_static_branches(system):
    s = system
    extra = catalog()["extension_example"]
    assert compile_policy(extra)
    expr = compile_policy(extra)
    assert dependencies(expr, s.request("p", "transfer_funds"), SOURCES) == {"contract3:t"}
    proposal = {**s.proposal, "policies": [extra, custom_policy({"op": "const", "value": False}, name="review", tools=["transfer_funds"], disposition="ESCALATE")]}
    s.activate(proposal)
    allowed_amount = s.request("boundary", "transfer_funds", {"to": "account-1", "amount": 175})
    assert s.auth(allowed_amount)["decision"] == "ESCALATE"
    denied = s.auth(s.request("over", "transfer_funds", {"to": "account-1", "amount": 176}))
    assert denied["decision"] == "DENY" and denied["policy"] == extra["policy_id"]
    assert {"policy:research_small_action.3", "policy:review.1", "policyset:t"} <= denied["footprint"].keys()
    for amount in (0, 174, 175):
        assert s.auth(s.request("v" + str(amount), "transfer_funds", {"to": "account-1", "amount": amount}))["decision"] == "ESCALATE"


def test_executor_A_can_use_its_actual_delivered_read_receipt_for_update(tmp_path):
    from tempfile import TemporaryDirectory
    from atomicroot.evaluation.scenarios import manifest
    from atomicroot.evaluation.runner import EvaluationAdapter
    from atomicroot.integration.config_workflow import ConfigWorkflow
    workload = manifest("stale_write")
    class Worker:
        binding = {"kind": "server-receipt-script-v1"}
        def __call__(self, view):
            if view["step"]: return {"kind": "done", "summary": "Completed node"}
            ref = workload["tasks"][0]["resources"][0]
            if view["node"] == "read": return {"kind": "action", "tool": "read_document", "args": {"resource": "file", "digest": ref["digest"]}}
            receipt = next(o["detail"]["receipt"]["receipt_id"] for o in view["observations"] if o["detail"].get("tool") == "read_document")
            return {"kind": "action", "tool": "update_document", "args": {"resource": "file", "digest": ref["digest"], "read_receipt": receipt, "content": "Updated through executor A"}}
    with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
        host = EvaluationAdapter(directory, workload, "atomicroot")
        flow = ConfigWorkflow(host.runtime, tmp_path / "write-checkpoint.sqlite", task="write-a", caller=host.user, worker=Worker())
        try:
            result = flow.start("write-flow")
            assert result["status"] == "SATISFIED", result
            assert host.runtime.store.get_state("document:file")["content"] == "Updated through executor A"
        finally: flow.close(); host.close()
