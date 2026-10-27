"""Bounded FIFO admission and fresh fallback across actual DB connections."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier, Event, Thread
import json

import pytest

from atomicroot.authority.ticket import generate_keypair
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.contention import FallbackConfig, WriterCoordinator, ContentionTimeout, ContentionCancelled
from atomicroot.framework.fallback import commit_fresh
from atomicroot.framework.identity import Principal
from atomicroot.integration.guarded import GuardedTools
from atomicroot.tests.phase3_support import System
from atomicroot.tests.test_phase36_tasks import ConfigSystem
from atomicroot.sim.harness import ControlledHarness


def test_measured_stales_trigger_fresh_fallback_no_blocking_hook_inside_gate(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    calls, deferred = [], []
    class Harness:
        def checkpoint(self, stage, action):
            assert not s.runtime.store.coordinator.held_exclusively()
            if stage == "before_cas":
                calls.append(action)
                if len(calls) <= 2:
                    contract = other.store.get_state("contract3:t")
                    other.store.set_state("contract3:t", {**contract, "objective": str(len(calls))})
            deferred.append(stage)
    s.runtime.authority.harness = s.runtime.gateway.harness = Harness()
    s.runtime.store.harness = s.runtime.authority.harness
    try:
        outcome = commit_fresh(s.runtime, s.request(), s.worker)
        assert outcome["commit"]["status"] == "COMMITTED", outcome
        assert outcome["stale_count"] == 2 and outcome["attempts"] == 3
        assert [h["mode"] for h in outcome["history"]] == ["optimistic", "optimistic", "fallback"]
        assert len(s.runtime.store.inspect_outbox()) == 1
        assert s.runtime.store._conn.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0] == 3
        assert "after_commit" in deferred
    finally: other.store.close(); s.runtime.store.close()


def test_dependency_expansion_releases_reacquires_union_and_has_bound(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    authority = s.runtime.authority.authorize
    calls = []
    try:
        # New dependencies can be discovered only after a complete fresh auth.
        # Inject one additional trusted read using a registered DSL definition.
        from atomicroot.tests.phase3_support import custom_policy
        def base(*args, **kwargs):
            result = authority(*args, **kwargs); calls.append(result)
            if len(calls) == 1: s.runtime.store.set_state("contract3:t", {**s.proposal, "objective": "changed"})
            return result
        def expanding(*args, **kwargs):
            if len(calls) == 1:
                definition = custom_policy({"op": "const", "value": True})
                with s.runtime.store.transaction() as conn:
                    s.runtime.store.put(conn, "policy:custom.1", definition)
                    s.runtime.store.put(conn, "policyset:t", [{"policy_id": "custom", "version": 1}])
            return base(*args, **kwargs)
        s.runtime.authority.authorize = expanding
        result = commit_fresh(s.runtime, s.request(), s.worker, config=FallbackConfig(stale_threshold=1))
        assert result["commit"]["status"] == "COMMITTED", result
        assert result["restarts"] == 1 and result["attempts"] == 3
        assert "policy:custom.1" in result["history"][1]["keys"]
    finally: s.runtime.store.close()


def test_fifo_admission_timeout_cancellation_release_and_canonical_keys():
    gate = WriterCoordinator()
    order, threads = [], []
    def writer(index, exclusive):
        with gate.acquire(exclusive=exclusive, keys=["z", "a", "z"], timeout=2) as keys:
            assert keys == ("a", "z")
            order.append(index)
    with gate.acquire(exclusive=True, keys=["held"]):
        assert set(gate.key_owners) == {"held"}
        with pytest.raises(ValueError, match="release before expanding"):
            _acquire(gate, exclusive=True, keys=["new"])
        for index, exclusive in [(1, True), (2, False), (3, True)]:
            thread = Thread(target=writer, args=(index, exclusive)); threads.append(thread); thread.start()
            with gate.condition:
                assert gate.condition.wait_for(lambda: len(gate.queue) == index, timeout=2)
        with ThreadPoolExecutor(1) as pool:
            timeout = pool.submit(lambda: _acquire(gate, timeout=.01))
            with pytest.raises(ContentionTimeout): timeout.result(2)
        cancelled = Event(); cancelled.set()
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(lambda: _acquire(gate, cancelled=cancelled))
            with pytest.raises(ContentionCancelled): future.result(2)
    for thread in threads: thread.join(3); assert not thread.is_alive()
    assert order == [1, 2, 3] and gate.active == 0 and gate.owner is None and not gate.queue
    with pytest.raises(ValueError): _acquire(gate, keys=["label:*"])
    with pytest.raises(RuntimeError):
        with gate.acquire(exclusive=True): raise RuntimeError("cancelled body")
    _acquire(gate)


def _acquire(gate, **kwargs):
    with gate.acquire(**kwargs): return True


WRITERS = ("gateway", "authority", "contract", "task_resolution", "approval", "scope", "destination", "storage", "label",
           "classification", "classification_begin", "classification_result", "claim", "receiver", "settlement", "legacy_state", "initializer")


@pytest.mark.parametrize("writer", WRITERS)
def test_all_writer_paths_obey_same_gate_separate_connections(writer, tmp_path):
    s = ConfigSystem(tmp_path / "ledger.sqlite"); s.activate()
    other = FrameworkRuntime(s.path, signing_key=s.runtime.authority._sk, clock=s.clock)
    request, principal = s.request()
    auth = s.runtime.authority.authorize(request, principal)
    preview = s.runtime.tasks.propose(s.spec, s.user)
    s.runtime.broker.decide(preview["review_id"], True, s.approver)
    pending = s.runtime.tasks.propose(s.spec, s.user)
    classifier = Principal("classifier", frozenset({"classifier"}), resources=s.owner.resources)
    proposal = s.runtime.classification.begin("d1", s.refs[0]["digest"], 1, "offline", "1", "criteria", "sha256:" + "a" * 64, classifier)
    result = {k: proposal[k] for k in ("resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash")}
    result.update(outcome="SUCCESS", candidate_label="SENSITIVE", confidence=.99, probabilities=None, covered_bytes=proposal["input_bytes"], truncated=False, reason="fixture")
    if writer != "classification_result": s.runtime.classification.record(proposal["proposal_id"], result, classifier)
    owner = Principal(s.owner.subject, s.owner.roles, frozenset({"t"}), s.owner.resources)
    with s.runtime.store.transaction() as conn:
        contract = s.runtime.store.value(conn, "contract3:t")[1]
        s.runtime.store.put(conn, "contract3:t", {**contract, "classification_restrictions": True})
    # Gate coverage tests need a fresh ticket after setup mutations.
    auth = s.runtime.authority.authorize(request, principal)
    claim, receipt = None, None
    if writer in {"claim", "receiver", "settlement"}:
        s.runtime.gateway.commit(auth["ticket"], auth["commit_args"], principal)
        if writer != "claim": claim = s.runtime.dispatcher.claim()
        if writer == "settlement": receipt = s.runtime.receiver.deliver(claim["task"], claim["operation"], json.loads(claim["payload"]))
    routes = {
        "gateway": lambda: other.gateway.commit(auth["ticket"], auth["commit_args"], principal),
        "authority": lambda: other.authority.authorize(request, principal),
        "contract": lambda: other.contracts.activate(preview["proposal_id"], preview["review_id"], s.approver),
        "task_resolution": lambda: other.tasks.propose(s.spec, s.user),
        "approval": lambda: other.broker.decide(pending["review_id"], True, s.approver),
        "scope": lambda: other.catalog.set_entitlement("t", "user", s.rights, s.admin),
        "destination": lambda: other.catalog.set_destination({"destination": "alice@corp.id", "kind": "recipient", "purposes": ["research"], "endpoint": None, "models": [], "labels": []}, s.admin),
        "storage": lambda: other.storage.ingest("d1", "new content", s.owner),
        "label": lambda: other.labels.set_label("d1", s.refs[0]["digest"], 1, "SENSITIVE", ["research"], s.owner),
        "classification": lambda: other.labels.accept_classification(proposal["proposal_id"], "t", "research", owner),
        "classification_begin": lambda: other.classification.begin("d1", s.refs[0]["digest"], 1, "offline", "1", "criteria", "sha256:" + "a" * 64, classifier),
        "classification_result": lambda: other.classification.record(proposal["proposal_id"], result, classifier),
        "claim": lambda: other.dispatcher.claim(),
        "receiver": lambda: other.receiver.deliver(claim["task"], claim["operation"], json.loads(claim["payload"])),
        "settlement": lambda: other.dispatcher.finish(claim, receipt),
        "legacy_state": lambda: other.store.set_state("fixture:independent", 1),
        "initializer": lambda: other.store.initialize_state("fixture:new", 0),
    }
    done = Event(); outcome = []
    def run():
        try: outcome.append(routes[writer]())
        except ValueError as exc: outcome.append(str(exc))  # a deliberately stale contract preview still enters admission
        finally: done.set()
    try:
        assert other.store.coordinator is s.runtime.store.coordinator
        with s.runtime.store.coordinator.acquire(exclusive=True, keys=["contract3:t"]):
            thread = Thread(target=run); thread.start()
            with s.runtime.store.coordinator.condition:
                assert s.runtime.store.coordinator.condition.wait_for(lambda: len(s.runtime.store.coordinator.queue) == 1, timeout=2)
            assert not done.is_set()
        thread.join(3)
        assert done.is_set() and not thread.is_alive() and outcome
    finally: other.store.close(); s.runtime.store.close()


def test_fallback_pending_review_does_not_hold_gate_and_grant_stays_fresh(tmp_path):
    s = System(tmp_path / "ledger.sqlite", label="UNKNOWN", unknown="ESCALATE")
    s.read()
    original = s.runtime.gateway.commit
    def stale(ticket, args, principal, **kwargs):
        s.runtime.store.set_state("contract3:t", {**s.proposal, "objective": "revision"})
        return original(ticket, args, principal, **kwargs)
    # Force measured stale on a read that needs no operation approval.
    s.runtime.gateway.commit = stale
    try:
        result = commit_fresh(s.runtime, s.request("read-2", "read_document"), s.worker,
                              config=FallbackConfig(stale_threshold=1, max_attempts=3))
        assert result["commit"]["status"] == "COMMITTED", result
        s.runtime.gateway.commit = original
        review = commit_fresh(s.runtime, s.request(), s.worker)
        assert review["authorization"]["decision"] == "ESCALATE"
        assert not s.runtime.store.coordinator.held_exclusively()
        grant = review["authorization"]["review_id"]
        s.runtime.broker.decide(grant, True, s.approver)
        s.runtime.labels.set_label("d", s.document["digest"], 1, "SENSITIVE", ["research"], s.owner)
        result = commit_fresh(s.runtime, s.request(), s.worker, grant=grant)
        assert result["authorization"]["decision"] != "ALLOW" and result["commit"] is None
    finally: s.runtime.store.close()


@pytest.mark.parametrize("consented", [False, True])
def test_ticket_and_grant_concurrent_replay_one_intent_separate_connections(tmp_path, consented):
    s = System(tmp_path / "ledger.sqlite", label="UNKNOWN" if consented else "PUBLIC", unknown="ESCALATE" if consented else "DENY")
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    if consented:
        s.read()
        review = s.auth()["review_id"]; s.runtime.broker.decide(review, True, s.approver)
        auths = [s.auth(grant_id=review), other.authority.authorize(s.request(), s.worker, grant_id=review)]
    else: auths = [s.auth()] * 2
    barrier = Barrier(2)
    def commit(runtime, auth):
        barrier.wait(timeout=3)
        return runtime.gateway.commit(auth["ticket"], auth["commit_args"], s.worker)
    try:
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(commit, runtime, auth) for runtime, auth in zip((s.runtime, other), auths)]
            statuses = [f.result(5)["status"] for f in futures]
        assert statuses.count("COMMITTED") == 1
        assert set(statuses) <= {"COMMITTED", "REJECTED", "OPERATION_ALREADY_COMMITTED", "STALE_TICKET"}
        assert len(s.runtime.store.inspect_outbox()) == (2 if consented else 1)
        if consented: assert s.runtime.broker.status(review, s.approver)["status"] == "CONSUMED"
    finally: other.store.close(); s.runtime.store.close()


def test_contention_storm_terminates_within_attempt_bounds_without_ledger_reset(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    barrier, first_committed = Barrier(6), Event()
    seen, sequence = set(), []
    from threading import Lock
    lock = Lock()
    class Schedule:
        def checkpoint(self, stage, op):
            with lock:
                sequence.append((stage, op))
                first = stage == "ticket_issued" and op not in seen
                if first: seen.add(op)
            if first: barrier.wait(timeout=5)
            if stage == "before_cas" and op != "storm-0": assert first_committed.wait(5)
            if stage == "after_commit" and op == "storm-0": first_committed.set()
    runtimes = [FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock, harness=Schedule()) for _ in range(6)]
    try:
        with ThreadPoolExecutor(6) as pool:
            futures = [pool.submit(commit_fresh, runtime, s.request(f"storm-{index}", "transfer_funds"), s.worker,
                                   config=FallbackConfig(stale_threshold=1, max_attempts=4, timeout=10)) for index, runtime in enumerate(runtimes)]
            results = [f.result(15) for f in futures]
        assert all(r["attempts"] <= 4 and r["restarts"] <= 2 for r in results)
        assert sum(r["stale_count"] for r in results) >= 5
        assert sum(r["commit"] is not None and r["commit"]["status"] == "COMMITTED" for r in results) == 5
        assert len(s.runtime.store.inspect_outbox()) == 5 and s.runtime.store.get_state("reserved:t") == 1_000_000
        assert s.runtime.store.get_state("budget:t") == 0
        assert all(not r.store.coordinator.held_exclusively() for r in runtimes)
        (tmp_path / "storm-schedule.json").write_text(json.dumps({"initial_budget": 0, "initial_reserved": 0,
            "limit": 1_000_000, "requests": [s.request(f"storm-{i}", "transfer_funds") for i in range(6)],
            "schedule": sequence, "results": results}, indent=2), encoding="utf-8")
    finally:
        for runtime in runtimes: runtime.store.close()
        s.runtime.store.close()


def test_dependency_restart_exhaustion_and_cancellation_return_terminal_without_effect(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    authority = s.runtime.authority.authorize
    calls = 0
    def expand(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            from atomicroot.tests.phase3_support import custom_policy
            with s.runtime.store.transaction() as conn:
                s.runtime.store.put(conn, "policy:new.1", custom_policy({"op": "const", "value": True}, name="new"))
                s.runtime.store.put(conn, "policyset:t", [{"policy_id": "new", "version": 1}])
        auth = authority(*args, **kwargs)
        if calls == 1: s.runtime.store.set_state("contract3:t", {**s.proposal, "objective": "updated"})
        return auth
    s.runtime.authority.authorize = expand
    try:
        result = commit_fresh(s.runtime, s.request(), s.worker, config=FallbackConfig(stale_threshold=1, max_restarts=0))
        assert result["reason"] == "DEPENDENCY_RESTART_EXHAUSTED" and not s.runtime.store.inspect_outbox()
        cancel = Event(); cancel.set()
        cancelled = commit_fresh(s.runtime, s.request("cancelled"), s.worker, cancelled=cancel)
        assert cancelled["reason"] == "CANCELLED" and cancelled["attempts"] == 0
    finally: s.runtime.store.close()


def test_coordinated_state_setter_preserves_exact_json_change_and_missing_key_semantics(tmp_path):
    runtime = FrameworkRuntime(str(tmp_path / "ledger.sqlite"))
    try:
        runtime.store.set_state("fixture:typed", 0)
        before = runtime.store.get_version("fixture:typed")
        runtime.store.set_state("fixture:typed", False)
        assert runtime.store.get_version("fixture:typed") == before + 1
        assert runtime.store.get_state("fixture:typed") is False
        runtime.store.set_state("fixture:typed", False)
        assert runtime.store.get_version("fixture:typed") == before + 1
        runtime.store.set_state("fixture:null", None)
        assert runtime.store.get_version("fixture:null") == 1
    finally: runtime.store.close()


def test_fallback_escalation_exits_gate_before_human_and_delivery(tmp_path):
    s = System(tmp_path / "ledger.sqlite", unknown="ESCALATE")
    other = FrameworkRuntime(s.path, signing_key=s.sk, clock=s.clock)
    changed = False
    class Arrival:
        def checkpoint(self, stage, action):
            nonlocal changed
            if stage == "before_cas" and action == "op" and not changed:
                changed = True
                other.labels.set_label("d", s.document["digest"], 1, "UNKNOWN", ["research"], s.owner)
                read = other.authority.authorize(s.request("read", "read_document"), s.worker)
                assert other.gateway.commit(read["ticket"], read["commit_args"], s.worker)["status"] == "COMMITTED"
    s.runtime.gateway.harness = Arrival()
    try:
        review = commit_fresh(s.runtime, s.request(), s.worker, config=FallbackConfig(stale_threshold=1))
        assert review["stale_count"] == 1 and review["attempts"] == 2
        assert review["history"][-1]["mode"] == "fallback"
        assert review["authorization"]["decision"] == "ESCALATE"
        assert not s.runtime.store.coordinator.held_exclusively() and s.runtime.store.coordinator.owner is None
        grant = review["authorization"]["review_id"]
        other.broker.decide(grant, True, s.approver)
        s.runtime.fallback = FallbackConfig(stale_threshold=1)
        receiver = s.runtime.receiver
        class CheckedReceiver:
            def deliver(self, task, op, payload):
                assert s.runtime.store.coordinator.owner is None and not s.runtime.store._conn.in_transaction
                return receiver.deliver(task, op, payload)
        observation = GuardedTools(s.runtime, receiver=CheckedReceiver()).execute(s.request(), s.worker, grant=grant)
        assert observation.status == "COMMITTED" and observation.detail["delivery"] == "RELEASED"
    finally: other.store.close(); s.runtime.store.close()
