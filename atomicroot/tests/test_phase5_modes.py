"""Paired mechanisms compare policy/history/CAS without changing logical sources."""
from copy import deepcopy
from dataclasses import replace
from tempfile import TemporaryDirectory

import pytest

from atomicroot.evaluation.modes import MODES, Capability, GLOBAL_KEY
from atomicroot.evaluation.scenarios import manifest, SCENARIOS
from atomicroot.evaluation.runner import run, replay, pair, EvaluationAdapter
from atomicroot.framework.app import create_phase3_app
from atomicroot.framework.identity import Principal


@pytest.mark.parametrize("name", SCENARIOS)
def test_six_modes_paired_ready_schedule_and_semantic_replay(name, tmp_path):
    workload = manifest(name)
    artifacts = [run(workload, mode) for mode in MODES]
    report = pair(artifacts)
    assert len(report["modes"]) == 6
    for artifact in artifacts:
        assert replay(artifact)["match"], (name, artifact["mode"])
        assert all(s["chosen"] in s["ready"] for s in artifact["run"]["schedule"])
        assert artifact["workload"] == workload
    outcomes = {a["mode"]: a for a in artifacts}
    if name in {"exfil", "budget"}:
        for mode in MODES[3:]:
            obs = outcomes[mode]["run"]["observations"]
            assert obs["auth-first"]["decision"] == obs["auth-second"]["decision"] == "ALLOW"
        for mode in MODES[:4]:
            assert outcomes[mode]["run"]["observations"]["commit-second"]["status"] == "COMMITTED"
            assert outcomes[mode]["oracle"]["accepted_violation_count"] == 1, outcomes[mode]["oracle"]
            assert outcomes[mode]["oracle"]["delivered_violation_count"] == 1
            if name == "exfil": assert outcomes[mode]["oracle"]["ground_truth_byte_disclosures"]
        for mode in MODES[4:]:
            assert outcomes[mode]["run"]["observations"]["commit-second"]["status"] == "STALE_TICKET"
            assert outcomes[mode]["oracle"]["accepted_violation_count"] == 0
    if name == "independent":
        assert outcomes["atomicroot"]["run"]["observations"]["commit-two"]["status"] == "COMMITTED"
        assert outcomes["global_version_atomicroot"]["run"]["observations"]["commit-two"]["status"] == "STALE_TICKET"
    if name == "once":
        assert all(a["oracle"]["accepted_intents"] == 1 and a["oracle"]["accepted_violation_count"] == 0 for a in artifacts)
    if name == "stale_write":
        for mode in MODES[:4]: assert outcomes[mode]["oracle"]["accepted_violations"]["write-a:write-op"] == ["no_write_after_stale_read"]
        assert outcomes["atomicroot"]["run"]["observations"]["commit"]["status"] == "STALE_TICKET"
    if name == "stale_before_authorize":
        for mode in MODES[3:]: assert outcomes[mode]["run"]["observations"]["auth"]["decision"] == "DENY"
    if name == "classification":
        for artifact in artifacts:
            assert artifact["run"]["observations"]["accept"]["status"] == "DECLINED"
        for mode in MODES[:3]: assert outcomes[mode]["oracle"]["ground_truth_delivered_leaks"]
        for mode in MODES[3:]: assert not outcomes[mode]["oracle"]["ground_truth_release_intents"]
    if name == "lost_ack":
        assert all(a["oracle"]["applied_effects"] == 1 and a["oracle"]["unknown_delivery_observations"] for a in artifacts)
    if name == "rollback":
        assert all(a["run"]["observations"]["rolled-back"]["outbox"] == [] for a in artifacts)
    if name == "contention":
        for mode in MODES[4:]:
            ob = outcomes[mode]["run"]["observations"]["execute"]
            assert ob["status"] == "COMMITTED" and ob["detail"]["fallback"]["stale_count"] == 2
            assert len(outcomes[mode]["run"]["trusted_hook_mutations"]) == 3


def test_reusable_capability_signature_subject_scope_expiry_and_reuse():
    workload = manifest("budget")
    with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
        host = EvaluationAdapter(directory, workload, "reusable_capability")
        try:
            data = workload["actions"][0]["data"]
            request, principal = host.request(data)
            authority = host.runtime.authority
            original = authority.capabilities[principal.subject]
            with pytest.raises(ValueError, match="subject/task"):
                original.validate(authority.verify_key, Principal("other", principal.roles, principal.tasks), request, host.inputs.clock())
            for cap in (replace(original, signature="00" * 64), replace(original, data={**original.data, "budget_limit": 100000})):
                authority.capabilities[principal.subject] = cap
                assert authority.authorize(request, principal)["decision"] == "EVALUATION_ERROR"
            authority.capabilities[principal.subject] = original
            wrong = {**request, "operation_id": "outside", "args": {"to": "outside.invalid", "amount": 300}}
            assert authority.authorize(wrong, principal)["decision"] == "DENY"
            assert authority.authorize(request, principal)["decision"] == "ALLOW"
            assert authority.authorize({**request, "operation_id": "another"}, principal)["decision"] == "ALLOW"
            host.inputs.advance(295)
            late = authority.authorize({**request, "operation_id": "late"}, principal)
            assert late["ticket"]["not_after"] < original.data["expires"]
            host.inputs.advance(5)
            assert host.runtime.gateway.commit(late["ticket"], late["commit_args"], principal)["status"] == "REJECTED"
            assert "expired" in authority.authorize({**request, "operation_id": "expired"}, principal)["explanation"]
        finally: host.close()


@pytest.mark.parametrize("mode", MODES)
def test_modes_cannot_expose_unsafe_service_or_provider_network(mode):
    with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
        workload = manifest("budget")
        host = EvaluationAdapter(directory, workload, mode)
        try:
            with pytest.raises(ValueError, match="cannot be exposed"): create_phase3_app(host.runtime, lambda _: host.user)
            request, principal = host.request(workload["actions"][0]["data"])
            for tool in ("classify_document", "model_inference"):
                assert host.runtime.authority.authorize({**request, "tool": tool}, principal)["decision"] == "EVALUATION_ERROR"
        finally: host.close()


def test_global_approval_own_consent_transition_and_final_freshness():
    from atomicroot.sim.scenarios import scenario
    workload = scenario("approval-replay"); workload["ground_truth"] = {}
    result = run(workload, "global_version_atomicroot")
    obs = result["run"]["observations"]
    assert obs["approve"]["status"] == "APPROVED"
    assert obs["auth"]["decision"] == "ALLOW", obs["auth"]
    assert obs["commit"]["status"] == "COMMITTED", obs["commit"]
    assert obs["replay"]["status"] == "REJECTED"


def test_global_instrumentation_covers_other_connections_and_executor_writers(tmp_path):
    from atomicroot.framework.app import FrameworkRuntime
    from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
    workload = manifest("budget")
    with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
        host = EvaluationAdapter(directory, workload, "global_version_atomicroot")
        other = FrameworkRuntime(str(host.path), signing_key=host.key, clock=host.inputs.clock)
        try:
            store = host.runtime.store
            initial = store.get_version(GLOBAL_KEY)
            other.store.set_state("unrelated:fixture", 1)
            assert store.get_version(GLOBAL_KEY) > initial
            initial = store.get_version(GLOBAL_KEY)
            flow = ConfigWorkflow(host.runtime, tmp_path / "checkpoint.sqlite", task="payments-a", caller=host.user,
                                  worker=ScriptedWorker({"first": [{"kind": "done", "summary": "No business effect"}],
                                      "second": [{"kind": "done", "summary": "No business effect"}], "join": [{"kind": "done", "summary": "Joined"}]}))
            try:
                flow.start("clock")
                assert store.get_version(GLOBAL_KEY) > initial
                with store.transaction() as conn:
                    before = store.value(conn, GLOBAL_KEY)[0]
                    conn.execute("INSERT INTO execution_actions VALUES ('payments-a','clock','first',99,'test-op','{}')")
                    assert store.value(conn, GLOBAL_KEY)[0] > before
                triggers = store._conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
                assert any("execution_outputs" in t[0] for t in triggers)
            finally: flow.close()
        finally: other.store.close(); host.close()


def test_actual_executor_A_guarded_wiring_preserves_operation_identity_across_modes(tmp_path):
    from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
    checkpoint = tmp_path / "shared-checkpoint.sqlite"
    identities = []
    for mode in MODES:
        workload = manifest("budget")
        spec = workload["tasks"][0]
        responses = {"first": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-a", "amount": 100}}, {"kind": "done", "summary": "Paid"}],
                     "second": [{"kind": "action", "tool": "transfer_funds", "args": {"to": "account-b", "amount": 100}}, {"kind": "done", "summary": "Paid"}],
                     "join": [{"kind": "done", "summary": "Joined"}]}
        with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
            host = EvaluationAdapter(directory, workload, mode)
            flow = ConfigWorkflow(host.runtime, checkpoint, task=spec["task_id"], caller=host.user, worker=ScriptedWorker(responses))
            try:
                result = flow.start("same-logical-run")
                assert result["status"] == "SATISFIED", (mode, result)
                rows = host.runtime.store.inspect_outbox()
                identities.append(sorted((r["agent"], r["operation"], r["digest"]) for r in rows))
                assert host.runtime.store.get_state("budget:payments-a") == 200
            finally: flow.close(); host.close()
        # Only this test-owned saver is removed between fresh isolated runs.
        for path in checkpoint.parent.glob(checkpoint.name + "*"): path.unlink()
    assert all(ids == identities[0] for ids in identities)


@pytest.mark.parametrize("mode", MODES)
def test_schema_and_unsupported_email_fields_apply_to_all_modes(mode):
    workload = manifest("recipient")
    bad = deepcopy(workload)
    bad["tasks"][0]["schema_version"] = 999
    with pytest.raises(ValueError, match="schema_version"): run(bad, mode)
    for field in ("cc", "bcc", "body_ref"):
        altered = deepcopy(workload)
        altered["actions"][0]["data"]["args"][field] = "mallory@outside.invalid"
        # Config remains valid; the shared immutable request schema rejects
        # unsupported fields before a baseline can issue a mechanism ticket.
        with pytest.raises(ValueError, match="arguments"): run(altered, mode)
