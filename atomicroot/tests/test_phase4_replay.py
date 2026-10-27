"""Finite semantic replay uses fresh trusted test keys, real core and SQLite."""
from copy import deepcopy
from pathlib import Path
import asyncio
import json

import pytest

from atomicroot.authority.ticket import args_hash
from atomicroot.sim.scheduler import Action, ReadyScheduler, load_artifact, save_artifact, compare_pair
from atomicroot.sim.replay import record, replay
from atomicroot.sim.scenarios import scenario, SCENARIOS
from atomicroot.sim.model_tape import ModelTape
from atomicroot.integration.providers import FakeModel


@pytest.mark.parametrize("name", SCENARIOS)
def test_critical_scenario_exact_replay(name, tmp_path):
    artifact = record(scenario(name))
    path = tmp_path / (name + ".json")
    save_artifact(path, artifact)
    repeated = replay(load_artifact(path))
    assert repeated["match"], repeated["schedule_divergence"]
    assert repeated["artifact"]["public_key"] != artifact["public_key"]
    assert artifact["run"]["terminal"] == "COMPLETED", artifact["run"]["blocked"]
    observations = artifact["run"]["observations"]
    assert "private_key" not in path.read_text()
    if name in {"budget-double-allow", "exfil-double-allow"}:
        assert observations["auth-first"]["decision"] == observations["auth-second"]["decision"] == "ALLOW"
        assert observations["commit-first"]["status"] == "COMMITTED"
        assert observations["commit-second"]["status"] == "STALE_TICKET"
        assert len(artifact["terminal_observations"]["outbox"]) == 1
    elif name.startswith("mutation-"):
        assert observations["mutation"].get("status") != "REJECTED", observations["mutation"]
        assert observations["commit"]["status"] == "STALE_TICKET", observations
    elif name.startswith("classification-"):
        expected = {"false-public": "DECLINED", "failure": "DECLINED", "abstention": "DECLINED", "restriction": "ACCEPTED_RESTRICTION", "stale-content": "STALE", "stale-label": "STALE"}
        assert observations["accept"]["status"] == expected[name.removeprefix("classification-")], observations["accept"]
        if name.endswith("restriction"): assert observations["release-commit"]["status"] == "STALE_TICKET"
    elif name == "operation-substitution": assert "reused" in observations["auth-changed"]["explanation"]
    elif name == "payload-substitution": assert observations["commit-changed"]["status"] == "REJECTED"
    elif name == "ticket-replay": assert observations["commit-again"]["status"] == "REJECTED"
    elif name == "ticket-forged":
        assert observations["forged"]["status"] == "REJECTED" and "signature" in observations["forged"]["reason"]
        assert not artifact["terminal_observations"]["outbox"]
    elif name == "approval-before": assert "stale" in observations["approve"]["reason"]
    elif name == "approval-after": assert observations["commit"]["status"] == "STALE_TICKET"
    elif name == "approval-replay":
        assert observations["commit"]["status"] == "COMMITTED"
        assert observations["replay"]["status"] == "REJECTED"
    elif name == "approval-forged": assert observations["forged"]["decision"] == "EVALUATION_ERROR"
    elif name == "worker-admin":
        assert observations["attack"]["status"] == "REJECTED"
        assert observations["direct"]["status"] == "CAPABILITY_REJECTED"
    elif name.startswith("recovery-"):
        outbox = artifact["terminal_observations"]["outbox"]
        assert len(outbox) == 1 and outbox[0]["status"] == "RELEASED"
        balances = [r["value"]["balance"] for r in artifact["terminal_observations"]["receiver"] if r["key"].startswith("account:")]
        assert balances == [300]
        if name.endswith("lease"): assert observations["old-ack"]["status"] == "IGNORED"
    elif name == "rollback-intent":
        assert observations["commit-failed"]["status"] == "REJECTED"
        assert observations["rolled-back"]["outbox"] == observations["rolled-back"]["events"] == []
        assert next(s["value"] for s in observations["rolled-back"]["state"] if s["key"] == "reserved:payments-a") == 0
        assert observations["commit-retry"]["status"] == "COMMITTED"
    elif name == "independent-keys":
        assert observations["commit-one"]["status"] == observations["commit-two"]["status"] == "COMMITTED"
    elif name.startswith("workflow-"):
        assert observations["recover"]["status"] == "SATISFIED", observations["recover"]
        if name == "workflow-review": assert observations["start"]["status"] == "REVIEW_WAIT"
    elif name == "fallback-contention": assert observations["execute"]["status"] == "RETRY_EXHAUSTED"


def test_scheduler_never_selects_unready_and_records_cross_mode_divergence():
    actions = [Action("a", "test", arrival=2), Action("b", "test", depends_on=("a",), priority=99), Action("c", "test")]
    scheduler = ReadyScheduler(actions, preferred=["b", "a", "c"])
    run = scheduler.run(lambda a, r: {"id": a.id})
    assert [s["chosen"] for s in run["schedule"]] == ["c", "a", "b"]
    assert all(s["chosen"] in s["ready"] for s in run["schedule"])
    assert run["schedule"][1]["tick"] == 2 and run["divergence"]
    blocked = scheduler.run(lambda a, r: {}, ready=lambda a, r: a.id != "a", exact_schedule=["a", "b", "c"])
    assert blocked["terminal"] == "BLOCKED" and blocked["blocked"] == ["a", "b"]
    with pytest.raises(ValueError): ReadyScheduler([Action("a", "x", depends_on=("a",))])


def test_security_fields_are_compared_and_raw_signature_is_retained():
    original = record(scenario("budget-double-allow"))
    assert original["run"]["observations"]["auth-first"]["ticket"]["signature"].startswith("ed25519:")
    for field, value in [("nonce", "wrong"), ("footprint", {}), ("args_hash", args_hash({})), ("not_after", "2027-01-01T00:00:00+00:00")]:
        changed = deepcopy(original)
        changed["run"]["observations"]["auth-first"]["ticket"][field] = value
        with pytest.raises(ValueError, match="semantic trace"): replay(changed)
    other = record(original["workload"], mode="fallback")
    paired = compare_pair(original, other)
    assert len(paired["schedules"]) == 2
    unpaired = deepcopy(other); unpaired["workload"]["actions"][0]["priority"] += 1
    with pytest.raises(ValueError, match="unpaired"): compare_pair(original, unpaired)


def test_paired_contention_has_visible_realized_divergence_and_fresh_fallback():
    optimistic = record(scenario("fallback-contention"))
    fallback = record(optimistic["workload"], mode="fallback", workspace=optimistic["bindings"]["checkpoint_workspace"])
    assert replay(fallback)["match"]
    assert fallback["run"]["observations"]["execute"]["status"] == "COMMITTED"
    assert len(fallback["run"]["trusted_hook_mutations"]) == len(optimistic["run"]["trusted_hook_mutations"]) == 3
    assert len(fallback["terminal_observations"]["outbox"]) == 1
    assert not optimistic["terminal_observations"]["outbox"]
    pair = compare_pair(optimistic, fallback)
    assert not pair["same_outcome"] and pair["observation_differences"] == ["execute"]


def test_model_tape_exact_binding_failure_and_offline_replay():
    model = FakeModel(lambda _: {"kind": "done", "summary": "synthetic"})
    tape = ModelTape(provider=model.provider, model=model.model, prompt_version="prompt-1", delegate=model)
    messages = [{"role": "user", "content": "Synthetic public context"}]
    result = asyncio.run(tape.generate(messages))
    offline = ModelTape(provider=model.provider, model=model.model, prompt_version="prompt-1", records=tape.records)
    assert asyncio.run(offline.generate(messages)) == result and len(model.calls) == 1
    for altered in ([{"role": "user", "content": "different"}],):
        with pytest.raises(ValueError, match="no exact"): asyncio.run(offline.generate(altered))
    for kwargs in ({"prompt_version": "prompt-2"}, {"model": "different"}):
        other = ModelTape(provider=model.provider, model=kwargs.get("model", model.model), prompt_version=kwargs.get("prompt_version", "prompt-1"), records=tape.records)
        with pytest.raises(ValueError): asyncio.run(other.generate(messages))
    with pytest.raises(ValueError): asyncio.run(offline.generate(messages, response_schema={"type": "object"}))
    failing = ModelTape(provider=model.provider, model=model.model, prompt_version="p", delegate=FakeModel(lambda _: TimeoutError("secret")))
    with pytest.raises(RuntimeError, match="TimeoutError"): asyncio.run(failing.generate(messages))
    assert "secret" not in json.dumps(failing.records)
    failed_replay = ModelTape(provider=model.provider, model=model.model, prompt_version="p", records=failing.records)
    with pytest.raises(RuntimeError, match="TimeoutError"): asyncio.run(failed_replay.generate(messages))
    outputs = iter([{"value": 1}, {"value": 2}])
    repeated_model = FakeModel(lambda _: next(outputs))
    repeated_tape = ModelTape(provider=model.provider, model=model.model, prompt_version="p", delegate=repeated_model)
    first = asyncio.run(repeated_tape.generate(messages)); second = asyncio.run(repeated_tape.generate(messages))
    assert first != second and len(repeated_model.calls) == len(repeated_tape.records) == 2
    playback = ModelTape(provider=model.provider, model=model.model, prompt_version="p", records=repeated_tape.records)
    assert asyncio.run(playback.generate(messages)) == first
    assert asyncio.run(playback.generate(messages)) == second
    with pytest.raises(ValueError): asyncio.run(playback.generate(messages))


def test_model_recorder_is_behind_guarded_egress_and_scope_revocation_blocks_calls(tmp_path):
    from atomicroot.tests.test_phase36_tasks import ConfigSystem
    from atomicroot.tests.test_phase37_executor import model_spec
    from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
    from atomicroot.integration.inference import ModelBridge
    from atomicroot.integration.providers import DisabledClassifier, Limits
    from atomicroot.integration.prompts import CONFIG_WORKER_VERSION
    s = ConfigSystem(tmp_path / "ledger.sqlite")
    spec = model_spec(s); s.activate(spec)
    fixture = ScriptedWorker({"a": [
        {"kind": "action", "tool": "read_document", "args": {"resource": "d1", "digest": s.refs[0]["digest"]}},
        {"kind": "action", "tool": "send_email", "args": {"to": "alice@corp.id", "body": "Synthetic summary"}}]})
    def respond(messages):
        view = json.loads(messages[-1]["content"])
        return fixture({"node": view["node"], "step": view["step"]})
    model = FakeModel(respond, provider="ollama")
    model.execution_binding = fixture.binding
    tape = ModelTape(provider=model.provider, model=model.model, prompt_version=CONFIG_WORKER_VERSION, delegate=model)
    limits = Limits(**s.runtime.tasks.status("t", s.user)["resolved"]["spec"]["limits"]["inference"])
    bridge = ModelBridge(s.runtime, tape, DisabledClassifier(), llm_limits=limits)
    flow = ConfigWorkflow(s.runtime, tmp_path / "checkpoint.sqlite", task="t", caller=s.user, bridge=bridge)
    try:
        result = flow.start("recorded")
        assert result["status"] == "SATISFIED", result
        assert len(tape.records) == len(model.calls) == 2
        offline = ModelTape(provider=model.provider, model=model.model, prompt_version=CONFIG_WORKER_VERSION, records=tape.records)
        for item in tape.records.values():
            assert asyncio.run(offline.generate(item["binding"]["messages"], response_schema=item["binding"]["response_schema"])) == item["response"]
        rights = deepcopy(s.rights); rights["scope"] = []
        s.runtime.catalog.set_entitlement("t", "user", rights, s.admin)
        blocked = flow.start("revoked")
        assert blocked["status"] == "REFUSED" and len(model.calls) == 2
    finally: flow.close(); s.runtime.store.close()


def test_checkpoint_reconstruction_rejects_foreign_or_existing_workspace(tmp_path):
    from tempfile import TemporaryDirectory
    from atomicroot.sim.replay import test_workspace as workspace
    with pytest.raises(ValueError, match="outside trusted"):
        with workspace(str(tmp_path / "foreign")): pass
    with TemporaryDirectory(prefix="atomicroot-phase4-") as directory:
        marker = Path(directory) / "preserve.txt"; marker.write_text("preserve")
        with pytest.raises(ValueError, match="already exists"):
            with workspace(directory): pass
        assert marker.read_text() == "preserve"
