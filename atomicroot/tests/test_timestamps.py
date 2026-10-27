"""Real observation clocks remain outside deterministic/security replay inputs."""
from copy import deepcopy
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import asyncio

import pytest

from atomicroot import observability
from atomicroot.observability import Stopwatch, event_times, protocol_run
from atomicroot.sim.scheduler import HookLog
from atomicroot.sim.scenarios import scenario
from atomicroot.sim.replay import record, replay
from atomicroot.evaluation.scenarios import manifest
from atomicroot.evaluation.runner import run, replay as replay_evaluation
from atomicroot.sim.model_tape import ModelTape
from atomicroot.integration.providers import FakeModel


def utc(value):
    result = datetime.fromisoformat(value)
    assert result.tzinfo is not None and result.utcoffset().total_seconds() == 0
    return result


def window(value):
    utc(value["started_at_utc"]); utc(value["finished_at_utc"])
    assert type(value["duration_ns"]) is int and value["duration_ns"] >= 0


def test_monotonic_duration_survives_wall_clock_adjustment(monkeypatch):
    points = iter([{"observed_at_utc": "2026-10-27T10:00:00+00:00", "monotonic_ns": 100, "process_id": 1},
                   {"observed_at_utc": "2026-10-27T09:59:59+00:00", "monotonic_ns": 125, "process_id": 1}])
    monkeypatch.setattr(observability, "point", lambda: next(points))
    timer = Stopwatch()
    assert timer.finish()["duration_ns"] == 25
    assert timer.finish()["duration_ns"] == 25


def test_hook_points_are_serialized_for_concurrent_observers():
    log = HookLog()
    with ThreadPoolExecutor(4) as pool: list(pool.map(lambda i: log.checkpoint("sample", str(i)), range(20)))
    assert len(log.steps) == 20
    assert [r["observed"]["monotonic_ns"] for r in log.steps] == sorted(r["observed"]["monotonic_ns"] for r in log.steps)
    for row in log.steps: utc(row["observed"]["observed_at_utc"])


def test_recording_points_do_not_replace_virtual_clock_or_security_fields():
    artifact = record(scenario("budget-double-allow"))
    window(artifact["observed_timing"]["run"])
    step_times = artifact["run"]["observed_timing"]["steps"]
    assert [s["action"] for s in step_times] == [s["chosen"] for s in artifact["run"]["schedule"]]
    for step in step_times: window(step)
    ticket = artifact["run"]["observations"]["auth-first"]["ticket"]
    assert ticket["not_before"] == artifact["workload"]["clock"]
    assert "observed_timing" not in ticket
    repeated = replay(artifact)
    assert repeated["match"]
    assert repeated["artifact"]["observed_timing"] != artifact["observed_timing"]
    # Metadata at the trusted root is separate; the same name inside worker
    # output must never be recursively erased to manufacture a replay match.
    changed = deepcopy(artifact)
    changed["run"]["observations"]["auth-first"]["observed_timing"] = {"hide": "worker data"}
    with pytest.raises(ValueError, match="semantic trace"): replay(changed)
    changed = deepcopy(artifact); changed["run"]["observations"]["auth-first"]["ticket"]["not_after"] = "2099-01-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="semantic trace"): replay(changed)


def test_old_artifact_without_observational_fields_still_replays():
    artifact = record(scenario("budget-double-allow"))
    artifact.pop("observed_timing")
    artifact["run"] = protocol_run(artifact["run"])
    for hook in artifact["hooks"]: hook.pop("observed")
    assert replay(artifact)["match"]


def test_oracle_events_link_to_actual_task_receipt_hook_and_export_time():
    artifact = run(manifest("independent"), "atomicroot")
    assert replay_evaluation(artifact)["match"]
    timings = artifact["observed_timing"]["events"]
    assert len(timings) == len(artifact["events"])
    for entry in timings:
        utc(entry["exported_at_utc"])
        assert entry["observed"] is not None
        utc(entry["observed"]["observed_at_utc"])
        hook = artifact["hooks"][entry["hook_index"]]
        if entry["kind"] == "APPLIED": assert hook["task"] == entry["task"]
    missing = event_times(artifact["events"], [], artifact["terminal_ledger"])
    assert all(e["observed"] is None and e["source"] == "source timing unavailable" for e in missing)


def test_deferred_points_are_marked_as_after_release():
    artifact = run(manifest("contention"), "global_version_atomicroot")
    hooks = [h for h in artifact["hooks"] if h.get("deferred")]
    assert hooks and all(h["observed_after"] == "fallback_release" for h in hooks)
    assert replay_evaluation(artifact)["match"]


def test_model_recording_has_time_but_response_binding_remains_exact():
    model = FakeModel(lambda _: {"value": "synthetic"})
    tape = ModelTape(provider=model.provider, model=model.model, prompt_version="time-v1", delegate=model)
    messages = [{"role": "user", "content": "Synthetic public fixture"}]
    response = asyncio.run(tape.generate(messages))
    item = next(iter(tape.records.values()))
    window(item["observed_timing"])
    offline = ModelTape(provider=model.provider, model=model.model, prompt_version="time-v1", records=tape.records)
    assert asyncio.run(offline.generate(messages)) == response
