"""Runner plans, result preservation and real child failure/timeout handling."""
import json
from pathlib import Path
import sys

import pytest

import run_tests


def test_profiles_select_bounded_existing_offline_commands(tmp_path):
    for profile in run_tests.PROFILES:
        commands = run_tests.plan(profile, tmp_path)
        assert commands and all(c.args[0] == sys.executable for c in commands)
    all_commands = run_tests.plan("all", tmp_path)
    assert [c.name for c in all_commands] == ["regression", "phase4-artifacts", "phase5-artifacts", "phase55-artifacts"]
    assert all(str(tmp_path) in " ".join(c.args) for c in all_commands)
    scenario = run_tests.plan("scenarios", tmp_path, scenario="budget")
    assert len(scenario) == 7 and all(c.dependency == "scenario-record" for c in scenario[1:])
    single = run_tests.plan("scenarios", tmp_path, scenario="budget", mode="atomicroot")
    assert len(single) == 2
    with pytest.raises(ValueError): run_tests.plan("quick", tmp_path, scenario="budget")
    with pytest.raises(ValueError): run_tests.plan("scenarios", tmp_path, mode="atomicroot")


@pytest.mark.parametrize("code,status", [(0, "PASSED"), (7, "FAILED")])
def test_child_output_exit_code_and_timestamps_are_preserved(tmp_path, code, status):
    command = run_tests.Command("synthetic", (sys.executable, "-c", f"print('fixture output'); raise SystemExit({code})"))
    result = run_tests.execute(command, tmp_path, 5)
    assert result["status"] == status and result["exit_code"] == code
    assert "fixture output" in (tmp_path / "synthetic.log").read_text()
    assert result["observed_timing"]["duration_ns"] > 0
    points = [json.loads(line) for line in (tmp_path / "progress.jsonl").read_text().splitlines()]
    assert points[0]["event"] == "COMMAND_STARTED" and points[-1]["event"] == "COMMAND_FINISHED"


def test_timeout_terminates_waiting_child_and_records_failure(tmp_path):
    command = run_tests.Command("wait", (sys.executable, "-c", "from threading import Event; Event().wait(1000)"))
    result = run_tests.execute(command, tmp_path, .3)
    assert result["status"] == "TIMEOUT" and result["exit_code"] == 124


def test_existing_output_and_invalid_timeout_do_not_overwrite_evidence(tmp_path):
    marker = tmp_path / "summary.json"; marker.write_text("existing evidence")
    with pytest.raises(SystemExit): run_tests.main(["quick", "--output", str(tmp_path)])
    assert marker.read_text() == "existing evidence"
    with pytest.raises(SystemExit): run_tests.main(["quick", "--timeout", "nan"])


def test_failed_dependencies_skip_replay_but_other_commands_run(tmp_path, monkeypatch):
    commands = [run_tests.Command("failed", (sys.executable, "-c", "raise SystemExit(3)")),
                run_tests.Command("replay", (sys.executable, "-c", "raise RuntimeError('must not run')"), "failed"),
                run_tests.Command("independent", (sys.executable, "-c", "print('continued')"))]
    monkeypatch.setattr(run_tests, "plan", lambda *a, **k: commands)
    output = tmp_path / "new-run"
    assert run_tests.main(["all", "--output", str(output)]) == 1
    report = json.loads((output / "summary.json").read_text())
    assert [r["status"] for r in report["commands"]] == ["FAILED", "SKIPPED", "PASSED"]
    assert report["status"] == "FAILED" and report["observed_timing"]["finished_at_utc"]
    assert not (output / "replay.log").exists()
    index = json.loads((output / "files.json").read_text())
    assert all(r["file_modified_at_utc"] and len(r["sha256"]) == 64 for r in index["files"])


def test_junit_suite_timestamp_and_counts(tmp_path):
    report = tmp_path / "pytest.xml"
    report.write_text('<testsuites><testsuite tests="2" failures="1" errors="0" skipped="0" time="1.5" timestamp="2026-10-27T00:00:00+00:00"/></testsuites>')
    result = run_tests.junit(report)
    assert result["tests"] == 2 and result["failures"] == 1 and result["suite_timestamps"][0].endswith("+00:00")
