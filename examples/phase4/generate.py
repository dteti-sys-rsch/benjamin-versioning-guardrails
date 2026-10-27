"""Regenerate finite Phase 4 evidence; no live models or benchmark search."""
from pathlib import Path
from time import perf_counter
import json
import sys
import asyncio
import argparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from atomicroot.observability import Stopwatch, point

from atomicroot.sim.replay import record, replay, environment
from atomicroot.sim.scheduler import save_artifact, artifact_schema, compare_pair
from atomicroot.sim.scenarios import scenario, SCENARIOS
from atomicroot.sim.model_tape import ModelTape
from atomicroot.integration.providers import FakeModel


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    output = parser.parse_args(argv).output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    timer = Stopwatch()
    started = perf_counter()
    checks = []
    for name in SCENARIOS:
        artifact = record(scenario(name))
        repeated = replay(artifact)
        if not repeated["match"]: raise AssertionError("replay divergence: " + name)
        save_artifact(output / "artifacts" / (name + ".json"), artifact)
        checks.append({"scenario": name, "terminal": artifact["run"]["terminal"], "steps": len(artifact["run"]["schedule"]),
                       "exact_replay": repeated["match"], "effect_count": len(artifact["terminal_observations"]["outbox"])})
        if name == "fallback-contention":
            fallback = record(artifact["workload"], mode="fallback", workspace=artifact["bindings"]["checkpoint_workspace"])
            if not replay(fallback)["match"]: raise AssertionError("fallback replay divergence")
            save_artifact(output / "artifacts" / "fallback-contention-exclusive.json", fallback)
            pair = compare_pair(artifact, fallback)
            (output / "paired-contention.json").write_text(json.dumps(pair, indent=2) + "\n", encoding="utf-8")
    (output / "replay-schema-v1.json").write_text(json.dumps(artifact_schema(), indent=2) + "\n", encoding="utf-8")
    # A synthetic provider-shaped response demonstrates the tape format. This is
    # not live validation; authorized live delegates use exactly the same API.
    model = FakeModel(lambda _: {"kind": "done", "summary": "Synthetic public result"})
    tape = ModelTape(provider=model.provider, model=model.model, prompt_version="phase4-example-v1", delegate=model)
    asyncio.run(tape.generate([{"role": "user", "content": "Synthetic public request"}]))
    (output / "model-tape.json").write_text(json.dumps({"schema_version": 1, "provider": tape.provider, "model": tape.model,
        "prompt_version": tape.prompt_version, "records": tape.records, "origin": "OFFLINE_FAKE"}, indent=2) + "\n", encoding="utf-8")
    summary = {"command": [sys.executable, str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)], "environment": environment(),
        "scenarios": checks, "fallback_replay": True, "live_calls": 0, "effects": "simulated", "validation_elapsed_seconds": round(perf_counter() - started, 3)}
    summary["observed_timing"] = {"run": timer.finish(), "generated_at_utc": point()["observed_at_utc"]}
    (output / "validation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"scenarios": len(checks), "exact_replays": len(checks) + 1, "directory": str(output)}))


if __name__ == "__main__": main()
