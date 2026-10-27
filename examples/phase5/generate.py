"""Finite deterministic Phase 5 records and exact offline replays, not a benchmark."""
from pathlib import Path
from time import perf_counter
import sys
import argparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from phase5_cli import save
from atomicroot.evaluation.scenarios import manifest, SCENARIOS
from atomicroot.evaluation.modes import MODES, feature_matrix
from atomicroot.evaluation.runner import run, replay, pair, evaluation_schema
from atomicroot.framework.policy_catalog import catalog
from atomicroot.sim.replay import environment
from atomicroot.observability import Stopwatch, point


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    directory = parser.parse_args(argv).output.resolve()
    timer = Stopwatch()
    started, checks = perf_counter(), []
    for name in SCENARIOS:
        workload = manifest(name)
        save(directory / "manifests" / (name + ".json"), workload)
        artifacts = []
        for mode in MODES:
            artifact = run(workload, mode)
            repeated = replay(artifact)
            if not repeated["match"]: raise AssertionError((name, mode, "replay divergence"))
            save(directory / "artifacts" / name / (mode + ".json"), artifact)
            artifacts.append(artifact)
            checks.append({"scenario": name, "mode": mode, "exact_replay": True, "terminal": artifact["run"]["terminal"],
                "accepted_intents": artifact["oracle"]["accepted_intents"], "accepted_violations": artifact["oracle"]["accepted_violation_count"],
                "delivered_violations": artifact["oracle"]["delivered_violation_count"], "ground_truth_leaks": len(artifact["oracle"]["ground_truth_delivered_leaks"]),
                "unknown_observations": artifact["oracle"]["unknown_delivery_observations"]})
        save(directory / "paired" / (name + ".json"), pair(artifacts))
    save(directory / "policy-catalog.json", catalog())
    save(directory / "six-mode-matrix.json", feature_matrix())
    save(directory / "evaluation-schema-v1.json", evaluation_schema())
    save(directory / "validation.json", {"schema_version": 1, "command": [sys.executable, str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)], "environment": environment(),
        "scenario_count": len(SCENARIOS), "mode_count": len(MODES), "runs": checks, "live_calls": 0, "effects": "SIMULATED",
        "validation_elapsed_seconds": round(perf_counter() - started, 3), "scope": "finite mechanism fixtures; no adaptive/full benchmark or formal proof",
        "observed_timing": {"run": timer.finish(), "generated_at_utc": point()["observed_at_utc"]}})
    print(f"{len(checks)} paired mechanism records; {len(checks)} exact replays matched; {len(SCENARIOS)} scenarios / six modes")


if __name__ == "__main__": main()
