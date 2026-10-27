"""Finite Phase 5 mechanism comparisons. No live models, attack search or benchmark."""
import argparse
import json
from pathlib import Path

from atomicroot.authority.ticket import freeze_json
from atomicroot.evaluation.modes import MODES, feature_matrix
from atomicroot.evaluation.scenarios import SCENARIOS, manifest
from atomicroot.evaluation.runner import run, replay, pair, evaluation_schema
from atomicroot.framework.policy_catalog import catalog


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 16 * 1024 * 1024: raise ValueError("evaluation artifact exceeds byte bound")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return freeze_json(json.loads(raw, object_pairs_hook=unique), max_bytes=16 * 1024 * 1024)


def save(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("catalog", "matrix", "list", "schema"): sub.add_parser(command)
    capture = sub.add_parser("record"); capture.add_argument("scenario", choices=SCENARIOS); capture.add_argument("output"); capture.add_argument("--mode", choices=MODES, default="atomicroot")
    repeat = sub.add_parser("replay"); repeat.add_argument("artifact")
    paired = sub.add_parser("compare"); paired.add_argument("scenario", choices=SCENARIOS); paired.add_argument("directory")
    args = parser.parse_args()
    try:
        if args.command == "schema": result = evaluation_schema()
        elif args.command == "catalog": result = catalog()
        elif args.command == "matrix": result = feature_matrix()
        elif args.command == "list": result = {"schema_version": 1, "scenarios": SCENARIOS, "modes": MODES}
        elif args.command == "record":
            artifact = run(manifest(args.scenario), args.mode); save(args.output, artifact)
            result = {"output": args.output, "oracle": artifact["oracle"], "blocked": artifact["run"]["blocked"]}
        elif args.command == "replay":
            report = replay(load(args.artifact)); result = {"match": report["match"]}
        else:
            workload = manifest(args.scenario)
            artifacts = [run(workload, mode) for mode in MODES]
            for artifact in artifacts: save(Path(args.directory) / (artifact["mode"] + ".json"), artifact)
            result = pair(artifacts); save(Path(args.directory) / "paired.json", result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("match") is False else 0
    except (ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)})); return 1


if __name__ == "__main__": raise SystemExit(main())
