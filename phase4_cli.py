"""Phase 4 offline scheduling, versioned artifacts and exact semantic replay."""
import argparse
import json

from atomicroot.sim.replay import record, replay
from atomicroot.sim.scheduler import load_artifact, save_artifact, compare_pair, artifact_schema
from atomicroot.sim.scenarios import scenario, SCENARIOS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    sub.add_parser("schema")
    capture = sub.add_parser("record")
    capture.add_argument("scenario", choices=SCENARIOS)
    capture.add_argument("output")
    capture.add_argument("--mode", choices=("optimistic", "fallback"), default="optimistic")
    repeat = sub.add_parser("replay"); repeat.add_argument("artifact"); repeat.add_argument("--output")
    pair = sub.add_parser("pair"); pair.add_argument("first"); pair.add_argument("second")
    args = parser.parse_args()
    try:
        if args.command == "schema": result = artifact_schema()
        elif args.command == "list": result = {"schema_version": 1, "scenarios": SCENARIOS}
        elif args.command == "record":
            artifact = record(scenario(args.scenario), mode=args.mode)
            save_artifact(args.output, artifact)
            result = {"artifact": args.output, "terminal": artifact["run"]["terminal"], "steps": len(artifact["run"]["schedule"]), "divergence": artifact["run"]["divergence"]}
        elif args.command == "replay":
            report = replay(load_artifact(args.artifact))
            if args.output: save_artifact(args.output, report["artifact"])
            result = {k: v for k, v in report.items() if k != "artifact"}
        else: result = compare_pair(load_artifact(args.first), load_artifact(args.second))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("match") is False else 0
    except (ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)})); return 1


if __name__ == "__main__": raise SystemExit(main())
