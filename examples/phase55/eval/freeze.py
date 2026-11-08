"""Write examples/phase55/eval/freeze.json: protocol/registry/source/case identities for evaluation runs.

Run on a clean, committed tree; commit the result. live_27b_suite.py refuses to run when the current
identities differ from this file, so no prompt, schema or case can be tuned after freezing.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from atomicroot.evaluation.goal_eval import freeze_state, load_cases
from atomicroot.observability import point
from examples.phase55.live_27b_suite import git_state

HERE = Path(__file__).resolve().parent


def main() -> int:
    cases = sorted(HERE.glob("*-cases.json"))
    for path in cases: load_cases(path)
    git = git_state()
    if git["dirty_tracked"]: raise SystemExit("tracked working tree is dirty; commit before freezing")
    state = {**freeze_state(cases), "base_commit": git["head"], "created": point()}
    (HERE / "freeze.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
