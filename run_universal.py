"""Universal Zero-Config CLI for AtomicRoot System B.

Runs arbitrary daily or enterprise goals without requiring a per-task `--environment <file.json>`.
Preserves full Z3 policy evaluation, Ed25519 single-use tickets, SQLite CAS freshness checks,
taint tracking (PUBLIC/SENSITIVE/UNKNOWN), and atomic outbox delivery.
"""
import argparse
import json
from pathlib import Path
import re
import time

from atomicroot.authority.ticket import args_hash
from atomicroot.integration.universal import (
    DEFAULT_UNIVERSAL_MODEL,
    run_universal_goal,
)
from atomicroot.observability import point


def _default_output_dir(goal):
    slug = re.sub(r"[^a-z0-9]+", "-", goal.lower()).strip("-")[:28] or "goal"
    stamp = int(time.time() * 1000) % 1000000
    digest = args_hash({"goal": goal, "t": stamp}).split(":")[-1][:8]
    return Path(".runs") / "universal" / f"{slug}-{digest}"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goal", required=True, help="Natural-language user goal to plan and execute")
    parser.add_argument("--output", type=Path, help="Output directory (auto-generated under .runs/universal/ if omitted)")
    parser.add_argument(
        "--doc",
        action="append",
        default=[],
        help="Optional inline or file document: name=content_or_path[:PUBLIC|SENSITIVE|UNKNOWN]",
    )
    parser.add_argument(
        "--allow-to",
        action="append",
        default=[],
        help="Optional pre-authorized recipient destination (otherwise requested dynamically via permission bundle)",
    )
    parser.add_argument("--budget", type=int, default=None, help="Explicit workspace budget ceiling (default: 0 or inferred from goal)")
    parser.add_argument("--provider", default="ollama", help="Model provider (default: ollama)")
    parser.add_argument("--model", default=DEFAULT_UNIVERSAL_MODEL, help=f"Model tag (default: {DEFAULT_UNIVERSAL_MODEL})")
    parser.add_argument("--clarification", help="Optional user clarification if the goal is ambiguous")
    parser.add_argument("--authorize-live", action="store_true", default=True, help="Authorize live local Ollama inference")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively before approving proposal/permissions")
    parser.add_argument("--no-execute", action="store_true", help="Stop after plan activation without running worker execution")
    args = parser.parse_args(argv)

    output_dir = args.output or _default_output_dir(args.goal)
    try:
        result = run_universal_goal(
            args.goal,
            output_dir,
            docs=args.doc,
            recipients=args.allow_to,
            provider=args.provider,
            model=args.model,
            budget_limit=args.budget,
            authorize_live=args.authorize_live,
            auto_approve=not args.interactive,
            execute=not args.no_execute,
            clarification=args.clarification,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["status"] in {"SATISFIED", "ACTIVE", "PAUSED", "REVIEW_WAIT", "NEEDS_CAPABILITY"} else 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "INVOCATION_FAILED",
                    "error": type(exc).__name__,
                    "reason": str(exc)[:256],
                    "observed": point(),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
