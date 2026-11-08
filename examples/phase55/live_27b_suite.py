"""Live System B goal suite on a local Ollama model (dynamic planner protocol in atomicroot.integration).

Cases come from a versioned case file (examples/phase55/eval/*-cases.json) that authors the ground
truth: accepted outcome classes, required/forbidden business effects, outputs and label truth.
Two automated reviewers exist:
  case  — legacy development reviewer; approves using the case's reviewer_expect (shares
          expectations with the case, so it is not independent of scoring).
  blind — approves every valid business proposal and pauses capability specifications; intent
          correctness is then judged only by the goal oracle (atomicroot.evaluation.goal_eval).

Evidence rules: a fresh output directory per invocation, no deletion or resume of runs, infra
failures kept as INFRA_ERROR, provenance and a SHA-256 manifest written with the results.
classify_document/JEV is out of scope.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import subprocess
import sys
import tempfile
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from atomicroot.evaluation.goal_eval import (
    aggregate_goal_runs,
    case_labels,
    evaluate_goal_run,
    freeze_state,
    goal_run_to_workload,
    load_cases,
    run_six_modes,
)
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration import dynamic_proposal as protocol
from atomicroot.integration.environment import (
    activate_intake,
    initialize_environment,
    local_identities,
    prepare_environment,
)
from atomicroot.integration.goals import GoalService
from atomicroot.integration.progress import Progress
from atomicroot.integration.providers import Limits, live_model, ollama_model_metadata
from atomicroot.integration.workspace import task_environment
from atomicroot.observability import point
from phase37_cli import build_workflow
from run_goal import run as run_goal_interactive

DEFAULT_MODEL = "qwen3.8:27b-q8_0"
DEFAULT_ENDPOINT = "http://localhost:11434/api"
DEFAULT_CASES = ROOT / "examples/phase55/eval/dev-cases.json"
DEFAULT_FREEZE = ROOT / "examples/phase55/eval/freeze.json"
REVIEWER = "TRUSTED_SYNTHETIC_TEST_OPERATOR"


def base_workspace(model: str = DEFAULT_MODEL, max_calls: int = 8) -> dict:
    return {
        "schema_version": 2,
        "purpose": "research",
        "resources": [],
        "destinations": [{"destination": "ollama", "kind": "provider", "purposes": ["research"],
                          "models": [model], "labels": ["PUBLIC", "UNKNOWN"], "endpoint": DEFAULT_ENDPOINT}],
        "provider": {"destination": "ollama", "model": model},
        "enabled_tools": [],
        "budget_limit": 0,
        "max_agents": 3,
        "limits": {"max_steps": 16, "max_in_flight": 2,
                   "inference": {"max_calls": max_calls, "max_tokens": 200000, "max_output_tokens": 4096,
                                 "max_retries": 0, "timeout": 180}},
        "planning": {"ttl": 3600, "max_repairs": 1, "max_replans": 2},
    }


def build_config(cases: dict, name: str, model: str) -> dict:
    """Workspace from the case file; provider/limits stay host-owned."""
    case = cases["cases"][name]
    ws = cases["workspaces"][case["workspace"]]
    config = base_workspace(model=model, max_calls=case["max_calls"])
    config["resources"] = deepcopy(ws["resources"])
    config["destinations"] += [{"destination": r, "kind": "recipient", "purposes": ["research"], "models": [],
                                "labels": [], "endpoint": None} for r in ws["recipients"]]
    config["enabled_tools"] = list(ws["enabled_tools"])
    config["budget_limit"] = ws["budget_limit"]
    return config


def case_reviewer(preview: dict, case: dict) -> str:
    """Development reviewer: shares the case's expectations, so it is not independent of scoring."""
    expect = case.get("reviewer_expect") or {}
    if preview["status"] == "NEEDS_CAPABILITY":
        reqs = preview.get("proposal", {}).get("capability_requests", [])
        return "approve" if any(expect.get("capability", "\0") in str(x.get("name", "")).lower() for x in reqs) else "reject"
    spec = preview.get("proposal", {}).get("spec") or {}
    hosts = {r["resource"] for r in spec.get("resources", []) if r.get("binding") == "host_context"}
    scope = [r for r in spec.get("scope", []) if r["resource"] not in hosts]
    accept = expect.get("accept", [])
    ok = bool(accept) and all(c in spec.get("acceptance", []) for c in accept)
    ok = ok and all(r["tool"] in set(expect.get("tools", [])) for r in scope)
    ok = ok and all(r["resource"] == want for r in scope for tool, want in expect.get("only", {}).items() if r["tool"] == tool)
    if expect.get("require_policy"): ok = ok and len(spec.get("policies", [])) > 0
    return "approve" if ok else "reject"


def blind_answer(question: str, case: dict, environment_digest: str) -> str:
    """Approve every valid business proposal; never authorize a capability specification.

    The clarification answer is the goal author's input from the case file, not a reviewer judgement.
    """
    if "displayed digest" in question: return environment_digest
    if "clarification" in question.lower(): return case.get("clarification", "")
    if "capability specification" in question: return "pause"
    return "approve"


def _decide(reviewer: str, preview: dict, case: dict) -> str:
    return case_reviewer(preview, case) if reviewer == "case" else "approve"


def _run_replan_stale(config, goal, path, case, reviewer, model_factory):
    """Plan -> owner mutates the stale resource -> stale activation rejected -> replan -> execute."""
    environment = task_environment(config, goal)
    prepared = prepare_environment(environment)
    limits = Limits(**prepared["intake_spec"]["limits"]["inference"])
    path.mkdir(parents=True)

    def save(name, value):
        p = path / name
        p.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        p.chmod(0o600)

    save("invocation.json", {"entrypoint": "live_27b_suite:replan_stale", "goal": goal, "output": str(path), "observed": point()})
    save("environment-preview.json", {**prepared, "observed": point()})
    decisions = [{"question": "Accept environment digest", "answer": prepared["digest"], "actor": REVIEWER}]
    key = SigningKey.generate()
    (path / "signing.key").write_bytes(bytes(key))
    runtime = FrameworkRuntime(str(path / "ledger.sqlite"), signing_key=key)
    try:
        setup = initialize_environment(runtime, environment, prepared["digest"])
        save("intake-preview.json", setup)
        user, approver = local_identities(runtime)
        runtime.broker.decide(setup["preview"]["review_id"], True, approver)
        activate_intake(runtime, approver)
        model = model_factory(environment["provider"]["destination"], environment["provider"]["model"], limits)
        progress = Progress(path / "progress.jsonl")
        service = GoalService(runtime, model, progress=progress, protocol=protocol)
        first = service.plan("goal", goal, "planning", environment["task_id"], user)
        save("proposal-preview-rev0.json", first)
        if first["status"] != "REVIEW_WAIT":
            result = {"status": first["status"], "stale_rejected": None, "observed": point()}
            save("goal-artifact.json", service.export("goal", user)); save("result.json", result)
            return result, decisions
        service.decide("goal", "approve", approver)
        stale = case["stale"]
        owner = Principal(user.subject, frozenset({"owner", "user"}), user.tasks, frozenset({stale["resource"]}))
        label = next(r["label"] for r in config["resources"] if r["resource"] == stale["resource"])
        ingested = runtime.storage.ingest(stale["resource"], stale["content"], owner)
        runtime.labels.set_label(stale["resource"], ingested["digest"], ingested["version"], label, ["research"], owner)
        stale_rejected = False
        try: service.activate("goal", approver)
        except ValueError: stale_rejected = True
        service.plan("goal", goal, "planning", environment["task_id"], user, replan=True)
        preview = service.status("goal", user, private=True)
        save("proposal-preview.json", preview)
        decision = _decide(reviewer, preview, case) if preview["status"] == "REVIEW_WAIT" else "pause"
        decisions.append({"question": "Approve replanned proposal", "answer": decision, "actor": REVIEWER, "stale_rejected": stale_rejected})
        if preview["status"] == "REVIEW_WAIT":
            service.decide("goal", decision, approver)
        if decision == "approve" and preview["status"] == "REVIEW_WAIT":
            service.activate("goal", approver)

            def factory(task, caller, budget):
                flow = build_workflow(runtime, path / "executor.sqlite", task, caller, mode="live", authorize_live=True, progress=progress)
                if flow.bridge: flow.bridge.budget = budget
                return flow
            result = {**service.execute("goal", user, factory), "stale_rejected": stale_rejected, "observed": point()}
        else:
            result = {"status": preview["status"] if decision == "pause" else "REJECTED", "stale_rejected": stale_rejected, "observed": point()}
        save("goal-artifact.json", service.export("goal", user)); save("result.json", result)
        return result, decisions
    finally:
        runtime.store.close()


def _verify_replay(config, goal, artifact_path, case) -> bool:
    if not artifact_path.exists(): return False
    art = json.loads(artifact_path.read_text(encoding="utf-8"))
    env = task_environment(config, goal)
    ts = art["planning"]["intake"]["expires"] - 1800
    with tempfile.TemporaryDirectory() as td:
        rt = FrameworkRuntime(Path(td) / "replay.sqlite", clock=lambda t=ts: datetime.fromtimestamp(t, timezone.utc))
        try:
            prep = prepare_environment(env)
            setup = initialize_environment(rt, env, prep["digest"])
            u, a = local_identities(rt)
            rt.broker.decide(setup["preview"]["review_id"], True, a)
            activate_intake(rt, a)
            stale = case.get("stale")
            if stale and art["planning"].get("revision", 0) > 0 and any(
                    r["resource"] == stale["resource"] and r["version"] == 2 for r in art["planning"]["catalog"]["resources"]):
                owner = Principal(u.subject, frozenset({"owner", "user"}), u.tasks, frozenset({stale["resource"]}))
                label = next(r["label"] for r in config["resources"] if r["resource"] == stale["resource"])
                ingested = rt.storage.ingest(stale["resource"], stale["content"], owner)
                rt.labels.set_label(stale["resource"], ingested["digest"], ingested["version"], label, ["research"], owner)
            GoalService(rt).register_intake(art["planning"]["intake"], Principal("admin", frozenset({"admin"})))
            return bool(GoalService(rt).replay(art, u).get("match"))
        except Exception:
            return False
        finally:
            rt.store.close()


def _probe_policies(runtime, task_id, user, probe) -> dict:
    """Evaluate every active custom policy with Z3 on authored probe requests; DENY wins."""
    from atomicroot.authority.policy_engine import StatusReader
    from atomicroot.framework.contracts import policy_key
    from atomicroot.framework.dsl import evaluate
    active = runtime.tasks.status(task_id, user)["resolved"]
    actor = runtime.tasks.principal(task_id, active["agents"][0]["id"], user)
    with runtime.store.snapshot() as snap:
        reader = StatusReader(snap)
        members = reader.read(f"policyset:{task_id}") or []
        if not members: return {"probed": False, "reason": "no_custom_policy", "ok": False}
        definitions = [reader.read(policy_key(m)) for m in members]
        results = []
        for index, check in enumerate(probe["checks"]):
            request = {"task_id": task_id, "agent_id": actor.subject, "operation_id": f"z3-probe-{index}", "purpose": "research",
                       "tool": probe["tool"], "recipient": check["args"].get("to", ""), "resource": check["args"].get("resource", ""),
                       "base_digest": "", "args": check["args"]}
            decisions = [evaluate({"definition": d}, {"reader": reader}, request).decision for d in definitions
                         if probe["tool"] in d.get("applies_to", [probe["tool"]])]
            decision = "DENY" if "DENY" in decisions else ("ALLOW" if decisions else "NOT_APPLICABLE")
            results.append({"args": check["args"], "expect": check["expect"], "decision": decision})
    return {"probed": True, "policies": [d["policy_id"] for d in definitions], "checks": results,
            "ok": all(r["decision"] == r["expect"] for r in results)}


def _infra_stub(reason) -> dict:
    """A run that produced no evaluable ledger; it stays in the denominator as INFRA_ERROR."""
    return {"session": "goal", "task_id": None, "planning_status": "INFRA_ERROR", "execution_status": None,
                  "outcome": "INFRA_ERROR", "passed": False, "invariants_ok": None, "policy_count": 0, "origin_count": 0,
                  "repairs": 0, "output_collision": [], "inference_attempts": 0, "completion_satisfied": None,
                  "goal_oracle": None, "planner_output_digest": None, "scope_breakdown": None, "infra_reason": reason,
                  "business_oracle": {"accepted_intents": 0, "accepted_violation_count": 0, "applied_effects": 0, "delivered_violation_count": 0},
                  "full_oracle": {"accepted_intents": 0, "accepted_violation_count": 0, "applied_effects": 0, "delivered_violation_count": 0}}


def _expected(case) -> str:
    return "SATISFIED" if "SATISFIED" in case["accepted_outcomes"] else "BLOCKED"


def _evaluate_run_dir(path, config, cases, name, rep, run_id) -> dict:
    case = cases["cases"][name]
    base = {"case": name, "pattern": case["pattern"], "repetition": rep, "run_id": run_id, "expected_outcome": _expected(case),
            "accepted_outcomes": case["accepted_outcomes"], "goal_digest": "sha256:" + hashlib.sha256(case["goal"].encode()).hexdigest()}
    if not (path / "ledger.sqlite").exists() or not (path / "signing.key").exists():
        return {**_infra_stub("no ledger"), **base, "replay_match": False, "six_mode_paired_consistent": None}
    runtime = FrameworkRuntime(str(path / "ledger.sqlite"), signing_key=SigningKey((path / "signing.key").read_bytes()))
    goal = case["goal"]
    try:
        user, _ = local_identities(runtime)
        env_task = task_environment(config, goal)["task_id"]
        ev = evaluate_goal_run(runtime, "goal", env_task, user, expected_outcome=base["expected_outcome"],
                               case={**case, "labels": case_labels(cases, name)})
        ev.update(base)
        if "policy_probe" in case and ev["outcome"] == "SATISFIED":
            ev["z3_policy_probe"] = _probe_policies(runtime, env_task, user, case["policy_probe"])
            ev["passed"] = ev["passed"] and ev["z3_policy_probe"]["ok"]
        ev["six_mode_paired_consistent"] = None
        if ev["outcome"] == "SATISFIED":
            initial = deepcopy(config["resources"])
            for r in initial:
                if case.get("stale") and r["resource"] == case["stale"]["resource"]: r["content"] = case["stale"]["content"]
            six = run_six_modes(goal_run_to_workload(runtime, env_task, initial_resources=initial, name=f"sixmode-{run_id}"))
            ev["six_mode_paired_consistent"] = all(m["oracle"]["accepted_violation_count"] == 0 for m in six["paired"]["modes"])
    except Exception as exc:
        ev = {**_infra_stub(f"evaluation {type(exc).__name__}: {str(exc)[:200]}"), **base}
    finally:
        runtime.store.close()
    ev["replay_match"] = _verify_replay(config, goal, path / "goal-artifact.json", case)
    return ev


def git_state(root: Path = ROOT) -> dict:
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    return {"head": git("rev-parse", "HEAD"), "dirty_tracked": bool(git("status", "--porcelain", "--untracked-files=no"))}


def write_manifest(directory: Path) -> Path:
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(directory).as_posix()}")
    manifest = directory / "MANIFEST.sha256"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def check_freeze(freeze_file: Path, case_files: list[Path]) -> dict:
    """Current protocol/registry/source/case hashes must equal the committed freeze manifest."""
    frozen = json.loads(Path(freeze_file).read_text(encoding="utf-8"))
    current = freeze_state(case_files)
    differences = sorted(k for k in current if frozen.get(k) != current[k])
    if differences: raise RuntimeError("freeze mismatch; tuning after freeze is not allowed: " + ", ".join(differences))
    return {"freeze_file": str(freeze_file), "base_commit": frozen.get("base_commit"), "matched": True}


def run_suite(output_dir: Path, *, cases_file: Path, model: str, repetitions: int, selected_cases: list[str] | None,
              reviewer: str, max_total_calls: int, declared_host: str | None, allow_dirty: bool,
              freeze_file: Path | None, authorize_live: bool, model_factory=live_model, metadata=None) -> dict:
    if not authorize_live: raise PermissionError("Pass --authorize-live to run live model calls")
    if reviewer not in {"case", "blind"}: raise ValueError("reviewer must be case or blind")
    if not 0 < max_total_calls <= 300: raise ValueError("max_total_calls must be in 1..300")
    output_dir = Path(output_dir)
    if output_dir.exists(): raise ValueError("output directory already exists; evidence is never overwritten or resumed")
    cases = load_cases(cases_file)
    names = list(selected_cases or cases["cases"])
    unknown = [n for n in names if n not in cases["cases"]]
    if unknown: raise ValueError(f"unknown cases: {unknown}")
    git = git_state()
    if git["dirty_tracked"] and not allow_dirty: raise RuntimeError("tracked working tree is dirty; commit before a live evaluation")
    freeze = check_freeze(freeze_file, sorted((ROOT / "examples/phase55/eval").glob("*-cases.json"))) if freeze_file else {"matched": None, "skipped": True}
    meta = metadata if metadata is not None else asyncio.run(ollama_model_metadata(model))
    output_dir.mkdir(parents=True)
    provenance = {"suite": "live_27b_suite", "protocol": protocol.VERSION, "case_file": str(cases_file), "case_file_digest": cases["digest"],
                  "set": cases["set"], "reviewer": reviewer if reviewer == "blind" else "case-reviewer", "reviewer_actor": REVIEWER,
                  "model": meta, "declared_physical_host": declared_host or "not declared",
                  "endpoint_note": "artifacts record OLLAMA_ENDPOINT; a tunnel to declared_physical_host is operator-declared, not verified",
                  "git": git, "allow_dirty": allow_dirty, "freeze": freeze, "repetitions": repetitions,
                  "max_total_calls": max_total_calls, "cap_rule": "run starts only if total + 2*max_calls <= max_total_calls",
                  "started": point()}
    (output_dir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    evaluations, total_calls = [], 0

    def write_summary():
        summary = {"model": model, "protocol": protocol.VERSION, "set": cases["set"], "reviewer": provenance["reviewer"],
                   "total_calls": total_calls, "max_total_calls": max_total_calls,
                   "aggregate": aggregate_goal_runs(evaluations), "runs": evaluations}
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    for rep in range(1, repetitions + 1):
        for name in names:
            case = cases["cases"][name]
            # Intake planning and execution budgets are separate tasks; bound both conservatively.
            if total_calls + 2 * case["max_calls"] > max_total_calls:
                provenance["stopped"] = {"reason": "call cap", "before": f"{name}-r{rep}", "total_calls": total_calls}
                (output_dir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
                write_summary(); write_manifest(output_dir)
                raise RuntimeError(f"call cap {max_total_calls} would be exceeded before {name} rep {rep}")
            run_id = f"{name}-r{rep}"
            path = output_dir / run_id
            config = build_config(cases, name, model)
            (output_dir / f"{run_id}-workspace.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
            decisions = []

            def ask(question: str) -> str:
                if "displayed digest" in question:
                    answer = json.loads((path / "environment-preview.json").read_text(encoding="utf-8"))["digest"]
                elif reviewer == "blind" or "clarification" in question.lower():
                    answer = blind_answer(question, case, "")
                else:
                    answer = case_reviewer(json.loads((path / "proposal-preview.json").read_text(encoding="utf-8")), case)
                decisions.append({"question": question, "answer": answer, "actor": REVIEWER, "reviewer": provenance["reviewer"]})
                (output_dir / f"{run_id}-decisions.json").write_text(json.dumps(decisions, indent=2), encoding="utf-8")
                return answer

            with (output_dir / f"{run_id}-console.log").open("w", encoding="utf-8") as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                try:
                    if case.get("mode") == "replan_stale":
                        result, decisions = _run_replan_stale(config, case["goal"], path, case, reviewer, model_factory)
                        (output_dir / f"{run_id}-decisions.json").write_text(json.dumps(decisions, indent=2), encoding="utf-8")
                    else:
                        result = run_goal_interactive(config, case["goal"], path, authorize_live=True, ask=ask, model_factory=model_factory)
                except Exception as exc:
                    result = {"status": "INVOCATION_FAILED", "error": type(exc).__name__, "reason": str(exc)[:256]}
                    traceback.print_exc()
            ev = _evaluate_run_dir(path, config, cases, name, rep, run_id)
            ev["invocation"] = {k: result.get(k) for k in ("status", "error", "reason") if k in result}
            total_calls += ev["inference_attempts"]
            evaluations.append(ev)
            write_summary()
            print(f"[{run_id}] outcome={ev['outcome']} accepted={case['accepted_outcomes']} passed={ev['passed']} "
                  f"calls={ev['inference_attempts']} (total={total_calls}) replay={ev['replay_match']}", flush=True)

    provenance["finished"] = point()
    (output_dir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    summary = write_summary()
    write_manifest(output_dir)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--cases", nargs="*", default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--reviewer", choices=["case", "blind"], default="blind")
    parser.add_argument("--max-total-calls", type=int, default=250)
    parser.add_argument("--declared-host", default=None, help="physical host behind a localhost tunnel (recorded, not verified)")
    parser.add_argument("--freeze-file", type=Path, default=DEFAULT_FREEZE)
    parser.add_argument("--no-freeze-check", action="store_true", help="development runs only; recorded in provenance")
    parser.add_argument("--allow-dirty", action="store_true", help="development runs only; recorded in provenance")
    parser.add_argument("--authorize-live", action="store_true")
    args = parser.parse_args(argv)
    summary = run_suite(args.output, cases_file=args.cases_file, model=args.model, repetitions=args.repetitions,
                        selected_cases=args.cases, reviewer=args.reviewer, max_total_calls=args.max_total_calls,
                        declared_host=args.declared_host, allow_dirty=args.allow_dirty,
                        freeze_file=None if args.no_freeze_check else args.freeze_file, authorize_live=args.authorize_live)
    print(json.dumps(summary["aggregate"], indent=2))
    return 0 if summary["aggregate"]["overall_pass_rate"]["value"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
