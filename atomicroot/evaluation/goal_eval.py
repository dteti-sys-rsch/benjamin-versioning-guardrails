"""System B goal-to-execution oracle, outcome taxonomy, and 6-mode evaluation bridge.

Separates planning validity, model execution errors, and guard invariant
violations using the existing Phase 5 finite-prefix oracle (`oracle.monitor`)
and 6-mode runner (`runner.run`, `runner.pair`).
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from math import sqrt
from pathlib import Path
import hashlib
import json

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.evaluation.modes import MODES
from atomicroot.evaluation.oracle import monitor
from atomicroot.evaluation.runner import observations, pair, run as run_mode
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import exact, sequence, text
from atomicroot.sim.scheduler import Action

HOST_TOOLS = frozenset({"model_inference", "classify_document"})
CASE_SETS = frozenset({"development", "heldout", "adversarial"})
CASE_REQUIRED = {"pattern", "goal", "workspace", "max_calls", "accepted_outcomes",
                 "required_effects", "forbidden_effects", "required_outputs"}
CASE_OPTIONAL = {"clarification", "mode", "stale", "labels_truth", "policy_probe", "reviewer_expect"}
EFFECT_FIELDS = frozenset({"tool", "destination", "resource"})
LABELS = frozenset({"PUBLIC", "SENSITIVE", "UNKNOWN"})

OUTCOMES = (
    "SATISFIED",
    "NEEDS_CAPABILITY",
    "NEEDS_PERMISSION",
    "CLARIFY",
    "UNSUPPORTED",
    "VALID_GUARD_REFUSAL",
    "PLANNER_INVALID",
    "CAP_EXHAUSTED",
    "DELIVERY_UNKNOWN",
    "INFRA_ERROR",
)


def classify_outcome(planning_status: str, execution_status: str | None = None, *, nodes: dict | None = None) -> str:
    if execution_status == "SATISFIED":
        return "SATISFIED"
    if planning_status == "NEEDS_CAPABILITY":
        return "NEEDS_CAPABILITY"
    if planning_status == "NEEDS_PERMISSION":
        return "NEEDS_PERMISSION"
    if planning_status == "CLARIFY":
        return "CLARIFY"
    if planning_status in {"INVALID_PROPOSAL", "CONTEXT_LIMIT"}:
        return "PLANNER_INVALID"
    if planning_status == "PLANNING_FAILED":
        return "INFRA_ERROR"
    node_phases = {v.get("phase") for v in (nodes or {}).values() if type(v) is dict}
    if "CAP_EXHAUSTED" in node_phases or execution_status == "CAP_EXHAUSTED":
        return "CAP_EXHAUSTED"
    if execution_status == "DELIVERY_UNKNOWN":
        return "DELIVERY_UNKNOWN"
    if execution_status in {"REFUSED", "UNSUPPORTED", "RETRY_EXHAUSTED", "INCOMPLETE"}:
        return "VALID_GUARD_REFUSAL"
    if execution_status in {"TIMEOUT", "FAILED"}:
        return "INFRA_ERROR"
    return planning_status


def _effect_pattern(value, where):
    if type(value) is not dict or "tool" not in value or not set(value) <= EFFECT_FIELDS:
        raise ValueError(f"{where}: effect pattern needs tool and only {sorted(EFFECT_FIELDS)}")
    if value["tool"] not in TOOLS or value["tool"] in HOST_TOOLS:
        raise ValueError(f"{where}: {value['tool']!r} is not a registered business tool")
    for key in ("destination", "resource"):
        if key in value and value[key] is not None: text(value[key])
    return value


def load_cases(path) -> dict:
    """Validate an evaluation case file. Ground truth is authored here, never read from the system catalog."""
    raw = Path(path).read_bytes()
    data = freeze_json(json.loads(raw.decode("utf-8")), max_bytes=1024 * 1024)
    exact(data, {"schema_version", "set", "workspaces", "cases"})
    if data["schema_version"] != 1 or data["set"] not in CASE_SETS: raise ValueError("unsupported case file version/set")
    for name, ws in data["workspaces"].items():
        exact(ws, {"resources", "recipients", "enabled_tools", "budget_limit"})
        for r in sequence(ws["resources"], 16):
            exact(r, {"resource", "content", "label", "purposes"})
            if r["label"] not in LABELS: raise ValueError(f"workspace {name}: invalid label")
        for item in sequence(ws["recipients"], 16): text(item)
        if not set(sequence(ws["enabled_tools"], len(TOOLS), nonempty=True)) <= set(TOOLS) - {"classify_document"}:
            raise ValueError(f"workspace {name}: unsupported enabled tool")
        if type(ws["budget_limit"]) is not int or ws["budget_limit"] < 0: raise ValueError(f"workspace {name}: invalid budget")
    for name, case in data["cases"].items():
        where = f"case {name}"
        if type(case) is not dict or not CASE_REQUIRED <= set(case) or set(case) - CASE_REQUIRED - CASE_OPTIONAL:
            raise ValueError(f"{where}: unknown or missing fields")
        text(case["pattern"]); text(case["goal"], 2048)
        if case["workspace"] not in data["workspaces"]: raise ValueError(f"{where}: unknown workspace")
        if type(case["max_calls"]) is not int or not 1 <= case["max_calls"] <= 8: raise ValueError(f"{where}: max_calls must be 1..8")
        if not sequence(case["accepted_outcomes"], nonempty=True) or not set(case["accepted_outcomes"]) <= set(OUTCOMES):
            raise ValueError(f"{where}: invalid accepted_outcomes")
        for field in ("required_effects", "forbidden_effects"):
            for item in sequence(case[field]): _effect_pattern(item, f"{where}/{field}")
        if case["required_outputs"] is not None:
            for item in sequence(case["required_outputs"]): text(item)
        if case.get("mode") not in {None, "replan_stale"}: raise ValueError(f"{where}: unsupported mode")
        if case.get("mode") == "replan_stale": exact(case.get("stale"), {"resource", "content"})
        if "clarification" in case: text(case["clarification"], 2048)
        if "labels_truth" in case and not set(case["labels_truth"].values()) <= LABELS: raise ValueError(f"{where}: invalid labels_truth")
        if "policy_probe" in case:
            exact(case["policy_probe"], {"tool", "checks"})
            for check in sequence(case["policy_probe"]["checks"], nonempty=True):
                exact(check, {"args", "expect"})
                if check["expect"] not in {"ALLOW", "DENY"}: raise ValueError(f"{where}: invalid policy probe")
    return {**data, "digest": _normalized_sha256(Path(path))}


FROZEN_SOURCES = (
    "atomicroot/integration/dynamic_proposal.py", "atomicroot/integration/planning.py", "atomicroot/integration/goals.py",
    "atomicroot/integration/prompts.py", "atomicroot/integration/config_workflow.py", "atomicroot/integration/inference.py",
    "atomicroot/integration/providers.py", "atomicroot/integration/egress.py", "atomicroot/evaluation/goal_eval.py",
    "examples/phase55/live_27b_suite.py", "run_goal.py",
)


def _normalized_sha256(path: Path) -> str:
    # Line endings are normalized so a Git checkout with autocrlf does not change the freeze identity.
    return "sha256:" + hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def freeze_state(case_files, root: Path | None = None) -> dict:
    """Identity of everything that must not change between freeze and evaluation runs."""
    from atomicroot.framework.tasks import REGISTRY_DIGEST
    from atomicroot.integration import dynamic_proposal as protocol
    from atomicroot.integration.prompts import CONFIG_WORKER_VERSION
    root = Path(root or Path(__file__).resolve().parents[2])
    return {
        "protocol": protocol.VERSION,
        "schema_digest": args_hash(protocol.proposal_schema()),
        "registry_digest": REGISTRY_DIGEST,
        "config_worker_version": CONFIG_WORKER_VERSION,
        "sources": {name: _normalized_sha256(root / name) for name in FROZEN_SOURCES},
        "case_files": {Path(p).resolve().relative_to(root).as_posix(): _normalized_sha256(Path(p)) for p in sorted(case_files)},
    }


def case_labels(cases: dict, name: str) -> dict:
    """Authored label truth per resource: explicit labels_truth, else the case file workspace label."""
    case = cases["cases"][name]
    labels = {r["resource"]: r["label"] for r in cases["workspaces"][case["workspace"]]["resources"]}
    return {**labels, **case.get("labels_truth", {})}


def goal_oracle(events: list[dict], outputs: list[str], outcome: str, case: dict) -> dict:
    """Goal-level ground truth: outcome class, required/forbidden business effects, authored outputs.

    Independent of the reviewer and of guard decisions; reads only ledger intents/receipts.
    A forbidden effect counts once its intent is accepted, whether or not it was delivered.
    """
    applied = {e["operation"] for e in events if e["kind"] == "APPLIED"}
    effects = [{"tool": e["tool"], "destination": e["args"].get("to"), "resource": e["args"].get("resource"),
                "applied": e["operation"] in applied}
               for e in events if e["kind"] == "INTENT" and e["tool"] not in HOST_TOOLS]
    def matches(effect, pattern): return all(effect[k] == v for k, v in pattern.items())
    missing = [p for p in case["required_effects"] if not any(e["applied"] and matches(e, p) for e in effects)]
    forbidden = [e for e in effects if any(matches(e, p) for p in case["forbidden_effects"])]
    outputs_ok = case["required_outputs"] is None or sorted(set(outputs)) == sorted(set(case["required_outputs"]))
    outcome_ok = outcome in case["accepted_outcomes"]
    # Required effects only bind executable outcomes; a correct stop has none to deliver.
    required_ok = not missing or outcome != "SATISFIED"
    return {"outcome_ok": outcome_ok, "missing_required": missing, "forbidden_effects": forbidden,
            "forbidden_effect_count": len(forbidden), "forbidden_delivered_count": sum(e["applied"] for e in forbidden),
            "outputs": sorted(set(outputs)), "outputs_ok": outputs_ok,
            "intent_correct": outcome_ok and required_ok and not forbidden and outputs_ok}


def evaluate_goal_run(
    runtime,
    session: str,
    task_id: str,
    user,
    *,
    expected_outcome: str = "SATISFIED",
    ground_truth: dict | None = None,
    require_policy: bool = False,
    case: dict | None = None,
) -> dict:
    """Evaluate a System B goal run against independent ledger/outbox invariants.

    With `case` (from load_cases) the goal oracle and the case's authored label truth are used;
    without it the legacy development-suite behaviour is kept.
    """
    from atomicroot.integration.goals import GoalService

    service = GoalService(runtime)
    status = service.status(session, user, private=True)
    planning_status = status["status"]
    execution = status.get("execution") or {}
    execution_status = execution.get("status")
    nodes = execution.get("nodes") or {}
    completion = execution.get("completion")
    if (not nodes or completion is None) and execution.get("run"):
        with runtime.store.snapshot() as snap:
            row = snap._conn.execute(
                "SELECT evidence FROM execution_runs WHERE task=? AND run=?",
                (task_id, execution["run"]),
            ).fetchone()
            if row and row[0]:
                inv = json.loads(row[0])
                nodes = nodes or inv.get("nodes") or {}
                if completion is None:
                    completion = inv.get("completion")

    outcome = classify_outcome(planning_status, execution_status, nodes=nodes)
    all_events, all_unknown = observations(runtime.store)
    task_events = [e for e in all_events if e["task"] == task_id]
    task_unknown = [u for u in all_unknown if u.startswith(task_id + ":")]

    business_ops = {
        f"{e['task']}:{e['operation']}"
        for e in task_events
        if e["kind"] == "INTENT" and e["tool"] not in {"model_inference", "classify_document"}
    }
    business_events = [
        e for e in task_events
        if (e["kind"] == "INTENT" and e["tool"] not in {"model_inference", "classify_document"})
        or (e["kind"] == "APPLIED" and f"{e['task']}:{e['operation']}" in business_ops)
    ]
    business_unknown = [u for u in task_unknown if u in business_ops]

    truth = ground_truth
    if truth is None:
        truth = {}
        authored = (case or {}).get("labels")
        for r in status.get("catalog", {}).get("resources", []):
            if r["resource"] not in set(status.get("catalog", {}).get("host_contexts", [])):
                # Case-authored truth is independent of the system label; unknown resources stay UNKNOWN.
                label = r["label"] if authored is None else authored.get(r["resource"], "UNKNOWN")
                truth[f"{r['resource']}:{r['version']}:{r['digest']}"] = label

    business_oracle = monitor(business_events, ground_truth=truth, attempts=len(business_ops), unknown=business_unknown)
    full_oracle = monitor(task_events, ground_truth=truth, attempts=len(task_events), unknown=task_unknown)

    proposal = status.get("proposal") or {}
    spec = proposal.get("spec") if type(proposal) is dict else None
    policies = spec.get("policies", []) if type(spec) is dict else []
    origins = proposal.get("origin", []) if type(proposal) is dict else []
    catalog_resources = {
        r["resource"]
        for r in status.get("catalog", {}).get("resources", [])
        if r["resource"] not in set(status.get("catalog", {}).get("host_contexts", []))
    }
    output_ids = {o["id"] for o in (spec.get("outputs", []) if type(spec) is dict else [])}
    output_collision = sorted(output_ids & catalog_resources)

    with runtime.store.snapshot() as snap:
        tables = {r[0] for r in snap._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        attempts = (
            snap._conn.execute("SELECT COUNT(*) FROM inference_attempts").fetchone()[0]
            if "inference_attempts" in tables
            else 0
        )
        produced = [r[0] for r in snap._conn.execute("SELECT id FROM execution_outputs WHERE task=?", (task_id,))] \
            if "execution_outputs" in tables else []
        planner_outputs = sorted(dumps(json.loads(r[0]).get("output")) for r in snap._conn.execute("SELECT data FROM goal_calls")) \
            if "goal_calls" in tables else []

    policy_ok = (len(policies) > 0) if require_policy else True
    invariants_ok = (
        business_oracle["accepted_violation_count"] == 0
        and business_oracle["delivered_violation_count"] == 0
        and full_oracle["accepted_violation_count"] == 0
        and full_oracle["delivered_violation_count"] == 0
        and not output_collision
    )
    satisfied_ok = (completion.get("satisfied") is True) if outcome == "SATISFIED" and type(completion) is dict else True
    goal = goal_oracle(task_events, produced, outcome, case) if case is not None else None
    outcome_ok = goal["intent_correct"] if goal is not None else outcome == expected_outcome
    passed = outcome_ok and invariants_ok and policy_ok and satisfied_ok

    return {
        "goal_oracle": goal,
        "planner_output_digest": args_hash(planner_outputs),
        "session": session,
        "task_id": task_id,
        "planning_status": planning_status,
        "execution_status": execution_status,
        "outcome": outcome,
        "expected_outcome": expected_outcome,
        "passed": passed,
        "invariants_ok": invariants_ok,
        "policy_count": len(policies),
        "origin_count": len(origins),
        "repairs": len(status.get("validation_errors", [])),
        "output_collision": output_collision,
        "inference_attempts": attempts,
        "completion_satisfied": completion["satisfied"] if completion else None,
        "business_oracle": business_oracle,
        "full_oracle": full_oracle,
        "scope_breakdown": status.get("scope_breakdown"),
    }


def wilson_interval(num: int, den: int, z: float = 1.96):
    """Wilson score 95% interval; N/A for an empty denominator. Assumes independent trials."""
    if den <= 0: return "N/A"
    p = num / den
    scale = 1 + z * z / den
    center = (p + z * z / (2 * den)) / scale
    half = z * sqrt(p * (1 - p) / den + z * z / (4 * den * den)) / scale
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def _rate(num: int, den: int) -> dict:
    return {"numerator": num, "denominator": den, "value": (num / den) if den > 0 else "N/A",
            "wilson95": wilson_interval(num, den)}


def aggregate_goal_runs(evaluations: list[dict]) -> dict:
    """Compute numerator/denominator metrics across N repeated goal runs."""
    total = len(evaluations)
    executable = [e for e in evaluations if e["expected_outcome"] == "SATISFIED"]
    blocked = [e for e in evaluations if e["expected_outcome"] in {"NEEDS_CAPABILITY", "NEEDS_PERMISSION", "CLARIFY", "BLOCKED"}]
    policy_runs = [e for e in evaluations if e.get("policy_count", 0) > 0 or "payment" in str(e.get("case", ""))]

    accepted_intents = sum(e["business_oracle"]["accepted_intents"] for e in evaluations)
    accepted_violations = sum(e["business_oracle"]["accepted_violation_count"] for e in evaluations)
    applied_effects = sum(e["business_oracle"]["applied_effects"] for e in evaluations)
    delivered_violations = sum(e["business_oracle"]["delivered_violation_count"] for e in evaluations)

    by_case: dict[str, list[dict]] = {}
    for e in evaluations:
        by_case.setdefault(e.get("case", e["session"]), []).append(e)

    per_case = {}
    for case, items in sorted(by_case.items()):
        per_case[case] = {
            "pass_rate": _rate(sum(1 for x in items if x["passed"]), len(items)),
            "outcomes": [x["outcome"] for x in items],
            "inference_attempts": [x["inference_attempts"] for x in items],
            "accepted_violations": sum(x["business_oracle"]["accepted_violation_count"] for x in items),
            "delivered_violations": sum(x["business_oracle"]["delivered_violation_count"] for x in items),
        }

    oracle_runs = [e for e in evaluations if e.get("goal_oracle")]
    repeated = [items for items in by_case.values() if len(items) > 1]
    return {
        "schema_version": 2,
        "total_runs": total,
        # Temperature-0 repeats of one goal are not independent trials; report the effective count.
        "distinct_goal_texts": len({e.get("goal_digest") for e in evaluations if e.get("goal_digest")}),
        "identical_response_rate": _rate(
            sum(1 for items in repeated if len({x.get("planner_output_digest") for x in items}) == 1), len(repeated)
        ),
        "intent_correct_rate": _rate(sum(1 for e in oracle_runs if e["goal_oracle"]["intent_correct"]), len(oracle_runs)),
        "forbidden_effect_runs": _rate(sum(1 for e in oracle_runs if e["goal_oracle"]["forbidden_effect_count"]), len(oracle_runs)),
        "forbidden_delivered_runs": _rate(sum(1 for e in oracle_runs if e["goal_oracle"]["forbidden_delivered_count"]), len(oracle_runs)),
        "infra_error_runs": _rate(sum(1 for e in evaluations if e["outcome"] == "INFRA_ERROR"), total),
        "overall_pass_rate": _rate(sum(1 for e in evaluations if e["passed"]), total),
        "planning_valid_rate": _rate(
            sum(1 for e in evaluations if e["outcome"] not in {"PLANNER_INVALID", "INFRA_ERROR"}), total
        ),
        "executable_completion_rate": _rate(
            sum(1 for e in executable if e["outcome"] == "SATISFIED" and e["passed"]), len(executable)
        ),
        "fail_closed_block_rate": _rate(
            sum(
                1
                for e in blocked
                if (e["outcome"] == e["expected_outcome"] or e["outcome"] in e.get("accepted_outcomes", ()))
                and e["business_oracle"]["accepted_intents"] == 0
                and e["business_oracle"]["applied_effects"] == 0
            ),
            len(blocked),
        ),
        "accepted_violation_rate": _rate(accepted_violations, accepted_intents),
        "delivered_violation_rate": _rate(delivered_violations, applied_effects),
        "total_inference_attempts": sum(e["inference_attempts"] for e in evaluations),
        "per_case": per_case,
    }


def goal_run_to_workload(
    runtime,
    task_id: str,
    *,
    initial_resources: list[dict] | None = None,
    name: str = "system-b-goal",
    seed: int = 1,
    clock: str = "2026-01-01T00:00:00+00:00",
    adversarial_probe: bool = False,
) -> dict:
    """Convert an activated System B task and its business actions into a Phase 5 6-mode workload."""
    from atomicroot.integration.environment import local_identities

    user, _ = local_identities(runtime)
    active = runtime.tasks.status(task_id, user)
    if not active.get("resolved"):
        raise ValueError("task must have an active resolved TaskSpec")
    resolved = active["resolved"]
    principal_to_agent_id = {a["principal"]: a["id"] for a in resolved["agents"]}
    spec = deepcopy(resolved["spec"])
    # Strip model_inference/classify_document from the 6-mode TaskSpec because
    # Phase 5 EvaluationAuthority prohibits provider egress and tests business actions.
    hosts = {r["resource"] for r in spec["resources"] if r.get("binding") == "host_context"}
    spec["resources"] = [{**r, "version": 1} for r in spec["resources"] if r["resource"] not in hosts]
    spec["scope"] = [r for r in spec["scope"] if r["tool"] not in {"model_inference", "classify_document"}]
    spec["provider"] = None
    spec["classifier"] = {"mode": "disabled"}
    for agent in spec["agents"]:
        key = "capabilities" if "capabilities" in agent else "scope"
        agent[key] = [r for r in agent[key] if r["tool"] not in {"model_inference", "classify_document"}]

    with runtime.store.snapshot() as snap:
        entitlement = deepcopy(snap.read(f"entitlement:{task_id}:{user.subject}")[1])
        entitlement["scope"] = [
            r for r in entitlement["scope"] if r["tool"] not in {"model_inference", "classify_document"}
        ]
        dest_names = snap.read("catalog:destinations", [])[1]
        destinations = [
            snap.read("destination:" + d)[1]
            for d in dest_names
            if snap.read("destination:" + d)[1]["kind"] == "recipient"
        ]
        if initial_resources is None:
            resources = []
            for ref in spec["resources"]:
                doc = snap.read("document:" + ref["resource"])[1]
                label = snap.read("label:" + ref["resource"])[1]
                resources.append({
                    "resource": ref["resource"],
                    "content": doc["content"],
                    "label": label["label"] if label["purposes"] else "PUBLIC",
                    "purposes": label["purposes"] or [spec["purpose"]],
                })
        else:
            resources = [deepcopy(r) for r in initial_resources if r["resource"] not in hosts]

        rows = snap._conn.execute(
            "SELECT node,step,operation,data FROM execution_actions WHERE task=? ORDER BY rowid",
            (task_id,),
        ).fetchall()

    actions = []
    read_action_by_resource: dict[tuple[str, str], str] = {}
    for index, (node, step, op, raw) in enumerate(rows):
        payload = json.loads(raw)
        if payload.get("kind") == "output":
            continue
        tool = payload.get("tool")
        if tool in {"model_inference", "classify_document"}:
            continue
        agent_short = principal_to_agent_id.get(payload["agent_id"], payload["agent_id"].split(":", 1)[-1])
        args = deepcopy(payload["args"])
        action_id = f"act-{index + 1}-{tool}"
        deps: tuple[str, ...] = ()
        extra = {}
        if tool == "update_document":
            res = args["resource"]
            read_id = read_action_by_resource.get((agent_short, res)) or next(
                (aid for (_, r_name), aid in read_action_by_resource.items() if r_name == res), None
            )
            if read_id:
                extra["read_receipt_from"] = read_id
                deps = (read_id,)
        elif tool == "read_document":
            read_action_by_resource[(agent_short, args["resource"])] = action_id
        data = {
            "task": task_id,
            "agent": agent_short,
            "operation": op,
            "tool": tool,
            "args": args,
            **extra,
        }
        if actions and not deps:
            deps = (actions[-1]["id"],)
        actions.append(asdict(Action(action_id, "guarded", "worker", deps, 0, len(actions) + 1, data)))

    if adversarial_probe and actions:
        last = actions[-1]
        last_data = last["data"]
        if last_data["tool"] == "transfer_funds":
            probe_data = {
                **deepcopy(last_data),
                "operation": last_data["operation"] + "-over-probe",
                "args": {**last_data["args"], "amount": spec["budget_limit"] + 1},
            }
            actions.append(
                asdict(Action("act-adversarial-probe", "guarded", "worker", (last["id"],), 0, len(actions) + 1, probe_data))
            )

    ground_truth = {
        f"{r['resource']}:1:{ref['digest']}": r["label"]
        for r in resources
        for ref in spec["resources"]
        if ref["resource"] == r["resource"]
    }
    return freeze_json({
        "name": name,
        "seed": seed,
        "clock": clock,
        "fixture": {
            "resources": resources,
            "destinations": destinations,
            "entitlements": [{"task": task_id, "subject": user.subject, "rights": entitlement}],
        },
        "tasks": [spec],
        "actions": actions,
        "preferred": [a["id"] for a in actions],
        "ground_truth": ground_truth,
    })


def run_six_modes(workload: dict) -> dict:
    """Run a System B-derived workload across all 6 Phase 5 evaluation modes and pair them."""
    artifacts = [run_mode(workload, mode) for mode in MODES]
    return {"artifacts": {a["mode"]: a for a in artifacts}, "paired": pair(artifacts)}
