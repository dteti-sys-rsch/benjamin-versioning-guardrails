"""Finite synthetic Phase 4 plans; trusted updater fixtures are explicit actors."""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json

from atomicroot.sim.scheduler import Action
from atomicroot.authority.ticket import args_hash

ROOT = Path(__file__).resolve().parents[2]


def example(name): return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def scenario(name):
    fixture = example("phase36/trusted-fixture.json")
    spec = example("phase36/payments.json" if name == "mutation-contract" or name.startswith(("budget", "recovery", "ticket", "payload", "operation", "approval", "worker", "independent", "rollback")) else "phase36/literature.json")
    task = spec["task_id"]
    payment = task == "payments-a"
    if payment: spec["policies"][0]["constraint"]["right"]["value"] = 300
    first_agent, second_agent = ("payer-a", "payer-b") if payment else ("reader-a", "sender")
    if not payment:
        first_agent = spec["agents"][0]["id"]
        second_agent = spec["agents"][-1]["id"]
    actions = []
    def add(id, kind, data=None, *, actor="worker", after=(), arrival=0, priority=0):
        actions.append(asdict(Action(id, kind, actor, tuple(after), arrival, priority, data or {})))
    pay = {"task": task, "agent": first_agent, "operation": "op-first", "tool": "transfer_funds", "args": {"to": "account-a", "amount": 300}}
    send = {"task": task, "agent": second_agent, "operation": "op-send", "tool": "send_email", "args": {"to": "alice@corp.id", "body": "Synthetic output"}}
    read = {"task": task, "agent": first_agent, "operation": "op-read", "tool": "read_document", "args": {"resource": spec["resources"][0]["resource"], "digest": spec["resources"][0]["digest"]}} if not payment else None
    request = pay if payment else read
    preferred = []
    tasks, responses, effect_order = [spec], {}, {}
    hook_mutations = []
    if name == "fallback-contention":
        add("execute", "guarded", read)
        hook_mutations = [{"stage": "before_cas", "operation": "op-read", "key": f"contract3:{task}"}] * 3
    elif name in {"budget-double-allow", "exfil-double-allow", "ticket-replay", "ticket-forged", "payload-substitution", "operation-substitution"}:
        if not payment:
            fixture["resources"][0]["label"] = "SENSITIVE"
            first, second = read, send
        else:
            first, second = pay, {**pay, "agent": second_agent, "operation": "op-second", "args": {"to": "account-b", "amount": 300}}
        add("auth-first", "authorize", first)
        if name == "ticket-forged":
            add("forged", "commit", {"authorization": "auth-first", "agent": first_agent, "tamper_signature": True}, after=("auth-first",))
        elif name == "operation-substitution":
            add("auth-changed", "authorize", {**first, "args": {"to": "account-a", "amount": 1}}, after=("auth-first",))
        elif name == "payload-substitution":
            add("commit-changed", "commit", {"authorization": "auth-first", "agent": first_agent,
                "replace_args": {"operation_id": "op-first", "purpose": "payments", "payload": {"to": "account-b", "amount": 300}}}, after=("auth-first",))
        elif name == "ticket-replay":
            add("commit-first", "commit", {"authorization": "auth-first", "agent": first_agent}, after=("auth-first",))
            add("commit-again", "commit", {"authorization": "auth-first", "agent": first_agent, "connection": 1}, after=("commit-first",))
        else:
            add("auth-second", "authorize", second)
            add("commit-first", "commit", {"authorization": "auth-first", "agent": first_agent}, after=("auth-first", "auth-second"))
            add("commit-second", "commit", {"authorization": "auth-second", "agent": second_agent, "connection": 1}, after=("commit-first",))
            preferred = ["auth-first", "auth-second", "commit-first", "commit-second"]
    elif name == "rollback-intent":
        add("auth", "authorize", pay)
        add("inject", "rollback_enable", actor="fault", after=("auth",))
        add("commit-failed", "commit", {"authorization": "auth", "agent": first_agent}, after=("inject",))
        add("rolled-back", "observe", actor="framework", after=("commit-failed",))
        add("remove-fault", "rollback_disable", actor="fault", after=("rolled-back",))
        add("commit-retry", "commit", {"authorization": "auth", "agent": first_agent}, after=("remove-fault",))
    elif name == "independent-keys":
        separate = deepcopy(spec); separate["task_id"] = "independent-a"
        fixture["entitlements"].append({**deepcopy(fixture["entitlements"][1]), "task": "independent-a"})
        tasks.append(separate)
        add("auth-one", "authorize", pay)
        add("auth-two", "authorize", {**pay, "task": "independent-a"})
        add("commit-one", "commit", {"authorization": "auth-one", "agent": first_agent}, after=("auth-one", "auth-two"))
        add("commit-two", "commit", {"authorization": "auth-two", "agent": first_agent, "connection": 1}, after=("commit-one",))
    elif name in {"workflow-checkpoint", "workflow-review"}:
        # Use the actual concurrent A executor and durable LangGraph checkpoints.
        # Each read is a distinct dependency-ready node; the join waits for both.
        spec["acceptance"] = [{"kind": "read", "resource": r["resource"]} for r in spec["resources"]]
        responses[task] = {n["id"]: [] for n in spec["workflow"]["nodes"]}
        for index, node in enumerate(spec["workflow"]["nodes"][:2]):
            ref = spec["resources"][index]
            responses[task][node["id"]] = [{"kind": "action", "tool": "read_document", "args": {"resource": ref["resource"], "digest": ref["digest"]}}, {"kind": "done", "summary": "Read"}]
        spec["limits"]["max_in_flight"] = 2
        effect_order[task] = [n["id"] for n in spec["workflow"]["nodes"][:2]]
        responses[task][spec["workflow"]["nodes"][-1]["id"]] = [{"kind": "done", "summary": "Joined"}]
        if name == "workflow-review":
            fixture["resources"][0]["label"] = "UNKNOWN"; spec["unknown_release"] = "ESCALATE"
            spec["acceptance"].append({"kind": "receipt", "tool": "send_email", "destination": "alice@corp.id"})
            responses[task][spec["workflow"]["nodes"][-1]["id"]] = [{"kind": "action", "tool": "send_email", "args": send["args"]}, {"kind": "done", "summary": "Sent"}]
            effect_order[task] += [spec["workflow"]["nodes"][-1]["id"]] * 2
        add("start", "workflow", {"task": task, "command": "start"}, actor="framework")
        add("restart", "restart", actor="fault", after=("start",))
        if name == "workflow-review":
            add("approve-flow", "approve_workflow", {"task": task, "source": "start"}, actor="trusted_fixture", after=("restart",))
        add("recover", "workflow", {"task": task, "command": "resume" if name == "workflow-review" else "recover"}, actor="framework", after=(actions[-1]["id"],))
    elif name.startswith("mutation-"):
        target = name.removeprefix("mutation-")
        # A release reads exposure; resource mutations target an actual read ticket.
        request = pay if payment else read if target in {"label", "content", "resource"} else send
        add("auth", "authorize", request)
        if target == "contract":
            add("mutation", "task_revision", {"task": task, "patch": {"budget_limit": 400}}, actor="trusted_fixture", after=("auth",))
        elif target == "policyset":
            definition = {"policy_id": "new-rule", "version": 1, "scope": "task", "applies_to": ["send_email"],
                "when": {"op": "const", "value": True}, "constraint": {"op": "const", "value": True}, "on_violation": "DENY"}
            add("mutation", "task_revision", {"task": task, "patch": {"policies": [*spec["policies"], definition]}}, actor="trusted_fixture", after=("auth",))
        elif target in {"label", "content"}:
            add("mutation", target, {"resource": fixture["resources"][0]["resource"], "label": "SENSITIVE", "purposes": ["research"], "content": "Changed synthetic bytes"}, actor="trusted_fixture", after=("auth",))
        else:
            suffix, patch = {"contract": (f"contract3:{task}", {"budget_limit": 1}),
                "policyset": (f"policyset:{task}", None), "delegation": (None, {"scope": []}),
                "recipient": ("destination:alice@corp.id", {"purposes": []}),
                "resource": (f"contract3:{task}", {"allowed_resources": []}),
                "membership": (f"agents:{task}", None)}[target]
            if target == "delegation":
                # Principal IDs are resolved at runtime, recorded in the artifact.
                principal = "ag-" + args_hash({"task": task, "parent": "local-user", "agent": second_agent}).split(":")[1][:32]
                suffix = f"delegation:{task}:{principal}"
            data = {"key": suffix, "patch": patch} if patch is not None else {"key": suffix, "value": [] if target == "membership" else [{"policy_id": "new-rule", "version": 1}]}
            add("mutation", "mutate", data, actor="trusted_fixture", after=("auth",))
        add("commit", "commit", {"authorization": "auth", "agent": request["agent"], "connection": 1}, after=("mutation",))
    elif name.startswith("classification-"):
        candidate = name.removeprefix("classification-")
        resource = fixture["resources"][0]["resource"]
        if candidate == "false-public": fixture["resources"][0]["label"] = "SENSITIVE"
        add("enable-restriction", "mutate", {"key": f"contract3:{task}", "patch": {"classification_restrictions": True}}, actor="trusted_fixture")
        add("begin", "classify_begin", {"resource": resource}, actor="trusted_fixture", after=("enable-restriction",))
        add("result", "classify_result", {"proposal": "begin", "candidate": "PUBLIC" if candidate == "false-public" else "SENSITIVE",
            "outcome": "ERROR" if candidate == "failure" else "SUCCESS", "confidence": .1 if candidate == "abstention" else .99}, actor="trusted_fixture", after=("begin",))
        if candidate in {"stale-content", "stale-label"}:
            add("change", "content" if candidate == "stale-content" else "label", {"resource": resource, "content": "Changed content", "label": "UNKNOWN", "purposes": ["research"]}, actor="trusted_fixture", after=("result",))
        if candidate == "restriction":
            add("read", "guarded", read, after=("result",))
            add("release-auth", "authorize", send, after=("read",))
        add("accept", "classify_accept", {"proposal": "begin", "task": task}, actor="trusted_fixture", after=(actions[-1]["id"],))
        if candidate == "restriction":
            add("release-commit", "commit", {"authorization": "release-auth", "agent": second_agent}, after=("accept",))
    elif name.startswith("approval-"):
        # A registered operation policy requests consent for a synthetic payment.
        spec["policies"] = [{"policy_id": "review-payment", "version": 1, "scope": "task", "applies_to": ["transfer_funds"],
            "when": {"op": "const", "value": True}, "constraint": {"op": "const", "value": False}, "on_violation": "ESCALATE"}]
        add("review", "authorize", pay)
        if name == "approval-forged": add("forged", "forged_consent", pay, after=("review",))
        else:
            if name == "approval-before": add("change", "mutate", {"key": f"contract3:{task}", "patch": {"objective": "revised objective"}}, actor="trusted_fixture", after=("review",))
            add("approve", "approve", {"review": "review"}, actor="trusted_fixture", after=(actions[-1]["id"],))
            if name != "approval-before":
                add("auth", "authorize", {**pay, "grant": "approve"}, after=("approve",))
                if name == "approval-after": add("change", "mutate", {"key": f"contract3:{task}", "patch": {"objective": "changed after review"}}, actor="trusted_fixture", after=("auth",))
                add("commit", "commit", {"authorization": "auth", "agent": first_agent}, after=(actions[-1]["id"],))
                if name == "approval-replay": add("replay", "commit", {"authorization": "auth", "agent": first_agent, "connection": 1}, after=("commit",))
    elif name.startswith("recovery-"):
        add("auth", "authorize", pay)
        before = name == "recovery-before-intent"
        if not before: add("commit", "commit", {"authorization": "auth", "agent": first_agent}, after=("auth",))
        add("crash", "crash_before_intent" if before else "crash_after_intent", actor="fault", after=(actions[-1]["id"],))
        add("restart", "restart", actor="fault", after=("crash",))
        if before: add("commit", "commit", {"authorization": "auth", "agent": first_agent}, after=("restart",))
        if name == "recovery-after-intent":
            add("rerun", "authorize", pay, after=("restart",))
            add("dispatch", "dispatch", actor="framework", after=("rerun",))
        else:
            add("claim", "claim", actor="framework", after=(actions[-1]["id"],))
            add("other-claim", "claim", {"connection": 1}, actor="framework", after=("claim",))
            add("apply", "receiver", {"claim": "claim"}, actor="framework", after=("claim",))
            if name == "recovery-lease":
                add("clock", "advance_clock", {"seconds": 31}, actor="fault", after=("apply",))
                add("claim-new", "claim", {"connection": 1}, actor="framework", after=("clock",))
                add("old-ack", "ack", {"claim": "claim", "receipt": "apply"}, actor="framework", after=("claim-new",))
                add("new-ack", "ack", {"claim": "claim-new", "receipt": "apply"}, actor="framework", after=("old-ack",))
            else:
                add("lost", "lost_ack", {"claim": "claim"}, actor="fault", after=("apply",))
                add("dispatch", "dispatch", actor="framework", after=("lost",))
    elif name == "worker-admin":
        add("attack", "worker_admin", {**pay, "destination": fixture["destinations"][0]})
        add("direct", "mutate", {"key": "budget:" + task, "value": 0})
    else: raise ValueError("unknown Phase 4 scenario: " + name)
    return {"name": name, "seed": 4, "clock": "2026-10-25T00:00:00+00:00", "fixture": fixture, "tasks": [spec],
            "actions": actions, "preferred": preferred or [a["id"] for a in actions], "responses": responses, "effect_order": effect_order,
            "hook_mutations": hook_mutations, "model_records": {}} | {"tasks": tasks}


SCENARIOS = ("budget-double-allow", "exfil-double-allow", "ticket-replay", "ticket-forged", "payload-substitution", "operation-substitution",
    "mutation-contract", "mutation-policyset", "mutation-delegation", "mutation-recipient", "mutation-resource", "mutation-membership", "mutation-label", "mutation-content",
    "classification-false-public", "classification-failure", "classification-abstention", "classification-restriction", "classification-stale-content", "classification-stale-label",
    "approval-before", "approval-after", "approval-replay", "approval-forged", "worker-admin",
    "recovery-before-intent", "recovery-after-intent", "recovery-lost-ack", "recovery-lease", "rollback-intent", "independent-keys", "workflow-checkpoint", "workflow-review", "fallback-contention")
