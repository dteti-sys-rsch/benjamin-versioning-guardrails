"""Paired finite workload/configuration plans, not adaptive attack search."""
from copy import deepcopy
from dataclasses import asdict
from atomicroot.framework.labels import content_digest
from atomicroot.authority.ticket import freeze_json
from atomicroot.sim.scenarios import scenario as phase4
from atomicroot.sim.scheduler import Action


SCENARIOS = ("exfil", "budget", "recipient", "revocation", "stale_write", "stale_before_authorize", "once", "independent",
             "lost_ack", "rollback", "approval", "classification", "contention")


def write_fixture():
    purpose, task, resource = "research", "write-a", "file"
    rule = lambda tool, dest=None: {"tool": tool, "resource": resource if tool != "send_email" else None,
        "destination": dest, "purpose": purpose, "max_amount": 0}
    scope = [rule("read_document"), rule("update_document"), rule("send_email", "alice@corp.id")]
    fixture = {"resources": [{"resource": resource, "content": "Synthetic initial file", "label": "PUBLIC", "purposes": [purpose]}],
        "destinations": [{"destination": "alice@corp.id", "kind": "recipient", "purposes": [purpose], "models": [], "labels": [], "endpoint": None}],
        "entitlements": [{"task": task, "subject": "local-user", "rights": {"scope": scope, "budget_limit": 0, "max_agents": 2,
            "limits": {"max_steps": 64, "max_in_flight": 4, "max_calls": 12, "max_tokens": 200000, "max_output_tokens": 1600, "max_retries": 2, "timeout": 120}}}]}
    ref = {"resource": resource, "digest": content_digest("Synthetic initial file"), "version": 1}
    spec = {"schema_version": 1, "task_id": task, "objective": "Guarded simulated update after verified read", "purpose": purpose,
        "resources": [ref], "scope": scope, "budget_limit": 0, "agents": [{"id": "writer", "role": "Read and update", "scope": scope}],
        "policies": [], "workflow": {"nodes": [{"id": "read", "agent": "writer", "depends_on": []}, {"id": "write", "agent": "writer", "depends_on": ["read"]}]},
        "outputs": [], "acceptance": [{"kind": "receipt", "tool": "update_document", "destination": None}], "provider": None,
        "classifier": {"mode": "disabled"}, "limits": {"max_steps": 8, "max_in_flight": 2, "inference": {}}, "unknown_release": "DENY"}
    return fixture, spec


def manifest(name):
    if name not in SCENARIOS: raise ValueError("unknown Phase 5 scenario")
    source = {"exfil": "exfil-double-allow", "budget": "budget-double-allow", "recipient": "exfil-double-allow", "revocation": "mutation-delegation",
        "once": "ticket-replay", "independent": "independent-keys", "lost_ack": "recovery-lost-ack", "rollback": "rollback-intent",
        "approval": "approval-after", "classification": "classification-false-public", "contention": "fallback-contention"}.get(name)
    workload = phase4(source) if source else {"name": name, "seed": 5, "clock": "2026-10-27T00:00:00+00:00", "responses": {}, "effect_order": {}, "hook_mutations": [], "model_records": {}}
    workload["name"] = name
    actions = workload.get("actions", [])
    if name == "exfil": actions[1]["data"]["args"]["body"] = workload["fixture"]["resources"][0]["content"]
    def action(id, kind, data=None, actor="worker", after=()):
        return asdict(Action(id, kind, actor, tuple(after), 0, 0, data or {}))
    if name == "recipient":
        send = deepcopy(actions[1]["data"]); send["args"]["to"] = "mallory@outside.invalid"
        workload["fixture"]["resources"][0]["label"] = "PUBLIC"
        actions = [action("auth", "authorize", send), action("commit", "commit", {"authorization": "auth", "agent": send["agent"]}, after=("auth",)),
                   action("dispatch", "dispatch", actor="framework", after=("commit",))]
    if name in {"stale_write", "stale_before_authorize"}:
        fixture, spec = write_fixture(); workload.update(fixture=fixture, tasks=[spec])
        read = {"task": "write-a", "agent": "writer", "operation": "read-op", "tool": "read_document", "args": {"resource": "file", "digest": spec["resources"][0]["digest"]}}
        write = {**read, "operation": "write-op", "tool": "update_document", "args": {**read["args"], "content": "Synthetic proposed update"}, "read_receipt_from": "read"}
        read_step = action("read", "guarded", read)
        auth = action("auth", "authorize", write, after=("read",))
        mutation = action("mutation", "content", {"resource": "file", "content": "Changed by trusted owner"}, actor="trusted_fixture", after=("auth",))
        if name == "stale_before_authorize":
            mutation["depends_on"] = ["read"]; auth["depends_on"] = ["mutation"]
            actions = [read_step, mutation, auth]
        else: actions = [read_step, auth, mutation]
        actions += [action("commit", "commit", {"authorization": "auth", "agent": "writer"}, after=(actions[-1]["id"],)),
                    action("dispatch", "dispatch", actor="framework", after=("commit",)),
                    action("reauthorize-old-read", "authorize", write, after=("dispatch",))]
    if name == "classification":
        workload["fixture"]["resources"][0]["label"] = "UNKNOWN"
        task = workload["tasks"][0]; reader = task["agents"][0]["id"]; sender = task["agents"][-1]["id"]
        ref = task["resources"][0]
        actions += [action("read", "guarded", {"task": task["task_id"], "agent": reader, "operation": "read-truth", "tool": "read_document", "args": {"resource": ref["resource"], "digest": ref["digest"]}}, after=("accept",)),
            action("send", "guarded", {"task": task["task_id"], "agent": sender, "operation": "send-truth", "tool": "send_email", "args": {"to": "alice@corp.id", "body": workload["fixture"]["resources"][0]["content"]}}, after=("read",))]
    if name in {"exfil", "budget", "revocation", "independent", "once"}:
        actions.append(action("dispatch", "dispatch", actor="framework", after=(actions[-1]["id"],)))
        if name in {"budget", "independent", "exfil"}: actions.append(action("dispatch-again", "dispatch", actor="framework", after=("dispatch",)))
    workload["actions"] = actions
    workload["preferred"] = [a["id"] for a in actions]
    truth = {}
    for resource in workload["fixture"]["resources"]:
        truth[f"{resource['resource']}:1:{content_digest(resource['content'])}"] = "SENSITIVE" if name == "classification" else resource["label"]
    workload["ground_truth"] = truth
    workload["pairing"] = "same TaskSpec, logical operations, immutable payload/source bindings, arrivals/priorities/fault plan across six modes"
    return freeze_json(workload, max_bytes=4 * 1024 * 1024)
