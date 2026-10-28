"""Synthetic bootstrap rights and scripted proposals, never a runtime use-case switch."""
from copy import deepcopy

from atomicroot.framework.identity import Principal
from atomicroot.integration.goals import GoalService
from atomicroot.integration.providers import FakeModel
from atomicroot.evaluation.scenarios import write_fixture
from atomicroot.framework.labels import content_digest
from phase36_cli import init_fixture

GOAL = "Read the file and write a proposed update after a fresh read, with amount at most 175."


def initialize(runtime):
    fixture, business = write_fixture()
    limits = {"max_calls": 12, "max_tokens": 200000, "max_output_tokens": 4096, "max_retries": 0, "timeout": 30}
    provider = {"destination": "openai", "model": "offline-script-v1"}
    context = {"resource": "goal-context", "digest": content_digest("Initial planner context"), "version": 1, "binding": "host_context"}
    file_ref = deepcopy(business["resources"][0])
    rule = lambda tool, resource: {"tool": tool, "resource": resource, "destination": "openai" if tool == "model_inference" else None, "purpose": "research", "max_amount": 0}
    scope = [rule("model_inference", "goal-context"), rule("model_inference", "file"), rule("read_document", "file")]
    intake_spec = {**deepcopy(business), "task_id": "planner-intake", "objective": "Authorize goal planning before business activation",
        "resources": [context, file_ref], "scope": scope, "agents": [{"id": "planner", "role": "Propose plans without business authority", "scope": scope}],
        "workflow": {"nodes": [{"id": "plan", "agent": "planner", "depends_on": []}]}, "provider": provider,
        "acceptance": [{"kind": "read", "resource": "file"}], "limits": {"max_steps": 8, "max_in_flight": 1, "inference": limits}}
    fixture["resources"].append({"resource": "goal-context", "content": "Initial planner context", "label": "UNKNOWN", "purposes": ["research"]})
    fixture["destinations"].append({"destination": "openai", "kind": "provider", "purposes": ["research"], "models": ["offline-script-v1"],
        "labels": ["PUBLIC", "UNKNOWN"], "endpoint": "https://api.openai.com/v1"})
    caps = {"max_steps": 64, "max_in_flight": 4, **limits}
    fixture["entitlements"][0]["rights"]["limits"].update(caps)
    fixture["entitlements"].append({"task": "planner-intake", "subject": "local-user", "rights": {"scope": scope, "budget_limit": 0, "max_agents": 2, "limits": caps}})
    init_fixture(runtime, fixture)
    user = Principal("local-user", frozenset({"user"}), frozenset({"planner-intake", "write-a"}))
    approver = Principal("local-human", frozenset({"approver"}), user.tasks)
    admin = Principal("local-admin", frozenset({"admin"}))
    preview = runtime.tasks.propose(intake_spec, user)
    runtime.broker.decide(preview["review_id"], True, approver)
    runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
    config = {"id": "planning", "intake_task": "planner-intake", "agent": "planner", "context_resource": "goal-context",
        "provider": "openai", "model": "offline-script-v1", "purpose": "research", "subject": "local-user", "targets": ["write-a"],
        "visible_resources": ["file"], "visible_destinations": ["alice@corp.id"], "expires": runtime.store.now() + 3600,
        "max_repairs": 1, "max_replans": 2}
    GoalService(runtime).register_intake(config, admin)
    return user, approver, admin, business, config, fixture, intake_spec


def proposal(spec, goal=GOAL):
    data = deepcopy(spec)
    data["policies"] = [{"policy_id": "goal_amount_limit", "version": 1, "scope": "task", "applies_to": ["update_document"],
        "when": {"op": "const", "value": True}, "constraint": {"op": "le", "left": {"op": "amount"}, "right": {"op": "const", "value": 175}}, "on_violation": "DENY"}]
    return {"status": "PROPOSAL", "spec": data, "assumptions": ["Synthetic file and simulated write; factual quality unverified"],
        "unsupported": [], "questions": [], "origin": [{"requirement": goal, "paths": ["/resources", "/scope", "/workflow", "/agents", "/budget_limit", "/policies", "/acceptance"], "reason": "Explicit offline synthesis fixture, not live model validation"}]}


def model_for(spec, goal=GOAL): return FakeModel(lambda _: proposal(spec, goal))
