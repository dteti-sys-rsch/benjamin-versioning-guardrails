"""Bounded synthetic B smoke test. Real Ollama planning; business effects simulated."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from atomicroot.evaluation.scenarios import write_fixture
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration.goals import GoalService
from atomicroot.integration.config_workflow import ConfigWorkflow
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.progress import Progress
from atomicroot.integration.providers import DisabledClassifier, Limits, live_model, model_configuration
from atomicroot.integration.prompts import CONFIG_WORKER_VERSION
from atomicroot.observability import Stopwatch, point
from atomicroot.sim.model_tape import ModelTape
from phase36_cli import init_fixture
from phase37_cli import build_workflow

GOALS = {
    "read": "Read resource file once. Do not update documents, send messages, or make payments. Complete with a verified read receipt.",
    "summary": "Read resource file and publish a short summary as output result. Do not update documents, send messages, or make payments. Use only Ollama qwen3:8b for model inference, with budget zero.",
    "unsupported": "Read resource file, then send a real WhatsApp message to a recipient. WhatsApp delivery is mandatory; return UNSUPPORTED if no registered WhatsApp adapter exists.",
}
CAPS = dict(max_calls=8, max_tokens=200000, max_output_tokens=3072, max_retries=0, timeout=120)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def bootstrap(runtime, *, fixture=None, intake=None, config=None, source_text=None):
    if fixture is None:
        fixture, intake = write_fixture()
        if source_text is not None:
            fixture["resources"][0]["content"] = source_text
        rule = lambda tool, resource: dict(tool=tool, resource=resource,
            destination="ollama" if tool == "model_inference" else None, purpose="research", max_amount=0)
        scope = [rule("read_document", "file"), rule("model_inference", "file"), rule("model_inference", "worker-context")]
        fixture["resources"] += [dict(resource=name, content="Synthetic initial model context", label="UNKNOWN", purposes=["research"])
                                 for name in ("goal-context", "worker-context")]
        fixture["destinations"] = [dict(destination="ollama", kind="provider", purposes=["research"], models=["qwen3:8b"],
            labels=["PUBLIC", "UNKNOWN"], endpoint=model_configuration("ollama", "qwen3:8b")["endpoint"])]
        rights = dict(scope=scope, budget_limit=0, max_agents=2, limits=dict(max_steps=12, max_in_flight=2, **CAPS))
        fixture["entitlements"][0]["rights"] = rights
        planning_scope = [rule("model_inference", "goal-context")]
        fixture["entitlements"].append(dict(task="planner-intake", subject="local-user",
            rights={**deepcopy(rights), "scope": planning_scope}))
        init_fixture(runtime, fixture)
        ref = runtime.store.get_state("document:goal-context")
        intake.update(task_id="planner-intake", objective="Authorize bounded synthetic local planning", resources=[{
            "resource": "goal-context", "digest": ref["digest"], "version": ref["version"], "binding": "host_context"}],
            scope=planning_scope, agents=[dict(id="planner", role="Propose a plan without business authority", scope=planning_scope)],
            policies=[], workflow={"nodes": [dict(id="plan", agent="planner", depends_on=[])]}, outputs=[],
            acceptance=[dict(kind="output", output="planning-result")],
            provider=dict(destination="ollama", model="qwen3:8b"), limits=dict(max_steps=6, max_in_flight=1, inference=CAPS))
        # Intake activation needs a structurally supported criterion, never executed as a business workflow.
        intake["outputs"] = [dict(id="planning-result", kind="artifact")]
        config = dict(id="planning", intake_task="planner-intake", agent="planner", context_resource="goal-context",
            provider="ollama", model="qwen3:8b", purpose="research", subject="local-user", targets=["write-a"],
            visible_resources=["file", "worker-context"], visible_destinations=["ollama"],
            expires=runtime.store.now() + 3600, max_repairs=1, max_replans=0)
    else:
        init_fixture(runtime, fixture)
    user = Principal("local-user", frozenset({"user"}), frozenset({"write-a", "planner-intake"}))
    approver = Principal("local-human", frozenset({"approver"}), user.tasks)
    preview = runtime.tasks.propose(intake, user)
    runtime.broker.decide(preview["review_id"], True, approver)
    runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
    GoalService(runtime).register_intake(config, Principal("local-admin", frozenset({"admin"})))
    return user, approver, fixture, intake, config


def snapshot(runtime):
    with runtime.store.snapshot() as snap:
        tables = {r[0] for r in snap._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        attempts = [dict(zip(("call", "status", "usage", "error", "reserved_tokens"), row)) for row in snap._conn.execute(
            "SELECT call_id,status,usage,error,reserved_tokens FROM inference_attempts ORDER BY rowid")] if "inference_attempts" in tables else []
        outputs = [json.loads(r[0]) for r in snap._conn.execute("SELECT data FROM execution_outputs")] if "execution_outputs" in tables else []
    return dict(document=runtime.store.get_state("document:file"), label=runtime.store.get_state("label:file"),
        contract=runtime.store.get_state("contract3:write-a"), outbox=runtime.store.inspect_outbox(), attempts=attempts, outputs=outputs)


def run_case(output, name):
    directory = output / name
    directory.mkdir()
    timer = Stopwatch()
    result = dict(case=name, goal=GOALS[name], model="qwen3:8b", provider="ollama", business_effects="SIMULATED")
    runtime = FrameworkRuntime(directory / "ledger.sqlite")
    try:
        user, approver, fixture, intake, config = bootstrap(runtime)
        for filename, data in (("trusted-fixture", fixture), ("intake-spec", intake), ("intake-permission", config)):
            save(directory / (filename + ".json"), data)
        save(directory / "initial-state.json", snapshot(runtime))
        progress = Progress(directory / "progress.jsonl")
        service = GoalService(runtime, live_model("ollama", "qwen3:8b", Limits(**CAPS)), progress=progress)
        plan = service.plan("live-goal", GOALS[name], "planning", "write-a", user)
        result.update(planning_status=plan["status"], validation_errors=plan.get("validation_errors", []))
        save(directory / "preview.json", service.status("live-goal", user, private=True))
        if plan["status"] == "REVIEW_WAIT" and name != "unsupported":
            spec = plan["proposal"]["spec"]
            criteria = spec["acceptance"]
            read_required = any(c == dict(kind="read", resource="file") for c in criteria)
            output_required = any(c == dict(kind="output", output="result") for c in criteria)
            if not read_required or (name == "summary" and not output_required):
                result["review"] = "REJECTED_GOAL_CRITERIA_OMITTED"
                service.decide("live-goal", "reject", approver)
            elif name == "summary" and spec["provider"] != dict(destination="ollama", model="qwen3:8b"):
                result["review"] = "REJECTED_MISSING_LIVE_PROVIDER"
                service.decide("live-goal", "reject", approver)
            else:
                # Trusted synthetic reviewer. Parent rights exclude updates, send, payments and remote egress.
                result["review"] = "APPROVED_SYNTHETIC_FIXTURE"
                service.decide("live-goal", "approve", approver)
                service.activate("live-goal", approver)
                mode = "live" if spec["provider"] else "scripted"
                result["worker_mode"] = mode
                responses = {n["id"]: [dict(kind="action", tool="read_document", args={"resource": "file",
                    "digest": next(r["digest"] for r in spec["resources"] if r["resource"] == "file")})] for n in spec["workflow"]["nodes"]}
                def factory(task, caller, budget):
                    flow = build_workflow(runtime, directory / "executor.sqlite", task, caller, mode=mode,
                        responses=responses if mode == "scripted" else None, authorize_live=True, progress=progress)
                    if flow.bridge: flow.bridge.budget = budget
                    return flow
                execution = service.execute("live-goal", user, factory)
                save(directory / "execution.json", execution)
                result["execution_status"] = execution["status"]
                if execution["status"] == "SATISFIED":
                    before = snapshot(runtime)
                    recovered = service.execute("live-goal", user, factory, command="recover")
                    after = snapshot(runtime)
                    result["recover"] = dict(status=recovered["status"], no_new_outbox=before["outbox"] == after["outbox"],
                        no_new_model_call=before["attempts"] == after["attempts"])
                    assert all((recovered["status"] == "SATISFIED", result["recover"]["no_new_outbox"], result["recover"]["no_new_model_call"]))
        elif plan["status"] == "REVIEW_WAIT":
            service.decide("live-goal", "reject", approver)
            result["review"] = "REJECTED_UNSUPPORTED_GOAL_OMITTED"
        artifact = service.export("live-goal", user)
        save(directory / "goal-artifact.json", artifact)
        replay = FrameworkRuntime(directory / "replay.sqlite")
        try:
            replay_user, *_ = bootstrap(replay, fixture=fixture, intake=intake, config=config)
            reproduced = GoalService(replay).replay(artifact, replay_user)
            result["proposal_replay"] = dict(match=reproduced["match"], status=reproduced["result"]["status"], live_delegate=False)
        finally:
            replay.store.close()
    except Exception as exc:
        result["error"] = dict(type=type(exc).__name__, reason=str(exc)[:512])
    finally:
        state = snapshot(runtime)
        save(directory / "final-state.json", state)
        result["inference_attempts"] = len(state["attempts"])
        result["business_intents"] = len([r for r in state["outbox"] if r["task"] == "write-a" and json.loads(r["payload"])["tool"] != "model_inference"])
        result["observed_timing"] = timer.finish()
        save(directory / "result.json", result)
        runtime.store.close()
    print(json.dumps(result), flush=True)
    return result


def worker_control(output, *, multi=False):
    """Isolate execution with a host-authored A plan; never call this live synthesis."""
    name = "worker-multi" if multi else "worker-control"
    directory = output / name
    directory.mkdir()
    timer = Stopwatch()
    runtime = FrameworkRuntime(directory / "ledger.sqlite")
    result = dict(case=name, plan_origin="TRUSTED_AUTHORED_A_CONTROL", model="qwen3:8b", business_effects="SIMULATED")
    tape = ModelTape(provider="ollama", model="qwen3:8b", prompt_version=CONFIG_WORKER_VERSION,
        delegate=live_model("ollama", "qwen3:8b", Limits(**CAPS)))
    try:
        user, approver, *_ = bootstrap(runtime, source_text=(
            "Synthetic benchmark notes. Trial A processed 12 records in 6 seconds. "
            "Trial B processed 12 records in 4 seconds. These are invented test data, not measured AtomicRoot performance."))
        _, spec = write_fixture()
        with runtime.store.snapshot() as snap:
            rights = snap.read("entitlement:write-a:local-user")[1]
        refs = []
        for name in ("file", "worker-context"):
            doc = runtime.store.get_state("document:" + name)
            ref = dict(resource=name, digest=doc["digest"], version=doc["version"])
            if name == "worker-context": ref["binding"] = "host_context"
            refs.append(ref)
        spec.update(objective="Read file and publish output result containing two sentences summarizing source contents. Omit workflow status, hashes and metadata.", resources=refs, scope=rights["scope"],
            agents=[dict(id="reader", role="Read and summarize the delivered source text", scope=rights["scope"])],
            workflow={"nodes": [dict(id="read-and-summarize", agent="reader", depends_on=[])]},
            outputs=[dict(id="result", kind="summary")], acceptance=[dict(kind="read", resource="file"), dict(kind="output", output="result")],
            provider=dict(destination="ollama", model="qwen3:8b"), limits=dict(max_steps=8, max_in_flight=1, inference=CAPS))
        if multi:
            spec["workflow"]["nodes"] = [dict(id="read", agent="reader", depends_on=[]), dict(id="summarize", agent="reader", depends_on=["read"])]
        preview = runtime.tasks.propose(spec, user)
        save(directory / "trusted-spec.json", spec)
        save(directory / "preview.json", preview)
        save(directory / "initial-state.json", snapshot(runtime))
        runtime.broker.decide(preview["review_id"], True, approver)
        runtime.contracts.activate(preview["proposal_id"], preview["review_id"], approver)
        progress = Progress(directory / "progress.jsonl")
        bridge = ModelBridge(runtime, tape, DisabledClassifier(), llm_limits=Limits(**CAPS), budget="worker-control", progress=progress)
        workflow = ConfigWorkflow(runtime, directory / "executor.sqlite", task="write-a", caller=user, bridge=bridge)
        workflow.start("live-control")
        execution = workflow.status("live-control")
        save(directory / "execution.json", execution)
        result["execution_status"] = execution["status"]
        if execution["status"] == "SATISFIED":
            before = snapshot(runtime)
            workflow.recover("live-control")
            after = snapshot(runtime)
            result["recover"] = dict(status=workflow.status("live-control")["status"],
                no_new_outbox=before["outbox"] == after["outbox"], no_new_model_call=before["attempts"] == after["attempts"])
            assert all((result["recover"]["status"] == "SATISFIED", result["recover"]["no_new_outbox"], result["recover"]["no_new_model_call"]))
    except Exception as exc:
        result["error"] = dict(type=type(exc).__name__, reason=str(exc)[:512])
    finally:
        save(directory / "model-records.json", tape.records)
        state = snapshot(runtime)
        save(directory / "final-state.json", state)
        result["inference_attempts"] = len(state["attempts"])
        result["observed_timing"] = timer.finish()
        save(directory / "result.json", result)
        runtime.store.close()
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authorize-live", action="store_true")
    parser.add_argument("--fixture-approve", action="store_true")
    parser.add_argument("--case", action="append", choices=(*GOALS, "worker-control", "worker-multi"))
    args = parser.parse_args()
    if not args.authorize_live or not args.fixture_approve:
        parser.error("explicit --authorize-live and --fixture-approve required for this synthetic demo")
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).read_bytes()
    (args.output / "runner.py").write_bytes(source)
    timer = Stopwatch()
    runs = [worker_control(args.output, multi=name == "worker-multi") if name.startswith("worker-") else run_case(args.output, name) for name in (args.case or GOALS)]
    save(args.output / "summary.json", dict(schema_version=1, command=[sys.executable, *sys.argv], observed=point(),
        runner_sha256=hashlib.sha256(source).hexdigest(), caps=CAPS, runs=runs, observed_timing=timer.finish(),
        scope="finite Fase 5.5 live smoke; no Phase 6 benchmark"))
    return 0 if all(r.get("execution_status") == "SATISFIED" if r["case"] != "unsupported" else
        r.get("planning_status") == "UNSUPPORTED" and r["business_intents"] == 0 for r in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
