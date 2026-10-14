"""Run executor A after Phase 3.6 preview/approval/activation. No author/planner call."""
import argparse
import json
from pathlib import Path

from nacl.signing import SigningKey
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.progress import Progress
from atomicroot.integration.providers import FakeModel, ReplayModel, DisabledClassifier, FakeClassifier, JevClassifier, Limits, live_model
from atomicroot.authority.ticket import args_hash
from phase36_cli import load, local_identities


def build_workflow(runtime, checkpoint_path, task, caller, *, mode="scripted", responses=None, replay=None,
                   authorize_live=False, trusted_router=False, classifier_mode="disabled", progress=None):
    active = runtime.tasks.status(task, caller)
    if active["status"] != "ACTIVE": raise ValueError("activate the reviewed task first")
    spec = active["resolved"]["spec"]
    if mode == "scripted":
        if responses is None: raise ValueError("explicit response fixture required")
        return ConfigWorkflow(runtime, checkpoint_path, task=task, caller=caller, worker=ScriptedWorker(responses))
    setting = spec["provider"]
    if not setting: raise ValueError("model inference is not in approved configuration")
    limits = Limits(**spec["limits"]["inference"])
    if mode == "fake":
        if setting["model"] != "offline-script-v1": raise ValueError("fake driver requires offline-script-v1 in approved config")
        fixture = ScriptedWorker(responses)
        def respond(messages):
            data = json.loads(messages[-1]["content"])
            return fixture({"node": data["node"], "step": data["step"]})
        model = FakeModel(respond, provider=setting["destination"])
        model.execution_binding = fixture.binding
    elif mode == "replay":
        if replay is None: raise ValueError("exact replay records required")
        model = ReplayModel(replay, provider=setting["destination"])
        model.model = setting["model"]
        model.execution_binding = args_hash(replay)
    elif mode == "live":
        if not authorize_live: raise PermissionError("live provider usage must be explicitly authorized")
        model = live_model(setting["destination"], setting["model"], limits, trusted_router=trusted_router)
    else: raise ValueError("unknown worker mode")
    configured = spec["classifier"]
    if configured["mode"] == "disabled":
        if classifier_mode != "disabled": raise ValueError("classifier not in approved config")
        classifier = DisabledClassifier()
    elif classifier_mode == "fake":
        classifier = FakeClassifier()
        if configured["model"] != classifier.model or configured["destination"] != classifier.provider:
            raise ValueError("fake classifier must match approved offline fixture ID")
        classifier.execution_binding = args_hash(classifier.response)
    elif classifier_mode == "jev":
        if not authorize_live: raise PermissionError("live classifier usage must be explicitly authorized")
        classifier = JevClassifier(configured["model"], limits)
    else: raise ValueError("choose the configured classifier driver explicitly")
    bridge = ModelBridge(runtime, model, classifier, llm_limits=limits, jev_limits=limits, progress=progress)
    return ConfigWorkflow(runtime, checkpoint_path, task=task, caller=caller, bridge=bridge)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=".runs/phase36")
    parser.add_argument("--task", required=True)
    parser.add_argument("--run", default="demo")
    parser.add_argument("--worker-mode", choices=("scripted", "fake", "replay", "live"), default="scripted")
    parser.add_argument("--responses")
    parser.add_argument("--replay")
    parser.add_argument("--classifier-mode", choices=("disabled", "fake", "jev"), default="disabled")
    parser.add_argument("--authorize-live", action="store_true")
    parser.add_argument("--trust-router-route", action="store_true")
    parser.add_argument("--quiet-progress", action="store_true")
    parser.add_argument("command", choices=("start", "resume", "recover", "status"))
    args = parser.parse_args()
    directory = Path(args.directory)
    if not (directory / "signing.key").exists(): parser.error("initialize and activate using phase36_cli first")
    runtime = FrameworkRuntime(str(directory / "ledger.sqlite"), signing_key=SigningKey((directory / "signing.key").read_bytes()))
    workflow = None
    try:
        user, _ = local_identities(runtime)
        # Status is a read of stored run metadata, independent of invocation driver.
        if args.command == "status":
            runtime.tasks.status(args.task, user)
            with runtime.store.snapshot() as snap:
                if not snap._conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_runs'").fetchone():
                    raise ValueError("unknown run")
                row = runtime.store.row(snap._conn, "SELECT binding,status,evidence FROM execution_runs WHERE task=? AND run=?", (args.task, args.run))
            if not row: raise ValueError("unknown run")
            evidence = row.pop("evidence")
            row["completion"] = json.loads(evidence) if evidence else None
            print(json.dumps(row, indent=2)); return 0
        workflow = build_workflow(runtime, directory / "executor.sqlite", args.task, user, mode=args.worker_mode,
            responses=load(args.responses) if args.responses else None, replay=load(args.replay) if args.replay else None,
            authorize_live=args.authorize_live, trusted_router=args.trust_router_route, classifier_mode=args.classifier_mode,
            progress=Progress(directory / "progress.jsonl", quiet=args.quiet_progress))
        getattr(workflow, args.command)(args.run)
        report = workflow.status(args.run)
        print(json.dumps(report, indent=2))
        return 0 if report["status"] in {"SATISFIED", "REVIEW_WAIT", "DELIVERY_UNKNOWN"} else 1
    except Exception as exc:
        print(json.dumps({"status": "INVOCATION_REJECTED", "error": type(exc).__name__})); return 1
    finally:
        if workflow: workflow.close()
        runtime.store.close()


if __name__ == "__main__": raise SystemExit(main())
