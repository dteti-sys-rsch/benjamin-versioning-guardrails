"""Trusted offline replay host for configuration A and protected protocol actions."""
from dataclasses import asdict
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
from threading import Barrier, Condition
import re
import shutil
import json
import platform

from nacl.signing import SigningKey
from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.contention import FallbackConfig
from atomicroot.framework.identity import Principal
from atomicroot.framework.tasks import REGISTRY_DIGEST
from atomicroot.integration.prompts import CONFIG_WORKER_VERSION
from atomicroot.sim.scheduler import SCHEMA_VERSION, TestInputs, HookLog, ReadyScheduler, semantic, validate_artifact


def environment():
    return {"python": platform.python_version(), "dependencies": {p: version(p) for p in
            ("z3-solver", "PyNaCl", "langgraph", "langgraph-checkpoint-sqlite")},
            "registry_digest": REGISTRY_DIGEST, "policy_encoding": "facts-and-not-constraints-v1",
            "prompt_version": CONFIG_WORKER_VERSION, "replay_host_version": 1}


def ledger(store):
    with store.snapshot() as snap:
        return {"state": [{"key": k, "version": v, "value": json.loads(raw)} for k, v, raw in snap._conn.execute(
                    "SELECT key,version,value FROM conflict_keys ORDER BY key")],
                "events": [dict(zip(("task", "agent", "tool", "payload_hash", "ticket_id", "nonce", "write_set", "time", "args"),
                    [task, agent, tool, digest, ticket, nonce, json.loads(writes), timestamp, json.loads(args)]))
                    for task, agent, tool, digest, ticket, nonce, writes, timestamp, args in snap._conn.execute(
                    "SELECT task_id,agent_id,tool,args_hash,ticket_id,nonce,write_set,timestamp,args FROM trace_events ORDER BY seq")],
                "outbox": [{**row, "payload": json.loads(row["payload"]), "receipt": json.loads(row["receipt"]) if row["receipt"] else None}
                           for row in store.inspect_outbox()],
                "authorizations": [{"ticket_id": ticket, "data": json.loads(data)} for ticket, data in snap._conn.execute(
                    "SELECT ticket,data FROM authorizations ORDER BY ticket")],
                "reviews": [{"id": review, "kind": kind, "task": task, "status": status, "expires": expires,
                             "data": json.loads(data), "approver": approver}
                            for review, kind, task, status, expires, data, approver in snap._conn.execute(
                    "SELECT id,kind,task,status,expires,data,approver FROM reviews ORDER BY id")],
                "receiver": [{"key": k, "value": json.loads(v)} for k, v in snap._conn.execute("SELECT key,value FROM receiver_state ORDER BY key")]}


class ReplayHost:
    def __init__(self, directory, workload, *, mode="optimistic"):
        if mode not in {"optimistic", "fallback"}: raise ValueError("unsupported Phase 4 guard configuration")
        self.workload = freeze_json(workload, max_bytes=4 * 1024 * 1024)
        self.path = Path(directory) / "ledger.sqlite"
        self.inputs = TestInputs(workload["seed"], workload["clock"])
        self.key = SigningKey.generate()  # never exported; replay issues new tickets
        self.mode, self.flows, self.hook_mutations = mode, {}, []
        self.hooks = ReplayHooks(self)
        self.effect_controls = {}
        self.runtime = self.connect()
        self.connections = [self.runtime]
        from phase36_cli import init_fixture
        init_fixture(self.runtime, workload["fixture"])
        self.tasks = {s["task_id"]: s for s in workload["tasks"]}
        scope = frozenset(self.tasks)
        self.user = Principal("local-user", frozenset({"user"}), scope)
        self.approver = Principal("local-human", frozenset({"approver"}), scope)
        self.owner = Principal("local-owner", frozenset({"owner"}), scope, resources=frozenset(
            r["resource"] for r in workload["fixture"]["resources"]))
        self.classifier = Principal("test-classifier", frozenset({"classifier"}), resources=self.owner.resources)
        for spec in self.tasks.values():
            preview = self.runtime.tasks.propose(spec, self.user)
            self.runtime.broker.decide(preview["review_id"], True, self.approver)
            self.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], self.approver)
        self.initial = {"ledger": ledger(self.runtime.store), "resolved": [self.runtime.tasks.status(t, self.user) for t in self.tasks]}
        self.hooks.steps.clear()

    def connect(self):
        return FrameworkRuntime(str(self.path), signing_key=self.key, clock=self.inputs.clock, id_factory=self.inputs.new_id,
                                harness=self.hooks, fallback=FallbackConfig() if self.mode == "fallback" else None)

    def runtime_for(self, action):
        index = action.data.get("connection", 0)
        if type(index) is not int or not 0 <= index <= 3: raise ValueError("connection outside fixture bound")
        while len(self.connections) <= index: self.connections.append(self.connect())
        return self.connections[index]

    def request(self, data):
        principal = self.runtime.tasks.principal(data["task"], data["agent"], self.user)
        return {"task_id": data["task"], "agent_id": principal.subject, "operation_id": data["operation"],
                "tool": data["tool"], "purpose": self.tasks[data["task"]]["purpose"], "args": data["args"]}, principal

    @staticmethod
    def ready(action, results):
        source = action.data.get("authorization")
        if source is not None and (source not in results or results[source].get("decision") != "ALLOW"): return False
        for field, required in (("claim", "task"), ("proposal", "proposal_id"), ("review", "review_id"), ("grant", "review_id")):
            reference = action.data.get(field)
            if reference is not None and (reference not in results or required not in results[reference]): return False
        receipt = action.data.get("receipt")
        if receipt is not None and (receipt not in results or "outcome" not in results[receipt]): return False
        if action.kind == "approve_workflow":
            previous = results.get(action.data["source"], {})
            return any(node.get("review") for node in previous.get("nodes", {}).values())
        return True

    def execute(self, action, results):
        data, kind = action.data, action.kind
        allowed = {"worker": {"authorize", "commit", "guarded", "forged_consent", "worker_admin"},
                   "trusted_fixture": {"mutate", "task_revision", "label", "content", "classify_begin", "classify_result", "classify_accept", "approve", "approve_workflow"},
                   "fault": {"advance_clock", "restart", "lost_ack", "crash_before_intent", "crash_after_intent", "rollback_enable", "rollback_disable"},
                   "framework": {"claim", "receiver", "ack", "dispatch", "workflow", "observe"}}
        if kind not in allowed[action.actor]: return {"status": "CAPABILITY_REJECTED", "actor": action.actor, "kind": kind}
        runtime = self.runtime_for(action)
        try:
            if kind in {"authorize", "guarded", "forged_consent", "worker_admin"}:
                request, principal = self.request(data)
                if kind == "worker_admin":
                    runtime.catalog.set_destination(data["destination"], principal)
                    raise AssertionError("worker admin must be rejected")
                if kind == "guarded":
                    from atomicroot.integration.guarded import GuardedTools
                    return GuardedTools(runtime).execute(request, principal).json()
                grant = results[data["grant"]]["review_id"] if "grant" in data else "user approved" if kind == "forged_consent" else None
                return runtime.authority.authorize(request, principal, grant_id=grant, action_id=action.id)
            if kind == "commit":
                auth = results[data["authorization"]]
                ticket, args = freeze_json(auth["ticket"]), freeze_json(auth["commit_args"])
                if "replace_args" in data: args = data["replace_args"]
                if data.get("tamper_signature"): ticket["signature"] = "ed25519:" + "00" * 64
                principal = self.runtime.tasks.principal(ticket["task_id"], data["agent"], self.user)
                return runtime.gateway.commit(ticket, args, principal, action_id=action.id)
            if kind == "mutate":
                # Only the trusted fixture has this authority. No arbitrary SQL,
                # signing, approver or direct ledger capability belongs to attacker.
                key = data["key"]
                if key.split(":")[0] not in {"contract3", "policyset", "policydef", "delegation", "agents", "entitlement", "destination", "catalog", "taskresolved"}:
                    raise ValueError("unregistered trusted mutation fixture")
                with runtime.store.transaction() as conn:
                    current = runtime.store.value(conn, key)[1]
                    value = {**current, **data["patch"]} if "patch" in data else data["value"]
                    runtime.store.put(conn, key, value)
                    runtime.store.audit(conn, "TRUSTED_UPDATER_FIXTURE", "test-owner", {"key": key, "value": value})
                return {"status": "UPDATED", "key": key, "version": runtime.store.get_version(key)}
            if kind == "task_revision":
                spec = {**self.tasks[data["task"]], **data["patch"]}
                preview = runtime.tasks.propose(spec, self.user)
                runtime.broker.decide(preview["review_id"], True, self.approver)
                return runtime.contracts.activate(preview["proposal_id"], preview["review_id"], self.approver)
            if kind == "label":
                doc = runtime.store.get_state("document:" + data["resource"])
                return runtime.labels.set_label(data["resource"], doc["digest"], doc["version"], data["label"], data["purposes"], self.owner)
            if kind == "content": return runtime.storage.ingest(data["resource"], data["content"], self.owner)
            if kind == "classify_begin":
                doc = runtime.store.get_state("document:" + data["resource"])
                return runtime.classification.begin(doc["resource"], doc["digest"], doc["version"], "offline-classifier", "1", "criteria-1", args_hash({"synthetic": True}), self.classifier)
            if kind == "classify_result":
                proposal = results[data["proposal"]]
                binding = {k: proposal[k] for k in ("resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash")}
                return runtime.classification.record(proposal["proposal_id"], {**binding, "outcome": data.get("outcome", "SUCCESS"),
                    "candidate_label": data.get("candidate", "SENSITIVE"), "confidence": data.get("confidence", .99),
                    "probabilities": None, "covered_bytes": proposal["input_bytes"], "truncated": False, "reason": "synthetic fixture"}, self.classifier)
            if kind == "classify_accept":
                return runtime.labels.accept_classification(results[data["proposal"]]["proposal_id"], data["task"], self.tasks[data["task"]]["purpose"], self.owner)
            if kind == "approve": return runtime.broker.decide(results[data["review"]]["review_id"], True, self.approver)
            if kind == "approve_workflow":
                reviews = [node["review"] for node in results[data["source"]]["nodes"].values() if node.get("review")]
                if not reviews: raise ValueError("workflow has no pending review")
                return {"decisions": [runtime.broker.decide(review, True, self.approver) for review in reviews]}
            if kind == "claim": return runtime.dispatcher.claim(task=data.get("task"), operation=data.get("operation")) or {"status": "IDLE"}
            if kind == "receiver":
                claim = results[data["claim"]]
                return runtime.receiver.deliver(claim["task"], claim["operation"], json.loads(claim["payload"]))
            if kind in {"ack", "lost_ack"}:
                claim = results[data["claim"]]
                return runtime.dispatcher.finish(claim, results[data["receipt"]]) if kind == "ack" else runtime.dispatcher.finish(claim, error="simulated lost ack")
            if kind == "dispatch": return runtime.dispatcher.dispatch_once(lose_ack=data.get("lose_ack", False))
            if kind == "advance_clock":
                self.inputs.advance(data["seconds"])
                return {"time": self.inputs.clock().isoformat()}
            if kind == "observe": return ledger(runtime.store)
            if kind in {"rollback_enable", "rollback_disable"}:
                # Fixed trusted fault fixture, never attacker SQL capability.
                with runtime.store.transaction() as conn:
                    if kind == "rollback_enable":
                        conn.execute("CREATE TEMP TRIGGER phase4_abort BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'simulated intent crash'); END")
                    else: conn.execute("DROP TRIGGER phase4_abort")
                return {"status": "FAULT_INSTALLED" if kind == "rollback_enable" else "FAULT_REMOVED"}
            if kind in {"crash_before_intent", "crash_after_intent"}: return {"status": "SIMULATED_PROCESS_STOP", "boundary": kind}
            if kind == "restart":
                for flow in self.flows.values(): flow.close()
                self.flows.clear()
                for old in self.connections: old.store.close()
                self.runtime = self.connect(); self.connections = [self.runtime]
                return {"status": "RESTARTED", "ledger": ledger(self.runtime.store)}
            if kind == "workflow":
                from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
                task, run = data["task"], data.get("run", "replay")
                if task not in self.flows:
                    control = self.effect_controls.setdefault(task, EffectOrder(self.workload["effect_order"][task]))
                    self.flows[task] = ConfigWorkflow(runtime, self.path.parent / (task + "-checkpoint.sqlite"), task=task,
                        caller=self.user, worker=ScriptedWorker(self.workload["responses"][task]), hook=control.checkpoint)
                flow = self.flows[task]
                getattr(flow, data.get("command", "start"))(run)
                return {**flow.status(run), "effect_schedule": self.effect_controls[task].choices}
            raise ValueError("unknown action")
        except (PermissionError, ValueError) as exc:
            return {"status": "REJECTED", "error": type(exc).__name__, "reason": str(exc)}

    def close(self):
        for flow in self.flows.values(): flow.close()
        for runtime in self.connections: runtime.store.close()


class EffectOrder:
    """Replay an A batch with real concurrent workers and ordered effect windows.

    The first two root workers rendezvous before selection. Only nodes already
    presented by executor A are ready; no hook runs within a DB transaction.
    """
    def __init__(self, plan):
        self.plan, self.index, self.choices = list(plan), 0, []
        self.condition, self.ready = Condition(), set()
        self.root_workers, self.root_effects = Barrier(2, timeout=5), Barrier(2, timeout=5)
        self.seen_workers, self.seen_effects = set(), set()

    def checkpoint(self, stage, node):
        if stage == "worker_ready" and node in self.plan[:2] and node not in self.seen_workers:
            with self.condition: self.seen_workers.add(node)
            self.root_workers.wait()
        if stage == "before_effect":
            with self.condition:
                self.ready.add(node)
                root = node in self.plan[:2] and node not in self.seen_effects
                self.seen_effects.add(node)
            if root: self.root_effects.wait()
            with self.condition:
                if not self.condition.wait_for(lambda: self.index < len(self.plan) and self.plan[self.index] == node, timeout=5):
                    raise TimeoutError("requested workflow effect unready; bounded replay stopped")
                self.choices.append({"chosen": node, "ready": sorted(self.ready)})
        if stage == "after_effect":
            with self.condition:
                self.ready.remove(node)
                self.index += 1
                self.condition.notify_all()


class ReplayHooks(HookLog):
    def __init__(self, host):
        super().__init__()
        self.host = host

    def checkpoint(self, stage, action_id, *, deferred=False):
        super().checkpoint(stage, action_id, deferred=deferred)
        plan = self.host.workload.get("hook_mutations", [])
        index = len(self.host.hook_mutations)
        if index >= len(plan): return
        mutation = plan[index]
        if (stage, action_id) != (mutation["stage"], mutation["operation"]): return
        if stage != "before_cas": raise ValueError("trusted contention fixture requires outside-transaction boundary")
        runtime = self.host.runtime
        if runtime.store.coordinator.held_exclusively() or runtime.store._conn.in_transaction:
            raise AssertionError("instrumentation cannot mutate while fallback gate/transaction is held")
        observation = {"actor": "trusted_updater_fixture", "stage": stage, "operation": action_id, "key": mutation["key"],
                       "deferred_until_fallback_release": deferred}
        self.host.hook_mutations.append(observation)
        key = mutation["key"]
        if key not in {"contract3:" + task for task in self.host.tasks}: raise ValueError("unregistered hook mutation")
        if len(self.host.connections) < 2: self.host.connections.append(self.host.connect())
        other = self.host.connections[1]
        with other.store.transaction() as conn:
            contract = other.store.value(conn, key)[1]
            other.store.put(conn, key, {**contract, "objective": "trusted contention revision " + str(index + 1)})
            other.store.audit(conn, "TRUSTED_CONTENTION_FIXTURE", "local-owner", observation)
        observation["version"] = other.store.get_version(key)


@contextmanager
def test_workspace(reconstruct=None):
    if reconstruct is None:
        with TemporaryDirectory(prefix="atomicroot-phase4-") as directory: yield directory
        return
    path = Path(reconstruct).resolve()
    temp_root = Path(gettempdir()).resolve()
    # Check the absolute target before creation/deletion. Existing paths are
    # rejected, including symlinks; artifacts cannot nominate arbitrary files.
    if path.parent != temp_root or re.fullmatch(r"atomicroot-phase4-[a-z0-9_-]{8,}", path.name) is None:
        raise ValueError("checkpoint workspace outside trusted temporary root")
    try: path.mkdir(exist_ok=False)
    except FileExistsError: raise ValueError("temporary checkpoint workspace already exists; replay not started") from None
    try: yield str(path)
    finally:
        if path.resolve().parent != temp_root or path.is_symlink(): raise ValueError("temporary workspace identity changed")
        shutil.rmtree(path)


def record(workload, *, mode="optimistic", expected=None, workspace=None):
    with test_workspace(workspace) as directory:
        host = ReplayHost(directory, workload, mode=mode)
        try:
            scheduler = ReadyScheduler(workload["actions"], preferred=workload["preferred"])
            run = scheduler.run(host.execute, ready=host.ready, exact_schedule=expected)
            run["trusted_hook_mutations"] = host.hook_mutations
            terminal = ledger(host.runtime.store)
            checkpointed = any(a["kind"] == "workflow" for a in workload["actions"])
            artifact = {"schema_version": SCHEMA_VERSION, "workload": workload, "environment": {**environment(), "guard": mode,
                "fallback_config": asdict(FallbackConfig()) if mode == "fallback" else None},
                "initial": host.initial, "public_key": bytes(host.key.verify_key).hex(),
                "bindings": {"checkpoint_workspace": str(Path(directory).resolve()) if checkpointed else None,
                             "reconstructed": ["temporary Ed25519 key and signatures"] + (["same physical checkpoint directory identity, initially empty"] if checkpointed else []),
                             "compared_verbatim": ["identity", "operation", "payload hashes", "ticket IDs", "nonce", "expiry", "footprint versions", "write sets", "executor/config/checkpoint binding"],
                             "fixture_authority": "local-user/local-human/local-owner are trusted fixtures, never attacker principals"},
                "run": run, "hooks": host.hooks.steps, "terminal_observations": terminal,
                "model_records": workload.get("model_records", {})}
            artifact["semantic_trace"] = semantic({"run": run, "terminal": terminal}, artifact["public_key"])
            return validate_artifact(artifact)
        finally: host.close()


def replay(artifact):
    validate_artifact(artifact)
    recorded_environment = {k: v for k, v in artifact["environment"].items() if k not in {"guard", "fallback_config"}}
    if environment() != recorded_environment: raise ValueError("replay environment/version divergence")
    if artifact["environment"]["fallback_config"] != (asdict(FallbackConfig()) if artifact["environment"]["guard"] == "fallback" else None):
        raise ValueError("replay fallback configuration divergence")
    checkpointed = any(a["kind"] == "workflow" for a in artifact["workload"]["actions"])
    result = record(artifact["workload"], mode=artifact["environment"]["guard"], expected=[s["chosen"] for s in artifact["run"]["schedule"]],
                    workspace=artifact["bindings"]["checkpoint_workspace"] if checkpointed else None)
    return {"match": result["semantic_trace"] == artifact["semantic_trace"] and result["initial"] == artifact["initial"] and not result["run"]["divergence"],
            "schedule_divergence": result["run"]["divergence"], "artifact": result}
