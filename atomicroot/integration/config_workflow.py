"""Executor A: approved finite DAG, staged guarded operations and ledger completion."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import TypedDict
from copy import deepcopy
import json
import os
import sqlite3

from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langsmith import tracing_context

from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.authority.policy_engine import valid_identity
from atomicroot.framework.identity import Principal
from atomicroot.framework.storage import dumps, uid
from atomicroot.integration.guarded import GuardedTools
from atomicroot.integration.prompts import config_messages, config_response_schema, CONFIG_WORKER_VERSION
from atomicroot.integration.progress import emit


class ConfigState(TypedDict, total=False):
    run: str
    binding: str
    nodes: dict
    batch: list
    route: str
    status: str
    completion: dict


_LOCKS = {}
_LOCKS_GUARD = Lock()


@contextmanager
def invocation_lock(path):
    """Nonblocking process/file exclusion for one checkpoint invocation only.

    This is not a business-state lock. No SQLite transaction is held while
    workers wait, and the OS releases the file lock on process death.
    """
    path = Path(path).resolve()
    with _LOCKS_GUARD: lock = _LOCKS.setdefault(str(path), Lock())
    if not lock.acquire(blocking=False): raise ValueError("run invocation already active")
    stream = None
    acquired = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        stream = path.open("a+b")
        stream.seek(0)
        if not stream.read(1): stream.write(b"0"); stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError: raise ValueError("run invocation already active") from None
        yield
    finally:
        if stream:
            if acquired:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_UN)
            stream.close()
        lock.release()


class ScriptedWorker:
    """Explicit offline fixture. It never calls a model or claims live inference."""
    def __init__(self, responses):
        self.responses = freeze_json(responses, max_bytes=32768)
        if type(self.responses) is not dict or any(type(v) is not list or len(v) > 64 for v in self.responses.values()):
            raise ValueError("bounded per-node response fixture required")
        self.binding = {"mode": "scripted_offline", "fixture": args_hash(self.responses)}

    def __call__(self, view):
        responses = self.responses.get(view["node"], [])
        return responses[view["step"]] if view["step"] < len(responses) else {"kind": "done", "summary": "fixture finished"}


class ConfigWorkflow:
    def __init__(self, runtime, checkpoint_path, *, task, caller, worker=None, bridge=None,
                 hook=None, after_effect=None):
        caller.require("user", task=task)
        active = runtime.tasks.status(task, caller)
        if active["status"] != "ACTIVE": raise ValueError("resolved task must be active")
        if (worker is None) == (bridge is None): raise ValueError("choose one explicit worker driver")
        self.runtime, self.task, self.caller = runtime, task, caller
        self.active, self.spec = active, active["resolved"]["spec"]
        self.worker, self.bridge, self.hook, self.after_effect = worker, bridge, hook, after_effect
        self.progress = getattr(bridge, "progress", None)
        self.tools = bridge.tools if bridge else GuardedTools(runtime)
        self.tools.max_dispatch = 1  # At most three persisted delivery attempts per node/operation.
        GuardedTools.validate_registry(self.tools.registry)
        self.principals = {a["id"]: runtime.tasks.principal(task, a["id"], caller) for a in self.spec["agents"]}
        self.agents = {a["id"]: a for a in active["resolved"]["agents"]}
        self.plan = {n["id"]: n for n in self.spec["workflow"]["nodes"]}
        self.contexts = {}
        self.path = Path(checkpoint_path).resolve()
        if bridge:
            setting = self.spec["provider"]
            if not setting or (bridge.model.provider, bridge.model.model) != (setting["destination"], setting["model"]):
                raise ValueError("model does not match approved provider")
            if vars(bridge.llm_limits) != self.spec["limits"]["inference"]:
                raise ValueError("inference limits must match approved caps")
            for agent in self.agents.values():
                contexts = [r["resource"] for r in self.spec["resources"] if r.get("binding") == "host_context" and
                            any(s["resource"] == r["resource"] for s in agent["scope"])]
                if len(contexts) != 1: raise ValueError("each model worker requires one approved host context")
                self.contexts[agent["id"]] = contexts[0]
            driver = {"mode": bridge.model.mode, "provider": bridge.model.provider, "model": bridge.model.model,
                      "limits": vars(bridge.llm_limits), "structured": bool(getattr(bridge.model, "structured_worker_output", False))}
            # Replay/fake responder bindings must remain exact across restarts.
            driver["fixture"] = getattr(bridge.model, "execution_binding", None)
            if not bridge.model.live and driver["fixture"] is None: raise ValueError("offline model driver requires explicit replay/fixture binding")
            if bridge.model.live:
                from atomicroot.integration.providers import model_configuration
                from dataclasses import asdict, is_dataclass
                configuration = model_configuration(bridge.model.provider, bridge.model.model)
                configuration.pop("key_environment", None)
                driver["configuration"] = {k: asdict(v) if is_dataclass(v) else v for k, v in configuration.items()}
                if configuration["endpoint"] != active["resolved"]["destinations"][setting["destination"]]["endpoint"]:
                    raise ValueError("provider endpoint not in reviewed configuration")
        else:
            driver = freeze_json(worker.binding)
            if self.spec["provider"] is not None: raise ValueError("approved model workflow requires a model driver")
        classifier = self.spec["classifier"]
        if classifier["mode"] != "disabled":
            if not bridge or (bridge.receiver.classifier.provider, bridge.receiver.classifier.model) != (classifier["destination"], classifier["model"]):
                raise ValueError("classifier does not match approved setting")
            if vars(bridge.receiver.jev_limits) != self.spec["limits"]["inference"]:
                raise ValueError("classifier caps must match approved caps")
            for node in classifier.get("before_nodes", [n["id"] for n in self.plan.values() if not n["depends_on"]]):
                scope = self.agents[self.plan[node]["agent"]]["scope"]
                if any(not any(r["tool"] == "classify_document" and r["resource"] == resource for r in scope) for resource in classifier["resources"]):
                    raise ValueError("classifier timing requires delegation on target node")
            driver["classifier"] = {"mode": bridge.receiver.classifier.mode, "threshold": bridge.receiver.records.threshold,
                                    "fixture": getattr(bridge.receiver.classifier, "execution_binding", None)}
            from atomicroot.integration.providers import CRITERIA, CRITERIA_VERSION
            driver["classifier"].update(criteria_version=CRITERIA_VERSION, criteria_hash=args_hash(CRITERIA))
            if not bridge.receiver.classifier.live and driver["classifier"]["fixture"] is None:
                raise ValueError("offline classifier requires explicit fixture binding")
        self.binding_data = {"resolved": active["binding"], "driver": driver, "executor": "config-executor-v1",
            "checkpoint": str(self.path), "prompt": CONFIG_WORKER_VERSION,
            "schemas": {a["id"]: config_response_schema(a, self.spec["outputs"]) for a in self.agents.values()}}
        self.binding = args_hash(self.binding_data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.saver = SqliteSaver(self.conn, serde=JsonPlusSerializer(allowed_msgpack_modules=[], allowed_json_modules=[]))
        with runtime.store._lock:
            runtime.store._conn.executescript("""
                CREATE TABLE IF NOT EXISTS execution_runs(task TEXT NOT NULL,run TEXT NOT NULL,binding TEXT NOT NULL,
                    config TEXT NOT NULL,status TEXT NOT NULL,evidence TEXT,PRIMARY KEY(task,run));
                CREATE TABLE IF NOT EXISTS execution_actions(task TEXT NOT NULL,run TEXT NOT NULL,node TEXT NOT NULL,
                    step INTEGER NOT NULL,operation TEXT NOT NULL UNIQUE,data TEXT NOT NULL,PRIMARY KEY(task,run,node,step));
                CREATE TABLE IF NOT EXISTS execution_outputs(task TEXT NOT NULL,run TEXT NOT NULL,id TEXT NOT NULL,
                    digest TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(task,run,id));
                CREATE TABLE IF NOT EXISTS execution_invocations(id TEXT PRIMARY KEY,task TEXT NOT NULL,run TEXT NOT NULL,
                    status TEXT NOT NULL,error TEXT,timestamp REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS execution_history(seq INTEGER PRIMARY KEY AUTOINCREMENT,task TEXT NOT NULL,
                    run TEXT NOT NULL,status TEXT NOT NULL,evidence TEXT NOT NULL,timestamp REAL NOT NULL);
            """)
        graph = StateGraph(ConfigState)
        for name in ("schedule", "decide", "stage", "effect", "wait", "finish"):
            graph.add_node(name, getattr(self, "_" + name))
        graph.add_edge(START, "schedule")
        graph.add_conditional_edges("schedule", lambda s: s["route"], {"decide": "decide", "finish": "finish"})
        graph.add_edge("decide", "stage")
        graph.add_conditional_edges("stage", lambda s: s["route"], {"effect": "effect", "schedule": "schedule", "wait": "wait"})
        graph.add_conditional_edges("effect", lambda s: s["route"], {"wait": "wait", "schedule": "schedule"})
        graph.add_conditional_edges("wait", lambda s: s["route"], {"effect": "effect", "schedule": "schedule"})
        graph.add_edge("finish", END)
        self.graph = graph.compile(checkpointer=self.saver)

    def close(self): self.conn.close()

    def config(self, run):
        valid_identity(run)
        return {"configurable": {"thread_id": self.task + ":" + run}, "recursion_limit": 10000}

    def operation(self, s, node, step, kind):
        return "op-" + args_hash({"task": self.task, "run": s["run"], "binding": self.binding,
                                 "node": node, "agent": self.plan[node]["agent"], "step": step, "kind": kind}).split(":")[1][:40]

    def start(self, run): return self._invoke(run, "start")
    def recover(self, run): return self._invoke(run, "recover")
    def resume(self, run): return self._invoke(run, "resume")

    def _invoke(self, run, mode):
        config = self.config(run)
        invocation = uid("invocation")
        try:
            with invocation_lock(self.path.parent / (args_hash({"task": self.task, "run": run}).split(":")[1] + ".lock")):
                current = self.runtime.tasks.status(self.task, self.caller)
                if current["binding"] != self.active["binding"]: raise ValueError("active config changed; new run required")
                with self.runtime.store.transaction() as conn:
                    row = self.runtime.store.row(conn, "SELECT * FROM execution_runs WHERE task=? AND run=?", (self.task, run))
                    if row and row["binding"] != self.binding: raise ValueError("run config/driver binding mismatch")
                    if mode == "start" and row: raise ValueError("run already exists; resume or recover")
                    if mode != "start" and not row: raise ValueError("unknown run")
                    if not row:
                        conn.execute("INSERT INTO execution_runs VALUES (?,?,?,?,?,NULL)", (self.task, run, self.binding, dumps(self.binding_data), "RUNNING"))
                state = self.graph.get_state(config)
                if mode == "start":
                    if state.values: raise ValueError("checkpoint exists; recover")
                    input_value = {"run": run, "binding": self.binding, "nodes": {n: {"step": 0, "phase": "READY", "observations": [],
                        "repairs": 0, "review_retries": 0, "classified": False} for n in self.plan}, "status": "RUNNING"}
                else:
                    if state.values and state.values.get("binding") != self.binding: raise ValueError("checkpoint binding mismatch")
                    if not state.values:
                        input_value = {"run": run, "binding": self.binding, "nodes": {n: {"step": 0, "phase": "READY", "observations": [],
                            "repairs": 0, "review_retries": 0, "classified": False} for n in self.plan}, "status": "RUNNING"}
                    else: input_value = Command(resume=True) if mode == "resume" and state.interrupts else None
                with tracing_context(enabled=False): result = self.graph.invoke(input_value, config, durability="sync")
                status = "REVIEW_WAIT" if result.get("__interrupt__") and result["status"] == "REVIEW_WAIT" else result["status"]
            self._invocation(invocation, run, status)
            return result
        except BaseException as exc:
            self._invocation(invocation, run, "INVOCATION_FAILED", type(exc).__name__)
            raise

    def _invocation(self, invocation, run, status, error=None):
        with self.runtime.store.transaction() as conn:
            conn.execute("INSERT INTO execution_invocations VALUES (?,?,?,?,?,?)", (invocation, self.task, run, status, error, self.runtime.store.now()))

    def status(self, run):
        self.config(run)
        self.runtime.tasks.status(self.task, self.caller)
        with self.runtime.store.snapshot() as snap:
            row = self.runtime.store.row(snap._conn, "SELECT * FROM execution_runs WHERE task=? AND run=?", (self.task, run))
            if not row: raise ValueError("unknown run")
            history = [dict(zip(("status", "evidence", "timestamp"), r)) for r in snap._conn.execute(
                "SELECT status,evidence,timestamp FROM execution_history WHERE task=? AND run=? ORDER BY seq", (self.task, run))]
            invocations = [dict(zip(("id", "status", "error"), r)) for r in snap._conn.execute(
                "SELECT id,status,error FROM execution_invocations WHERE task=? AND run=? ORDER BY rowid", (self.task, run))]
        state = self.graph.get_state(self.config(run))
        return {"task": self.task, "run": run, "binding": row["binding"], "status": row["status"],
            "completion": json.loads(row["evidence"]) if row["evidence"] else None,
            "history": [{**h, "evidence": json.loads(h["evidence"])} for h in history], "invocations": invocations,
            "nodes": {n: {k: v for k, v in data.items() if k in {"step", "phase", "review", "review_retries", "reason"}} for n, data in state.values.get("nodes", {}).items()}}

    def _checkpoint(self, stage, node):
        if self.hook: self.hook(stage, node)

    def _schedule(self, s):
        if s["binding"] != self.binding: raise ValueError("checkpoint binding mismatch")
        bad = next((v["phase"] for v in s["nodes"].values() if v["phase"] not in {"READY", "DONE"}), None)
        if bad: return {"route": "finish", "status": bad}
        if all(v["phase"] == "DONE" for v in s["nodes"].values()): return {"route": "finish", "status": "CHECKING"}
        selected, agents = [], set()
        for node, definition in self.plan.items():
            if s["nodes"][node]["phase"] != "READY" or not all(s["nodes"][d]["phase"] == "DONE" for d in definition["depends_on"]): continue
            if definition["agent"] in agents: continue  # One mutable context stream per concrete agent.
            selected.append(node); agents.add(definition["agent"])
            if len(selected) == self.spec["limits"]["max_in_flight"]: break
        if not selected: return {"route": "finish", "status": "FAILED"}
        return {"batch": selected, "route": "decide", "status": "RUNNING"}

    def _observations(self, s, node):
        ancestors = set()
        def visit(name):
            if name in ancestors: return
            ancestors.add(name)
            for dep in self.plan[name]["depends_on"]: visit(dep)
        visit(node)
        return [ob for name in self.plan if name in ancestors for ob in s["nodes"][name]["observations"]]

    def _decide_one(self, s, node):
        data = deepcopy(s["nodes"][node])
        step, agent_id = data["step"], self.plan[node]["agent"]
        if step >= self.spec["limits"]["max_steps"]: return {**data, "phase": "RETRY_EXHAUSTED"}
        observations = self._observations(s, node)
        try:
            self._checkpoint("worker_ready", node)
            classifier = self.spec["classifier"]
            targets = classifier.get("before_nodes", [n["id"] for n in self.plan.values() if not n["depends_on"]])
            if classifier["mode"] != "disabled" and node in targets and not data["classified"]:
                for resource in classifier["resources"]:
                    ref = next(r for r in self.spec["resources"] if r["resource"] == resource)
                    result = self.bridge.classify(self.operation(s, node, 0, "classification-" + resource), self.task + ":" + s["run"],
                        resource=resource, digest=ref["digest"], version=ref["version"], principal=self.principals[agent_id], task=self.task, purpose=self.spec["purpose"])
                    if result["status"] == "COMMITTED" and result["detail"].get("delivery") == "RELEASED":
                        proposal = result["detail"]["receipt"]["result"]["classification"]
                        if proposal["candidate_label"] == "SENSITIVE":
                            owner = Principal("classification-rule-host", frozenset({"owner"}), tasks=frozenset({self.task}), resources=frozenset({resource}))
                            self.runtime.labels.accept_classification(proposal["proposal_id"], self.task, self.spec["purpose"], owner)
                    else: return {**data, "phase": "FAILED"}
                data["classified"] = True
            with self.runtime.store.snapshot() as snap:
                catalog = [{k: r[k] for k in ("resource", "digest", "version")} for r in self.spec["resources"] if r.get("binding") != "host_context"]
                counters = {"spent": snap.read("budget:" + self.task)[1], "reserved": snap.read("reserved:" + self.task)[1]}
            view = {"node": node, "agent": self.agents[agent_id], "step": step, "observations": observations,
                    "catalog": catalog, "counters": counters, "objective": self.spec["objective"]}
            if self.bridge:
                sources = []
                for ob in observations:
                    source = ob.get("detail", {}).get("source")
                    if source and source not in sources: sources.append(source)
                response = self.bridge.worker(self.operation(s, node, step, "inference"), self.task + ":" + s["run"],
                    messages=config_messages(self.spec, self.agents[agent_id], node, step, observations, catalog, counters), sources=sources,
                    context_resource=self.contexts[agent_id], principal=self.principals[agent_id], task=self.task, purpose=self.spec["purpose"],
                    execution={"run": s["run"], "binding": self.binding, "node": node, "step": step, "agent": agent_id})
            else: response = self.worker(freeze_json(view))
            self._checkpoint("worker_returned", node)
            return {**data, "phase": "DECIDED", "response": freeze_json(response, max_bytes=16384)}
        except Exception as exc:
            # Provider/worker details are untrusted and may include secrets.
            from atomicroot.integration.inference import InferenceUnavailable
            if isinstance(exc, InferenceUnavailable):
                ob = exc.observation
                if ob.status == "COMMITTED" and ob.detail["delivery"] in {"UNKNOWN", "PENDING", "RELEASING"}:
                    return {**data, "phase": "INFERENCE_WAIT" if ob.detail["attempts"] < 3 else "DELIVERY_UNKNOWN",
                            "reason": "delivery_pending" if ob.detail["attempts"] < 3 else "delivery_retry_exhausted"}
                data["observations"].append({**ob.json(), "node": node, "agent": self.principals[agent_id].subject, "step": step})
                if ob.status == "DENY": return {**data, "phase": "REFUSED"}
            return {**data, "phase": "TIMEOUT" if isinstance(exc, TimeoutError) else "FAILED", "error": type(exc).__name__}

    def _parallel(self, s, fn):
        # Only the coordinator returns a single merged checkpoint; workers never
        # write graph state. SQLite commits still serialize at the store boundary.
        with ThreadPoolExecutor(max_workers=self.spec["limits"]["max_in_flight"]) as pool:
            results = list(pool.map(lambda node: (node, fn(s, node)), s["batch"]))
        return {**s["nodes"], **dict(results)}

    def _decide(self, s): return {"nodes": self._parallel(s, self._decide_one)}

    def _stage(self, s):
        nodes = deepcopy(s["nodes"])
        for node in s["batch"]:
            data = nodes[node]
            if data["phase"] != "DECIDED": continue
            response = data.pop("response")
            try:
                kind = response.get("kind") if type(response) is dict else None
                if kind == "done":
                    if set(response) != {"kind", "summary"} or type(response["summary"]) is not str: raise ValueError("invalid done proposal")
                    data["phase"] = "DONE"; continue
                if kind == "output":
                    if set(response) != {"kind", "output", "content"} or response["output"] not in {o["id"] for o in self.spec["outputs"]}:
                        raise ValueError("unsupported output")
                    if type(response["content"]) is not str or not 0 < len(response["content"].encode("utf-8")) <= 8192: raise ValueError("bounded output required")
                    pending = response
                else:
                    if kind != "action" or set(response) != {"kind", "tool", "args"}: raise ValueError("invalid action proposal")
                    pending = self.tools.stage({"tool": response["tool"], "args": response["args"]}, principal=self.principals[self.plan[node]["agent"]],
                        task=self.task, purpose=self.spec["purpose"], operation=self.operation(s, node, data["step"], "action"))
                op = self.operation(s, node, data["step"], "action")
                with self.runtime.store.transaction() as conn:
                    previous = self.runtime.store.row(conn, "SELECT operation,data FROM execution_actions WHERE task=? AND run=? AND node=? AND step=?",
                        (self.task, s["run"], node, data["step"]))
                    if previous and (previous["operation"], previous["data"]) != (op, dumps(pending)): raise ValueError("staged payload changed; new step/operation required")
                    conn.execute("INSERT OR IGNORE INTO execution_actions VALUES (?,?,?,?,?,?)", (self.task, s["run"], node, data["step"], op, dumps(pending)))
                data.update(phase="STAGED", pending=pending, grant=None)
                emit(self.progress, "ACTION", role=self.plan[node]["agent"], operation=op, step=data["step"], status="STAGED")
            except Exception as exc:
                data.update(step=data["step"] + 1, repairs=data["repairs"] + 1,
                    phase="UNSUPPORTED" if data["repairs"] >= 2 else "READY")
                data["observations"].append({"status": "REJECTED", "node": node, "detail": {"reason": type(exc).__name__}})
        route = "effect" if any(nodes[n]["phase"] == "STAGED" for n in s["batch"]) else "wait" if any(v["phase"] == "INFERENCE_WAIT" for v in nodes.values()) else "schedule"
        status = "DELIVERY_UNKNOWN" if route == "wait" else s["status"]
        if route == "wait":
            with self.runtime.store.transaction() as conn:
                conn.execute("UPDATE execution_runs SET status=? WHERE task=? AND run=?", (status, self.task, s["run"]))
        return {"nodes": nodes, "route": route, "status": status}

    def _effect_one(self, s, node):
        data = deepcopy(s["nodes"][node])
        if data["phase"] not in {"STAGED", "DELIVERY_WAIT"}: return data
        self._checkpoint("before_effect", node)
        principal = self.principals[self.plan[node]["agent"]]
        if data["pending"].get("kind") == "output":
            payload = {**data["pending"], "node": node, "step": data["step"], "agent": principal.subject,
                       "sources": [ob["operation_id"] for ob in self._observations(s, node) if ob.get("operation_id")], "binding": self.binding}
            digest = args_hash(payload)
            with self.runtime.store.transaction() as conn:
                previous = self.runtime.store.row(conn, "SELECT digest FROM execution_outputs WHERE task=? AND run=? AND id=?", (self.task, s["run"], payload["output"]))
                if previous and previous["digest"] != digest:
                    return {**data, "phase": "UNSUPPORTED", "reason": "output_binding_conflict"}
                conn.execute("INSERT OR IGNORE INTO execution_outputs VALUES (?,?,?,?,?)", (self.task, s["run"], payload["output"], digest, dumps(payload)))
                self.runtime.store.audit(conn, "OUTPUT_ACCEPTED", principal.subject, {"task": self.task, "run": s["run"], "output": payload["output"], "digest": digest})
            observation = {"status": "OUTPUT_STORED", "operation_id": self.operation(s, node, data["step"], "action"),
                "detail": {"output": payload["output"], "digest": digest, "content": payload["content"],
                           "source_operations": payload["sources"], "instruction_trust": "UNTRUSTED", "factual_accuracy": "UNVERIFIED"}}
        else:
            observation = self.tools.execute(data["pending"], principal, grant=data.get("grant")).json()
        if self.after_effect: self.after_effect(node, observation)
        self._checkpoint("after_effect", node)
        status = observation["status"]
        if status == "ESCALATE": return {**data, "phase": "REVIEW", "review": observation["detail"]["review_id"]}
        if status == "COMMITTED" and observation["detail"]["delivery"] not in {"RELEASED", "FAILED"}:
            return {**data, "phase": "DELIVERY_WAIT" if observation["detail"]["attempts"] < 3 else "DELIVERY_UNKNOWN",
                    "reason": "delivery_pending" if observation["detail"]["attempts"] < 3 else "delivery_retry_exhausted"}
        data["observations"].append({**observation, "node": node, "agent": principal.subject, "step": data["step"]})
        phase = {"DENY": "REFUSED", "EVALUATION_ERROR": "FAILED", "RETRY_EXHAUSTED": "RETRY_EXHAUSTED", "REJECTED": "UNSUPPORTED"}.get(status, "READY")
        if status == "COMMITTED" and observation["detail"]["delivery"] == "FAILED": phase = "FAILED"
        data.update(phase=phase, step=data["step"] + 1, grant=None, pending={})
        return data

    def _effect(self, s):
        nodes = self._parallel(s, self._effect_one)
        waiting = any(v["phase"] in {"REVIEW", "DELIVERY_WAIT", "INFERENCE_WAIT"} for v in nodes.values())
        status = "REVIEW_WAIT" if any(v["phase"] == "REVIEW" for v in nodes.values()) else "DELIVERY_UNKNOWN" if waiting else "RUNNING"
        with self.runtime.store.transaction() as conn:
            conn.execute("UPDATE execution_runs SET status=? WHERE task=? AND run=?", (status, self.task, s["run"]))
        return {"nodes": nodes, "route": "wait" if waiting else "schedule", "status": status}

    def _wait(self, s):
        nodes = deepcopy(s["nodes"])
        pending = []
        for node, data in nodes.items():
            if data["phase"] != "REVIEW": continue
            review = self.runtime.broker.status(data["review"], self.principals[self.plan[node]["agent"]])
            status = review["effective_status"]
            if status == "REJECTED": data["phase"] = "REVIEW_REJECTED"
            elif status in {"STALE", "EXPIRED"}:
                data["review_retries"] += 1
                data.update(phase="STAGED" if data["review_retries"] <= 2 else "RETRY_EXHAUSTED", grant=None)
            elif status == "APPROVED": data.update(phase="STAGED", grant=data["review"])
            else: pending.append({"node": node, "review_id": data["review"], "status": status})
        delivery = [n for n, d in nodes.items() if d["phase"] == "DELIVERY_WAIT"]
        inference = [n for n, d in nodes.items() if d["phase"] == "INFERENCE_WAIT"]
        if pending or delivery or inference:
            interrupt({"kind": "runtime_wait", "reviews": pending, "delivery_pending": delivery, "inference_pending": inference,
                       "note": "Broker decision/reconciliation required; resume data is not a grant."})
            if pending: return self._wait(s)
            for node in inference: nodes[node]["phase"] = "READY"
        batch = [n for n, d in nodes.items() if d["phase"] in {"STAGED", "DELIVERY_WAIT"}]
        return {"nodes": nodes, "batch": batch, "route": "effect" if batch else "schedule", "status": "RUNNING"}

    def completion(self, run):
        """Registered existence/delivery predicates, not a factual-quality oracle."""
        evidence = []
        with self.runtime.store.snapshot() as snap:
            rows = snap._conn.execute("SELECT a.operation,a.data,b.status,b.payload,b.receipt,r.receipt FROM execution_actions a "
                "JOIN outbox b ON b.task=a.task AND b.operation=a.operation JOIN receiver_receipts r ON r.task=b.task AND r.operation=b.operation "
                "WHERE a.task=? AND a.run=?", (self.task, run)).fetchall()
            delivered = []
            for op, action, status, payload, receipt, proof in rows:
                if status != "RELEASED" or not receipt or receipt != proof: continue
                receipt, action, payload = json.loads(receipt), json.loads(action), json.loads(payload)
                if receipt["outcome"] != "DELIVERED" or action.get("tool") != payload["tool"] or action.get("args") != payload["args"]: continue
                delivered.append((op, action, receipt, payload))
            for criterion in self.spec["acceptance"]:
                matches = []
                if criterion["kind"] in {"read", "receipt"}:
                    for op, action, receipt, payload in delivered:
                        if criterion["kind"] == "read":
                            ref = next(r for r in self.spec["resources"] if r["resource"] == criterion["resource"])
                            match = action["tool"] == "read_document" and action["args"] == {"resource": ref["resource"], "digest": ref["digest"]} and payload["resource_snapshot"]["version"] == ref["version"]
                        else: match = action["tool"] == criterion["tool"] and action["args"].get("to") == criterion["destination"]
                        if match: matches.append({"operation": op, "receipt_id": receipt["receipt_id"]})
                else:
                    row = snap._conn.execute("SELECT digest,data FROM execution_outputs WHERE task=? AND run=? AND id=?", (self.task, run, criterion["output"])).fetchone()
                    if row and args_hash(json.loads(row[1])) == row[0] and json.loads(row[1])["binding"] == self.binding:
                        matches.append({"output": criterion["output"], "digest": row[0]})
                evidence.append({"criterion": criterion, "satisfied": bool(matches), "evidence": matches})
        return {"satisfied": bool(evidence) and all(e["satisfied"] for e in evidence), "criteria": evidence,
                "quality": "NOT_EVALUATED", "business_effects": "SIMULATED"}

    def _finish(self, s):
        completion = self.completion(s["run"])
        status = ("SATISFIED" if completion["satisfied"] else "INCOMPLETE") if s["status"] == "CHECKING" else s["status"]
        with self.runtime.store.transaction() as conn:
            conn.execute("UPDATE execution_runs SET status=?,evidence=? WHERE task=? AND run=?", (status, dumps(completion), self.task, s["run"]))
            conn.execute("INSERT INTO execution_history(task,run,status,evidence,timestamp) VALUES (?,?,?,?,?)", (self.task, s["run"], status, dumps(completion), self.runtime.store.now()))
        emit(self.progress, "WORKFLOW", status=status)
        return {"status": status, "completion": completion}
