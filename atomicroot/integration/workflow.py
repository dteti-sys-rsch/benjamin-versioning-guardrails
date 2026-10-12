"""LangGraph authoring/execution, durable staged operations and Broker interrupts."""
from typing import TypedDict, Any
import sqlite3

from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langsmith import tracing_context

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.integration.prompts import author_messages, worker_messages
from atomicroot.integration.guarded import GuardedTools, Observation
from atomicroot.integration.progress import emit


class State(TypedDict, total=False):
    goal: str
    run: str
    proposal: dict
    unsupported: list
    feedback: list
    repairs: int
    review: dict
    contract: dict
    step: int
    role: str
    done: list
    observations: list
    response: dict
    pending: dict
    grant: str | None
    route: str
    status: str
    review_retries: int


def operation_id(run, step, role, purpose):
    return "op-" + args_hash({"run": run, "step": step, "role": role, "purpose": purpose}).split(":")[1][:40]


class AgentWorkflow:
    def __init__(self, runtime, bridge, checkpoint_path, *, task, principals, approver,
                 context_resources, host, max_steps=6, max_repairs=2, after_effect=None,
                 host_validator=None, scope_limits=None):
        if set(principals) != {"reader", "executor"} or len({p.subject for p in principals.values()}) != 2:
            raise ValueError("two distinct concrete worker identities required")
        if not 1 <= max_steps <= 8 or not 0 <= max_repairs <= 3: raise ValueError("invalid workflow bounds")
        for p in principals.values(): p.require("worker", task=task)
        approver.require("approver", task=task)
        self.runtime, self.bridge, self.task = runtime, bridge, task
        self.principals, self.approver, self.context_resources, self.host = principals, approver, context_resources, host
        self.max_steps, self.max_repairs, self.after_effect = max_steps, max_repairs, after_effect
        self.host_validator, self.scope_limits = host_validator, scope_limits or {}
        self.progress = getattr(bridge, "progress", None)
        GuardedTools.validate_registry(bridge.tools.registry)
        self.conn = sqlite3.connect(str(checkpoint_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.saver = SqliteSaver(self.conn, serde=JsonPlusSerializer(allowed_msgpack_modules=[], allowed_json_modules=[]))
        g = StateGraph(State)
        for name in ("author", "preview", "contract_review", "decide", "stage", "effect", "operation_review"):
            g.add_node(name, getattr(self, "_" + name))
        g.add_edge(START, "author")
        g.add_edge("author", "preview")
        g.add_conditional_edges("preview", lambda s: s["route"], {"repair": "author", "review": "contract_review", "end": END})
        g.add_conditional_edges("contract_review", lambda s: s["route"], {"preview": "preview", "decide": "decide", "end": END})
        g.add_conditional_edges("decide", lambda s: s["route"], {"stage": "stage", "preview": "preview", "decide": "decide", "end": END})
        g.add_conditional_edges("stage", lambda s: s["route"], {"effect": "effect", "decide": "decide"})
        g.add_conditional_edges("effect", lambda s: s["route"], {"review": "operation_review", "decide": "decide"})
        g.add_conditional_edges("operation_review", lambda s: s["route"], {"effect": "effect", "decide": "decide"})
        self.graph = g.compile(checkpointer=self.saver)

    def close(self): self.conn.close()

    def config(self, run):
        return {"configurable": {"thread_id": self.task + ":" + run}, "recursion_limit": 100}

    def start(self, run, goal):
        config = self.config(run)
        if self.graph.get_state(config).values: raise ValueError("thread already exists; resume it")
        return self.invoke({"run": run, "goal": goal, "repairs": 0, "step": 0, "role": "reader", "done": [],
                            "observations": [], "feedback": [], "review_retries": 0, "status": "AUTHORING"}, run)

    def invoke(self, input, run):
        # Disable accidental external tracing of model inputs/checkpoint contents.
        with tracing_context(enabled=False):
            return self.graph.invoke(input, self.config(run), durability="sync")

    def resume(self, run, value=None): return self.invoke(Command(resume=value if value is not None else {}), run)
    def recover(self, run): return self.invoke(None, run)

    def _author(self, s):
        emit(self.progress, "AUTHOR", role="author", repairs=s["repairs"])
        output = self.bridge.author(operation_id(self.task + ":" + s["run"], s["step"] * 4 + s["repairs"], "author", "author"), s["run"],
                                    author_messages(s["goal"], self.host, s["feedback"], self.scope_limits))
        try:
            proposal, unsupported = self._proposal(output)
            return {"proposal": proposal, "unsupported": unsupported}
        except ValueError as exc:
            return {"proposal": {}, "unsupported": [str(exc)]}

    def _proposal(self, output):
        output = freeze_json(output)
        if type(output) is not dict or set(output) != {"kind", "proposal", "unsupported"} or output["kind"] != "contract":
            raise ValueError("contract response schema invalid")
        p, unsupported = output["proposal"], output["unsupported"]
        if type(p) is not dict or p.get("task_id") != self.task: raise ValueError("host task binding mismatch")
        if type(unsupported) is not list or len(unsupported) > 16 or any(type(v) is not str or len(v) > 256 for v in unsupported):
            raise ValueError("invalid unsupported requirements")
        if set(p.get("allowed_agents", [])) != {v.subject for v in self.principals.values()}:
            raise ValueError("proposal must use host worker identities")
        if self.host_validator: self.host_validator(p)
        return p, unsupported

    def _preview(self, s):
        validation = self.runtime.contracts.validate(s["proposal"])
        if not validation["valid"] or s.get("unsupported"):
            emit(self.progress, "CONTRACT_VALIDATION", status="INVALID", repairs=s["repairs"])
            failures = s.get("unsupported", []) + validation["unsupported"]
            if s["repairs"] >= self.max_repairs:
                return {"route": "end", "status": "NEEDS_CLARIFICATION", "feedback": failures}
            return {"route": "repair", "repairs": s["repairs"] + 1, "feedback": failures}
        review = self.runtime.contracts.propose(validation["proposal"], self.principals["reader"])
        emit(self.progress, "CONTRACT_VALIDATION", status="VALID", tools=len(validation["proposal"]["allowed_tools"]), budget=validation["proposal"]["budget_limit"])
        return {"review": review, "route": "review", "status": "CONTRACT_REVIEW"}

    def _contract_review(self, s):
        r = self.runtime
        if self.host_validator: self.host_validator(s["proposal"])
        review = r.broker.status(s["review"]["review_id"], self.approver)
        if review["effective_status"] in {"STALE", "EXPIRED"}: return self._renew_contract(s)
        if review["status"] == "REJECTED": return {"route": "end", "status": "CONTRACT_REJECTED"}
        while review["status"] == "PENDING":
            emit(self.progress, "CONTRACT_REVIEW", status="PENDING", review=review["id"])
            interrupt({"kind": "contract", "review_id": review["id"], "preview": review["data"]["preview"],
                       "user_goal": s["goal"],
                       "unsupported": s.get("unsupported", []), "repair_feedback": s.get("feedback", []),
                       "note": "Decide via trusted Broker; resume is not approval."})
            review = r.broker.status(review["id"], self.approver)
            if review["effective_status"] in {"STALE", "EXPIRED"}: return self._renew_contract(s)
            if review["status"] == "REJECTED": return {"route": "end", "status": "CONTRACT_REJECTED"}
        if review["status"] == "APPROVED":
            r.contracts.activate(s["review"]["proposal_id"], review["id"], self.approver)
        elif review["status"] == "CONSUMED":
            with r.store._lock:
                p = r.store.row(r.store._conn, "SELECT status FROM proposals WHERE id=?", (s["review"]["proposal_id"],))
            if not p or p["status"] != "ACTIVE": return {"route": "end", "status": "REVIEW_SUPERSEDED"}
        else: return {"route": "end", "status": "REVIEW_UNAVAILABLE"}
        with r.store.snapshot() as snapshot: contract = snapshot.read(f"contract3:{self.task}")[1]
        emit(self.progress, "CONTRACT_ACTIVE", status="ACTIVE", budget=contract["budget_limit"])
        return {"contract": contract, "route": "decide", "status": "RUNNING", "repairs": 0, "unsupported": []}

    def _renew_contract(self, s):
        emit(self.progress, "CONTRACT_REVIEW", status="RENEW_REQUIRED")
        count = s.get("review_retries", 0) + 1
        return {"route": "preview" if count <= 2 else "end", "review_retries": count,
                "status": "REVIEW_RETRY_EXHAUSTED" if count > 2 else "CONTRACT_REVIEW"}

    def _decide(self, s):
        if s["step"] >= self.max_steps: return {"route": "end", "status": "STEP_LIMIT"}
        role = s["role"]
        if role in s["done"]: role = "executor" if role == "reader" else "reader"
        if role in s["done"]: return {"route": "end", "status": "DONE"}
        with self.runtime.store.snapshot() as snapshot:
            contract = snapshot.read(f"contract3:{self.task}")[1]
            counters = {"spent": snapshot.read(f"budget:{self.task}")[1], "reserved": snapshot.read(f"reserved:{self.task}")[1]}
            catalog = []
            for resource in contract["allowed_resources"]:
                if resource in self.context_resources.values(): continue
                _, doc = snapshot.read(f"document:{resource}")
                if doc: catalog.append({k: doc[k] for k in ("resource", "digest", "version")})
        if self.host_validator:
            try: self.host_validator(contract)
            except ValueError:
                emit(self.progress, "CONTRACT_VALIDATION", status="HOST_SCOPE_REJECTED")
                return {"route": "end", "status": "HOST_SCOPE_REJECTED"}
        sources = []
        for ob in s["observations"]:
            source = ob["detail"].get("source")
            if source and source not in sources: sources.append(source)
        try:
            emit(self.progress, "WORKER", role=role, step=s["step"], observations=len(s["observations"]))
            response = self.bridge.worker(operation_id(self.task + ":" + s["run"], s["step"], role, "inference"), s["run"],
                messages=worker_messages(role, s["goal"], contract, s["observations"], catalog, counters, self.scope_limits), sources=sources,
                context_resource=self.context_resources[role], principal=self.principals[role], task=self.task, purpose=contract["purpose"])
        except Exception as exc:
            emit(self.progress, "WORKER", role=role, status="MODEL_BLOCKED_OR_FAILED", error=type(exc).__name__)
            return {"route": "end", "status": "MODEL_BLOCKED_OR_FAILED", "feedback": [str(exc)]}
        if type(response) is dict and response.get("kind") == "done" and set(response) == {"kind", "summary"} and type(response["summary"]) is str:
            emit(self.progress, "WORKER", role=role, status="DONE")
            done = s["done"] + [role]
            return {"done": done, "role": "executor" if role == "reader" else "reader", "step": s["step"] + 1,
                    "route": "end" if len(done) == 2 else "decide", "status": "DONE" if len(done) == 2 else "RUNNING"}
        if type(response) is dict and response.get("kind") == "contract":
            try: proposal, unsupported = self._proposal(response)
            except ValueError as exc:
                emit(self.progress, "CONTRACT_VALIDATION", role=role, status="HOST_SCOPE_REJECTED")
                return self._observed(s, Observation("REJECTED", "none", {"reason": str(exc)}), role)
            return {"proposal": proposal, "unsupported": unsupported, "route": "preview", "step": s["step"] + 1, "repairs": 0, "review_retries": 0}
        return {"response": response, "role": role, "route": "stage"}

    def _stage(self, s):
        op = operation_id(self.task + ":" + s["run"], s["step"], s["role"], "action")
        try:
            response = s["response"]
            if type(response) is not dict or set(response) != {"kind", "tool", "args"} or response["kind"] != "action":
                raise ValueError("protected/unsupported action response fields")
            request = self.bridge.tools.stage({"tool": response["tool"], "args": response["args"]}, principal=self.principals[s["role"]],
                task=self.task, purpose=s["contract"]["purpose"], operation=op)
            # This node completes and checkpoints before effect can be retried.
            emit(self.progress, "ACTION", role=s["role"], tool=request["tool"], operation=op, status="STAGED")
            return {"pending": request, "grant": None, "route": "effect", "review_retries": 0}
        except Exception as exc:
            emit(self.progress, "ACTION", role=s["role"], status="REJECTED", error=type(exc).__name__)
            return self._observed(s, Observation("REJECTED", op, {"reason": str(exc)}), s["role"])

    def _observed(self, s, observation, role):
        return {"observations": s["observations"] + [observation.json()], "step": s["step"] + 1,
                "role": "executor" if role == "reader" else "reader", "route": "decide", "pending": {}, "grant": None}

    def _effect(self, s):
        result = self.bridge.tools.execute(s["pending"], self.principals[s["role"]], grant=s.get("grant"))
        if result.status == "ESCALATE": return {"review": result.detail, "route": "review", "status": "OPERATION_REVIEW"}
        if self.after_effect: self.after_effect(result)
        return self._observed(s, result, s["role"])

    def _operation_review(self, s):
        review_id = s["review"]["review_id"]
        principal = self.principals[s["role"]]
        review = self.runtime.broker.status(review_id, principal)
        while review["status"] == "PENDING" and review["effective_status"] == "PENDING":
            emit(self.progress, "OPERATION_REVIEW", status="PENDING", review=review_id)
            interrupt({"kind": "operation", "review_id": review_id, "review": review,
                       "note": "Trusted Broker approval required; model/resume text is not a grant."})
            review = self.runtime.broker.status(review_id, principal)
        if review["status"] == "REJECTED":
            return self._observed(s, Observation("DENY", s["pending"]["operation_id"], {"reason": "trusted review rejected"}), s["role"])
        if review["effective_status"] in {"STALE", "EXPIRED"}:
            count = s.get("review_retries", 0) + 1
            if count > 2:
                return self._observed(s, Observation("RETRY_EXHAUSTED", s["pending"]["operation_id"], {"reason": "review renewal bound"}), s["role"])
            return {"grant": None, "route": "effect", "review_retries": count}
        if review["effective_status"] != "APPROVED": raise ValueError("approval unavailable")
        return {"grant": review_id, "route": "effect", "status": "RUNNING"}
