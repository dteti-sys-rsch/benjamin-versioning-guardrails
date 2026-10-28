"""Trusted intake and reviewed dynamic plans, sharing resolver, Broker and executor A."""
import json
import math

from atomicroot.authority.policy_engine import valid_identity
from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.identity import Principal
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import exact, sequence, text
from atomicroot.framework.tasks import REGISTRY_DIGEST
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.planning import PLANNER_VERSION, ARTIFACT_FIELDS, parse_proposal, proposal_schema, messages
from atomicroot.integration.providers import DisabledClassifier, Limits
from atomicroot.integration.progress import emit
from atomicroot.observability import point, Stopwatch
from atomicroot.sim.model_tape import ModelTape

INTAKE_FIELDS = {"id", "intake_task", "agent", "context_resource", "provider", "model", "purpose", "subject", "targets",
                 "visible_resources", "visible_destinations", "expires", "max_repairs", "max_replans"}


class GoalService:
    def __init__(self, runtime, model=None, *, records=None, progress=None):
        if getattr(runtime, "evaluation_only", False): raise ValueError("goal service requires safe main runtime")
        self.runtime, self.store, self.model, self.progress = runtime, runtime.store, model, progress
        self.records = records
        with self.store._lock:
            self.store._conn.executescript("""
                CREATE TABLE IF NOT EXISTS goal_sessions(id TEXT PRIMARY KEY,owner TEXT NOT NULL,task TEXT NOT NULL,intake TEXT NOT NULL,data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS goal_revisions(session TEXT NOT NULL,revision INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(session,revision));
                CREATE TABLE IF NOT EXISTS goal_calls(operation TEXT PRIMARY KEY,data TEXT NOT NULL);
            """)

    def register_intake(self, config, principal):
        principal.require("admin")
        config = freeze_json(config); exact(config, INTAKE_FIELDS)
        for field in ("id", "intake_task", "agent", "context_resource", "provider", "subject"): valid_identity(config[field])
        text(config["model"]); text(config["purpose"])
        for field in ("targets", "visible_resources", "visible_destinations"):
            for name in sequence(config[field]): text(name)
            if len(set(config[field])) != len(config[field]): raise ValueError("duplicate intake visibility")
        if not config["targets"] or config["intake_task"] in config["targets"]: raise ValueError("business task must differ from intake")
        if type(config["expires"]) not in (int, float) or not math.isfinite(config["expires"]) or config["expires"] <= self.store.now():
            raise ValueError("future intake expiry required")
        for field, maximum in (("max_repairs", 1), ("max_replans", 2)):
            if type(config[field]) is not int or not 0 <= config[field] <= maximum: raise ValueError("invalid planning bound")
        caller = Principal(config["subject"], frozenset({"user"}), frozenset([config["intake_task"], *config["targets"]]))
        active = self.runtime.tasks.status(config["intake_task"], caller)
        spec = active["resolved"]["spec"] if active["resolved"] else None
        if not spec or spec["provider"] != {"destination": config["provider"], "model": config["model"]} or spec["purpose"] != config["purpose"]:
            raise ValueError("intake requires its own reviewed provider TaskSpec")
        agent = next((a for a in spec["agents"] if a["id"] == config["agent"]), None)
        if not agent or any(r["tool"] not in {"model_inference", "read_document"} for r in spec["scope"]):
            raise ValueError("intake delegates planning/reads only, never business tools")
        if not any(r["resource"] == config["context_resource"] and r.get("binding") == "host_context" for r in spec["resources"]):
            raise ValueError("reviewed host context required")
        with self.store.transaction() as conn:
            if self.store.value(conn, "taskresolved:" + config["intake_task"])[1] != active["binding"]:
                raise ValueError("intake changed during registration")
            self.store.put(conn, "goalintake:" + config["id"], config)
            self.store.audit(conn, "GOAL_INTAKE_REGISTERED", principal.subject, {"id": config["id"], "digest": args_hash(config)})
        return {"status": "REGISTERED", "id": config["id"], "digest": args_hash(config)}

    def _intake(self, intake, task, principal, snap):
        valid_identity(intake); valid_identity(task)
        principal.require("user", task=task)
        config = snap.read("goalintake:" + intake)[1]
        if not config or config["subject"] != principal.subject or task not in config["targets"]:
            raise PermissionError("no authorized intake for caller/target")
        principal.require("user", task=config["intake_task"])
        if self.store.now() >= config["expires"]: raise PermissionError("intake expired")
        return config

    def discover(self, intake, task, principal):
        with self.store.snapshot() as snap:
            config = self._intake(intake, task, principal, snap)
            rights = snap.read(f"entitlement:{task}:{principal.subject}")[1]
            if not rights: raise PermissionError("no target entitlement")
            scope = [r for r in rights["scope"] if
                (r["resource"] is None or r["resource"] in config["visible_resources"]) and
                (r["destination"] is None or r["destination"] in config["visible_destinations"])]
            resources = []
            for name in sorted({r["resource"] for r in scope if r["resource"]}):
                doc, label = snap.read("document:" + name)[1], snap.read("label:" + name)[1]
                if doc and label: resources.append({"resource": name, "digest": doc["digest"], "version": doc["version"], "label": label["label"]})
            destinations = [snap.read("destination:" + name)[1] for name in sorted({r["destination"] for r in scope if r["destination"]})]
            if any(d is None for d in destinations): raise ValueError("catalog destination unavailable")
            return {"scope": scope, "resources": resources, "destinations": destinations, "budget_limit": rights["budget_limit"],
                "max_agents": rights["max_agents"], "limits": rights["limits"], "registry_digest": REGISTRY_DIGEST,
                "visibility": "authorized metadata only; content requires an explicit guarded read"}

    def _session(self, session, principal):
        valid_identity(session)
        with self.store.snapshot() as snap:
            row = self.store.row(snap._conn, "SELECT * FROM goal_sessions WHERE id=?", (session,))
        if not row or row["owner"] != principal.subject: raise PermissionError("goal session not owned by caller")
        principal.require("user", task=row["task"])
        return {**row, "data": json.loads(row["data"])}

    def _revision(self, session, revision=None):
        with self.store.snapshot() as snap:
            row = snap._conn.execute("SELECT revision,data FROM goal_revisions WHERE session=? " +
                ("ORDER BY revision DESC LIMIT 1" if revision is None else "AND revision=?"),
                (session,) if revision is None else (session, revision)).fetchone()
        if not row: raise ValueError("unknown goal revision")
        return json.loads(row[1])

    def _save(self, session, data):
        with self.store.transaction() as conn:
            conn.execute("UPDATE goal_revisions SET data=? WHERE session=? AND revision=?", (dumps(data), session, data["revision"]))

    def plan(self, session, goal, intake, task, principal, *, context_resources=(), replan=False, recover=False):
        valid_identity(session); text(goal, 2048)
        context_resources = list(context_resources)
        for name in sequence(context_resources): valid_identity(name)
        if len(set(context_resources)) != len(context_resources): raise ValueError("duplicate context source")
        catalog = self.discover(intake, task, principal)
        with self.store.snapshot() as snap: config = self._intake(intake, task, principal, snap)
        request = {"goal": goal, "context_resources": context_resources}
        previous, recovering = None, None
        if replan and recover: raise ValueError("recover and replan are distinct operations")
        with self.store.transaction() as conn:
            row = self.store.row(conn, "SELECT * FROM goal_sessions WHERE id=?", (session,))
            if row:
                if (row["owner"], row["task"], row["intake"], row["data"]) != (principal.subject, task, intake, dumps(request)):
                    raise ValueError("session binding changed; original goal/context cannot be replaced")
                old = conn.execute("SELECT revision,data FROM goal_revisions WHERE session=? ORDER BY revision DESC LIMIT 1", (session,)).fetchone()
                if not replan and not recover: return json.loads(old[1])
                if recover:
                    recovering = json.loads(old[1])
                    if recovering["status"] not in {"PLANNING", "PLANNING_FAILED"}: return recovering
                    if recovering["catalog"] != catalog or recovering["intake"] != config:
                        raise ValueError("planning context changed; explicit new revision required")
                    revision = old[0]
                    if recovering["previous_revision"] is not None:
                        previous = json.loads(conn.execute("SELECT data FROM goal_revisions WHERE session=? AND revision=?", (session, recovering["previous_revision"])).fetchone()[0])
                else:
                    previous = json.loads(old[1]); revision = old[0] + 1
                if previous and previous["status"] == "PLANNING": raise ValueError("planning in progress; no concurrent replan")
                if self.store.value(conn, "goalexecuting:" + task)[1]: raise ValueError("recover running goal before replan")
                old_run = previous.get("execution", {}).get("run") if previous else None
                if old_run:
                    state = conn.execute("SELECT status FROM execution_runs WHERE task=? AND run=?", (task, old_run)).fetchone()
                    if state and state[0] in {"RUNNING", "REVIEW_WAIT", "DELIVERY_UNKNOWN"}: raise ValueError("resume/reconcile previous run before replanning")
                if revision > config["max_replans"]: raise ValueError("replan bound exhausted")
            else:
                if replan or recover: raise ValueError("no original goal")
                revision = 0
                conn.execute("INSERT INTO goal_sessions VALUES (?,?,?,?,?)", (session, principal.subject, task, intake, dumps(request)))
            data = recovering or {"revision": revision, "status": "PLANNING", "catalog": catalog, "catalog_digest": args_hash(catalog),
                "intake": config, "schema_digest": args_hash(proposal_schema()), "prompt_version": PLANNER_VERSION,
                "registry_digest": REGISTRY_DIGEST, "calls": [], "created": point(), "previous_revision": previous["revision"] if previous else None}
            if not recovering:
                conn.execute("INSERT INTO goal_revisions VALUES (?,?,?)", (session, revision, dumps(data)))
                self.store.put(conn, "goalhead:" + session, {"revision": revision, "goal_digest": args_hash(request)})
            else:
                data["status"] = "PLANNING"; data.pop("error", None)
            if self.store.value(conn, "goalexecuting:" + task)[1] is None: self.store.put(conn, "goalexecuting:" + task, False, initial=True)
        timer = Stopwatch()
        try:
            if self.model is None: raise ValueError("trusted planner driver not configured")
            if (self.model.provider, self.model.model) != (config["provider"], config["model"]): raise ValueError("planner model differs from intake")
            active = self.runtime.tasks.status(config["intake_task"], principal)
            spec = active["resolved"]["spec"]
            limits = Limits(**spec["limits"]["inference"])
            data["intake_binding"] = {"spec_digest": active["resolved"]["spec_digest"], "limits": vars(limits),
                "endpoint": active["resolved"]["destinations"][config["provider"]]["endpoint"]}
            if self.model.live:
                if self.model.provider != "ollama" and limits.spend_cap_usd is None:
                    raise PermissionError("paid live planning requires explicitly verified pricing/spend bounds")
                from atomicroot.integration.providers import model_configuration
                endpoint = model_configuration(self.model.provider, self.model.model)["endpoint"]
                if endpoint != active["resolved"]["destinations"][config["provider"]]["endpoint"]: raise ValueError("planner endpoint differs from approved intake")
            saved_records = dict(self.records or data.get("model_records", {}))
            if recovering:
                with self.store.snapshot() as snap:
                    for operation in data["calls"]:
                        row = snap._conn.execute("SELECT data FROM goal_calls WHERE operation=?", (operation,)).fetchone()
                        if row: saved_records.update(json.loads(row[0]).get("model_records", {}))
            tape = self.model if isinstance(self.model, ModelTape) else ModelTape(provider=self.model.provider, model=self.model.model,
                prompt_version=PLANNER_VERSION, delegate=self.model, records=saved_records)
            bridge = ModelBridge(self.runtime, tape, DisabledClassifier(), llm_limits=limits, progress=self.progress, budget="goal:" + session)
            agent = self.runtime.tasks.principal(config["intake_task"], config["agent"], principal)
            sources, contents = [], []
            for name in context_resources:
                ref = next((r for r in spec["resources"] if r["resource"] == name and r.get("binding") != "host_context"), None)
                if not ref or name not in config["visible_resources"]: raise PermissionError("context read outside intake")
                operation = "goal-read-" + args_hash({"session": session, "revision": revision, "resource": name})[7:47]
                observation = bridge.tools.execute({"task_id": config["intake_task"], "agent_id": agent.subject, "operation_id": operation,
                    "tool": "read_document", "purpose": config["purpose"], "args": {"resource": name, "digest": ref["digest"]}}, agent)
                if observation.status != "COMMITTED" or observation.detail.get("delivery") != "RELEASED": raise ValueError("context read unavailable")
                receipt = observation.detail["receipt"]
                contents.append({"resource": name, "untrusted_content": receipt["result"]["content"]})
                sources.append({"resource": name, "digest": ref["digest"]})
            error, draft = None, None
            for attempt in range(config["max_repairs"] + 1):
                prompt_catalog = {**catalog, "planning_constraints": data["intake_binding"], **({"authorized_context": contents} if contents else {})}
                prompt = messages(goal, task, prompt_catalog, previous=previous.get("proposal") if previous else None, error=error, draft=draft)
                planning = {"session": session, "revision": revision, "attempt": attempt, "intake": intake,
                    "intake_digest": args_hash(config), "schema_digest": args_hash(proposal_schema())}
                operation = "plan-" + args_hash(planning)[7:47]
                context = {"messages": prompt, "sources": sources, "provider": self.model.provider,
                    "model": self.model.model, "prompt_version": PLANNER_VERSION, "planning": planning}
                call = {"planning": planning, "context_hash": args_hash(context), "context": context}
                with self.store.transaction() as conn:
                    conn.execute("INSERT OR IGNORE INTO goal_calls VALUES (?,?)", (operation, dumps(call)))
                if operation not in data["calls"]: data["calls"].append(operation)
                self._save(session, data)
                output = bridge.worker(operation, "goal:" + session, messages=prompt, sources=sources,
                    context_resource=config["context_resource"], principal=agent, task=config["intake_task"], purpose=config["purpose"], planning=planning)
                call.update(output=output, model_records=tape.records, observed=point())
                with self.store.transaction() as conn: conn.execute("UPDATE goal_calls SET data=? WHERE operation=?", (dumps(call), operation))
                try:
                    proposal = parse_proposal(output, task, goal)
                    if proposal["status"] != "PROPOSAL":
                        data.update(status=proposal["status"], proposal=proposal); break
                    if not {r["resource"] for r in proposal["spec"]["resources"]} <= {r["resource"] for r in catalog["resources"]}:
                        raise ValueError("proposal resource outside discovered catalog")
                    fields = ("tool", "resource", "destination", "purpose")
                    if any(not any(all(r[k] == allowed[k] for k in fields) for allowed in catalog["scope"]) for r in proposal["spec"]["scope"]):
                        raise ValueError("proposal outside discovered scope")
                    if previous and previous.get("proposal", {}).get("spec"):
                        old = previous["proposal"]["spec"]
                        if any(c not in proposal["spec"]["acceptance"] for c in old["acceptance"]): raise ValueError("replan cannot remove original completion requirements")
                        if any(p not in proposal["spec"]["policies"] for p in old["policies"]): raise ValueError("replan cannot remove approved goal policy")
                    valid = self.runtime.tasks.validate(proposal["spec"], principal)
                    if not valid["valid"]: raise ValueError("; ".join(valid["unsupported"]))
                    # Every material plan is explicitly reviewed, including extra scope.
                    provenance = {"proposal": proposal, "goal_digest": args_hash(request), "catalog_digest": data["catalog_digest"], "prompt": PLANNER_VERSION}
                    with self.store.transaction() as conn:
                        key = f"goalproposal:{session}:{revision}"
                        self.store.put(conn, key, provenance)
                        head = self.store.value(conn, "goalhead:" + session)[1]
                        executing = self.store.value(conn, "goalexecuting:" + task)[1]
                    if head["revision"] != revision: raise ValueError("goal revision superseded")
                    if executing: raise ValueError("resume/reconcile running goal before plan preview")
                    preview = self.runtime.tasks.propose(proposal["spec"], principal,
                        review_bindings={key: args_hash(provenance), "goalhead:" + session: args_hash(head), "goalexecuting:" + task: args_hash(executing)})
                    data.update(status="REVIEW_WAIT", proposal=proposal, preview=preview,
                        warnings=["Minimum scope and goal alignment require review; valid DSL is not semantic intent proof."],
                        resolved_digest=valid["digest"])
                    required = {c["tool"] if c["kind"] == "receipt" else "read_document" for c in proposal["spec"]["acceptance"] if c["kind"] != "output"}
                    if "update_document" in required: required.add("read_document")
                    if proposal["spec"]["provider"]: required.add("model_inference")
                    if proposal["spec"]["classifier"]["mode"] != "disabled": required.add("classify_document")
                    extra = [r for r in proposal["spec"]["scope"] if r["tool"] not in required]
                    if extra: data["warnings"].append({"kind": "EXTRA_SCOPE_REQUIRES_JUSTIFICATION", "rules": extra,
                        "reason": "not referenced by registered completion criteria or their mandatory dependencies"})
                    break
                except (ValueError, KeyError, TypeError) as exc:
                    error = str(exc)[:256]
                    raw = output.get("spec") if type(output) is dict else None
                    # Replan already carries the complete prior proposal. Avoid
                    # duplicating it in diagnostic hints under the content cap.
                    draft = {k: raw[k] for k in ("resources", "scope", "agents", "workflow", "provider", "outputs", "acceptance")
                        if k in raw} if type(raw) is dict and previous is None else None
                    data.setdefault("validation_errors", []).append({"attempt": attempt, "error": error})
                    if attempt == config["max_repairs"]: data.update(status="INVALID_PROPOSAL", error=error)
            data["model_records"] = tape.records
        except Exception as exc:
            data.update(status="PLANNING_FAILED", error=type(exc).__name__)
            if "tape" in locals(): data["model_records"] = tape.records
            if "operation" in locals() and "call" in locals():
                call.update(error=type(exc).__name__, observed=point())
                with self.store.transaction() as conn: conn.execute("UPDATE goal_calls SET data=? WHERE operation=?", (dumps(call), operation))
        data["observed_timing"] = timer.finish()
        self._save(session, data)
        emit(self.progress, "GOAL_PLAN", status=data["status"], repairs=len(data.get("validation_errors", [])))
        return data

    def status(self, session, principal, *, private=False):
        if private and "approver" in principal.roles:
            with self.store.snapshot() as snap: row = self.store.row(snap._conn, "SELECT * FROM goal_sessions WHERE id=?", (session,))
            if not row: raise ValueError("unknown goal session")
            principal.require("approver", task=row["task"])
            record = {**row, "data": json.loads(row["data"])}
        else: record = self._session(session, principal)
        data = self._revision(session)
        if private: return {"session": session, "task": record["task"], "request": record["data"], **data}
        return {"session": session, "task": record["task"], "revision": data["revision"], "status": data["status"],
            "review_id": data.get("preview", {}).get("review_id"), "execution_status": data.get("execution", {}).get("status"),
            "observed_timing": data.get("observed_timing")}

    def decide(self, session, decision, principal):
        if decision not in {"approve", "reject", "pause"}: raise ValueError("unknown decision")
        data = self._revision(session)
        with self.store.snapshot() as snap: row = self.store.row(snap._conn, "SELECT task FROM goal_sessions WHERE id=?", (session,))
        if not row: raise ValueError("unknown goal")
        principal.require("approver", task=row["task"])
        if data["status"] != "REVIEW_WAIT": raise ValueError("goal is not awaiting review")
        review = data["preview"]["review_id"]
        if decision == "pause": return {"status": "PAUSED", "review_id": review}
        result = self.runtime.broker.decide(review, decision == "approve", principal)
        if decision == "reject": data["status"] = "REJECTED"; self._save(session, data)
        return result

    def activate(self, session, principal):
        data = self._revision(session)
        preview = data.get("preview")
        if data["status"] != "REVIEW_WAIT" or not preview: raise ValueError("goal has no activatable preview")
        self._continuation(session, data)
        result = self.runtime.contracts.activate(preview["proposal_id"], preview["review_id"], principal)
        data.update(status="ACTIVE", active=result); self._save(session, data)
        return result

    def _continuation(self, session, data):
        """Reconcile committed effects and explicitly cancel uncommitted old stages."""
        if data["previous_revision"] is None: return None
        previous = self._revision(session, data["previous_revision"])
        run = previous.get("execution", {}).get("run")
        if not run: return None
        task = data["proposal"]["spec"]["task_id"]
        with self.store.snapshot() as snap:
            row = snap._conn.execute("SELECT status FROM execution_runs WHERE task=? AND run=?", (task, run)).fetchone()
            if row and row[0] in {"RUNNING", "REVIEW_WAIT", "DELIVERY_UNKNOWN"}: raise ValueError("resume/reconcile previous run before plan activation")
            if snap._conn.execute("SELECT 1 FROM outbox WHERE task=? AND status IN ('PENDING','RELEASING','UNKNOWN')", (task,)).fetchone():
                raise ValueError("pending committed effects require reconciliation before replan")
            rows = snap._conn.execute("SELECT a.node,a.operation,a.data,b.status FROM execution_actions a LEFT JOIN outbox b ON b.task=a.task AND b.operation=a.operation WHERE a.task=? AND a.run=?", (task, run)).fetchall()
            carried = [row[0] for row in snap._conn.execute("SELECT node FROM execution_carryover WHERE task=? AND run=?", (task, run))]
        retained = set(carried) | set(previous.get("execution", {}).get("retained_nodes", []))
        cancelled = []
        for node, op, raw, status in rows:
            action = json.loads(raw)
            if status is None: cancelled.append(op)
            elif status == "RELEASED" and action.get("tool") not in {"read_document", "model_inference", "classify_document"}: retained.add(node)
        old, new = previous["proposal"]["spec"], data["proposal"]["spec"]
        for node in retained:
            definition = next(n for n in old["workflow"]["nodes"] if n["id"] == node)
            agent = next(a for a in old["agents"] if a["id"] == definition["agent"])
            if definition not in new["workflow"]["nodes"] or agent not in new["agents"]:
                raise ValueError("committed business node/identity must be retained unchanged")
        return {"run": run, "retained_nodes": sorted(retained), "cancelled_uncommitted_operations": cancelled}

    def execute(self, session, principal, factory, *, command="start"):
        from atomicroot.integration.config_workflow import invocation_lock
        record = self._session(session, principal)
        workflow = factory(record["task"], principal, "goal:" + session)
        try:
            # Reuse executor invocation exclusion, never a business-state gate.
            # A concurrent recover cannot clear another invocation's control flag.
            path = workflow.path.parent / ("goal-" + args_hash({"task": record["task"]})[7:39] + ".lock")
            with invocation_lock(path): return self._execute(session, principal, workflow, command=command)
        finally: workflow.close()

    def _execute(self, session, principal, workflow, *, command):
        record = self._session(session, principal)
        data = self._revision(session)
        if data["status"] != "ACTIVE": raise ValueError("activate exact reviewed goal plan before execution")
        if command not in {"start", "recover", "resume", "status"}: raise ValueError("unknown execution command")
        current = self.runtime.tasks.status(record["task"], principal)
        if current["resolved"]["spec"] != data["proposal"]["spec"]: raise ValueError("active goal plan changed; new preview required")
        budget = "goal:" + session
        run = "goal-" + args_hash({"session": session, "revision": data["revision"]})[7:39]
        if command != "status":
            with self.store.transaction() as conn:
                guard = self.store.value(conn, "goalexecuting:" + record["task"])[1]
                if guard and (command == "start" or guard.get("session") != session or guard.get("revision") != data["revision"]):
                    raise ValueError("goal execution already active; recover the same run")
                latest = conn.execute("SELECT revision FROM goal_revisions WHERE session=? ORDER BY revision DESC LIMIT 1", (session,)).fetchone()[0]
                if latest != data["revision"]: raise ValueError("goal revision changed before execution")
                self.store.put(conn, "goalexecuting:" + record["task"], {"session": session, "revision": data["revision"], "run": run})
            data["execution"] = {**data.get("execution", {}), "run": run, "status": "RUNNING"}
            self._save(session, data)
        try:
            if workflow.bridge:
                workflow.bridge.budget = budget
                workflow.bridge.memo.aggregate_budget = budget
                intake = self.runtime.tasks.status(data["intake"]["intake_task"], principal)["resolved"]["spec"]["limits"]["inference"]
                models = [(workflow.bridge.model, workflow.bridge.llm_limits)]
                if workflow.spec["classifier"]["mode"] != "disabled": models.append((workflow.bridge.receiver.classifier, workflow.bridge.receiver.jev_limits))
                for model, limits in models:
                    caps = vars(limits)
                    for field in ("max_calls", "max_tokens", "max_output_tokens", "max_retries", "timeout"):
                        if caps[field] > intake[field]: raise ValueError("worker/classifier cap exceeds intake session bound")
                    for field in ("input_price_per_million", "output_price_per_million", "spend_cap_usd"):
                        if caps[field] != intake[field]: raise ValueError("session pricing/spend binding changed")
                    if model.live and model.provider != "ollama" and caps["spend_cap_usd"] is None:
                        raise PermissionError("paid live execution requires verified pricing/spend bounds")
                if workflow.bridge.model.live and workflow.bridge.model.provider != "ollama" and (workflow.bridge.model.provider, workflow.bridge.model.model) != (data["intake"]["provider"], data["intake"]["model"]):
                    raise ValueError("new paid provider/model requires its own verified intake pricing binding")
            continuation = self._continuation(session, data) if command == "start" else None
            if command == "start": workflow.start(run, continuation=continuation)
            elif command != "status": getattr(workflow, command)(run)
            result = workflow.status(run)
            data["execution"] = {**data.get("execution", {}), "status": result["status"], "completion": result.get("completion"), **(continuation or {}), "run": run}
            self._save(session, data)
            return result
        finally:
            if command != "status":
                with self.store.transaction() as conn: self.store.put(conn, "goalexecuting:" + record["task"], False)

    def export(self, session, principal):
        record = self._session(session, principal)
        data = self._revision(session)
        with self.store.snapshot() as snap:
            history = [json.loads(row[0]) for row in snap._conn.execute("SELECT data FROM goal_revisions WHERE session=? ORDER BY revision", (session,))]
        value = {"schema_version": 1, "request": {"session": session, "task": record["task"], "intake": record["intake"], **record["data"]},
            "planning": data, "history": history, "replay_scope": "initial intake replay or frozen latest-revision resolution; executor/checkpoint replay uses A",
            "reconstructed": ["temporary signing key and fresh protocol tickets", "resolved proposal/review IDs"],
            "binding_preserved": ["goal/context/catalog", "provider/model/prompt/schema", "request payload and resource versions", "intake expiry; ticket/review expiry is reconstructed"], "exported": point()}
        return {**value, "digest": args_hash(value)}

    def replay(self, artifact, principal):
        artifact = freeze_json(artifact, max_bytes=4 * 1024 * 1024)
        if not ARTIFACT_FIELDS <= set(artifact) or set(artifact) - ARTIFACT_FIELDS - {"history"}: raise ValueError("unsupported goal replay fields")
        if artifact.get("schema_version") != 1 or artifact.get("digest") != args_hash({k: v for k, v in artifact.items() if k != "digest"}):
            raise ValueError("goal replay artifact binding mismatch")
        request, original = artifact["request"], artifact["planning"]
        with self.store.snapshot() as snap:
            if snap._conn.execute("SELECT 1 FROM goal_sessions WHERE id=?", (request["session"],)).fetchone():
                raise ValueError("replay requires a fresh prepared database/session, never a cached result")
        if original["catalog"] != self.discover(request["intake"], request["task"], principal): raise ValueError("replay catalog/environment divergence")
        if original["schema_digest"] != args_hash(proposal_schema()) or original["registry_digest"] != REGISTRY_DIGEST or original["prompt_version"] != PLANNER_VERSION:
            raise ValueError("replay schema/registry/prompt divergence")
        with self.store.snapshot() as snap: config = self._intake(request["intake"], request["task"], principal, snap)
        if config != original["intake"]: raise ValueError("replay intake scope/expiry divergence")
        if "intake_binding" in original:
            active = self.runtime.tasks.status(config["intake_task"], principal)["resolved"]
            binding = {"spec_digest": active["spec_digest"], "limits": active["spec"]["limits"]["inference"],
                "endpoint": active["destinations"][config["provider"]]["endpoint"]}
            if binding != original["intake_binding"]: raise ValueError("replay intake plan/endpoint/caps divergence")
        if original["revision"] != 0: return self._replay_revision(artifact, principal)
        tape = ModelTape(provider=original["intake"]["provider"], model=original["intake"]["model"],
            prompt_version=PLANNER_VERSION, records=original["model_records"])
        service = GoalService(self.runtime, tape, progress=self.progress)
        repeated = service.plan(request["session"], request["goal"], request["intake"], request["task"], principal,
            context_resources=request["context_resources"])
        expected = "REVIEW_WAIT" if original["status"] in {"ACTIVE", "REJECTED"} else original["status"]
        return {"match": repeated.get("proposal") == original.get("proposal") and repeated["status"] == expected, "result": repeated}

    def _replay_revision(self, artifact, principal):
        """Replay bound responses against a matching prepared current snapshot.

        This is frozen B-to-A resolution, not restoration of historical ledgers,
        grants, calls or deliveries. Approval IDs and review are always new.
        """
        import asyncio
        request, original = artifact["request"], artifact["planning"]
        history = artifact.get("history", [])
        revision = original["revision"]
        if len(history) != revision + 1 or history[-1] != original or [h["revision"] for h in history] != list(range(revision + 1)):
            raise ValueError("complete bound proposal revision history required")
        if not original.get("proposal") or original["proposal"]["status"] != "PROPOSAL":
            raise ValueError("frozen revision resolution requires an executable proposal; failure recording remains available")
        previous = history[-2].get("proposal")
        tape = ModelTape(provider=original["intake"]["provider"], model=original["intake"]["model"],
            prompt_version=PLANNER_VERSION, records=original["model_records"])
        matched = False
        for record in sorted(tape.records.values(), key=lambda r: (r["binding"]["context_digest"], r["binding"]["ordinal"])):
            binding = record["binding"]
            context = json.loads(binding["messages"][-1]["content"])
            supplied = context["allowed_catalog"]
            if supplied.get("planning_constraints") != original.get("intake_binding"):
                raise ValueError("frozen intake endpoint/caps binding mismatch")
            catalog = {k: v for k, v in supplied.items() if k not in {"authorized_context", "planning_constraints"}}
            try: response = asyncio.run(tape.generate(binding["messages"], response_schema=binding["response_schema"]))
            except RuntimeError:
                if "error" in record: continue
                raise
            if context["goal"] != request["goal"] or context["target_task"] != request["task"] or catalog != original["catalog"] or context.get("previous") != previous:
                continue  # An archive may also contain validated responses from earlier revisions.
            try: candidate = parse_proposal(response["output"], request["task"], request["goal"])
            except (ValueError, TypeError, KeyError): continue  # Recorded invalid repair attempt remains in the artifact.
            if candidate == original["proposal"]: matched = True
        if not matched: raise ValueError("no exact recorded response for this proposal")
        proposal = original["proposal"]
        if previous and previous.get("spec"):
            for field in ("acceptance", "policies"):
                if any(item not in proposal["spec"][field] for item in previous["spec"][field]): raise ValueError("replayed revision removed a requirement")
        valid = self.runtime.tasks.validate(proposal["spec"], principal)
        if not valid["valid"]: raise ValueError("replay resolution rejected: " + "; ".join(valid["unsupported"]))
        key = f"goalproposal:replay-{request['session']}:{revision}"
        evidence = {"artifact_digest": artifact["digest"], "proposal": proposal, "mode": "frozen revision resolution"}
        with self.store.transaction() as conn: self.store.put(conn, key, evidence)
        preview = self.runtime.tasks.propose(proposal["spec"], principal, review_bindings={key: args_hash(evidence)})
        return {"match": True, "result": {"status": "REVIEW_WAIT", "proposal": proposal, "preview": preview,
            "scope": "frozen latest revision via A; historical grants/effects are not replayed as new actions", "network_calls": 0}}
