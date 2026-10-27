"""One offline scenario/adapter interface and versioned six-mode replay evidence."""
from dataclasses import asdict
from tempfile import TemporaryDirectory
import json

from nacl.signing import VerifyKey
from atomicroot.authority.ticket import args_hash, canonical_json_bytes, freeze_json
from atomicroot.framework.runtime import validate_request
from atomicroot.sim.replay import ReplayHost, environment, ledger
from atomicroot.sim.scheduler import ReadyScheduler, semantic
from atomicroot.evaluation.modes import configure_evaluation, MODES
from atomicroot.evaluation.oracle import monitor
from atomicroot.observability import Stopwatch, point, protocol_run, event_times

ARTIFACT_FIELDS = ("schema_version", "mode", "workload", "pairing_digest", "environment", "public_key", "initial", "run", "hooks", "events", "terminal_ledger", "oracle", "capabilities", "bindings", "semantic_trace")


def evaluation_schema():
    from atomicroot.framework.task_spec import task_schema
    from atomicroot.sim.scheduler import artifact_schema
    definitions = task_schema()["$defs"]
    definitions["action"] = artifact_schema()["$defs"]["action"]
    properties = {name: {"type": "object"} for name in ARTIFACT_FIELDS}
    properties["observed_timing"] = {"type": "object"}
    properties.update(schema_version={"const": 1}, mode={"enum": list(MODES)}, public_key={"type": "string", "pattern": "^[a-f0-9]{64}$"},
        pairing_digest={"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}, hooks={"type": "array"}, events={"type": "array"},
        workload={"type": "object", "required": ["tasks", "actions", "fixture", "preferred", "ground_truth"], "properties": {
            "tasks": {"type": "array", "items": {"$ref": "#/$defs/task_spec"}},
            "actions": {"type": "array", "maxItems": 2048, "items": {"$ref": "#/$defs/action"}}}})
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:atomicroot:phase5:evaluation:1", "type": "object",
        "required": list(ARTIFACT_FIELDS), "additionalProperties": False, "properties": properties, "$defs": definitions}


class EvaluationAdapter(ReplayHost):
    def __init__(self, directory, workload, mode):
        self.guard_mode = mode
        try:
            super().__init__(directory, workload)
            self._prepare(self.runtime)
            self.initial = {"ledger": ledger(self.runtime.store), "resolved": [self.runtime.tasks.status(t, self.user) for t in self.tasks]}
            # Initialize known operation arrivals before the paired auth wave;
            # global tickets must not be self-staled by lazy ID registration.
            prepared = set()
            for item in workload["actions"]:
                if item["kind"] in {"authorize", "guarded", "forged_consent"} and "read_receipt_from" not in item["data"]:
                    request, principal = self.request(item["data"])
                    request = validate_request(request, principal)
                    identity = (request["task_id"], request["operation_id"])
                    if identity in prepared: continue
                    self.runtime.authority._register_operation(request, args_hash(request))
                    prepared.add(identity)
            self.initial["prepared_ledger"] = ledger(self.runtime.store)
            self.hooks.steps.clear()
        except BaseException:
            if hasattr(self, "connections"): self.close()
            raise

    def _prepare(self, runtime):
        runtime.evaluation_only = True
        configure_evaluation(runtime, self.guard_mode, self.user)
        if not hasattr(self, "capability_archive"): self.capability_archive = runtime.authority.capabilities
        else: runtime.authority.capabilities = self.capability_archive

    def runtime_for(self, action):
        previous = len(self.connections)
        runtime = super().runtime_for(action)
        for connection in self.connections[previous:]: self._prepare(connection)
        return runtime

    def execute(self, action, results):
        if "read_receipt_from" in action.data:
            data = freeze_json(action.data)
            reference = data.pop("read_receipt_from")
            data["args"]["read_receipt"] = results[reference]["detail"]["receipt"]["receipt_id"]
            from atomicroot.sim.scheduler import Action
            action = Action(action.id, action.kind, action.actor, action.depends_on, action.arrival, action.priority, data)
        result = super().execute(action, results)
        if action.kind == "restart":
            self._prepare(self.runtime)
        return result


def semantic_trace(value, public_key):
    if type(value) is dict:
        if set(value) == {"data", "signature"} and "subject" in value["data"]:
            try:
                VerifyKey(bytes.fromhex(public_key)).verify(canonical_json_bytes(value["data"]), bytes.fromhex(value["signature"]))
                return {"data": value["data"], "signature": {"algorithm": "Ed25519", "verified": True,
                        "payload_digest": args_hash(value["data"]), "key_role": "temporary-evaluation-authority"}}
            except Exception: return value
        return {k: semantic_trace(v, public_key) for k, v in semantic(value, public_key).items()}
    if type(value) is list: return [semantic_trace(v, public_key) for v in value]
    return value


def observations(store):
    events = []
    with store.snapshot() as snap:
        for task, agent, tool, raw in snap._conn.execute("SELECT task_id,agent_id,tool,args FROM trace_events ORDER BY seq"):
            args = json.loads(raw)
            events.append({"kind": "INTENT", "task": task, "agent": agent, "tool": tool, "operation": args["operation_id"],
                "args": {k: v for k, v in args.items() if not k.startswith("_") and k != "operation_id"}, "facts": args["_intent_facts"]})
        for task, operation, raw in snap._conn.execute("SELECT task,operation,receipt FROM receiver_receipts ORDER BY rowid"):
            events.append({"kind": "APPLIED", "task": task, "operation": operation, "receipt": json.loads(raw)})
        unknown = [task + ":" + op for task, op in snap._conn.execute("SELECT task,operation FROM outbox WHERE status IN ('UNKNOWN','RELEASING')")]
    # Facts on each intent are captured at that intent's linearization. Applied
    # receipts refer to the matching immutable intent; subsequent policy changes
    # do not retroactively alter the accepted basis.
    return events, unknown


def run(workload, mode, *, expected=None):
    timer = Stopwatch()
    if mode not in MODES: raise ValueError("unknown guard mode")
    if any(a["kind"] == "workflow" for a in workload["actions"]):
        raise ValueError("Phase 5 mechanism manifests schedule protocol boundaries from a TaskSpec plan, not opaque workflow calls")
    with TemporaryDirectory(prefix="atomicroot-phase5-") as directory:
        host = EvaluationAdapter(directory, workload, mode)
        try:
            scheduler = ReadyScheduler(workload["actions"], preferred=workload["preferred"])
            realized = scheduler.run(host.execute, ready=host.ready, exact_schedule=expected)
            realized["trusted_hook_mutations"] = host.hook_mutations
            events, unknown = observations(host.runtime.store)
            attempts = sum(a["kind"] in {"authorize", "guarded", "commit", "forged_consent", "worker_admin"} and a["id"] in realized["observations"] for a in workload["actions"])
            result = {"schema_version": 1, "mode": mode, "workload": freeze_json(workload, max_bytes=4 * 1024 * 1024),
                "pairing_digest": args_hash(workload), "environment": environment(), "public_key": bytes(host.key.verify_key).hex(),
                "initial": host.initial, "run": realized, "hooks": host.hooks.steps, "events": events,
                "terminal_ledger": ledger(host.runtime.store), "oracle": monitor(events, ground_truth=workload["ground_truth"], attempts=attempts, unknown=unknown),
                "capabilities": {subject: asdict(cap) for subject, cap in host.runtime.authority.capabilities.items()},
                "bindings": {"reconstructed": ["temporary trusted Ed25519 key and signatures"], "compared_verbatim": ["identity", "payload/source digests", "operation", "nonce", "expiry", "footprint", "read provenance", "scope/contract basis"],
                    "source": "TaskSpec/plan/delegations from Phase 3.6 resolver; trusted updater fixtures separate from attacker; fake/simulated effects only"}}
            result["oracle"]["unknown_delivery_observations"] = [key for key, value in realized["observations"].items()
                if value.get("status") == "UNKNOWN" or value.get("detail", {}).get("delivery") == "UNKNOWN"]
            result["oracle"]["attempted_logical_operations"] = len({(a["data"]["task"], a["data"]["operation"]) for a in workload["actions"]
                if a["id"] in realized["observations"] and a["kind"] in {"authorize", "guarded", "forged_consent"}})
            result["observed_timing"] = {"schema_version": 1, "run": timer.finish(), "exported_at_utc": point()["observed_at_utc"],
                "events": event_times(events, host.hooks.steps, result["terminal_ledger"]),
                "meaning": "UTC post-transaction observation, not exact linearization time; monotonic counters are local to the recording process"}
            result["semantic_trace"] = semantic_trace(comparable(result), result["public_key"])
            return result
        finally: host.close()


def comparable(artifact):
    value = {k: artifact[k] for k in ("initial", "run", "events", "terminal_ledger", "oracle", "capabilities")}
    value["run"] = protocol_run(value["run"])
    return value


def replay(artifact):
    required = set(ARTIFACT_FIELDS)
    if type(artifact) is not dict or not required <= set(artifact) or set(artifact) - required - {"observed_timing"}:
        raise ValueError("unsupported evaluation artifact fields")
    if artifact["schema_version"] != 1 or artifact["environment"] != environment(): raise ValueError("evaluation schema/environment divergence")
    if artifact["pairing_digest"] != args_hash(artifact["workload"]): raise ValueError("workload binding mismatch")
    if artifact["semantic_trace"] != semantic_trace(comparable(artifact), artifact["public_key"]):
        raise ValueError("evaluation semantic binding mismatch")
    repeated = run(artifact["workload"], artifact["mode"], expected=[s["chosen"] for s in artifact["run"]["schedule"]])
    return {"match": repeated["semantic_trace"] == artifact["semantic_trace"] and not repeated["run"]["divergence"], "artifact": repeated}


def pair(artifacts):
    timer = Stopwatch()
    if len(artifacts) != len(MODES) or {a["mode"] for a in artifacts} != set(MODES): raise ValueError("six distinct modes required")
    if any(a["pairing_digest"] != args_hash(a["workload"]) for a in artifacts): raise ValueError("workload binding mismatch")
    if len({a["pairing_digest"] for a in artifacts}) != 1: raise ValueError("unpaired workload/arrival/priority/fault plan")
    return {"schema_version": 1, "pairing_digest": artifacts[0]["pairing_digest"], "scenario": artifacts[0]["workload"]["name"],
        "observed_timing": {"comparison": timer.finish(), "generated_at_utc": point()["observed_at_utc"]},
        "modes": [{"mode": a["mode"], "schedule": a["run"]["schedule"], "divergence": a["run"]["divergence"], "blocked": a["run"]["blocked"],
                   "recording_window": a.get("observed_timing", {}).get("run"),
                   "oracle": a["oracle"]} for a in artifacts]}
