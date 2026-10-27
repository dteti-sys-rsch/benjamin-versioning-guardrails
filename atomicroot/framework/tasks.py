"""Trusted TaskSpec resolution, admin catalog, and atomic contract attachment."""
import json
from dataclasses import asdict

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.authority.policy_engine import (
    And, Or, Eq, Le, Const, SetConst, Member, Subset, Ref, RequestField, RequestAmount, StatusReader, solve, money_integer, valid_identity,
)
from atomicroot.framework.identity import Principal
from atomicroot.framework.registry import TOOLS, SOURCES, RESOLUTION_RECORDS
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import TaskSpec, exact, text, sequence, rules
from atomicroot.framework.schema import schema


REGISTRY_DIGEST = args_hash({"tools": [asdict(t) | {"required": sorted(t.required)} for t in TOOLS.values()],
    "request_schema": schema()["$defs"]["request"],
    "structured_sources": RESOLUTION_RECORDS,
    "sources": [{"name": name, "prefix": s.prefix, "identity": s.identity, "type": s.value_type} for name, s in SOURCES.items()]})


def scope_expression(scope, *, resource=None):
    """Correlated tuples are encoded in the existing AST; Z3 decides scope."""
    return Or(tuple(And((Eq(RequestField("tool"), Const(r["tool"])),
        Eq(RequestField("resource") if resource is None else Const(resource), Const(r["resource"] or "")),
        Eq(RequestField("recipient"), Const(r["destination"] or "")),
        Eq(RequestField("purpose"), Const(r["purpose"])), Le(RequestAmount(), Const(r["max_amount"])))) for r in scope))


def rule_request(task, rule):
    return {"task_id": task, "tool": rule["tool"], "resource": rule["resource"] or "",
            "recipient": rule["destination"] or "", "purpose": rule["purpose"], "args": {"amount": rule["max_amount"]}}


class TrustedCatalog:
    def __init__(self, store): self.store = store

    def set_destination(self, data, principal):
        principal.require("admin")
        data = freeze_json(data)
        exact(data, {"destination", "kind", "purposes", "endpoint", "models", "labels"})
        text(data["destination"])
        if type(data["kind"]) is not str or data["kind"] not in {"recipient", "provider"}: raise ValueError("invalid destination kind")
        for name in ("purposes", "models", "labels"):
            sequence(data[name], 16)
            for v in data[name]: text(v)
            if len(set(data[name])) != len(data[name]): raise ValueError("duplicate destination metadata")
        if not data["purposes"]: raise ValueError("explicit destination purposes required")
        if data["kind"] == "recipient":
            if data["endpoint"] is not None or data["models"] or data["labels"]:
                raise ValueError("recipient is not an inference provider")
        else:
            # Fixed supported adapter endpoints, selected by trusted admin only.
            endpoints = {"ollama": "http://localhost:11434/api", "groq": "https://api.groq.com/openai/v1",
                         "openai": "https://api.openai.com/v1", "9router": "http://localhost:20128/v1",
                         "typesafe": "https://api.typesafe.ai"}
            if data["destination"] not in endpoints or data["endpoint"] != endpoints[data["destination"]]:
                raise ValueError("unsupported provider endpoint")
            if not data["models"] or not data["labels"] or not set(data["labels"]) <= {"PUBLIC", "SENSITIVE", "UNKNOWN"}:
                raise ValueError("explicit provider model/data scope required")
        with self.store.transaction() as conn:
            key = "destination:" + data["destination"]
            if self.store.value(conn, key)[1] is None:
                members = self.store.value(conn, "catalog:destinations")[1] or []
                if len(members) >= 64: raise ValueError("catalog membership bound")
                self.store.put(conn, "catalog:destinations", sorted(members + [data["destination"]]))
            self.store.put(conn, key, data)
            self.store.audit(conn, "DESTINATION_UPDATED", principal.subject, data)

    def set_entitlement(self, task, subject, data, principal):
        principal.require("admin")
        valid_identity(task); valid_identity(subject)
        data = freeze_json(data)
        exact(data, {"scope", "budget_limit", "max_agents", "limits"})
        data["scope"] = rules(data["scope"])
        money_integer(data["budget_limit"])
        if type(data["max_agents"]) is not int or not 1 <= data["max_agents"] <= 16: raise ValueError("invalid agent bound")
        exact(data["limits"], {"max_steps", "max_in_flight", "max_calls", "max_tokens", "max_output_tokens", "max_retries", "timeout"})
        for value in data["limits"].values():
            if type(value) is not int or not 0 <= value <= 1_000_000: raise ValueError("integer entitlement limit required")
        with self.store.transaction() as conn:
            self.store.put(conn, f"entitlement:{task}:{subject}", data)
            self.store.audit(conn, "ENTITLEMENT_UPDATED", principal.subject, {"task": task, "subject": subject, "entitlement": data})

    def status(self, principal):
        principal.require("admin")
        with self.store.snapshot() as snapshot:
            return {"membership_version": snapshot.version("catalog:destinations"),
                    "destinations": [snapshot.read("destination:" + d)[1] for d in snapshot.read("catalog:destinations", [])[1]],
                    "registry_digest": REGISTRY_DIGEST, "tool_requests": schema()["$defs"]["request"],
                    "structured_sources": RESOLUTION_RECORDS}


def artifact(snapshot, binding):
    exact(binding, {"id", "digest"})
    valid_identity(binding["id"])
    text(binding["digest"])
    row = snapshot._conn.execute("SELECT digest,data FROM resolved_tasks WHERE id=?", (binding["id"],)).fetchone()
    if row is None or row[0] != binding["digest"]: raise ValueError("unknown resolved task binding")
    data = json.loads(row[1])
    if args_hash(data) != row[0] or data["registry_digest"] != REGISTRY_DIGEST:
        raise ValueError("resolved task/registry binding mismatch")
    return data


def contract_attachment(snapshot, proposal):
    mode = snapshot.read(f"taskmode:{proposal['task_id']}")[1]
    binding = proposal.get("task_binding")
    if mode is None and binding is None: return None
    if mode is None or binding is None: raise ValueError("managed task requires resolved binding")
    data = artifact(snapshot, binding)
    if data["owner"] != mode["owner"] or data["contract"] != {k: v for k, v in proposal.items() if k != "task_binding"}:
        raise ValueError("resolved contract mismatch; request new resolution")
    return data


def activate_attachment(store, conn, proposal):
    from atomicroot.store.trace_store import Snapshot
    data = contract_attachment(Snapshot(conn), proposal)
    if data is None: return
    task = proposal["task_id"]
    old_members = store.value(conn, f"agents:{task}")[1] or []
    members = [a["principal"] for a in data["agents"]]
    store.put(conn, f"agents:{task}", sorted(members))
    for agent in data["agents"]:
        store.put(conn, f"delegation:{task}:{agent['principal']}", agent)
    for removed in set(old_members) - set(members):
        store.put(conn, f"delegation:{task}:{removed}", {"scope": [], "role": "revoked", "principal": removed})
    store.put(conn, f"taskresolved:{task}", proposal["task_binding"])


class TaskService:
    def __init__(self, store, contracts): self.store, self.contracts = store, contracts

    def _resolve(self, value, principal, snapshot):
        spec = TaskSpec.parse(value)
        data = spec.data
        task = data["task_id"]
        principal.require("user", task=task)
        reader = StatusReader(snapshot, SOURCES)
        mode_key = f"taskmode:{task}"
        mode = snapshot.read(mode_key)[1]
        if mode is not None and mode["owner"] != principal.subject: raise PermissionError("task belongs to another parent")
        if mode is None and (snapshot.read(f"contract3:{task}")[1] is not None or snapshot.read(f"contract:{task}")[1] is not None):
            raise ValueError("legacy active task requires explicit migration; no silent delegation")
        entitlement = reader.read(f"entitlement:{task}:{principal.subject}")
        rights = rules(entitlement["scope"])
        if len(data["agents"]) > entitlement["max_agents"]: raise ValueError("agent count outside entitlement")
        if data["budget_limit"] > money_integer(entitlement["budget_limit"]): raise ValueError("task budget outside entitlement")
        caps = data["limits"]["inference"] | {k: data["limits"][k] for k in ("max_steps", "max_in_flight")}
        for k, bound in entitlement["limits"].items():
            if caps[k] > bound: raise ValueError("execution cap outside entitlement: " + k)
        for rule in data["scope"]:
            result = solve("delegable_scope", scope_expression(rights), rule_request(task, rule), reader, [])
            if result.decision != "ALLOW": raise ValueError("scope outside entitlement or evaluation error: " + result.decision)
        for ref in data["resources"]:
            document = reader.read("document:" + ref["resource"])
            if document["digest"] != ref["digest"] or document["version"] != ref["version"]:
                raise ValueError("stale resource reference")
            reader.read("label:" + ref["resource"])
        destinations = {}
        for name in sorted({r["destination"] for r in data["scope"] if r["destination"] is not None}):
            destination = reader.read("destination:" + name)
            if data["purpose"] not in destination["purposes"]: raise ValueError("destination purpose not authorized")
            destinations[name] = destination
        egress = []
        for rule in data["scope"]:
            if rule["tool"] in {"classify_document", "model_inference"}:
                dest = destinations[rule["destination"]]
                setting = data["provider"] if rule["tool"] == "model_inference" else data["classifier"]
                if dest["kind"] != "provider" or setting["model"] not in dest["models"]:
                    raise ValueError("unregistered provider/model")
                egress.append({"provider": rule["destination"], "resource": rule["resource"],
                               "purpose": rule["purpose"], "labels": dest["labels"]})
            elif rule["destination"] is not None and destinations[rule["destination"]]["kind"] != "recipient":
                raise ValueError("business destination must be a recipient")
        agents = [{**a, "principal": "ag-" + args_hash({"task": task, "parent": principal.subject, "agent": a["id"]}).split(":")[1][:32]}
                  for a in data["agents"]]
        contract = {"task_id": task, "objective": data["objective"], "purpose": data["purpose"], "budget_limit": data["budget_limit"],
            "allowed_resources": sorted(r["resource"] for r in data["resources"]),
            "allowed_tools": sorted({r["tool"] for r in data["scope"]}), "allowed_recipients": sorted(destinations),
            "allowed_agents": sorted(a["principal"] for a in agents), "policies": data["policies"],
            "unknown_release": data["unknown_release"], "classification_restrictions": data["classifier"]["mode"] != "disabled",
            "inference_egress": [json.loads(v) for v in sorted({dumps(r) for r in egress})]}
        contract = self.contracts._validate(contract, snapshot, resolving=True)
        basis = reader.footprint(set())
        for key in (mode_key, f"contract3:{task}", f"policyset:{task}"):
            basis[key] = snapshot.version(key)
        for policy in contract["policies"]:
            from atomicroot.framework.contracts import policy_key
            basis[policy_key(policy)] = snapshot.version(policy_key(policy))
        return {"schema_version": 1, "spec": data, "spec_digest": spec.digest, "contract": contract,
                "owner": principal.subject, "agents": agents, "basis": basis, "registry_digest": REGISTRY_DIGEST,
                "destinations": destinations, "unsupported": [],
                "assumptions": ["trusted identity/catalog fixtures, not production authentication",
                    "scope validity does not prove minimum intent alignment", "workflow and acceptance are stored, not executed in Phase 3.6"],
                "provenance": {"resources": data["resources"], "scope_source": "admin entitlement", "label_source": "LabelManager"}}

    def validate(self, value, principal):
        try:
            with self.store.snapshot() as snapshot: data = self._resolve(value, principal, snapshot)
            return {"valid": True, "resolved": data, "digest": args_hash(data), "unsupported": []}
        except PermissionError: raise
        except Exception as exc: return {"valid": False, "unsupported": [str(exc)]}

    def propose(self, value, principal):
        try:
            with self.store.snapshot() as snapshot: data = self._resolve(value, principal, snapshot)
        except (TypeError, KeyError) as exc:
            raise ValueError("malformed TaskSpec or policy definition") from exc
        task, mode_key = data["spec"]["task_id"], "taskmode:" + data["spec"]["task_id"]
        with self.store.transaction() as conn:
            if self.store.stale(conn, data["basis"]): raise ValueError("resolution stale; request new preview")
            if self.store.value(conn, mode_key)[1] is None:
                # Reserve the managed namespace before review. This grants no worker rights.
                self.store.put(conn, mode_key, {"owner": principal.subject})
            data["basis"][mode_key] = self.store.value(conn, mode_key)[0]
            binding = {"id": self.store.new_id("resolved"), "digest": args_hash(data)}
            conn.execute("INSERT INTO resolved_tasks(id,task,digest,data) VALUES (?,?,?,?)",
                         (binding["id"], task, binding["digest"], dumps(data)))
        # A race between publishing and preview fails closed against the pinned basis.
        author = Principal(principal.subject, frozenset({"worker"}), principal.tasks)
        return self.contracts.propose({**data["contract"], "task_binding": binding}, author)

    def status(self, task, principal):
        valid_identity(task)
        if task not in principal.tasks: raise PermissionError("task outside authenticated scope")
        with self.store.snapshot() as snapshot:
            mode = snapshot.read(f"taskmode:{task}")[1]
            if mode is None: raise ValueError("no managed task")
            if principal.subject != mode["owner"] and "approver" not in principal.roles and "admin" not in principal.roles:
                raise PermissionError("task status not owned by caller")
            binding = snapshot.read(f"taskresolved:{task}")[1]
            return {"task_id": task, "status": "ACTIVE" if binding else "DRAFT", "binding": binding,
                    "resolved": artifact(snapshot, binding) if binding else None}

    def principal(self, task, agent_id, caller):
        caller.require("user", task=task)
        with self.store.snapshot() as snapshot:
            mode = snapshot.read(f"taskmode:{task}")[1]
            if mode is None or mode["owner"] != caller.subject: raise PermissionError("parent identity mismatch")
            binding = snapshot.read(f"taskresolved:{task}")[1]
            if binding is None: raise ValueError("task not active")
            agent = next((a for a in artifact(snapshot, binding)["agents"] if a["id"] == agent_id), None)
            if agent is None: raise ValueError("agent not delegated")
            return Principal(agent["principal"], frozenset({"worker"}), frozenset({task}))


def delegation_constraints(reader, request):
    task, agent = request["task_id"], request["agent_id"]
    mode = reader.read(f"taskmode:{task}")
    active_binding = reader.read(f"taskresolved:{task}")
    active = artifact(reader.snapshot, active_binding)
    if reader.snapshot._conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_actions'").fetchone():
        staged = reader.snapshot._conn.execute("SELECT a.data,r.config FROM execution_actions a JOIN execution_runs r "
            "ON a.task=r.task AND a.run=r.run WHERE a.task=? AND a.operation=?", (task, request["operation_id"])).fetchone()
        if staged:
            incoming = {k: request[k] for k in ("task_id", "agent_id", "operation_id", "tool", "purpose")}
            incoming["args"] = {k: request["args"][k] for k in TOOLS[request["tool"]].required}
            if json.loads(staged[1])["resolved"] != active_binding or json.loads(staged[0]) != incoming:
                raise ValueError("staged execution config/payload binding mismatch")
    reader.read(f"agents:{task}")
    delegation = reader.read(f"delegation:{task}:{agent}")
    entitlement = reader.read(f"entitlement:{task}:{mode['owner']}")
    constraints = [("agent_membership", Member(RequestField("agent_id"), Ref("agent_members", "task")), "DENY"),
                   ("agent_scope", scope_expression(rules(delegation["scope"])), "DENY"),
                   ("parent_scope", scope_expression(rules(entitlement["scope"])), "DENY"),
                   ("parent_budget", Le(Const(active["spec"]["budget_limit"]), Const(money_integer(entitlement["budget_limit"]))), "DENY")]
    caps = active["spec"]["limits"]["inference"] | {k: active["spec"]["limits"][k] for k in ("max_steps", "max_in_flight")}
    cap_checks = [Le(Const(caps[k]), Const(v)) for k, v in entitlement["limits"].items()]
    cap_checks.append(Le(Const(len(active["agents"])), Const(entitlement["max_agents"])))
    constraints.append(("parent_execution_caps", And(tuple(cap_checks)), "DENY"))
    if request["recipient"]:
        destination = reader.read("destination:" + request["recipient"])
        original = active["destinations"].get(request["recipient"])
        constraints.append(("destination_scope", And((Member(RequestField("purpose"), SetConst(tuple(destination["purposes"]))),
            Eq(Const(destination["kind"]), Const("provider" if request["tool"] in {"model_inference", "classify_document"} else "recipient")),
            Eq(Const(destination["endpoint"] or ""), Const((original or {}).get("endpoint") or "")))), "DENY"))
    resources = {r["resource"]: r for r in active["spec"]["resources"]}
    names = ([request["resource"]] if request["resource"] else []) + [s["resource"] for s in request.get("model_source_bindings", [])]
    for resource in sorted(set(names)):
        doc = reader.read("document:" + resource)
        ref = resources.get(resource)
        host_context = ref is not None and ref.get("binding") == "host_context" and request["tool"] == "model_inference" and resource == request["resource"]
        if host_context:
            # The approved exception pins identity/scope, while each immutable job
            # pins new bytes/version/caller. Worker-created context bytes cannot qualify.
            row = reader.snapshot._conn.execute("SELECT data FROM inference_jobs WHERE id=?", (request["operation_id"],)).fetchone()
            job = json.loads(row[0]) if row else {}
            if (job.get("task"), job.get("principal"), job.get("resource"), job.get("digest"), job.get("version"), job.get("resolved_binding")) != (
                    task, agent, resource, doc["digest"], doc["version"], reader.read(f"taskresolved:{task}")):
                raise ValueError("unbound host context")
        constraints.append(("resolved_resource:" + resource, And((Const(ref is not None),
            Eq(Const(doc["digest"]), Const(doc["digest"] if host_context else (ref or {}).get("digest", ""))),
            Eq(Const(doc["version"]), Const(doc["version"] if host_context else (ref or {}).get("version", 0))))), "DENY"))
        if resource != request["resource"]:
            # Model sources require correlated inference scope for this agent and parent.
            for name, scope in (("source_agent_scope", delegation["scope"]), ("source_parent_scope", entitlement["scope"])):
                constraints.append((name + ":" + resource, scope_expression(rules(scope), resource=resource), "DENY"))
    if request["tool"] in {"model_inference", "classify_document"}:
        setting = active["spec"]["provider"] if request["tool"] == "model_inference" else active["spec"]["classifier"]
        constraints.append(("resolved_provider", And((Const(setting is not None),
            Eq(RequestField("recipient"), Const((setting or {}).get("destination", ""))),
            Member(Const((setting or {}).get("model", "")), SetConst(tuple(destination["models"]))),
            Member(Const(request["resolved_label"]), SetConst(tuple(destination["labels"]))),
            Subset(Ref("exposure", "task"), SetConst(tuple(destination["labels"]))))), "DENY"))
        if request["tool"] == "model_inference":
            context = json.loads(reader.read("document:" + request["resource"])["content"])
            constraints.append(("resolved_model", Eq(Const(context["model"]), Const(setting["model"])), "DENY"))
    return constraints
