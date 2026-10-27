"""Phase 3 authorization and intent Commit reuse the shared AST, tickets and CAS."""
from datetime import datetime, timedelta
import json
import re
from dataclasses import asdict

from nacl.signing import SigningKey

from atomicroot.authority.policy_engine import StatusReader, solve, valid_identity, money_integer, EvaluationError
from atomicroot.authority.ticket import Ticket, freeze_json, args_hash, create_ticket
from atomicroot.framework.registry import TOOLS, SOURCES
from atomicroot.framework.dsl import builtin_constraints, evaluate
from atomicroot.framework.contracts import policy_key
from atomicroot.framework.labels import LabelManager
from atomicroot.framework.storage import dumps


def validate_request(request, principal):
    request = freeze_json(request)
    if type(request) is not dict or set(request) != {"task_id", "agent_id", "operation_id", "tool", "purpose", "args"}:
        raise ValueError("unsupported or missing request fields")
    for field in ("task_id", "agent_id", "operation_id"): valid_identity(request[field])
    principal.require("worker", task=request["task_id"])
    if request["agent_id"] != principal.subject: raise PermissionError("caller identity mismatch")
    if type(request["purpose"]) is not str or not request["purpose"] or len(request["purpose"]) > 256:
        raise ValueError("invalid purpose")
    tool = TOOLS.get(request["tool"])
    args = request["args"]
    if tool is None or type(args) is not dict or set(args) != tool.required:
        raise ValueError("tool arguments require concrete payload; body_ref and worker metadata unsupported")
    if tool.spending: money_integer(args["amount"])
    if request["tool"] == "update_document":
        from atomicroot.framework.labels import content_digest
        content_digest(args["content"])
        valid_identity(args["read_receipt"])
    for key in ("to", "body"):
        if key in args and (type(args[key]) is not str or not args[key] or len(args[key].encode("utf-8")) > (8192 if key == "body" else 256)):
            raise ValueError("invalid concrete text argument")
    if tool.resource:
        valid_identity(args["resource"])
        if type(args["digest"]) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", args["digest"]) is None:
            raise ValueError("verified resource digest required")
    return request


def envelope(request):
    # Operation identity, purpose and all concrete arguments share the signature.
    return {"operation_id": request["operation_id"], "purpose": request["purpose"], "payload": request["args"]}


def review_facts(values):
    """Evidence carries resource identity/version, never private read bytes."""
    result = freeze_json(values)
    for key, value in list(result.items()):
        if key.startswith("document:"):
            result[key] = {name: value[name] for name in (
                "resource", "digest", "version", "source", "stored_by",
                "instruction_trust", "factual_accuracy") if name in value}
    return result


def operation_status(store, task, operation, digest, principal):
    principal.require("worker", task=task)
    with store._lock:
        row = store.row(store._conn, "SELECT * FROM operations WHERE task=? AND operation=?", (task, operation))
        if row is None or row["agent"] != principal.subject or row["digest"] != digest:
            raise PermissionError("operation identity/digest mismatch")
        outbox = store.row(store._conn, "SELECT status,attempts,receipt,error FROM outbox WHERE task=? AND operation=?", (task, operation))
    return {"operation_id": operation, "committed": outbox is not None,
            "status": "PROPOSED" if outbox is None else "COMMITTED",
            "delivery": None if outbox is None else outbox["status"],
            "attempts": 0 if outbox is None else outbox["attempts"],
            "receipt": json.loads(outbox["receipt"]) if outbox and outbox["receipt"] else None,
            "error": outbox["error"] if outbox else None}


class RuntimeAuthority:
    def __init__(self, store, broker, signing_key=None, harness=None):
        self.store, self.broker = store, broker
        self._sk = signing_key or SigningKey.generate()
        self.verify_key = self._sk.verify_key
        self.harness = harness

    def _managed(self, snapshot, reader, request):
        if snapshot.read(f"taskmode:{request['task_id']}")[1] is None: return []
        from atomicroot.framework.tasks import delegation_constraints
        return delegation_constraints(reader, request)

    def _constraints(self, request, managed): return builtin_constraints(request) + managed

    def _include_policy(self, definition, request): return request["tool"] in definition["applies_to"]

    def _additional_reads(self, reader): pass

    def _expiry(self, now, principal): return now + timedelta(seconds=30)

    def _register_operation(self, request, digest):
        task, op = request["task_id"], request["operation_id"]
        with self.store.transaction() as conn:
            if self.store.value(conn, f"contract3:{task}")[1] is None:
                raise ValueError("active contract required")
            row = self.store.row(conn, "SELECT * FROM operations WHERE task=? AND operation=?", (task, op))
            if row:
                if row["digest"] != digest or row["agent"] != request["agent_id"]:
                    raise ValueError("operation_id reused with different payload or identity")
            else:
                if request["tool"] == "update_document":
                    from atomicroot.framework.operations import read_basis
                    self.store.put(conn, f"readbasis:{task}:{op}", read_basis(self.store, conn, request))
                conn.execute("INSERT INTO operations(task,operation,agent,digest,request) VALUES (?,?,?,?,?)",
                             (task, op, request["agent_id"], digest, dumps(request)))
                self.store.put(conn, f"operation:{task}:{op}", False, initial=True)
                self.store.put(conn, f"consent:{task}:{op}", {"status": "NONE"}, initial=True)

    def authorize(self, request, principal, *, grant_id=None, action_id=None):
        try:
            request = validate_request(request, principal)
            digest = args_hash(request)
            task, op = request["task_id"], request["operation_id"]
            self._register_operation(request, digest)
            status = operation_status(self.store, task, op, digest, principal)
            if status["committed"]:
                return {**status, "request_digest": digest, "idempotent_status": True}
            with self.store.snapshot() as snapshot:
                if self.harness:
                    if self.store.coordinator.held_exclusively(): self.store.observe("snapshot_authorization", action_id)
                    else: self.harness.checkpoint("snapshot_authorization", action_id)
                reader = StatusReader(snapshot, SOURCES)
                self._additional_reads(reader)
                contract = reader.read(f"contract3:{task}")
                members = reader.read(f"policyset:{task}")
                reader.read(f"operation:{task}:{op}")
                reader.read(f"consent:{task}:{op}")
                spec = TOOLS[request["tool"]]
                normalized = {**request, "args": {**request["args"], "amount": request["args"].get("amount", 0)},
                              "recipient": request["args"].get("to", ""), "resource": request["args"].get("resource", ""),
                              "unknown_release": contract["unknown_release"], "resolved_label": "PUBLIC"}
                normalized["base_digest"] = request["args"].get("digest", "")
                normalized["inference_egress"] = contract.get("inference_egress", [])
                resource = None
                if spec.resource:
                    digest = request["args"]["digest"]
                    if request["tool"] == "update_document": digest = reader.read("document:" + normalized["resource"])["digest"]
                    resource, label = LabelManager.resolve(reader, normalized["resource"], digest, request["purpose"])
                    normalized["resolved_label"] = label
                if request["tool"] == "model_inference":
                    from atomicroot.integration.egress import validate_model_context
                    normalized["model_source_bindings"] = validate_model_context(reader, resource, normalized)
                managed_constraints = self._managed(snapshot, reader, normalized)
                results = [(name, disposition, solve(name, expr, normalized, reader, []))
                           for name, expr, disposition in self._constraints(normalized, managed_constraints)]
                if type(members) is not list or len(members) > 8: raise EvaluationError("invalid policy set")
                for member in members:
                    definition = reader.read(policy_key(member))
                    if self._include_policy(definition, normalized):
                        result = evaluate({"definition": definition}, {"reader": reader}, normalized)
                        results.append((definition["policy_id"], definition["on_violation"], result))
                footprint = reader.footprint(set())
                errors = [(name, r) for name, _, r in results if r.decision not in ("ALLOW", "DENY")]
                hard = [(name, r) for name, disposition, r in results if r.decision == "DENY" and disposition == "DENY"]
                escalations = [(name, r) for name, disposition, r in results if r.decision == "DENY" and disposition == "ESCALATE"]
                if errors: return {"decision": "EVALUATION_ERROR", "policy": errors[0][0], "explanation": errors[0][1].explanation}
                if hard:
                    name, result = hard[0]
                    return {**asdict(result), "footprint": footprint, "facts": review_facts(reader.values), "policy": name, "decision": "DENY"}
                business_fp = {k: v for k, v in footprint.items() if k != f"consent:{task}:{op}"}
                snapshot_facts = review_facts(reader.values)
                plan = {"tool": request["tool"], "args": request["args"], "amount": normalized["args"]["amount"],
                        "resolved_label": normalized["resolved_label"], "resource_snapshot": resource}
            if escalations and grant_id is None:
                with self.store.transaction() as conn:
                    if self.store.stale(conn, footprint): raise ValueError("review basis changed; authorize again")
                    review = self.broker.create(conn, "operation", task, {"digest": digest, "agent_id": request["agent_id"],
                        "operation_id": op, "tool": request["tool"], "request": request,
                        "footprint": business_fp, "snapshot": snapshot_facts,
                        "contract_version": footprint[f"contract3:{task}"], "policy_set_version": footprint[f"policyset:{task}"],
                        "violations": [name for name, _ in escalations]})
                return {"decision": "ESCALATE", "review_id": review, "request_digest": digest,
                        "footprint": business_fp, "explanation": "explicit operation consent required"}
            if grant_id is not None:
                # Even if the new evaluation allows, never silently carry old consent to a new state.
                with self.store.transaction() as conn:
                    self.broker.validate_grant(conn, grant_id, "operation", task, digest,
                                               agent=request["agent_id"], operation=op, tool=request["tool"])
                    if self.store.stale(conn, footprint): raise ValueError("grant snapshot changed; new review required")
            write_set = spec.write_set(task, op, grant_id, resource=request["args"].get("resource"))
            ticket = create_ticket(task, request["agent_id"], request["tool"], envelope(request), footprint, write_set,
                                   self._sk, clock=self.store._clock, id_factory=self.store.new_id)
            now = self.store._clock()
            ticket.not_before = now.isoformat()
            ticket.not_after = self._expiry(now, principal).isoformat()
            ticket.sign(self._sk)
            with self.store.transaction() as conn:
                conn.execute("INSERT INTO authorizations(ticket,task,operation,data) VALUES (?,?,?,?)",
                             (ticket.ticket_id, task, op, dumps({"request": request, "digest": digest,
                                "grant_id": grant_id, "plan": plan, "ticket": ticket.to_dict()})))
            if self.harness:
                if self.store.coordinator.held_exclusively(): self.store.observe("ticket_issued", action_id)
                else: self.harness.checkpoint("ticket_issued", action_id)
            return {"decision": "ALLOW", "ticket": ticket.to_dict(), "commit_args": envelope(request), "request_digest": digest}
        except Exception as exc:
            return {"decision": "EVALUATION_ERROR", "explanation": str(exc)}


class IntentGateway:
    def __init__(self, store, broker, verify_key, harness=None):
        self.store, self.broker, self.verify_key, self.harness = store, broker, verify_key, harness

    def _freshness(self, conn, footprint): return self.store.stale(conn, footprint)

    def commit(self, ticket_data, args, principal, *, action_id=None):
        try:
            ticket = Ticket.from_dict(freeze_json(ticket_data))
            args = freeze_json(args)
            if not ticket.verify(self.verify_key): raise ValueError("invalid signature")
            principal.require("worker", task=ticket.task_id)
            if ticket.agent_id != principal.subject: raise PermissionError("caller identity mismatch")
            if args_hash(args) != ticket.args_hash: raise ValueError("args hash mismatch")
            if self.harness:
                if self.store.coordinator.held_exclusively(): self.store.observe("before_cas", action_id)
                else: self.harness.checkpoint("before_cas", action_id)
            with self.store.transaction() as conn:
                start = datetime.fromisoformat(ticket.not_before)
                end = datetime.fromisoformat(ticket.not_after)
                if not start <= self.store._clock() <= end: raise ValueError("expired ticket")
                if conn.execute("SELECT 1 FROM trace_events WHERE ticket_id=? OR nonce=?", (ticket.ticket_id, ticket.nonce)).fetchone():
                    raise ValueError("ticket replay")
                row = self.store.row(conn, "SELECT * FROM authorizations WHERE ticket=?", (ticket.ticket_id,))
                if row is None: raise ValueError("unregistered authorization")
                authorization = json.loads(row["data"])
                if authorization["ticket"] != ticket.to_dict(): raise ValueError("authorization binding mismatch")
                task, op = row["task"], row["operation"]
                if conn.execute("SELECT 1 FROM outbox WHERE task=? AND operation=?", (task, op)).fetchone():
                    return {"status": "OPERATION_ALREADY_COMMITTED", "operation_id": op, "use_status_endpoint": True}
                stale = self._freshness(conn, ticket.footprint)
                if stale: return {"status": "STALE_TICKET", "stale_keys": stale}
                grant = authorization["grant_id"]
                if ticket.write_set != TOOLS[ticket.tool].write_set(task, op, grant, resource=authorization["request"]["args"].get("resource")):
                    raise ValueError("tool registry write set mismatch")
                if grant:
                    self.broker.validate_grant(conn, grant, "operation", task, authorization["digest"],
                                               agent=ticket.agent_id, operation=op, tool=ticket.tool)
                plan = authorization["plan"]
                from atomicroot.framework.operations import intent_facts
                observed = intent_facts(self.store, conn, authorization["request"])
                if TOOLS[ticket.tool].spending:
                    key = f"reserved:{task}"
                    value = money_integer(self.store.value(conn, key)[1])
                    self.store.put(conn, key, money_integer(value + plan["amount"]))
                if ticket.tool == "read_document":
                    key = f"exposure:{task}"
                    exposure = self.store.value(conn, key)[1]
                    self.store.put(conn, key, sorted(set(exposure) | {plan["resolved_label"]}))
                if ticket.tool == "update_document":
                    from atomicroot.framework.labels import write_content
                    plan["resource_update"] = write_content(self.store, conn, plan["args"]["resource"], plan["args"]["content"], ticket.agent_id,
                                                          sensitive="SENSITIVE" in observed["exposure"])
                self.store.put(conn, f"operation:{task}:{op}", True)
                if grant:
                    self.broker.consume(conn, grant)
                    self.store.put(conn, f"consent:{task}:{op}", {"status": "CONSUMED", "review_id": grant})
                conn.execute("INSERT INTO trace_events(event_id,task_id,agent_id,tool,args_hash,ticket_id,nonce,write_set,timestamp,args) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (self.store.new_id("event"), task, ticket.agent_id, ticket.tool, ticket.args_hash, ticket.ticket_id,
                              ticket.nonce, dumps(ticket.write_set), self.store._clock().isoformat(),
                              dumps({**authorization["request"]["args"], "operation_id": op,
                                     "_intent_facts": observed,
                                     "_resolved_data_class": "sensitive" if plan["resolved_label"] == "SENSITIVE" else plan["resolved_label"]})))
                conn.execute("INSERT INTO outbox(task,operation,ticket,agent,digest,payload,status,amount) VALUES (?,?,?,?,?,?,'PENDING',?)",
                             (task, op, ticket.ticket_id, ticket.agent_id, authorization["digest"], dumps(plan), plan["amount"]))
            if self.harness:
                if self.store.coordinator.held_exclusively(): self.store.observe("after_commit", action_id)
                else: self.harness.checkpoint("after_commit", action_id)
            return {"status": "COMMITTED", "operation_id": op, "delivery": "PENDING"}
        except Exception as exc:
            return {"status": "REJECTED", "reason": str(exc)}
