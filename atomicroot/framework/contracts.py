"""Strict proposal -> preview/diff -> authorized approval -> active revision."""
import json
from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.authority.policy_engine import valid_identity, money_integer, finite_strings, MAX_STATE_BYTES
from atomicroot.framework.registry import TOOLS, registry_preview
from atomicroot.framework.dsl import compile_policy
from atomicroot.framework.storage import dumps, uid


FIELDS = frozenset({"task_id", "objective", "purpose", "budget_limit", "allowed_tools",
                    "allowed_resources", "allowed_recipients", "allowed_agents", "unknown_release", "policies"})
OPTIONAL_FIELDS = frozenset({"classification_restrictions", "inference_egress", "task_binding"})


def policy_key(definition):
    return f"policy:{definition['policy_id']}.{definition['version']}"


class ContractService:
    def __init__(self, store, broker): self.store, self.broker = store, broker

    def _validate(self, proposal, snapshot, *, resolving=False):
        proposal = freeze_json(proposal)
        if type(proposal) is not dict or not FIELDS <= set(proposal) or not set(proposal) <= FIELDS | OPTIONAL_FIELDS:
            raise ValueError("unsupported or missing proposal fields; activation is all-or-nothing")
        valid_identity(proposal["task_id"])
        money_integer(proposal["budget_limit"])
        for k in ("objective", "purpose"):
            if type(proposal[k]) is not str or not proposal[k] or len(proposal[k]) > 256:
                raise ValueError("bounded nonempty objective/purpose required")
        for k in ("allowed_tools", "allowed_resources", "allowed_recipients", "allowed_agents"):
            if type(proposal[k]) is not list: raise ValueError("scope must be a finite list")
            proposal[k] = list(finite_strings(proposal[k]))
        if not proposal["allowed_tools"] or not set(proposal["allowed_tools"]) <= TOOLS.keys():
            raise ValueError("unsupported or empty tool scope")
        if not proposal["allowed_agents"]: raise ValueError("explicit agent delegation required")
        for identity in proposal["allowed_resources"] + proposal["allowed_agents"]: valid_identity(identity)
        if proposal["unknown_release"] not in ("DENY", "ESCALATE"): raise ValueError("unsupported UNKNOWN release rule")
        if "classification_restrictions" in proposal and type(proposal["classification_restrictions"]) is not bool:
            raise ValueError("classification_restrictions must be boolean")
        rules = proposal.get("inference_egress", [])  # official default: no inference egress
        if type(rules) is not list or len(rules) > 16: raise ValueError("invalid inference egress scope")
        for rule in rules:
            if type(rule) is not dict or set(rule) != {"provider", "resource", "purpose", "labels"}:
                raise ValueError("unsupported inference scope fields")
            valid_identity(rule["provider"])
            valid_identity(rule["resource"])
            if (rule["provider"] not in proposal["allowed_recipients"] or
                    rule["resource"] not in proposal["allowed_resources"] or rule["purpose"] != proposal["purpose"]):
                raise ValueError("inference scope must fit approved contract scope")
            if (type(rule["labels"]) is not list or not rule["labels"] or len(rule["labels"]) > 3 or
                    any(type(v) is not str or v not in {"PUBLIC", "SENSITIVE", "UNKNOWN"} for v in rule["labels"])):
                raise ValueError("explicit inference data labels required")
        if type(proposal["policies"]) is not list or len(proposal["policies"]) > 8:
            raise ValueError("at most eight custom policies")
        definitions, seen = [], set()
        for definition in proposal["policies"]:
            if type(definition) is not dict: raise ValueError("policy must be a definition or version reference")
            if set(definition) == {"policy_id", "version"}:
                _, existing = snapshot.read(policy_key(definition))
                if existing is None: raise ValueError("unknown approved policy version")
                definition = existing
            compile_policy(definition)
            if definition["policy_id"] in seen: raise ValueError("duplicate policy id")
            seen.add(definition["policy_id"])
            key = policy_key(definition)
            _, existing = snapshot.read(key)
            if existing is not None and existing != definition:
                raise ValueError("policy version immutable; propose a new version")
            definitions.append(definition)
        proposal["policies"] = definitions
        if len(dumps(proposal).encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("contract exceeds state size limit")
        if not resolving:
            from atomicroot.framework.tasks import contract_attachment
            contract_attachment(snapshot, proposal)
        return proposal

    def validate(self, proposal):
        try:
            with self.store.snapshot() as snapshot: result = self._validate(proposal, snapshot)
            return {"valid": True, "proposal": result, "unsupported": []}
        except Exception as exc:
            return {"valid": False, "unsupported": [str(exc)]}

    def propose(self, proposal, principal):
        principal.require("worker", task=proposal.get("task_id"))
        with self.store.snapshot() as snapshot:
            data = self._validate(proposal, snapshot)
            task = data["task_id"]
            base, old = snapshot.read(f"contract3:{task}")
            if old is None and snapshot.read(f"contract:{task}")[1] is not None:
                raise ValueError("legacy task requires explicit state migration; use a new Phase 3 task")
            footprint = {f"contract3:{task}": base, f"policyset:{task}": snapshot.version(f"policyset:{task}")}
            labels = []
            for resource in data["allowed_resources"]:
                for key in (f"document:{resource}", f"label:{resource}"):
                    footprint[key] = snapshot.version(key)
                _, document = snapshot.read(f"document:{resource}")
                _, label = snapshot.read(f"label:{resource}")
                if document is None: raise ValueError(f"resource has no registered storage source: {resource}")
                labels.append({"resource": resource, "label": label,
                               "needs_label": not label or label["label"] == "UNKNOWN" or data["purpose"] not in label["purposes"]})
            for definition in data["policies"]:
                key = policy_key(definition)
                footprint[key] = snapshot.version(key)
            from atomicroot.framework.tasks import contract_attachment
            attachment = contract_attachment(snapshot, data)
            if attachment:
                if self.store.stale(snapshot._conn, attachment["basis"]):
                    raise ValueError("resolution stale; new preview required")
                footprint.update(attachment["basis"])
            old = old or {}
            diff = {k: {"before": old.get(k), "after": v} for k, v in data.items() if old.get(k) != v}
            preview = {"proposal": data, "base_version": base, "diff": diff, "labels": labels,
                       "fact_sources": registry_preview(), "unsupported": [],
                       "assumptions": ["task-level exposure is conservative", "external content is untrusted instructions",
                                       "owner labels do not certify factual accuracy"],
                       "built_in_policies": ["scope", "provider_scope", "budget_monotone", "no_exfil_after_sensitive", "unknown_release"]}
            if attachment:
                preview["resolved_task"] = attachment
            digest = args_hash({"proposal": data, "base_version": base, "preview": preview})
        proposal_id = uid("proposal")
        with self.store.transaction() as conn:
            if self.store.stale(conn, footprint): raise ValueError("preview basis changed; request new diff")
            review = self.broker.create(conn, "contract", task, {"digest": digest, "footprint": footprint,
                "preview": preview, "proposal_id": proposal_id, "agent_id": principal.subject})
            conn.execute("INSERT INTO proposals(id,task,digest,base,status,data,review) VALUES (?,?,?,?,'DRAFT',?,?)",
                         (proposal_id, task, digest, base, dumps(data), review))
        return {"proposal_id": proposal_id, "review_id": review, "digest": digest, "status": "DRAFT", "preview": preview}

    def activate(self, proposal_id, review_id, principal):
        with self.store.transaction() as conn:
            row = self.store.row(conn, "SELECT * FROM proposals WHERE id=?", (proposal_id,))
            if row is None: raise ValueError("unknown proposal")
            principal.require("approver", task=row["task"])
            if row["status"] != "DRAFT" or review_id != row["review"]: raise ValueError("proposal not activatable")
            self.broker.validate_grant(conn, review_id, "contract", row["task"], row["digest"])
            data = json.loads(row["data"])
            from atomicroot.store.trace_store import Snapshot
            self._validate(data, Snapshot(conn))
            task = row["task"]
            # Initializers are official and only run for a new task; resume never resets.
            _, old = self.store.value(conn, f"contract3:{task}")
            for key, value in ((f"budget:{task}", 0), (f"reserved:{task}", 0), (f"exposure:{task}", [])):
                if old is None: self.store.put(conn, key, value, initial=True)
                elif self.store.value(conn, key)[1] is None: raise ValueError("missing ledger fact; explicit repair required")
            references = []
            for definition in data["policies"]:
                key = policy_key(definition)
                _, existing = self.store.value(conn, key)
                if existing is not None and existing != definition: raise ValueError("policy revision conflict")
                if existing is None: self.store.put(conn, key, definition)
                references.append({"policy_id": definition["policy_id"], "version": definition["version"]})
            self.store.put(conn, f"contract3:{task}", data)
            self.store.put(conn, f"policyset:{task}", references)
            from atomicroot.framework.tasks import activate_attachment
            activate_attachment(self.store, conn, data)
            version = self.store.value(conn, f"contract3:{task}")[0]
            conn.execute("UPDATE proposals SET status='SUPERSEDED' WHERE task=? AND status='ACTIVE'", (task,))
            conn.execute("UPDATE proposals SET status='ACTIVE',activated_version=? WHERE id=?", (version, proposal_id))
            self.broker.consume(conn, review_id)
            self.store.audit(conn, "CONTRACT_ACTIVATED", principal.subject,
                             {"proposal_id": proposal_id, "review_id": review_id, "digest": row["digest"], "version": version})
        return {"status": "ACTIVE", "version": version, "proposal_id": proposal_id}
