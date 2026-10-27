"""Six explicit guard configurations sharing the production schema/protocol core."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import local

from atomicroot.authority.ticket import canonical_json_bytes, freeze_json
from atomicroot.authority.policy_engine import Const, Le, RequestAmount, Ref, dependencies
from atomicroot.framework.runtime import RuntimeAuthority, IntentGateway
from atomicroot.framework.approval import ApprovalBroker
from atomicroot.framework.tasks import scope_expression
from atomicroot.framework.contention import FallbackConfig
from atomicroot.framework.dsl import builtin_constraints, compile_policy
from atomicroot.framework.registry import SOURCES

GLOBAL_KEY = "global:policy"
MODES = ("no_guard", "stateless_per_action", "reusable_capability", "stateful_non_atomic", "global_version_atomicroot", "atomicroot")
UNSAFE = frozenset(MODES[:4])
HISTORY = ("budget:", "reserved:", "exposure:", "operation:", "consent:", "readbasis:")


@dataclass(frozen=True)
class Capability:
    """Baseline-only reusable grant. Main capability enforcement stays Phase 3.6."""
    data: dict
    signature: str

    @classmethod
    def issue(cls, key, principal, task, scope, limit, expires):
        data = freeze_json({"subject": principal.subject, "task": task, "scope": scope, "budget_limit": limit, "expires": expires})
        return cls(data, key.sign(canonical_json_bytes(data)).signature.hex())

    def validate(self, key, principal, request, now):
        from datetime import datetime
        try: key.verify(canonical_json_bytes(self.data), bytes.fromhex(self.signature))
        except Exception: raise ValueError("invalid reusable capability signature") from None
        if (self.data["subject"], self.data["task"]) != (principal.subject, request["task_id"]): raise ValueError("capability subject/task mismatch")
        if now >= datetime.fromisoformat(self.data["expires"]): raise ValueError("capability expired")


class EvaluationAuthority(RuntimeAuthority):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.coverage = local()

    def authorize(self, request, principal, **kwargs):
        self.coverage.omitted = []
        if request.get("tool") in {"model_inference", "classify_document"}:
            return {"decision": "EVALUATION_ERROR", "explanation": "evaluation modes prohibit provider egress; use separately authorized fake/replay records"}
        if self.mode == "reusable_capability":
            try: self.capabilities[principal.subject].validate(self.verify_key, principal, request, self.store._clock())
            except Exception as exc: return {"decision": "EVALUATION_ERROR", "explanation": str(exc)}
        result = super().authorize(request, principal, **kwargs)
        if self.mode in MODES[:3]:
            result["evaluation_coverage"] = {"mode": self.mode, "omitted_custom_rules": self.coverage.omitted,
                "history_rules": "UNSUPPORTED/PARTIAL", "shared_protocol": "schema/identity/internal ticket single-use/operation uniqueness/outbox/dedupe remain enabled",
                "policy_authorization": self.mode != "no_guard"}
        return result

    def _managed(self, snapshot, reader, request):
        return [] if self.mode in {"no_guard", "reusable_capability"} else super()._managed(snapshot, reader, request)

    def _constraints(self, request, managed):
        if self.mode == "no_guard": return []
        if self.mode == "reusable_capability":
            grant = self.capabilities[request["agent_id"]].data
            return [("frozen_capability_scope", scope_expression(grant["scope"]), "DENY"),
                    ("static_action_limit", Le(RequestAmount(), Const(grant["budget_limit"])), "DENY")]
        if self.mode == "stateless_per_action":
            constraints = [(n, e, d) for n, e, d in builtin_constraints(request) if n in {"scope", "provider_scope"}]
            return constraints + [("static_action_limit", Le(RequestAmount(), Ref("budget_limit", "task")), "DENY")] + managed
        return super()._constraints(request, managed)

    def _include_policy(self, definition, request):
        if request["tool"] not in definition["applies_to"]: return False
        if self.mode in {"no_guard", "reusable_capability"}:
            self.coverage.omitted.append(definition["policy_id"])
            return False
        if self.mode == "stateless_per_action":
            if any(key.startswith(HISTORY) for key in dependencies(compile_policy(definition), request, SOURCES)):
                self.coverage.omitted.append(definition["policy_id"])
                return False
        return super()._include_policy(definition, request)

    def _additional_reads(self, reader):
        if self.mode == "global_version_atomicroot": reader.read(GLOBAL_KEY)

    def _expiry(self, now, principal):
        deadline = super()._expiry(now, principal)
        return min(deadline, datetime.fromisoformat(self.capabilities[principal.subject].data["expires"]) - timedelta(microseconds=1)) if self.mode == "reusable_capability" else deadline


class EvaluationGateway(IntentGateway):
    def _freshness(self, conn, footprint):
        if self.mode in UNSAFE: return []
        if self.mode == "global_version_atomicroot":
            if GLOBAL_KEY not in footprint: raise ValueError("missing global freshness binding")
            return self.store.stale(conn, {GLOBAL_KEY: footprint[GLOBAL_KEY]})
        return super()._freshness(conn, footprint)


class GlobalBroker(ApprovalBroker):
    def _decision_basis(self, conn, row, approve):
        if approve and row["kind"] == "operation" and GLOBAL_KEY in row["data"]["footprint"]:
            # The just-validated human basis is unchanged except for this exact
            # consent transition. Rebind that infrastructure change atomically;
            # no other business writer can interleave in this transaction.
            row["data"]["footprint"][GLOBAL_KEY] = self.store.value(conn, GLOBAL_KEY)[0]
            conn.execute("UPDATE reviews SET data=? WHERE id=?", (canonical_json_bytes(row["data"]).decode(), row["id"]))


def install_global_instrumentation(store):
    """DB triggers cover every conflict-key writer, including other connections.

    Installed on every isolated mode database for paired instrumentation. Only
    global mode uses this version for freshness. Metadata ticket rows do not bump
    the policy clock; otherwise issuing a ticket would invalidate itself.
    """
    with store.transaction() as conn:
        conn.execute("INSERT OR IGNORE INTO conflict_keys VALUES (?,0,'0')", (GLOBAL_KEY,))
        for action, row in (("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")):
            conn.execute(f"CREATE TRIGGER IF NOT EXISTS phase5_global_{action.lower()} AFTER {action} ON conflict_keys "
                         f"WHEN {row}.key != 'global:policy' BEGIN UPDATE conflict_keys SET version=version+1 WHERE key='global:policy'; END")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("execution_actions", "execution_outputs", "execution_runs", "inference_jobs"):
            if table not in tables: continue
            for action in ("INSERT", "UPDATE", "DELETE"):
                transition = "UPDATE OF config,binding" if table == "execution_runs" and action == "UPDATE" else action
                conn.execute(f"CREATE TRIGGER IF NOT EXISTS phase5_global_{table}_{action.lower()} AFTER {transition} ON {table} "
                             "BEGIN UPDATE conflict_keys SET version=version+1 WHERE key='global:policy'; END")
    store.register_evaluation_tables = lambda: install_global_instrumentation(store)


def configure_evaluation(runtime, mode, user):
    if mode not in MODES or not getattr(runtime, "evaluation_only", False): raise ValueError("isolated evaluation host required")
    install_global_instrumentation(runtime.store)
    broker = GlobalBroker(runtime.store) if mode == "global_version_atomicroot" else ApprovalBroker(runtime.store)
    old = runtime.authority
    authority = EvaluationAuthority(runtime.store, broker, old._sk, old.harness)
    authority.mode, authority.capabilities = mode, {}
    gateway = EvaluationGateway(runtime.store, broker, authority.verify_key, runtime.gateway.harness)
    gateway.mode = mode
    runtime.broker = runtime.contracts.broker = broker
    runtime.authority, runtime.gateway = authority, gateway
    runtime.fallback = FallbackConfig() if mode in MODES[4:] else None
    with runtime.store.snapshot() as snap:
        for task in user.tasks:
            binding = snap.read(f"taskresolved:{task}")[1]
            if binding is None: continue
            from atomicroot.framework.tasks import artifact
            active = artifact(snap, binding)
            for agent in active["agents"]:
                # Snapshot is already open: derive the same host identity from
                # the reviewed artifact rather than nesting a read transaction.
                from atomicroot.framework.identity import Principal
                principal = Principal(agent["principal"], frozenset({"worker"}), frozenset({task}))
                authority.capabilities[principal.subject] = Capability.issue(old._sk, principal, task, agent["scope"],
                    active["spec"]["budget_limit"], (runtime.store._clock() + timedelta(seconds=300)).isoformat())
    return runtime


def feature_matrix():
    rows = []
    for mode in MODES:
        rows.append({"mode": mode, "policy": "none" if mode == "no_guard" else "frozen scope/static amount" if mode == "reusable_capability" else "static/request plus delegation; history policies unsupported" if mode == "stateless_per_action" else "all applicable Z3",
            "history": mode in MODES[3:], "scope": "none" if mode == "no_guard" else "signed frozen relation" if mode == "reusable_capability" else "Phase 3.6 current relations",
            "signature": "signed mechanism envelope in all modes; reusable mode additionally verifies reusable subject/scope/expiry grant",
            "single_use": "mechanism ticket/nonce yes; reusable grant no", "freshness": "none" if mode in UNSAFE else "global policy version" if mode == MODES[4] else "concrete footprint CAS",
            "approval": "shared Broker if an escalation is produced; no approval claim for omitted policies", "outbox": True, "db_operation_uniqueness": True,
            "simulated_receiver_dedupe": True, "fallback": mode in MODES[4:], "provider_egress": "PROHIBITED in this harness",
            "executor_A": "same ConfigWorkflow and GuardedTools with scripted worker; mechanism replay uses explicit protocol-boundary manifests",
            "unsupported": ["history-dependent custom rules", "exposure", "cumulative budget", "read freshness"] if mode in MODES[:3] else []})
    return {"schema_version": 1, "modes": rows, "shared_constraints": "schema, host identity, immutable operation/payload registration, adapter receipt validity, SQLite uniqueness, outbox and receiver dedupe remain enabled; these can protect unsafe baselines"}
