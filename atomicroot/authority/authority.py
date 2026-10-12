"""Trusted policy authority: one SQLite snapshot, all applicable policies."""
from __future__ import annotations

from typing import Any
from types import MappingProxyType
from nacl.signing import SigningKey, VerifyKey

from atomicroot.authority.ticket import create_ticket, freeze_json
from atomicroot.authority.policy_engine import StatusReader, valid_identity, EvaluationError, money_integer
from atomicroot.authority.policies import no_exfil_after_sensitive, budget_monotone
from atomicroot.store.trace_store import TraceStore


TOOL_POLICIES = MappingProxyType({
    "send_email": ("no_exfil_after_sensitive",),
    "send_http": ("no_exfil_after_sensitive",),
    "upload_file": ("no_exfil_after_sensitive",),
    "read_document": ("no_exfil_after_sensitive",),
    "transfer_funds": ("budget_monotone",),
    "make_payment": ("budget_monotone",),
    "purchase": ("budget_monotone",),
})
POLICY_EVALUATORS = MappingProxyType({
    "no_exfil_after_sensitive": no_exfil_after_sensitive.evaluate,
    "budget_monotone": budget_monotone.evaluate,
})


class TaskContextStore:
    """Trusted setup interface. Contract and document class live in SQLite."""

    def __init__(self, store: TraceStore | None = None):
        self.store = store

    def bind(self, store: TraceStore):
        self.store = store

    def register_task(self, task_id: str, context: dict[str, Any]):
        valid_identity(task_id)
        if self.store is None:
            raise RuntimeError("TaskContextStore must be bound")
        cap = context.get("budget_cap", 0)
        money_integer(cap)
        self.store.register_task_state(task_id, cap)

    def register_document(self, doc_id: str, data_class: str):
        valid_identity(doc_id)
        if data_class not in {"finance", "sensitive", "internal", "public"}:
            raise ValueError("invalid data class")
        if self.store is None:
            raise RuntimeError("TaskContextStore must be bound")
        self.store.set_state(f"class:{doc_id}", data_class)

    def get_context(self, task_id: str) -> dict[str, Any]:
        return self.store.get_state(f"contract:{task_id}", {})

    def get_taint_classes(self, task_id: str) -> set[str]:
        return set(self.store.get_state(f"taint:{task_id}", []))

    def get_cumulative_spend(self, task_id: str) -> int:
        return self.store.get_state(f"budget:{task_id}", 0)


class PolicyAuthority:
    def __init__(self, store: TraceStore, task_ctx: TaskContextStore,
                 signing_key: SigningKey | None = None, harness=None, *, external_tools=None):
        self.store = store
        self.task_ctx = task_ctx
        task_ctx.bind(store)
        self._sk = signing_key or SigningKey.generate()
        self.verify_key: VerifyKey = self._sk.verify_key
        self.harness = harness
        # Freeze trusted tool definitions for this service lifetime. Request
        # fields cannot change them; there is no runtime classification setter.
        external = frozenset(no_exfil_after_sensitive.EXTERNAL_TOOLS if external_tools is None else external_tools)
        if not external <= TOOL_POLICIES.keys():
            raise ValueError("unsupported external tool definition")
        self._policy_context = MappingProxyType({"external_tools": external})
        for tool, names in TOOL_POLICIES.items():
            store.initialize_state(f"policies:{tool}", list(names))

    def configure_tool_policies(self, tool: str, names: list[str]) -> None:
        """Trusted membership update only; no policy authoring or worker endpoint."""
        self._validate_membership(tool, names)
        self.store.set_state(f"policies:{tool}", names)

    @staticmethod
    def _validate_membership(tool: str, names) -> None:
        if (tool not in TOOL_POLICIES or type(names) is not list or
                not names or len(names) > len(POLICY_EVALUATORS) or
                any(type(name) is not str or name not in POLICY_EVALUATORS for name in names) or
                len(set(names)) != len(names) or not set(TOOL_POLICIES[tool]) <= set(names)):
            raise EvaluationError("missing, invalid or unsupported active policy membership")

    def authorize(self, request: dict[str, Any], *, caller_agent_id: str | None = None,
                  action_id: str | None = None) -> dict[str, Any]:
        try:
            # Bind evaluation and signing to the same isolated concrete input.
            request = freeze_json(request)
            if not isinstance(request, dict):
                raise EvaluationError("request must be object")
            task_id = valid_identity(request["task_id"])
            agent_id = valid_identity(request["agent_id"])
            if caller_agent_id != agent_id:
                raise EvaluationError("caller identity mismatch")
            tool = request["tool"]
            if tool not in TOOL_POLICIES:
                raise EvaluationError("unknown tool")
            args = request["args"]
            if not isinstance(args, dict):
                raise EvaluationError("args must be object")
            if tool in {"transfer_funds", "make_payment", "purchase"}:
                amount = args.get("amount")
                money_integer(amount)
            if tool == "read_document":
                valid_identity(args["doc_id"])
            with self.store.snapshot() as snapshot:
                if self.harness:
                    self.harness.checkpoint("snapshot_authorization", action_id)
                reader = StatusReader(snapshot)
                names = reader.read(f"policies:{tool}")
                self._validate_membership(tool, names)
                results = []
                # Every policy uses the same pinned SQLite snapshot and reader.
                for pname in names:
                    results.append((pname, POLICY_EVALUATORS[pname](
                        self._policy_context, {"reader": reader}, request)))
                if any(r.decision not in {"ALLOW", "DENY", "EVALUATION_ERROR"} for _, r in results):
                    raise EvaluationError("unsupported policy evaluation outcome")
                error = next(((p, r) for p, r in results if r.decision == "EVALUATION_ERROR"), None)
                if error:
                    p, r = error
                    return {"decision": "EVALUATION_ERROR", "policy": p,
                            "explanation": r.explanation}
                denial = next(((p, r) for p, r in results if r.decision == "DENY"), None)
                if denial:
                    p, r = denial
                    return {"decision": "DENY", "policy": p,
                            "explanation": r.explanation,
                            "trigger_event": r.trigger_event,
                            "violating_action": r.violating_action,
                            "evidence_events": r.evidence_events,
                            "facts": r.facts, "witness": r.witness}
                footprint = reader.footprint(set().union(*(set(r.footprint) for _, r in results)))
                write_set = list(dict.fromkeys(k for _, r in results for k in r.write_set))
                ticket = create_ticket(task_id, agent_id, tool, args, footprint,
                                       write_set, self._sk)
            if self.harness:
                self.harness.checkpoint("ticket_issued", action_id)
            return ticket.to_dict()
        except Exception as exc:
            return {"decision": "EVALUATION_ERROR", "explanation": str(exc)}
