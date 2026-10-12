"""One host-supplied worker capability: authorize -> CAS -> outbox observation."""
from dataclasses import dataclass, asdict
from types import MappingProxyType
import asyncio
import json

from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.runtime import validate_request, operation_status
from atomicroot.integration.progress import emit

WORKER_TOOLS = frozenset({"read_document", "send_email", "transfer_funds", "deploy"})


@dataclass(frozen=True)
class Observation:
    status: str
    operation_id: str
    detail: dict
    def json(self): return asdict(self)


class GuardedTools:
    def __init__(self, runtime, *, receiver=None, max_reauth=2, max_dispatch=2, progress=None):
        if not 0 <= max_reauth <= 3 or not 1 <= max_dispatch <= 3: raise ValueError("invalid tool retry bounds")
        self.runtime, self.receiver = runtime, receiver or runtime.receiver
        self.max_reauth, self.max_dispatch = max_reauth, max_dispatch
        self.progress = progress
        self.registry = MappingProxyType({"guarded_action": self})

    @staticmethod
    def validate_registry(registry):
        if set(registry) != {"guarded_action"} or type(registry["guarded_action"]) is not GuardedTools:
            raise ValueError("only the guarded_action wrapper may be registered")

    def stage(self, action, *, principal, task, purpose, operation, host_inference=False):
        action = freeze_json(action)
        if type(action) is not dict or set(action) != {"tool", "args"}: raise ValueError("protected/unsupported model fields")
        allowed = {"classify_document", "model_inference"} if host_inference else WORKER_TOOLS
        if action["tool"] not in allowed:
            raise ValueError("tool outside worker capability; model_inference/classify_document are host-managed; choose from available_actions")
        request = {"task_id": task, "agent_id": principal.subject, "operation_id": operation,
                   "purpose": purpose, "tool": action["tool"], "args": action["args"]}
        return validate_request(request, principal)

    def execute(self, request, principal, *, grant=None):
        request = validate_request(request, principal)
        r, op = self.runtime, request["operation_id"]
        # Immutable request and operation identity persist across every retry.
        for attempt in range(self.max_reauth + 1):
            if grant:
                review = r.broker.status(grant, principal)
                if review["effective_status"] != "APPROVED":
                    if review["effective_status"] == "REJECTED": return Observation("DENY", op, {"reason": "trusted review rejected"})
                    grant = None  # new server review, never silently reuse stale consent
            auth = r.authority.authorize(request, principal, grant_id=grant, action_id=op)
            emit(self.progress, "INFERENCE_EGRESS" if request["tool"] == "model_inference" else "AUTHORIZATION", tool=request["tool"], operation=op,
                 status=auth.get("decision") or "ALREADY_COMMITTED")
            if auth.get("decision") == "ESCALATE":
                return Observation("ESCALATE", op, {"review_id": auth["review_id"], "reason": auth["explanation"]})
            if auth.get("decision") != "ALLOW" and not auth.get("idempotent_status"):
                return Observation(auth.get("decision", "EVALUATION_ERROR"), op, {"reason": auth.get("explanation", "authorization failed"), "policy": auth.get("policy")})
            if auth.get("decision") == "ALLOW":
                committed = r.gateway.commit(auth["ticket"], auth["commit_args"], principal, action_id=op)
                if request["tool"] != "model_inference" or committed["status"] not in {"COMMITTED", "OPERATION_ALREADY_COMMITTED"}:
                    emit(self.progress, "COMMIT", tool=request["tool"], operation=op, status=committed["status"])
                if committed["status"] == "STALE_TICKET":
                    if attempt == self.max_reauth: return Observation("RETRY_EXHAUSTED", op, committed)
                    continue
                if committed["status"] not in {"COMMITTED", "OPERATION_ALREADY_COMMITTED"}:
                    return Observation("REJECTED", op, committed)
            for _ in range(self.max_dispatch):
                status = operation_status(r.store, request["task_id"], op, args_hash(request), principal)
                if status["delivery"] in {"RELEASED", "FAILED"}: break
                claim = r.dispatcher.claim(task=request["task_id"], operation=op)
                if claim is None: break
                try:
                    payload = json.loads(claim["payload"])
                    if hasattr(self.receiver, "adeliver"):
                        receipt = asyncio.run(self.receiver.adeliver(claim["task"], op, payload))
                    else:
                        receipt = self.receiver.deliver(claim["task"], op, payload)
                    r.dispatcher.finish(claim, receipt)
                except Exception as exc:
                    r.dispatcher.finish(claim, error=type(exc).__name__)
            status = operation_status(r.store, request["task_id"], op, args_hash(request), principal)
            if request["tool"] != "model_inference" or status["delivery"] != "RELEASED":
                emit(self.progress, "DELIVERY", tool=request["tool"], operation=op, status=status["delivery"])
            detail = {"tool": request["tool"], "committed": True, "delivery": status["delivery"], "receipt": status["receipt"], "attempts": status["attempts"]}
            if request["tool"] == "read_document" and status["receipt"]:
                detail["source"] = {"resource": request["args"]["resource"], "digest": request["args"]["digest"]}
                detail["instruction_trust"] = "UNTRUSTED"
            return Observation("COMMITTED", op, detail)
        raise AssertionError("unreachable bounded reauthorization")
