"""Six benchmark families over the existing extensible AST/Z3 enforcement."""
from dataclasses import asdict, dataclass
from atomicroot.framework.registry import FACT_REGISTRY


@dataclass(frozen=True)
class BenchmarkPolicy:
    policy_id: str
    applicability: str
    constraints: tuple[str, ...]
    keys: tuple[str, ...]
    authority: str
    transitions: str
    evidence: str
    limits: str


CATALOG = (
    BenchmarkPolicy("no_exfil_after_sensitive", "external business release; scoped provider exception remains separately authorized",
        ("no_exfil_after_sensitive", "unknown_release", "provider_scope"), ("exposure:{task}", "label:{resource}", "document:{resource}", "contract3:{task}"),
        "Gateway/LabelManager/approved contract", "exposure union before read delivery; owner labels and accepted restrictions remain distinct",
        "read intent, content binding, official label, classification proposal/restriction and release intent",
        "UNKNOWN follows explicit DENY/ESCALATE; classifier PUBLIC and worker claims never declassify"),
    BenchmarkPolicy("budget_monotone", "all actions; positive amounts only on spending tools", ("budget_monotone",),
        ("budget:{task}", "reserved:{task}", "contract3:{task}"), "Gateway/Dispatcher/ContractService",
        "reserve at intent, move reserved to used once after receipt; ambiguous outcome retains reservation",
        "intent facts and independently persisted receiver receipt", "integer smallest units, nonnegative bounded; no exactly-once provider billing claim"),
    BenchmarkPolicy("cap_subset", "managed A tasks", ("scope", "agent_scope", "parent_scope", "agent_membership", "parent_budget", "parent_execution_caps"),
        ("delegation:{task}:{agent}", "agents:{task}", "entitlement:{task}:{parent}", "taskresolved:{task}", "taskmode:{task}", "contract3:{task}"),
        "TaskService/ContractService/TrustedCatalog", "reviewed relation activation/revocation and aggregate membership version",
        "resolved TaskSpec, parent rights and actual per-agent correlated tuples", "reuses Phase 3.6 scope_expression and delegation_constraints, no second capability system in main runtime"),
    BenchmarkPolicy("recipient_pinned", "external tools", ("scope", "agent_scope", "parent_scope", "destination_scope"),
        ("contract3:{task}", "destination:{recipient}", "delegation:{task}:{agent}", "entitlement:{task}:{parent}"),
        "reviewed contract/delegation and admin destination catalog", "concrete destination is immutable in signed payload and outbox",
        "authorized payload hash, accepted intent and applied receiver destination", "cc/bcc/body_ref rejected; no alias/group resolver; unknown destination denied"),
    BenchmarkPolicy("no_write_after_stale_read", "update_document", ("no_write_after_stale_read",),
        ("readbasis:{task}:{operation}", "document:{resource}", "label:{resource}"), "trusted read receiver/RuntimeAuthority/Gateway",
        "immutable delivered receipt binds task/agent/resource/version/digest; write advances content and label atomically at intent",
        "server read_binding, immutable readbasis and actual document at acceptance", "stale receipt is not renewed by reauthorization; new read and reviewed plan may be required"),
    BenchmarkPolicy("irreversible_once", "each task-scoped logical operation ID", ("irreversible_once",),
        ("operation:{task}:{operation}", "consent:{task}:{operation}"), "Gateway/ApprovalBroker",
        "false to true, unique outbox/task-operation and ticket/nonce consume in same transaction",
        "logical operation digest, intent count and separate receiver receipt", "status reread is not new intent; a new ID does not prove a different semantic action; finite-prefix monitor only"),
)


def catalog():
    return {"schema_version": 1, "evaluator": "Z3 only", "query": "facts AND NOT(all applicable constraints)",
        "results": {"SAT": "DENY", "UNSAT": "candidate ALLOW after prerequisites", "UNKNOWN/error/missing/inconsistent": "no ticket"},
        "composition": "all applicable constraints; static all-branch plus trusted dynamic dependency union and policy-set membership; hard DENY wins",
        "benchmarks": [asdict(p) for p in CATALOG], "facts": [asdict(f) for f in FACT_REGISTRY.values()],
        "extension_example": {"policy_id": "research_small_action", "version": 3, "scope": "task", "applies_to": ["transfer_funds"],
            "when": {"op": "const", "value": True}, "constraint": {"op": "and", "children": [
                {"op": "le", "left": {"op": "amount"}, "right": {"op": "const", "value": 175}},
                {"op": "not", "child": {"op": "lt", "left": {"op": "ref", "fact": "budget_limit", "scope": "task"}, "right": {"op": "const", "value": 175}}}]},
            "on_violation": "DENY"}}
