"""Strict JSON front end for the shared Phase 2/3 typed AST; Z3 only."""
from atomicroot.authority.policy_engine import (
    Ref, Const, SetConst, RequestAmount, RequestField, Add, Sub, Eq, Le, Lt,
    Not, And, Or, If, Member, Subset, ast_type, dependencies, solve, EvaluationError,
    valid_identity, MAX_AST_NODES, MAX_AST_DEPTH,
)
from atomicroot.framework.registry import SOURCES, TOOLS


BINARY = {"add": Add, "sub": Sub, "eq": Eq, "le": Le, "lt": Lt,
          "member": Member, "subset": Subset}
RESERVED_POLICIES = frozenset({"no_exfil_after_sensitive", "budget_monotone", "scope", "unknown_release", "provider_scope",
    "agent_scope", "agent_membership", "parent_scope", "parent_budget", "destination_scope", "resolved_provider", "resolved_model"})


def parse_expr(data):
    count = 0
    def visit(node, depth):
        nonlocal count
        count += 1
        if count > MAX_AST_NODES or depth > MAX_AST_DEPTH or type(node) is not dict:
            raise EvaluationError("invalid or oversized JSON AST")
        op = node.get("op")
        fields = {"const": {"value"}, "set": {"values"}, "ref": {"fact", "scope"},
                  "request": {"name"}, "amount": set(), "not": {"child"},
                  "and": {"children"}, "or": {"children"}, "if": {"condition", "yes", "no"}}
        expected = {"left", "right"} if op in BINARY else fields.get(op)
        if expected is None or set(node) != expected | {"op"}:
            raise EvaluationError("unsupported AST operation or fields")
        if op == "const": return Const(node["value"])
        if op == "set":
            if type(node["values"]) is not list: raise EvaluationError("set expects array")
            return SetConst(tuple(node["values"]))
        if op == "ref": return Ref(node["fact"], node["scope"])
        if op == "request": return RequestField(node["name"])
        if op == "amount": return RequestAmount()
        if op in BINARY: return BINARY[op](visit(node["left"], depth + 1), visit(node["right"], depth + 1))
        if op == "not": return Not(visit(node["child"], depth + 1))
        if op in ("and", "or"):
            if type(node["children"]) is not list or len(node["children"]) > MAX_AST_NODES:
                raise EvaluationError("invalid children")
            return (And if op == "and" else Or)(tuple(visit(c, depth + 1) for c in node["children"]))
        return If(*(visit(node[k], depth + 1) for k in ("condition", "yes", "no")))
    expr = visit(data, 1)
    ast_type(expr, SOURCES)
    return expr


def compile_policy(definition):
    if set(definition) != {"policy_id", "version", "scope", "applies_to", "when", "constraint", "on_violation"}:
        raise EvaluationError("unsupported policy fields")
    valid_identity(definition["policy_id"])
    if definition["policy_id"] in RESERVED_POLICIES:
        raise EvaluationError("built-in safety policies cannot be overridden")
    if type(definition["version"]) is not int or not 1 <= definition["version"] <= 1_000_000:
        raise EvaluationError("invalid policy version")
    if definition["scope"] != "task" or definition["on_violation"] not in ("DENY", "ESCALATE"):
        raise EvaluationError("unsupported scope or violation disposition")
    applies = definition["applies_to"]
    if type(applies) is not list or not applies or len(applies) > len(TOOLS) or any(t not in TOOLS for t in applies):
        raise EvaluationError("unknown tool")
    expr = If(parse_expr(definition["when"]), parse_expr(definition["constraint"]), Const(True))
    if ast_type(expr, SOURCES) != "bool": raise EvaluationError("constraint must be boolean")
    for tool in applies:
        # A known fact source can still be impossible to resolve for a tool.
        # Validate every static branch against the tool's request shape now.
        dependencies(expr, {"task_id": "preview", "operation_id": "preview",
                            "args": {"resource": "preview"} if TOOLS[tool].resource else {}}, SOURCES)
    return expr


def evaluate(task_context, trace_snapshot, request):
    """Same public evaluator interface; one reader/snapshot for every policy."""
    definition = task_context["definition"]
    return solve(definition["policy_id"], compile_policy(definition), request,
                 trace_snapshot["reader"], [])


def builtin_constraints(request):
    tool = TOOLS[request["tool"]]
    task = lambda name: Ref(name, "task")
    scope = [Member(RequestField("tool"), task("allowed_tools")),
             Member(RequestField("agent_id"), task("allowed_agents")),
             Eq(RequestField("purpose"), task("purpose"))]
    if tool.external: scope.append(Member(RequestField("recipient"), task("allowed_recipients")))
    if tool.resource: scope.append(Member(RequestField("resource"), task("allowed_resources")))
    sensitive = Member(Const("SENSITIVE"), task("exposure"))
    unknown = Member(Const("UNKNOWN"), task("exposure"))
    if tool.resource and tool.external:
        sensitive = Or((sensitive, Const(request["resolved_label"] == "SENSITIVE")))
        unknown = Or((unknown, Const(request["resolved_label"] == "UNKNOWN")))
    inference = request["tool"] in {"classify_document", "model_inference"}
    model_context = request["tool"] == "model_inference"
    # Separate pre-existing ingestion authorization, never a predicted label.
    provider_rules = []
    if inference:
        for rule in request.get("inference_egress", []):
            if rule["resource"] != request["resource"]: continue
            constraints = (
                Eq(RequestField("recipient"), Const(rule["provider"])),
                Eq(RequestField("resource"), Const(rule["resource"])),
                Eq(RequestField("purpose"), Const(rule["purpose"])),
                Member(Const(request["resolved_label"]), SetConst(tuple(rule["labels"])))
            )
            if model_context: constraints += (Subset(task("exposure"), SetConst(tuple(rule["labels"]))),)
            provider_rules.append(And(constraints))
    provider_scope = Or(tuple(provider_rules)) if inference else Const(True)
    # Model context is server-created and checked against every input's approved
    # provider scope by Authority. This exception authorizes inference only;
    # sensitive external release remains a hard DENY for business tools.
    if model_context:
        source_rules = []
        for source in request["model_source_bindings"]:
            applicable = []
            for rule in request.get("inference_egress", []):
                if rule["resource"] != source["resource"]: continue
                applicable.append(And((
                    Eq(RequestField("recipient"), Const(rule["provider"])),
                    Eq(RequestField("purpose"), Const(rule["purpose"])),
                    Member(Const(source["label"]), SetConst(tuple(rule["labels"])))
                )))
            source_rules.append(Or(tuple(applicable)))
        provider_scope = And((provider_scope, *source_rules))
    return [
        ("scope", And(tuple(scope)), "DENY"),
        ("provider_scope", provider_scope, "DENY"),
        ("budget_monotone", Le(Add(Add(task("budget_used"), task("budget_reserved")), RequestAmount()), task("budget_limit")), "DENY"),
        ("no_exfil_after_sensitive", If(Const(tool.external and not model_context), Not(sensitive), Const(True)), "DENY"),
        ("unknown_release", If(Const(tool.external and not inference), Not(unknown), Const(True)), request["unknown_release"]),
    ]
