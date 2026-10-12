"""Small typed policy AST, static dependencies, instrumented state reads, Z3."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from types import MappingProxyType
import json
import re
import threading
from functools import wraps

import z3


class EvaluationError(ValueError):
    pass


IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_INTEGER = (1 << 63) - 1
MAX_AST_NODES = 256
MAX_AST_DEPTH = 32
MAX_STATE_BYTES = 16_384
MAX_SOLVER_TIMEOUT_MS = 1000
SOLVER_RESOURCE_LIMIT = 100_000
DATA_CLASSES = frozenset({"finance", "sensitive", "internal", "public"})


def money_integer(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise EvaluationError("money must be a nonnegative integer <= 2^63-1 in smallest units")
    return value


def valid_identity(value: Any) -> str:
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise EvaluationError("invalid resource/task identity")
    return value


@dataclass(frozen=True)
class Ref:
    kind: str  # name in the trusted FACT_SOURCES table
    identity: str  # task | document


@dataclass(frozen=True)
class Const:
    value: bool | int


@dataclass(frozen=True)
class RequestAmount:
    pass


@dataclass(frozen=True)
class RequestField:
    name: str


REQUEST_FIELDS = MappingProxyType({"tool": "str", "agent_id": "str", "purpose": "str",
                                  "recipient": "str", "resource": "str"})


@dataclass(frozen=True)
class SetConst:
    values: tuple[str, ...]


@dataclass(frozen=True)
class Eq:
    left: Any
    right: Any


@dataclass(frozen=True)
class Lt:
    left: Any
    right: Any


@dataclass(frozen=True)
class Sub:
    left: Any
    right: Any


@dataclass(frozen=True)
class Member:
    left: Any
    right: Any


@dataclass(frozen=True)
class Subset:
    left: Any
    right: Any


@dataclass(frozen=True)
class Or:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class Add:
    left: Any
    right: Any


@dataclass(frozen=True)
class Le:
    left: Any
    right: Any


@dataclass(frozen=True)
class Not:
    child: Any


@dataclass(frozen=True)
class And:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class If:
    condition: Any
    yes: Any
    no: Any


@dataclass
class PolicyResult:
    decision: str
    footprint: dict[str, int]
    write_set: list[str]
    explanation: str = ""
    trigger_event: dict[str, Any] | None = None
    violating_action: dict[str, Any] | None = None
    evidence_events: list[dict[str, Any]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    witness: dict[str, Any] | None = None


def _cap(raw):
    if not isinstance(raw, dict) or "budget_cap" not in raw:
        raise EvaluationError("missing contract cap")
    return money_integer(raw["budget_cap"])


def _tainted(raw):
    if not isinstance(raw, list) or len(raw) > len(DATA_CLASSES) or any(
            not isinstance(v, str) or v not in DATA_CLASSES for v in raw):
        raise EvaluationError("invalid or unsupported taint facts")
    return bool(set(raw) & {"finance", "sensitive"})


@dataclass(frozen=True)
class FactSource:
    """Trusted source descriptor; extensions add a decoder and conflict-key scope."""
    prefix: str
    identity: str
    value_type: str
    decode: Any


FACT_SOURCES = MappingProxyType({
    "spent": FactSource("budget", "task", "int", money_integer),
    "cap": FactSource("contract", "task", "int", _cap),
    "tainted": FactSource("taint", "task", "bool", _tainted),
})


def resolve(ref: Ref, request: dict[str, Any], sources=None) -> str:
    spec = (FACT_SOURCES if sources is None else sources).get(ref.kind)
    if spec is None or ref.identity != spec.identity:
        raise EvaluationError("unsupported fact source or identity scope")
    if ref.identity == "task":
        identity = valid_identity(request["task_id"])
    elif ref.identity == "document":
        identity = valid_identity(request["args"].get("doc_id", request["args"].get("resource")))
    elif ref.identity == "operation":
        identity = valid_identity(request["task_id"]) + ":" + valid_identity(request["operation_id"])
    else:
        raise EvaluationError("unknown identity")
    return f"{spec.prefix}:{identity}"


def ast_type(node: Any, sources=None) -> str:
    """Bound traversal first, then check every node's operand types."""
    pending = [(node, 1)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise EvaluationError("AST exceeds node/depth limits")
        if type(current) in (Ref, Const, RequestAmount, RequestField, SetConst):
            children = ()
        elif type(current) in (Add, Le, Sub, Lt, Eq, Member, Subset):
            children = (current.left, current.right)
        elif type(current) is Not:
            children = (current.child,)
        elif type(current) in (And, Or) and type(current.children) is tuple:
            children = current.children
        elif type(current) is If:
            children = (current.condition, current.yes, current.no)
        else:
            raise EvaluationError("unsupported AST node")
        if len(children) + count > MAX_AST_NODES:
            raise EvaluationError("AST exceeds node limits")
        pending.extend((child, depth + 1) for child in children)

    def infer(current):
        if type(current) is Const:
            if type(current.value) is bool:
                return "bool"
            if type(current.value) is int and abs(current.value) <= MAX_INTEGER:
                return "int"
            if type(current.value) is str and len(current.value) <= 256:
                return "str"
            raise EvaluationError("invalid or oversized constant")
        if type(current) is SetConst:
            finite_strings(current.values)
            return "set"
        if type(current) is RequestField:
            if current.name not in REQUEST_FIELDS:
                raise EvaluationError("unknown request field")
            return REQUEST_FIELDS[current.name]
        if type(current) is RequestAmount:
            return "int"
        if type(current) is Ref:
            spec = (FACT_SOURCES if sources is None else sources).get(current.kind)
            if spec is None or current.identity != spec.identity:
                raise EvaluationError("unsupported fact source or identity scope")
            return spec.value_type
        if type(current) in (Add, Le, Sub, Lt):
            if infer(current.left) != "int" or infer(current.right) != "int":
                raise EvaluationError("arithmetic operands must be integer")
            return "int" if type(current) in (Add, Sub) else "bool"
        if type(current) is Eq:
            if infer(current.left) != infer(current.right):
                raise EvaluationError("equality types must match")
            return "bool"
        if type(current) in (Member, Subset):
            if infer(current.left) != ("str" if type(current) is Member else "set") or infer(current.right) != "set":
                raise EvaluationError("invalid finite set operands")
            return "bool"
        if type(current) is Not:
            if infer(current.child) != "bool":
                raise EvaluationError("Not operand must be boolean")
            return "bool"
        if type(current) in (And, Or):
            if any(infer(child) != "bool" for child in current.children):
                raise EvaluationError("And operands must be boolean")
            return "bool"
        if infer(current.condition) != "bool":
            raise EvaluationError("If condition must be boolean")
        yes, no = infer(current.yes), infer(current.no)
        if yes != no:
            raise EvaluationError("If branch types must match")
        return yes
    return infer(node)


def dependencies(node: Any, request: dict[str, Any], sources=None) -> set[str]:
    """Visit every branch, even when runtime evaluation will not take it."""
    ast_type(node, sources)
    def visit(current):
        if isinstance(current, Ref):
            return {resolve(current, request, sources)}
        if isinstance(current, (Const, RequestAmount, RequestField, SetConst)):
            return set()
        if isinstance(current, (Add, Le, Sub, Lt, Eq, Member, Subset)):
            return visit(current.left) | visit(current.right)
        if isinstance(current, Not):
            return visit(current.child)
        if isinstance(current, (And, Or)):
            return set().union(*(visit(c) for c in current.children))
        return visit(current.condition) | visit(current.yes) | visit(current.no)
    return visit(node)


class StatusReader:
    """The only route to policy state; all reads use one SQLite Snapshot."""

    def __init__(self, snapshot, sources=None):
        self.snapshot = snapshot
        self.sources = FACT_SOURCES if sources is None else sources
        self.reads: dict[str, int] = {}
        self.values: dict[str, Any] = {}

    def read(self, key: str) -> Any:
        missing = object()
        version, value = self.snapshot.read(key, missing)
        if value is missing:
            raise EvaluationError(f"missing fact: {key}")
        if type(version) is not int or version < 0:
            raise EvaluationError("invalid fact version")
        if len(json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_STATE_BYTES:
            raise EvaluationError("fact exceeds size limit")
        self.reads[key] = version
        self.values[key] = value
        return value

    def footprint(self, static_keys: set[str]) -> dict[str, int]:
        footprint = {}
        for key in sorted(static_keys | self.reads.keys()):
            missing = object()
            version, value = self.snapshot.read(key, missing)
            if value is missing:
                raise EvaluationError(f"missing static dependency: {key}")
            footprint[key] = version
        return footprint


def finite_strings(value):
    if type(value) not in (list, tuple) or len(value) > 64 or any(
            type(v) is not str or len(v) > 256 for v in value):
        raise EvaluationError("expected finite string set (<=64 items, <=256 chars/item)")
    return tuple(sorted(set(value)))


def literal(value, kind):
    if kind == "bool":
        if type(value) is not bool:
            raise EvaluationError("expected boolean fact")
        return z3.BoolVal(value)
    if kind == "int":
        if type(value) is not int or abs(value) > MAX_INTEGER:
            raise EvaluationError("expected bounded integer fact")
        return z3.IntVal(value)
    if kind == "str":
        if type(value) is not str or len(value) > 256:
            raise EvaluationError("expected bounded string fact")
        return z3.StringVal(value)
    if kind == "set":
        result = z3.EmptySet(z3.StringSort())
        for item in finite_strings(value):
            result = z3.SetAdd(result, z3.StringVal(item))
        return result
    raise EvaluationError("unknown fact type")


def encode(node: Any, request: dict[str, Any], reader: StatusReader,
           facts: list[Any], cache: dict[str, Any]):
    if isinstance(node, Const):
        if type(node.value) is bool:
            return z3.BoolVal(node.value)
        if type(node.value) is int:
            return z3.IntVal(node.value)
        if type(node.value) is str:
            return z3.StringVal(node.value)
        raise EvaluationError("invalid constant")
    if isinstance(node, SetConst):
        return literal(node.values, "set")
    if isinstance(node, RequestField):
        return literal(request[node.name], REQUEST_FIELDS[node.name])
    if isinstance(node, RequestAmount):
        amount = money_integer(request["args"].get("amount"))
        return z3.IntVal(amount)
    if isinstance(node, Ref):
        key = resolve(node, request, reader.sources)
        # Several typed fields may share one versioned row (e.g. contract).
        spec = reader.sources[node.kind]
        cache_key = key if reader.sources is FACT_SOURCES else f"{key}/{node.kind}"
        if cache_key not in cache:
            value = spec.decode(reader.read(key))
            concrete = literal(value, spec.value_type)
            symbol = z3.Const(f"state_{len(cache)}", concrete.sort())
            facts.append(symbol == concrete)
            cache[cache_key] = symbol
        return cache[cache_key]
    if isinstance(node, (Sub, Lt, Eq, Member, Subset)):
        left = encode(node.left, request, reader, facts, cache)
        right = encode(node.right, request, reader, facts, cache)
        if isinstance(node, Sub): return left - right
        if isinstance(node, Lt): return left < right
        if isinstance(node, Eq): return left == right
        if isinstance(node, Member): return z3.IsMember(left, right)
        return z3.IsSubset(left, right)
    if isinstance(node, Add):
        return encode(node.left, request, reader, facts, cache) + encode(node.right, request, reader, facts, cache)
    if isinstance(node, Le):
        return encode(node.left, request, reader, facts, cache) <= encode(node.right, request, reader, facts, cache)
    if isinstance(node, Not):
        return z3.Not(encode(node.child, request, reader, facts, cache))
    if isinstance(node, And):
        return z3.And(*(encode(c, request, reader, facts, cache) for c in node.children))
    if isinstance(node, Or):
        return z3.Or(*(encode(c, request, reader, facts, cache) for c in node.children))
    if isinstance(node, If):
        # Encoding all branches also records their dynamic dependencies.
        return z3.If(encode(node.condition, request, reader, facts, cache),
                     encode(node.yes, request, reader, facts, cache),
                     encode(node.no, request, reader, facts, cache))
    raise EvaluationError("unsupported AST node")


_Z3_LOCK = threading.RLock()


def _serialized_z3(function):
    @wraps(function)
    def run(*args, **kwargs):
        # The shared default Z3 context is process-local and must not be used
        # concurrently by API threads with separate database connections.
        with _Z3_LOCK:
            return function(*args, **kwargs)
    return run


@_serialized_z3
def solve(policy: str, expr: Any, request: dict[str, Any], reader: StatusReader,
          write_set: list[str], *, timeout_ms: int = 1000,
          solver_factory=None) -> PolicyResult:
    """SAT(facts AND NOT safe)=DENY; UNSAT=ALLOW; other outcomes fail closed."""
    try:
        if type(timeout_ms) is not int or not 0 < timeout_ms <= MAX_SOLVER_TIMEOUT_MS:
            raise EvaluationError("invalid solver timeout")
        if ast_type(expr, reader.sources) != "bool":
            raise EvaluationError("policy root must be boolean")
        static_keys = dependencies(expr, request, reader.sources)
        facts: list[Any] = []
        cache: dict[str, Any] = {}
        safe = encode(expr, request, reader, facts, cache)
        solver = (solver_factory or z3.Solver)()
        solver.set(timeout=timeout_ms, rlimit=SOLVER_RESOURCE_LIMIT)
        solver.add(*facts)
        consistency = solver.check()
        if consistency == z3.unsat:
            raise EvaluationError("inconsistent facts")
        if consistency != z3.sat:
            reason = solver.reason_unknown() if hasattr(solver, "reason_unknown") else str(consistency)
            raise EvaluationError(f"facts consistency unresolved: {reason}")
        solver.push()
        solver.add(z3.Not(safe))
        outcome = solver.check()
        footprint = reader.footprint(static_keys)
        if outcome == z3.unsat:
            return PolicyResult("ALLOW", footprint, write_set, f"{policy}: allowed")
        if outcome != z3.sat:
            reason = solver.reason_unknown() if hasattr(solver, "reason_unknown") else str(outcome)
            raise EvaluationError(f"solver outcome UNKNOWN: {reason}")
        model = solver.model()
        witness = {key: str(model.eval(sym, model_completion=True)) for key, sym in cache.items()}
        task_id = request["task_id"]
        events = reader.snapshot.events(task_id)
        if policy == "no_exfil_after_sensitive":
            evidence = [e for e in events if e["tool"] == "read_document" and
                        json.loads(e["args"]).get("_resolved_data_class") in {"finance", "sensitive"}]
            explanation = f"task {task_id} was exposed to sensitive data; external send denied"
        elif policy == "budget_monotone":
            evidence = [e for e in events if e["tool"] in {"transfer_funds", "make_payment", "purchase"}]
            explanation = f"projected spend exceeds contract cap for task {task_id}"
        else:
            evidence = events
            explanation = f"{policy}: constraint violated for task {task_id}"
        return PolicyResult("DENY", footprint, [], explanation,
                            evidence[-1] if evidence else None,
                            {"tool": request["tool"], "args": request["args"]},
                            evidence, dict(reader.values), witness)
    except Exception as exc:
        return PolicyResult("EVALUATION_ERROR", {}, [], f"{policy}: {exc}")
