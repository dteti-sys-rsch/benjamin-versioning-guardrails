"""Z3 policy: cumulative committed spend plus the proposed spend <= contract cap."""
from __future__ import annotations

from typing import Any
from atomicroot.authority.policy_engine import (
    Ref, RequestAmount, Const, Add, Le, If, StatusReader, solve, PolicyResult,
)

SPENDING_TOOLS = frozenset({"transfer_funds", "make_payment", "purchase"})


def evaluate(task_context: dict[str, Any], trace_snapshot: dict[str, Any],
             request: dict[str, Any]) -> PolicyResult:
    try:
        reader: StatusReader = trace_snapshot["reader"]
        spending = request["tool"] in SPENDING_TOOLS
        amount = RequestAmount() if spending else Const(0)
        within_cap = Le(Add(Ref("spent", "task"), amount), Ref("cap", "task"))
        safe = If(Const(spending), within_cap, Const(True))
        writes = [f"budget:{request['task_id']}"] if spending else []
        return solve("budget_monotone", safe, request, reader, writes)
    except Exception as exc:
        return PolicyResult("EVALUATION_ERROR", {}, [], f"budget_monotone: {exc}")
