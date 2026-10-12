"""Z3 policy: no external send after task exposure to finance/sensitive data."""
from __future__ import annotations

from typing import Any
from atomicroot.authority.policy_engine import (
    Ref, Const, Not, If, StatusReader, solve, PolicyResult, DATA_CLASSES,
    EvaluationError, valid_identity,
)

EXTERNAL_TOOLS = frozenset({"send_email", "send_http", "upload_file"})


def evaluate(task_context: dict[str, Any], trace_snapshot: dict[str, Any],
             request: dict[str, Any]) -> PolicyResult:
    """Only Z3 decides policy safety; Python validates and compiles concrete facts."""
    try:
        reader: StatusReader = trace_snapshot["reader"]
        external_tools = task_context.get("external_tools", EXTERNAL_TOOLS)
        external = request["tool"] in external_tools
        safe = If(Const(external), Not(Ref("tainted", "task")), Const(True))
        task_id = valid_identity(request["task_id"])
        write_set = []
        if request["tool"] == "read_document":
            doc_id = valid_identity(request["args"]["doc_id"])
            data_class = reader.read(f"class:{doc_id}")
            if not isinstance(data_class, str) or data_class not in DATA_CLASSES:
                raise EvaluationError("unsupported document classification")
            if request["args"].get("data_class", data_class) != data_class:
                raise EvaluationError("classification mismatch")
            if data_class in {"finance", "sensitive"}:
                write_set = [f"taint:{task_id}"]
        return solve("no_exfil_after_sensitive", safe, request, reader, write_set)
    except Exception as exc:
        return PolicyResult("EVALUATION_ERROR", {}, [], f"no_exfil_after_sensitive: {exc}")
