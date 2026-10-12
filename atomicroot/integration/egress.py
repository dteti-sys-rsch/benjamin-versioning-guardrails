"""Validate exact model context using the Authority's existing snapshot reader."""
import json
from atomicroot.framework.labels import LabelManager
from atomicroot.authority.policy_engine import valid_identity


def validate_model_context(reader, document, request):
    context = json.loads(document["content"])
    fields = {"messages", "sources", "provider", "model", "prompt_version"}
    if type(context) is not dict or set(context) not in (fields, fields | {"response_schema"}):
        raise ValueError("invalid server model context")
    if context["provider"] != request["recipient"] or not isinstance(context["model"], str):
        raise ValueError("model provider binding mismatch")
    if type(context["messages"]) is not list or type(context["sources"]) is not list:
        raise ValueError("invalid model messages/sources")
    if "response_schema" in context:
        from atomicroot.integration.prompts import worker_response_schema
        # Use the same Authority snapshot; schema cannot grant another tool or
        # become a worker-controlled escape from the host's capability bounds.
        contract = reader.read(f"contract3:{request['task_id']}")
        if context["provider"] != "ollama" or context["response_schema"] != worker_response_schema(contract):
            raise ValueError("untrusted worker response schema")
    for message in context["messages"]:
        if type(message) is not dict or set(message) != {"role", "content"} or message["role"] not in {"system", "user"} or type(message["content"]) is not str:
            raise ValueError("invalid model message")
    bindings = []
    for source in context["sources"]:
        if type(source) is not dict or set(source) != {"resource", "digest"}: raise ValueError("invalid source binding")
        valid_identity(source["resource"])
        _, label = LabelManager.resolve(reader, source["resource"], source["digest"], request["purpose"])
        bindings.append({"resource": source["resource"], "label": label})
    # Derive concrete facts only. Permission predicates are encoded in the same
    # trusted AST as every other policy and evaluated by Z3, not this reader.
    return bindings
