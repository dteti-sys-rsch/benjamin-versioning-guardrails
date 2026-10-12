"""Machine-readable JSON grammar generated from the trusted registry/node catalog."""
from atomicroot.authority.policy_engine import MAX_INTEGER, REQUEST_FIELDS
from atomicroot.framework.registry import SOURCES, TOOLS
from atomicroot.framework.dsl import BINARY

IDENTITY = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 256}
MONEY = {"type": "integer", "minimum": 0, "maximum": MAX_INTEGER}
FINITE = {"type": "array", "maxItems": 64, "uniqueItems": True, "items": {"type": "string", "maxLength": 256}}


def obj(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def schema():
    ref = {"$ref": "#/$defs/expression"}
    variants = [
        obj({"op": {"const": "const"}, "value": {"type": ["boolean", "integer", "string"]}}),
        obj({"op": {"const": "set"}, "values": FINITE}),
        obj({"op": {"const": "request"}, "name": {"enum": list(REQUEST_FIELDS)}}),
        obj({"op": {"const": "amount"}}),
        obj({"op": {"const": "not"}, "child": ref}),
        obj({"op": {"enum": ["and", "or"]}, "children": {"type": "array", "maxItems": 256, "items": ref}}),
        obj({"op": {"const": "if"}, "condition": ref, "yes": ref, "no": ref}),
        obj({"op": {"enum": list(BINARY)}, "left": ref, "right": ref}),
    ]
    for name, source in SOURCES.items():
        variants.append(obj({"op": {"const": "ref"}, "fact": {"const": name}, "scope": {"const": source.identity}}))
    policy = obj({"policy_id": IDENTITY, "version": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                  "scope": {"const": "task"}, "applies_to": {"type": "array", "minItems": 1, "maxItems": len(TOOLS), "items": {"enum": list(TOOLS)}},
                  "when": ref, "constraint": ref, "on_violation": {"enum": ["DENY", "ESCALATE"]}})
    proposal = obj({"task_id": IDENTITY, "objective": TEXT, "purpose": TEXT, "budget_limit": MONEY,
                    "allowed_tools": {"type": "array", "minItems": 1, "maxItems": len(TOOLS), "items": {"enum": list(TOOLS)}},
                    "allowed_resources": {**FINITE, "items": IDENTITY}, "allowed_recipients": FINITE,
                    "allowed_agents": {**FINITE, "minItems": 1, "items": IDENTITY},
                    "unknown_release": {"enum": ["DENY", "ESCALATE"]},
                    "policies": {"type": "array", "maxItems": 8, "items": {"oneOf": [
                        {"$ref": "#/$defs/policy"}, obj({"policy_id": IDENTITY, "version": {"type": "integer", "minimum": 1}})]}}})
    proposal["properties"]["classification_restrictions"] = {"type": "boolean", "default": False}
    proposal["properties"]["task_binding"] = obj({"id": IDENTITY,
        "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}})
    proposal["properties"]["inference_egress"] = {"type": "array", "maxItems": 16, "default": [], "items": obj({
        "provider": IDENTITY, "resource": IDENTITY, "purpose": TEXT,
        "labels": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"enum": ["PUBLIC", "SENSITIVE", "UNKNOWN"]}}})}
    binding = {"resource": IDENTITY, "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
               "content_version": {"type": "integer", "minimum": 1}, "model_id": TEXT, "model_version": TEXT,
               "criteria_version": TEXT, "criteria_hash": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}}
    result = obj({**binding, "outcome": {"enum": ["SUCCESS", "ERROR", "TIMEOUT", "MISSING_CONTENT"]},
                  "candidate_label": {"enum": ["PUBLIC", "SENSITIVE", "UNKNOWN"]},
                  "confidence": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
                  "probabilities": {"type": ["object", "null"], "additionalProperties": False,
                                    "properties": {name: {"type": "number", "minimum": 0, "maximum": 1}
                                                   for name in ("PUBLIC", "SENSITIVE", "UNKNOWN")}},
                  "covered_bytes": {"type": "integer", "minimum": 0}, "truncated": {"type": "boolean"},
                  "reason": {"type": "string", "maxLength": 256}})
    result["properties"].update({
        "option_order": {"const": ["PUBLIC", "SENSITIVE", "UNKNOWN"]},
        "reported_model": {"type": ["string", "null"], "maxLength": 256},
        "provider_mode": {"enum": ["disabled", "fake", "replay", "jev", None]},
        "usage": {"type": ["object", "null"], "additionalProperties": False,
                  "properties": {k: {"type": ["integer", "null"], "minimum": 0} for k in ("input_tokens", "output_tokens")}},
        "extraction": {"type": ["object", "null"]}})
    arguments = {"to": TEXT, "body": {"type": "string", "minLength": 1, "maxLength": 8192},
                 "amount": MONEY, "resource": IDENTITY, "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}}
    requests = [obj({"task_id": IDENTITY, "agent_id": IDENTITY, "operation_id": IDENTITY,
                     "purpose": TEXT, "tool": {"const": name}, "args": obj({k: arguments[k] for k in sorted(tool.required)})})
                for name, tool in TOOLS.items()]
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "AtomicRoot Phase 3 contract and request schema",
            "description": "Also enforce UTF-8 byte limits, AST types, 256 nodes/depth32, registered sources and current versions in the service.",
            "$defs": {"expression": {"oneOf": variants}, "policy": policy, "proposal": proposal,
                      "request": {"oneOf": requests}, "classification_begin": obj(binding),
                      "classification_result": result, "classification_accept": obj({"task_id": IDENTITY, "purpose": TEXT})},
            "oneOf": [{"$ref": "#/$defs/proposal"}, {"$ref": "#/$defs/request"}]}
