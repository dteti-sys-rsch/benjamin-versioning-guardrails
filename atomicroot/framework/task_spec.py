"""Versioned explicit input; finite plans and scoped host inference contexts."""
from dataclasses import dataclass, fields
import json
import re

from atomicroot.authority.policy_engine import valid_identity, money_integer
from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.storage import dumps
from atomicroot.integration.providers import Limits


SPEC_FIELDS = frozenset({"schema_version", "task_id", "objective", "purpose", "resources", "scope", "budget_limit",
    "agents", "policies", "workflow", "outputs", "acceptance", "provider", "classifier", "limits", "unknown_release"})
RULE_FIELDS = frozenset({"tool", "resource", "destination", "purpose", "max_amount"})


def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("unknown or missing fields: " + ",".join(sorted(names)))


def text(value, limit=256):
    if type(value) is not str or not value or len(value.encode("utf-8")) > limit:
        raise ValueError("bounded nonempty text required")
    return value


def sequence(value, limit=16, *, nonempty=False):
    if type(value) is not list or len(value) > limit or (nonempty and not value):
        raise ValueError("invalid bounded collection")
    return value


def unique(items, key):
    ids = [item[key] for item in items]
    if len(ids) != len(set(ids)): raise ValueError("duplicate/conflicting " + key)


def rules(value):
    result = freeze_json(sequence(value, 12))
    for rule in result:
        exact(rule, RULE_FIELDS)
        if type(rule["tool"]) is not str: raise ValueError("tool must be a name")
        tool = TOOLS.get(rule["tool"])
        if tool is None: raise ValueError("unsupported tool")
        text(rule["purpose"])
        money_integer(rule["max_amount"])
        if tool.resource: valid_identity(rule["resource"])
        elif rule["resource"] is not None: raise ValueError("tool has no resource argument")
        if tool.external: text(rule["destination"])
        elif rule["destination"] is not None: raise ValueError("internal tool has no destination")
        if not tool.spending and rule["max_amount"] != 0: raise ValueError("nonfinancial tool bound must be zero")
    encoded = [dumps(r) for r in result]
    if len(encoded) != len(set(encoded)): raise ValueError("duplicate scope rule")
    return sorted(result, key=dumps)


@dataclass(frozen=True)
class TaskSpec:
    """Canonical bytes are immutable; callers receive independent decoded values."""
    serialized: str

    @property
    def data(self): return json.loads(self.serialized)

    @property
    def digest(self): return args_hash(self.data)

    @classmethod
    def parse(cls, value):
        data = freeze_json(value, max_bytes=32768)
        exact(data, SPEC_FIELDS)
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError("unsupported TaskSpec schema_version")
        valid_identity(data["task_id"])
        text(data["objective"]); text(data["purpose"])
        money_integer(data["budget_limit"])
        if type(data["unknown_release"]) is not str or data["unknown_release"] not in {"DENY", "ESCALATE"}: raise ValueError("invalid UNKNOWN rule")
        for ref in sequence(data["resources"]):
            exact(ref, {"resource", "digest", "version"} | ({"binding"} if "binding" in ref else set()))
            if "binding" in ref and ref["binding"] != "host_context": raise ValueError("unsupported content binding")
            valid_identity(ref["resource"])
            if type(ref["digest"]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", ref["digest"]):
                raise ValueError("invalid resource digest")
            if type(ref["version"]) is not int or ref["version"] < 1: raise ValueError("invalid resource version")
        unique(data["resources"], "resource")
        resource_ids = {r["resource"] for r in data["resources"]}
        data["scope"] = rules(data["scope"])
        if not data["scope"]: raise ValueError("explicit nonempty task scope required")
        for rule in data["scope"]:
            if rule["purpose"] != data["purpose"]: raise ValueError("scope purpose mismatch")
            if rule["resource"] is not None and rule["resource"] not in resource_ids:
                raise ValueError("missing resource reference")
            if rule["max_amount"] > data["budget_limit"]: raise ValueError("operation exceeds task budget")
            if any(r["resource"] == rule["resource"] and r.get("binding") == "host_context" for r in data["resources"]) and rule["tool"] != "model_inference":
                raise ValueError("host context is exclusively an inference resource")
        if resource_ids != {r["resource"] for r in data["scope"] if r["resource"] is not None}:
            raise ValueError("resource references must match explicit task scope")
        for agent in sequence(data["agents"], nonempty=True):
            exact(agent, {"id", "role", "scope"})
            valid_identity(agent["id"]); text(agent["role"])
            agent["scope"] = rules(agent["scope"])
            # Structural subset only: parent authorization is still decided by Z3.
            if any(rule not in data["scope"] for rule in agent["scope"]):
                raise ValueError("agent rules must be an explicit subset of task rules")
        unique(data["agents"], "id")
        sequence(data["policies"], 8)  # ContractService compiles definitions/references.
        exact(data["workflow"], {"nodes"})
        nodes = sequence(data["workflow"]["nodes"], 32, nonempty=True)
        for node in nodes:
            exact(node, {"id", "agent", "depends_on"})
            valid_identity(node["id"]); valid_identity(node["agent"])
            if node["agent"] not in {a["id"] for a in data["agents"]}: raise ValueError("unknown workflow agent")
            sequence(node["depends_on"], 32)
            for dep in node["depends_on"]: valid_identity(dep)
            if len(set(node["depends_on"])) != len(node["depends_on"]): raise ValueError("duplicate dependency")
        unique(nodes, "id")
        pending = {n["id"]: set(n["depends_on"]) for n in nodes}
        if any(not deps <= pending.keys() for deps in pending.values()): raise ValueError("missing workflow node")
        while pending:
            ready = {name for name, deps in pending.items() if not deps}
            if not ready: raise ValueError("workflow must be acyclic")
            pending = {name: deps - ready for name, deps in pending.items() if name not in ready}
        for output in sequence(data["outputs"]):
            exact(output, {"id", "kind"}); valid_identity(output["id"])
            if type(output["kind"]) is not str or output["kind"] not in {"summary", "artifact"}: raise ValueError("unsupported output kind")
        unique(data["outputs"], "id")
        for requirement in sequence(data["acceptance"], 32):
            kind = requirement.get("kind") if type(requirement) is dict else None
            if kind == "read":
                exact(requirement, {"kind", "resource"})
                if not any(r["tool"] == "read_document" and r["resource"] == requirement["resource"] for r in data["scope"]):
                    raise ValueError("required read outside task scope")
            elif kind == "receipt":
                exact(requirement, {"kind", "tool", "destination"})
                if not any(r["tool"] == requirement["tool"] and r["destination"] == requirement["destination"] for r in data["scope"]):
                    raise ValueError("required receipt outside task scope")
            elif kind == "output":
                exact(requirement, {"kind", "output"})
                if requirement["output"] not in {o["id"] for o in data["outputs"]}: raise ValueError("missing output")
            else: raise ValueError("unsupported acceptance operator")
        for rule in data["scope"]:
            if not any(rule in a["scope"] for a in data["agents"]): raise ValueError("task rule has no delegated agent")
        for ref in data["resources"]:
            if ref.get("binding") == "host_context" and sum(any(r["resource"] == ref["resource"] for r in a["scope"]) for a in data["agents"]) != 1:
                raise ValueError("host context requires one delegated agent")
        provider = data["provider"]
        if provider is not None:
            exact(provider, {"destination", "model"}); text(provider["destination"]); text(provider["model"])
            if not any(r["tool"] == "model_inference" for r in data["scope"]): raise ValueError("provider requires explicit inference scope")
        classifier = data["classifier"]
        if classifier == {"mode": "disabled"}: pass
        else:
            exact(classifier, {"mode", "destination", "model", "resources"} | ({"before_nodes"} if "before_nodes" in classifier else set()))
            if classifier["mode"] != "jev": raise ValueError("unsupported classifier mode")
            text(classifier["destination"]); text(classifier["model"])
            sequence(classifier["resources"])
            if not classifier["resources"] or len(set(classifier["resources"])) != len(classifier["resources"]):
                raise ValueError("invalid classifier targets")
            for resource in classifier["resources"]:
                if not any(r["tool"] == "classify_document" and r["resource"] == resource and
                           r["destination"] == classifier["destination"] for r in data["scope"]):
                    raise ValueError("classifier target outside scope")
            if "before_nodes" in classifier:
                sequence(classifier["before_nodes"], 32, nonempty=True)
                if len(set(classifier["before_nodes"])) != len(classifier["before_nodes"]) or not set(classifier["before_nodes"]) <= {n["id"] for n in nodes}:
                    raise ValueError("invalid classifier timing")
        for rule in data["scope"]:
            setting = provider if rule["tool"] == "model_inference" else classifier if rule["tool"] == "classify_document" else None
            if rule["tool"] in {"model_inference", "classify_document"} and (
                    not setting or setting.get("destination") != rule["destination"] or
                    (rule["tool"] == "classify_document" and rule["resource"] not in setting.get("resources", []))):
                raise ValueError("inference scope/settings mismatch")
        exact(data["limits"], {"max_steps", "max_in_flight", "inference"})
        for name, ceiling in (("max_steps", 64), ("max_in_flight", 16)):
            if type(data["limits"][name]) is not int or not 1 <= data["limits"][name] <= ceiling:
                raise ValueError("invalid execution limit")
        inference = data["limits"]["inference"]
        if type(inference) is not dict or not set(inference) <= {f.name for f in fields(Limits)}:
            raise ValueError("unsupported inference limit")
        if "timeout" in inference and type(inference["timeout"]) is not int: raise ValueError("TaskSpec timeout uses integer seconds")
        data["limits"]["inference"] = vars(Limits(**inference))
        return cls(dumps(data))


def task_schema():
    """Service parser remains authoritative for relational checks and byte bounds."""
    from atomicroot.framework.schema import obj, schema, IDENTITY, TEXT, MONEY
    rule = obj({"tool": {"enum": list(TOOLS)}, "resource": {"type": ["string", "null"]},
                "destination": {"type": ["string", "null"]}, "purpose": TEXT, "max_amount": MONEY})
    bounded = lambda item, maximum=16: {"type": "array", "maxItems": maximum, "items": item}
    settings = obj({"destination": TEXT, "model": TEXT})
    result = schema()
    result["$defs"]["task_spec"] = obj({
        "schema_version": {"const": 1}, "task_id": IDENTITY, "objective": TEXT, "purpose": TEXT,
        "resources": bounded({"oneOf": [obj({"resource": IDENTITY, "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                                  "version": {"type": "integer", "minimum": 1}}), obj({"resource": IDENTITY,
                                  "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}, "version": {"type": "integer", "minimum": 1},
                                  "binding": {"const": "host_context"}})]}),
        "scope": bounded(rule, 12), "budget_limit": MONEY,
        "agents": bounded(obj({"id": IDENTITY, "role": TEXT, "scope": bounded(rule, 12)})),
        "policies": result["$defs"]["proposal"]["properties"]["policies"],
        "workflow": obj({"nodes": bounded(obj({"id": IDENTITY, "agent": IDENTITY,
                                               "depends_on": bounded(IDENTITY, 32)}), 32)}),
        "outputs": bounded(obj({"id": IDENTITY, "kind": {"enum": ["summary", "artifact"]}})),
        "acceptance": bounded({"oneOf": [obj({"kind": {"const": "read"}, "resource": IDENTITY}),
            obj({"kind": {"const": "receipt"}, "tool": {"enum": list(TOOLS)}, "destination": {"type": ["string", "null"], "maxLength": 256}}),
            obj({"kind": {"const": "output"}, "output": IDENTITY})]}, 32),
        "provider": {"oneOf": [{"type": "null"}, settings]},
        "classifier": {"oneOf": [obj({"mode": {"const": "disabled"}}),
            *[obj({"mode": {"const": "jev"}, "destination": TEXT, "model": TEXT, "resources": bounded(IDENTITY),
                   **({"before_nodes": bounded(IDENTITY, 32)} if timing else {})}) for timing in (False, True)]]},
        "limits": obj({"max_steps": {"type": "integer", "minimum": 1, "maximum": 64},
                       "max_in_flight": {"type": "integer", "minimum": 1, "maximum": 16},
                       "inference": {"type": "object", "additionalProperties": False, "properties": {
                           f.name: ({"type": ["number", "null"]} if f.name in {"spend_cap_usd", "input_price_per_million", "output_price_per_million"}
                                    else {"type": "integer"}) for f in fields(Limits)}}}),
        "unknown_release": {"enum": ["DENY", "ESCALATE"]}})
    result["oneOf"] = [{"$ref": "#/$defs/task_spec"}]
    result["title"] = "AtomicRoot TaskSpec v1"
    return result
