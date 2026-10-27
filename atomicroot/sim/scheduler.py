"""Dependency-ready finite schedules and versioned, inspectable replay artifacts."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
import json
import random

from nacl.signing import VerifyKey
from atomicroot.authority.ticket import Ticket, args_hash, freeze_json
from atomicroot.observability import point, Stopwatch, protocol_run

SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class TestInputs:
    """Explicit test-only clock, IDs and schedule RNG; never replaces crypto RNG."""
    __test__ = False
    def __init__(self, seed=0, start="2026-10-25T00:00:00+00:00"):
        self.value = datetime.fromisoformat(start)
        if self.value.tzinfo is None: raise ValueError("timezone required")
        self.seed, self.random = seed, random.Random(seed)
        self.counter, self.lock = 0, Lock()

    def clock(self): return self.value
    def advance(self, seconds):
        if type(seconds) is not int or seconds < 0: raise ValueError("nonnegative integer clock step required")
        self.value += timedelta(seconds=seconds)
    def new_id(self, prefix):
        with self.lock:
            self.counter += 1
            return f"{prefix}-test-{self.seed}-{self.counter:08d}"


@dataclass(frozen=True)
class Action:
    id: str
    kind: str
    actor: str = "worker"
    depends_on: tuple[str, ...] = ()
    arrival: int = 0
    priority: int = 0
    data: dict = field(default_factory=dict)

    def __post_init__(self):
        if (type(self.id) is not str or not 0 < len(self.id) <= 128 or
                type(self.kind) is not str or not self.kind or
                self.actor not in {"worker", "trusted_fixture", "fault", "framework"} or
                type(self.arrival) is not int or self.arrival < 0 or
                type(self.priority) is not int or abs(self.priority) > 1_000_000 or
                len(set(self.depends_on)) != len(self.depends_on) or
                any(type(x) is not str for x in self.depends_on) or type(self.data) is not dict):
            raise ValueError("invalid scheduled action")
        freeze_json(self.data)


class HookLog:
    def __init__(self): self.steps, self.lock = [], Lock()
    def checkpoint(self, stage, action_id, *, deferred=False, task=None):
        observation = {"stage": stage, "action": action_id}
        if deferred: observation.update(deferred=True, observed_after="fallback_release")
        if task is not None: observation["task"] = task
        with self.lock:
            observation["observed"] = point()
            self.steps.append(observation)
    def context_checkpoint(self, stage, action_id, *, task=None, deferred=False):
        self.checkpoint(stage, action_id, task=task, deferred=deferred)
    def deferred_checkpoint(self, stage, action_id):
        self.checkpoint(stage, action_id, deferred=True)


class ReadyScheduler:
    """Actions are protocol boundaries, never partial database transactions.

    FIFO breaks equal priorities; a finite action bound limits priority starvation.
    A hostile scheduler can still withhold a required dependency indefinitely.
    """
    def __init__(self, actions, *, preferred=(), max_steps=2048):
        self.actions = [a if isinstance(a, Action) else Action(**a) for a in actions]
        if not 1 <= len(self.actions) <= max_steps <= 2048: raise ValueError("invalid action bound")
        ids = [a.id for a in self.actions]
        if len(set(ids)) != len(ids): raise ValueError("duplicate action id")
        known, reachable = set(ids), set()
        if any(not set(a.depends_on) <= known for a in self.actions): raise ValueError("unknown dependency")
        while True:
            added = {a.id for a in self.actions if set(a.depends_on) <= reachable} - reachable
            if not added: break
            reachable |= added
        if reachable != known: raise ValueError("cyclic dependencies")
        if len(set(preferred)) != len(preferred) or not set(preferred) <= known: raise ValueError("invalid preferred plan")
        self.preferred, self.max_steps = list(preferred), max_steps

    def run(self, execute, *, ready=lambda a, results: True, exact_schedule=None):
        results, schedule, divergence = {}, [], []
        timer, windows = Stopwatch(), []
        tick = 0
        while len(results) < len(self.actions):
            candidates = [a for a in self.actions if a.id not in results and a.arrival <= tick and
                          set(a.depends_on) <= results.keys() and ready(a, results)]
            if not candidates:
                arrivals = [a.arrival for a in self.actions if a.id not in results and a.arrival > tick]
                if arrivals: tick = min(arrivals); continue
                break
            ranked = sorted(candidates, key=lambda a: (-a.priority, self.actions.index(a)))
            desired = (exact_schedule[len(schedule)] if exact_schedule is not None and len(schedule) < len(exact_schedule)
                       else next((p for p in self.preferred if p not in results), None))
            chosen = next((a for a in ranked if a.id == desired), ranked[0])
            if desired is not None and chosen.id != desired:
                divergence.append({"step": len(schedule), "requested": desired, "chosen": chosen.id, "reason": "requested action unready"})
            step_timer = Stopwatch()
            observation = execute(chosen, results)
            windows.append({"step": len(schedule), "action": chosen.id, **step_timer.finish()})
            results[chosen.id] = freeze_json(observation, max_bytes=MAX_ARTIFACT_BYTES)
            schedule.append({"tick": tick, "ready": sorted(a.id for a in candidates), "chosen": chosen.id})
            tick += 1
        if exact_schedule is not None and len(schedule) != len(exact_schedule):
            divergence.append({"reason": "schedule length changed", "expected": len(exact_schedule), "actual": len(schedule)})
        return {"schedule": schedule, "observations": results, "divergence": divergence,
                "observed_timing": {**timer.finish(), "steps": windows},
                "terminal": "COMPLETED" if len(results) == len(self.actions) else "BLOCKED",
                "blocked": [a.id for a in self.actions if a.id not in results]}


def semantic(value, public_key):
    """Retain every signed field; replace only key-specific signature bytes by proof.

    Raw tickets remain in the artifact. IDs/nonces/expiry/footprint/write sets and
    exact payload hashes are compared verbatim, including failed attack tickets.
    """
    if isinstance(value, dict):
        if set(value) == set(Ticket.__dataclass_fields__):
            ticket = Ticket.from_dict(value)
            if not ticket.verify(VerifyKey(bytes.fromhex(public_key))): return value
            return {**value, "signature": {"algorithm": "Ed25519", "verified": ticket.verify(VerifyKey(bytes.fromhex(public_key))),
                    "signed_payload_digest": args_hash(json.loads(ticket.canonical_bytes())), "key_role": "temporary-test-authority"}}
        return {k: semantic(v, public_key) for k, v in value.items()}
    if isinstance(value, list): return [semantic(v, public_key) for v in value]
    return value


def save_artifact(path, artifact):
    validate_artifact(artifact)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(artifact, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def validate_artifact(artifact):
    fields = {"schema_version", "workload", "environment", "initial", "public_key", "bindings", "run", "hooks", "terminal_observations", "semantic_trace", "model_records"}
    if type(artifact) is not dict or not fields <= set(artifact) or set(artifact) - fields - {"observed_timing"} or artifact["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported replay artifact schema")
    freeze_json(artifact, max_bytes=MAX_ARTIFACT_BYTES)
    # A replay artifact has no key material field. Model inputs must be approved
    # public/synthetic data before recording; never serialize runtime objects.
    VerifyKey(bytes.fromhex(artifact["public_key"]))
    ReadyScheduler(artifact["workload"]["actions"], preferred=artifact["workload"]["preferred"])
    if artifact["semantic_trace"] != semantic({"run": protocol_run(artifact["run"]), "terminal": artifact["terminal_observations"]}, artifact["public_key"]):
        raise ValueError("semantic trace binding mismatch")
    return artifact


def artifact_schema():
    fields = ["schema_version", "workload", "environment", "initial", "public_key", "bindings", "run", "hooks", "terminal_observations", "semantic_trace", "model_records"]
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:atomicroot:phase4:replay:1",
        "type": "object", "additionalProperties": False, "required": fields,
        "properties": {"schema_version": {"const": SCHEMA_VERSION}, "public_key": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "hooks": {"type": "array", "items": {"type": "object", "required": ["stage", "action"], "additionalProperties": False,
                "properties": {"stage": {"type": "string"}, "action": {"type": ["string", "null"]},
                               "deferred": {"type": "boolean"}, "observed_after": {"const": "fallback_release"},
                               "task": {"type": "string"}, "observed": {"type": "object"}}}},
            "observed_timing": {"type": "object"},
            "workload": {"type": "object", "required": ["name", "seed", "clock", "fixture", "tasks", "actions", "preferred"],
                "properties": {"actions": {"type": "array", "minItems": 1, "maxItems": 2048, "items": {"$ref": "#/$defs/action"}},
                    "preferred": {"type": "array", "uniqueItems": True, "items": {"type": "string"}},
                    "seed": {"type": "integer"}, "clock": {"type": "string", "format": "date-time"}, "tasks": {"type": "array", "minItems": 1}}},
            **{k: {"type": "object"} for k in fields if k not in {"schema_version", "public_key", "hooks", "workload"}}},
        "$defs": {"action": {"type": "object", "additionalProperties": False,
            "required": ["id", "kind", "actor", "depends_on", "arrival", "priority", "data"],
            "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 128}, "kind": {"type": "string", "minLength": 1},
                "actor": {"enum": ["worker", "trusted_fixture", "fault", "framework"]},
                "depends_on": {"type": "array", "uniqueItems": True, "items": {"type": "string"}},
                "arrival": {"type": "integer", "minimum": 0}, "priority": {"type": "integer", "minimum": -1000000, "maximum": 1000000},
                "data": {"type": "object"}}}}}


def load_artifact(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_ARTIFACT_BYTES: raise ValueError("artifact exceeds byte bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return validate_artifact(json.loads(raw, object_pairs_hook=unique))


def compare_pair(first, second):
    """Pair exogenous inputs; preserve realized schedules and semantic divergence."""
    timer = Stopwatch()
    if first["workload"] != second["workload"]: raise ValueError("unpaired workload/arrival/priority/fault plan")
    left, right = first["run"], second["run"]
    return {"workload_digest": args_hash(first["workload"]), "same_outcome": first["semantic_trace"] == second["semantic_trace"],
            "observed_timing": {"comparison": timer.finish(), "generated_at_utc": point()["observed_at_utc"]},
            "schedules": [left["schedule"], right["schedule"]], "divergence": [left["divergence"], right["divergence"]],
            "blocked": [left["blocked"], right["blocked"]],
            "schedule_differences": [{"step": i, "first": left["schedule"][i] if i < len(left["schedule"]) else None,
                                      "second": right["schedule"][i] if i < len(right["schedule"]) else None}
                                     for i in range(max(len(left["schedule"]), len(right["schedule"])))
                                     if (left["schedule"][i] if i < len(left["schedule"]) else None) != (right["schedule"][i] if i < len(right["schedule"]) else None)],
            "observation_differences": [key for key in sorted(left["observations"].keys() | right["observations"].keys())
                if first["semantic_trace"]["run"]["observations"].get(key) != second["semantic_trace"]["run"]["observations"].get(key)]}
