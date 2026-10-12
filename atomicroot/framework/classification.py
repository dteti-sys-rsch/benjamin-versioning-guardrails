"""Classifier evidence intake only. Effective state is owned by Label Manager."""
from dataclasses import dataclass, asdict, replace
import json
import math
import re

from atomicroot.authority.policy_engine import valid_identity
from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.framework.storage import dumps, uid

LABELS = frozenset({"PUBLIC", "SENSITIVE", "UNKNOWN"})
MIN_CONFIDENCE = 0.8  # provisional abstention threshold, not a correctness guarantee
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def text(value, name):
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError(f"invalid {name}")
    return value


def probability(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("probability/confidence must be finite in [0,1]")
    return value


@dataclass(frozen=True)
class ClassificationProposal:
    proposal_id: str
    resource: str
    digest: str
    content_version: int
    base_label_version: int
    base_label_hash: str
    model_id: str
    model_version: str
    criteria_version: str
    criteria_hash: str
    created_at: str
    submitted_by: str
    input_bytes: int
    candidate_label: str = "UNKNOWN"
    reported_candidate: str | None = None
    probabilities: dict | None = None
    confidence: float | None = None
    evaluated_at: str | None = None
    covered_bytes: int = 0
    truncated: bool = False
    status: str = "REQUESTED"
    reason: str = "awaiting classifier evidence"
    accepted: dict | None = None
    base_label: dict | None = None
    option_order: tuple[str, ...] = ("PUBLIC", "SENSITIVE", "UNKNOWN")
    usage: dict | None = None
    extraction: dict | None = None
    threshold: float = MIN_CONFIDENCE
    reported_model: str | None = None
    provider_mode: str | None = None


class ClassificationProposals:
    def __init__(self, store, *, threshold=MIN_CONFIDENCE):
        self.store = store
        self.threshold = probability(threshold)

    def load(self, conn, proposal_id):
        row = self.store.row(conn, "SELECT data FROM classification_proposals WHERE id=?", (proposal_id,))
        if row is None: raise ValueError("unknown classification proposal")
        return ClassificationProposal(**json.loads(row["data"]))

    def save(self, conn, proposal):
        conn.execute("UPDATE classification_proposals SET status=?,data=? WHERE id=?",
                     (proposal.status, dumps(asdict(proposal)), proposal.proposal_id))

    def begin(self, resource, digest, content_version, model_id, model_version,
              criteria_version, criteria_hash, principal):
        valid_identity(resource)
        principal.require("classifier", resource=resource)
        for name, value in (("model_id", model_id), ("model_version", model_version), ("criteria_version", criteria_version)):
            text(value, name)
        if type(digest) is not str or not DIGEST.fullmatch(digest) or type(criteria_hash) is not str or not DIGEST.fullmatch(criteria_hash):
            raise ValueError("exact content and criteria SHA-256 required")
        if type(content_version) is not int or content_version < 1: raise ValueError("invalid content version")
        with self.store.transaction() as conn:
            _, document = self.store.value(conn, f"document:{resource}")
            label_version, label = self.store.value(conn, f"label:{resource}")
            if not document or label is None: raise ValueError("missing registered content/label")
            if (document["digest"], document["version"]) != (digest, content_version):
                raise ValueError("stale classification input")
            proposal = ClassificationProposal(
                proposal_id=uid("classification"), resource=resource, digest=digest, content_version=content_version,
                base_label_version=label_version, base_label_hash=args_hash(label), base_label=freeze_json(label),
                model_id=model_id, model_version=model_version, criteria_version=criteria_version, criteria_hash=criteria_hash,
                created_at=self.store._clock().isoformat(), submitted_by=principal.subject,
                input_bytes=len(document["content"].encode("utf-8")), threshold=self.threshold)
            conn.execute("INSERT INTO classification_proposals(id,resource,status,data) VALUES (?,?,?,?)",
                         (proposal.proposal_id, resource, proposal.status, dumps(asdict(proposal))))
            self.store.audit(conn, "CLASSIFICATION_REQUESTED", principal.subject, asdict(proposal))
        # No content or network access is exposed by the evidence intake.
        return asdict(proposal)

    def record(self, proposal_id, result, principal):
        result = freeze_json(result)
        required = {"resource", "digest", "content_version", "model_id", "model_version",
                    "criteria_version", "criteria_hash", "outcome", "candidate_label",
                    "confidence", "probabilities", "covered_bytes", "truncated", "reason"}
        optional = {"option_order", "usage", "extraction", "reported_model", "provider_mode"}
        if type(result) is not dict or not required <= set(result) or not set(result) <= required | optional:
            raise ValueError("invalid classification result schema")
        if "option_order" in result and result["option_order"] != ["PUBLIC", "SENSITIVE", "UNKNOWN"]:
            raise ValueError("classification option order mismatch")
        usage = result.get("usage")
        if usage is not None:
            if type(usage) is not dict or not set(usage) <= {"input_tokens", "output_tokens"}:
                raise ValueError("invalid usage")
            if any(v is not None and (type(v) is not int or v < 0) for v in usage.values()):
                raise ValueError("invalid token usage")
        extraction = result.get("extraction")
        if extraction is not None and type(extraction) is not dict: raise ValueError("invalid extraction metadata")
        reported_model = result.get("reported_model")
        if reported_model is not None: text(reported_model, "reported model")
        provider_mode = result.get("provider_mode")
        if provider_mode is not None and provider_mode not in {"disabled", "fake", "replay", "jev"}:
            raise ValueError("invalid classifier mode")
        if (type(result["candidate_label"]) is not str or result["candidate_label"] not in LABELS or
                type(result["outcome"]) is not str or result["outcome"] not in {"SUCCESS", "TIMEOUT", "ERROR", "MISSING_CONTENT"}):
            raise ValueError("unknown label/outcome")
        if type(result["truncated"]) is not bool or type(result["covered_bytes"]) is not int:
            raise ValueError("invalid coverage")
        if type(result["reason"]) is not str or len(result["reason"]) > 256: raise ValueError("invalid reason")
        confidence = result["confidence"]
        if confidence is not None: probability(confidence)
        probabilities = result["probabilities"]
        if probabilities is not None:
            if type(probabilities) is not dict or not probabilities or not set(probabilities) <= LABELS:
                raise ValueError("invalid probability labels")
            for value in probabilities.values(): probability(value)
            if abs(sum(probabilities.values()) - 1) > 1e-6: raise ValueError("probabilities must sum to one")
        with self.store.transaction() as conn:
            proposal = self.load(conn, proposal_id)
            principal.require("classifier", resource=proposal.resource)
            if principal.subject != proposal.submitted_by: raise PermissionError("proposal submitter mismatch")
            if proposal.status != "REQUESTED": raise ValueError("classification result already recorded")
            for key in ("resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash"):
                value = getattr(proposal, key)
                if type(result[key]) is not type(value) or result[key] != value:
                    raise ValueError("cached result content/model/criteria binding mismatch")
            if not 0 <= result["covered_bytes"] <= proposal.input_bytes: raise ValueError("invalid coverage")
            candidate, status, reason = result["candidate_label"], "PROPOSED", result["reason"]
            if result["outcome"] != "SUCCESS":
                candidate, status, reason = "UNKNOWN", "ERROR", result["outcome"] + ": " + reason
            elif (result["truncated"] or result["covered_bytes"] < proposal.input_bytes or
                  confidence is None or confidence < proposal.threshold or candidate == "UNKNOWN"):
                candidate, status, reason = "UNKNOWN", "ABSTAINED", "incomplete/low-confidence/UNKNOWN: " + reason
            proposal = replace(proposal, candidate_label=candidate, reported_candidate=result["candidate_label"],
                probabilities=probabilities, confidence=confidence, evaluated_at=self.store._clock().isoformat(),
                covered_bytes=result["covered_bytes"], truncated=result["truncated"], status=status, reason=reason,
                usage=usage, extraction=extraction, reported_model=reported_model, provider_mode=provider_mode)
            self.save(conn, proposal)
            self.store.audit(conn, "CLASSIFICATION_RESULT", principal.subject, asdict(proposal))
        return asdict(proposal)

    def status(self, proposal_id, principal):
        with self.store._lock: proposal = self.load(self.store._conn, proposal_id)
        if proposal.resource not in principal.resources or not principal.roles & {"classifier", "owner"}:
            raise PermissionError("classification outside authenticated resource scope")
        return asdict(proposal)
