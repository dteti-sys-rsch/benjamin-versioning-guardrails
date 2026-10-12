"""Explicit owner labels bind one resource version/digest and purpose set."""
import hashlib
import json
from dataclasses import asdict, replace
from atomicroot.authority.policy_engine import valid_identity, finite_strings
from atomicroot.authority.ticket import freeze_json, args_hash
from atomicroot.framework.classification import ClassificationProposals


def content_digest(content):
    if type(content) is not str or len(content.encode("utf-8")) > 8192:
        raise ValueError("content must be a string <=8192 bytes")
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


class StorageService:
    def __init__(self, store): self.store = store

    def ingest(self, resource, content, principal, *, source="owner upload"):
        valid_identity(resource)
        principal.require("owner", resource=resource)
        digest = content_digest(content)
        if source not in {"owner upload", "trusted metadata", "external document"}:
            raise ValueError("unregistered provenance source")
        with self.store.transaction() as conn:
            _, old = self.store.value(conn, f"document:{resource}")
            version = (old["version"] if old else 0) + 1
            data = {"resource": resource, "digest": digest, "version": version,
                    "content": content, "source": source, "stored_by": principal.subject,
                    "instruction_trust": "UNTRUSTED", "factual_accuracy": "UNVERIFIED"}
            self.store.put(conn, f"document:{resource}", data)
            # Every content/version update invalidates label scope, even same bytes.
            self.store.put(conn, f"label:{resource}", {"label": "UNKNOWN", "digest": digest,
                "version": version, "purposes": [], "label_set_by": "StorageService",
                "source": "official default: new version", "resource": resource})
            self.store.audit(conn, "INGEST", principal.subject, {k: v for k, v in data.items() if k != "content"})
        return {"resource": resource, "digest": digest, "version": version}


class LabelManager:
    def __init__(self, store): self.store = store

    def set_label(self, resource, digest, version, label, purposes, principal):
        valid_identity(resource)
        principal.require("owner", resource=resource)
        if label not in {"PUBLIC", "SENSITIVE", "UNKNOWN"}: raise ValueError("unsupported label")
        purposes = list(finite_strings(freeze_json(purposes)))
        if not purposes: raise ValueError("explicit purpose scope required")
        with self.store.transaction() as conn:
            _, document = self.store.value(conn, f"document:{resource}")
            if not document or document["digest"] != digest or document["version"] != version:
                raise ValueError("label requires current content version and digest")
            data = {"resource": resource, "digest": digest, "version": version, "label": label,
                    "purposes": purposes, "source": "authenticated owner attestation",
                    "label_set_by": principal.subject}
            _, previous = self.store.value(conn, f"label:{resource}")
            if previous and previous.get("restrictions"):
                data["restrictions"] = previous["restrictions"]
            self.store.put(conn, f"label:{resource}", data)
            # A result already in shared memory keeps its task-level provenance.
            # Tightening the official basis invalidates pending release intents
            # in this same transaction, just like accepting a restriction.
            affected = self._propagate_label(conn, resource, digest, label, purposes)
            self.store.audit(conn, "LABEL", principal.subject, data)
            if affected:
                self.store.audit(conn, "LABEL_EXPOSURE", principal.subject, {"resource": resource, "affected_tasks": affected})
        return data

    def _propagate_label(self, conn, resource, digest, label, purposes):
        affected = set()
        rows = conn.execute("SELECT o.task,o.request FROM operations o JOIN outbox b "
                            "ON o.task=b.task AND o.operation=b.operation").fetchall()
        for task, raw in rows:
            request = json.loads(raw)
            if request["tool"] != "read_document" or request["args"] != {"resource": resource, "digest": digest}: continue
            effective = label if request["purpose"] in purposes else "UNKNOWN"
            key = f"exposure:{task}"
            _, exposure = self.store.value(conn, key)
            if exposure is None: raise ValueError("missing exposure for recorded read")
            updated = sorted(set(exposure) | {effective})
            if updated != exposure:
                self.store.put(conn, key, updated)
                affected.add(task)
        return sorted(affected)

    def accept_classification(self, proposal_id, task_id, purpose, principal):
        """Owner review can only add a contract-approved conservative restriction."""
        valid_identity(task_id)
        records = ClassificationProposals(self.store)
        with self.store.transaction() as conn:
            proposal = records.load(conn, proposal_id)
            principal.require("owner", resource=proposal.resource, task=task_id)
            if proposal.status not in {"PROPOSED", "ABSTAINED", "ERROR"}:
                raise ValueError("classification proposal already decided or incomplete")
            _, document = self.store.value(conn, f"document:{proposal.resource}")
            label_version, label = self.store.value(conn, f"label:{proposal.resource}")
            stale = (not document or label is None or
                     (document["digest"], document["version"]) != (proposal.digest, proposal.content_version) or
                     label_version != proposal.base_label_version or args_hash(label) != proposal.base_label_hash)
            if stale:
                proposal = replace(proposal, status="STALE", reason="content or reviewed label basis changed")
            elif proposal.status != "PROPOSED" or proposal.candidate_label != "SENSITIVE":
                proposal = replace(proposal, status="DECLINED", reason="classifier evidence cannot authorize PUBLIC or clear UNKNOWN")
            else:
                _, contract = self.store.value(conn, f"contract3:{task_id}")
                if (not contract or contract.get("classification_restrictions", False) is not True or
                        purpose != contract["purpose"] or proposal.resource not in contract["allowed_resources"]):
                    raise ValueError("active contract does not authorize classification restriction scope")
                restriction = {"label": "SENSITIVE", "digest": proposal.digest, "version": proposal.content_version,
                               "purpose": purpose, "proposal_id": proposal_id, "accepted_by": principal.subject,
                               "task_id": task_id}
                # Official label/provenance is preserved; versioning uses its existing key.
                updated = {**label, "restrictions": label.get("restrictions", []) + [restriction]}
                self.store.put(conn, f"label:{proposal.resource}", updated)
                affected = set()
                for exposed_task, raw in conn.execute("SELECT task_id,args FROM trace_events WHERE tool='read_document'").fetchall():
                    args = json.loads(raw)
                    if args.get("resource") == proposal.resource and args.get("digest") == proposal.digest:
                        affected.add(exposed_task)
                for exposed_task in sorted(affected):
                    key = f"exposure:{exposed_task}"
                    _, exposure = self.store.value(conn, key)
                    if exposure is None: raise ValueError("missing exposure for recorded read")
                    self.store.put(conn, key, sorted(set(exposure) | {"SENSITIVE"}))
                accepted = {"restriction": restriction, "label_version": label_version + 1,
                            "affected_tasks": sorted(affected)}
                proposal = replace(proposal, status="ACCEPTED_RESTRICTION", reason="explicit owner review", accepted=accepted)
            records.save(conn, proposal)
            self.store.audit(conn, "CLASSIFICATION_" + proposal.status, principal.subject, asdict(proposal))
        return asdict(proposal)

    @staticmethod
    def resolve(reader, resource, digest, purpose):
        document = reader.read(f"document:{resource}")
        label = reader.read(f"label:{resource}")
        if document["digest"] != digest: raise ValueError("resource digest changed; resolve before authorization")
        if label["label"] not in {"PUBLIC", "SENSITIVE", "UNKNOWN"}: raise ValueError("invalid label fact")
        scoped = (label["digest"] == digest and label["version"] == document["version"]
                  and purpose in label["purposes"])
        effective = label["label"] if scoped else "UNKNOWN"
        for restriction in label.get("restrictions", []):
            if (restriction["digest"], restriction["version"], restriction["purpose"]) == (digest, document["version"], purpose):
                if restriction["label"] != "SENSITIVE": raise ValueError("invalid conservative restriction")
                effective = "SENSITIVE"
        return document, effective
