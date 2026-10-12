"""Trusted provider dispatcher. Network only follows an immutable accepted intent."""
import json
from dataclasses import asdict

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.storage import dumps, uid
from atomicroot.framework.identity import Principal
from atomicroot.framework.classification import ClassificationProposals
from atomicroot.integration.memo import InferenceMemo, InferenceInProgress
from atomicroot.integration.providers import CRITERIA, CRITERIA_VERSION, OPTIONS, Limits, validate_choice
from atomicroot.integration.guarded import GuardedTools
from atomicroot.integration.prompts import AUTHOR_VERSION, WORKER_VERSION, worker_response_schema


class InferenceReceiver:
    def __init__(self, runtime, memo, model, classifier, *, llm_limits=Limits(), jev_limits=Limits(), threshold=.8):
        self.runtime, self.memo = runtime, memo
        self.model, self.classifier = model, classifier
        self.llm_limits, self.jev_limits = llm_limits, jev_limits
        self.records = ClassificationProposals(runtime.store, threshold=threshold)

    async def adeliver(self, task, operation, payload):
        tool = payload["tool"]
        if tool not in {"model_inference", "classify_document"}:
            return self.runtime.receiver.deliver(task, operation, payload)
        store, digest = self.runtime.store, args_hash(payload)
        with store._lock:
            proof = store.row(store._conn, "SELECT * FROM receiver_receipts WHERE task=? AND operation=?", (task, operation))
            accepted = store.row(store._conn, "SELECT payload FROM outbox WHERE task=? AND operation=?", (task, operation))
        if not accepted or json.loads(accepted["payload"]) != payload: raise PermissionError("accepted inference intent required")
        if proof:
            if proof["digest"] != digest: raise ValueError("receiver payload mismatch")
            return json.loads(proof["receipt"])
        job = self.memo.job(operation)
        if not job or job["task"] != task or job["tool"] != tool: raise ValueError("missing bound inference job")
        document = payload["resource_snapshot"]
        if (document["resource"], document["digest"], document["version"]) != (job["resource"], job["digest"], job["version"]):
            raise ValueError("inference content version mismatch")
        if tool == "model_inference":
            context = json.loads(document["content"])
            if context["model"] != self.model.model or context["provider"] != self.model.provider:
                raise ValueError("configured model changed; new inference intent required")
            async def generate():
                if "response_schema" in context:
                    return await self.model.generate(context["messages"], response_schema=context["response_schema"])
                return await self.model.generate(context["messages"])
            result = await self.memo.run(operation, job["budget"], "LLM", self.model.model, context, self.llm_limits, generate)
        else:
            if payload["args"]["to"] != self.classifier.provider or job["model"] != self.classifier.model:
                raise ValueError("classifier provider/model changed; new intent required")
            result = await self._classify(operation, job, document)
        receipt = {"outcome": "DELIVERED", "receipt_id": uid("receipt"), "result": result}
        with store.transaction() as conn:
            previous = store.row(conn, "SELECT * FROM receiver_receipts WHERE task=? AND operation=?", (task, operation))
            if previous: return json.loads(previous["receipt"])
            conn.execute("INSERT INTO receiver_receipts(task,operation,digest,receipt) VALUES (?,?,?,?)", (task, operation, digest, dumps(receipt)))
            store.audit(conn, "INFERENCE_RETURNED", "InferenceReceiver", {"task": task, "operation": operation, "kind": tool})
        return receipt

    async def _classify(self, operation, job, document):
        p = Principal(job["classifier"], frozenset({"classifier"}), resources=frozenset({document["resource"]}))
        proposal = self.records.status(job["proposal_id"], p)
        if proposal["status"] != "REQUESTED": return {"classification": proposal}
        state = {"trusted_context": {"purpose": job["purpose"], "provider": self.classifier.provider,
                  "authoritative_label": proposal["base_label"], "content_version": document["version"]},
                 "untrusted_document": document["content"]}
        binding = {"state": state, "criteria": job["criteria"], "criteria_version": job["criteria_version"],
                   "scope": job["scope"], "base_label_hash": proposal["base_label_hash"], "digest": document["digest"]}
        response = None
        try:
            response = await self.memo.run(operation, job["budget"], "JEV", self.classifier.model, binding, self.jev_limits,
                                          lambda: self.classifier.classify(state, job["criteria"]))
            response = validate_choice(response, job["model"])
        except InferenceInProgress:
            raise
        except Exception as exc:
            response = {"outcome": "ERROR", "candidate_label": "UNKNOWN", "confidence": None, "probabilities": None,
                        "usage": None, "reason": "CLASSIFIER_ERROR: " + type(exc).__name__,
                        "actual_model": response.get("actual_model") if type(response) is dict else None}
        result = {key: proposal[key] for key in ("resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash")}
        result.update({key: response.get(key) for key in ("outcome", "candidate_label", "confidence", "probabilities", "usage")})
        result.update(covered_bytes=len(document["content"].encode("utf-8")), truncated=False,
                      option_order=list(OPTIONS), reason=response.get("reason", "classifier result"), extraction=job["extraction"],
                      reported_model=response.get("actual_model"), provider_mode=self.classifier.mode)
        recorded = self.records.record(job["proposal_id"], result, p)
        return {"classification": recorded}


class ModelBridge:
    def __init__(self, runtime, model, classifier, *, llm_limits=Limits(), jev_limits=Limits(), threshold=.8, bootstrap_authorized=False, progress=None):
        self.runtime, self.model = runtime, model
        self.progress = progress
        self.memo = InferenceMemo(runtime.store, progress=progress)
        self.receiver = InferenceReceiver(runtime, self.memo, model, classifier, llm_limits=llm_limits, jev_limits=jev_limits, threshold=threshold)
        self.tools = GuardedTools(runtime, receiver=self.receiver, progress=progress)
        self.bootstrap_authorized, self.llm_limits = bootstrap_authorized, llm_limits

    def author(self, key, budget, messages):
        import asyncio
        if not self.bootstrap_authorized: raise PermissionError("initial authoring provider usage not authorized")
        return asyncio.run(self.memo.run(key, budget, "LLM", self.model.model, {"messages": messages, "provider": self.model.provider,
                                  "prompt_version": AUTHOR_VERSION}, self.llm_limits, lambda: self.model.generate(messages)))["output"]

    def worker(self, key, budget, *, messages, sources, context_resource, principal, task, purpose):
        context = {"messages": messages, "sources": sources, "provider": self.model.provider,
                   "model": self.model.model, "prompt_version": WORKER_VERSION}
        if getattr(self.model, "structured_worker_output", False):
            with self.runtime.store.snapshot() as snap: contract = snap.read(f"contract3:{task}")[1]
            context["response_schema"] = worker_response_schema(contract)
        job = self.memo.job(key)
        if job:
            if job["context_hash"] != args_hash(context): raise ValueError("model node replay context changed")
        else:
            owner = Principal("model-context-host", frozenset({"owner"}), resources=frozenset({context_resource}))
            content = dumps(context)
            doc = self.runtime.storage.ingest(context_resource, content, owner)
            job = self.memo.save_job(key, {"task": task, "tool": "model_inference", "resource": context_resource,
                "digest": doc["digest"], "version": doc["version"], "context_hash": args_hash(context), "budget": budget})
        request = self.tools.stage({"tool": "model_inference", "args": {"resource": job["resource"], "digest": job["digest"], "to": self.model.provider}},
                                  principal=principal, task=task, purpose=purpose, operation=key, host_inference=True)
        observation = self.tools.execute(request, principal)
        if observation.status != "COMMITTED" or observation.detail["delivery"] != "RELEASED":
            raise ValueError("model egress blocked/unavailable: " + dumps(observation.json()))
        return observation.detail["receipt"]["result"]["output"]

    def classify(self, key, budget, *, resource, digest, version, principal, task, purpose, criteria=None,
                 criteria_version=CRITERIA_VERSION, extraction=None):
        provider = self.receiver.classifier
        criteria = freeze_json(criteria or CRITERIA)
        if set(criteria) != set(OPTIONS): raise ValueError("registered classifier criteria required")
        metadata = extraction or {"format": "text", "parts": 1, "complete": True, "ocr_supported": False}
        if metadata.get("complete") is not True:
            return {"status": "UNKNOWN", "reason": "incomplete extraction; no inference"}
        job = self.memo.job(key)
        if not job:
            classifier = Principal("classifier-host", frozenset({"classifier"}), resources=frozenset({resource}))
            proposal = self.receiver.records.begin(resource, digest, version, "JEV", provider.model,
                criteria_version, args_hash(criteria), classifier)
            with self.runtime.store.snapshot() as snap: scope = snap.read(f"contract3:{task}")[1]
            job = self.memo.save_job(key, {"task": task, "tool": "classify_document", "resource": resource, "digest": digest,
                "version": version, "budget": budget, "purpose": purpose, "proposal_id": proposal["proposal_id"],
                "classifier": classifier.subject, "criteria": criteria, "criteria_version": criteria_version,
                "model": provider.model, "scope": scope, "extraction": metadata})
        if (job["digest"], job["version"], job["model"], job["criteria"], job["criteria_version"], job["purpose"], job["resource"]) != (
                digest, version, provider.model, criteria, criteria_version, purpose, resource):
            raise ValueError("classification replay content/model/criteria/scope mismatch")
        request = self.tools.stage({"tool": "classify_document", "args": {"resource": resource, "digest": digest, "to": provider.provider}},
                                  principal=principal, task=task, purpose=purpose, operation=key, host_inference=True)
        return self.tools.execute(request, principal).json()
