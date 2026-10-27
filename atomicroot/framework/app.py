"""Composition root and role-separated Phase 3 HTTP API for future adapters."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atomicroot.framework.storage import FrameworkStore
from atomicroot.framework.identity import Principal
from atomicroot.framework.approval import ApprovalBroker
from atomicroot.framework.contracts import ContractService
from atomicroot.framework.labels import StorageService, LabelManager
from atomicroot.framework.runtime import RuntimeAuthority, IntentGateway, operation_status
from atomicroot.framework.outbox import Dispatcher, SimulatedReceiver
from atomicroot.framework.registry import registry_preview
from atomicroot.framework.schema import schema
from atomicroot.framework.classification import ClassificationProposals
from atomicroot.framework.tasks import TaskService, TrustedCatalog


class FrameworkRuntime:
    def __init__(self, path=":memory:", *, signing_key=None, clock=None, harness=None, id_factory=None, fallback=None):
        self.store = FrameworkStore(path, clock=clock, harness=harness, id_factory=id_factory)
        self.fallback = fallback
        self.broker = ApprovalBroker(self.store)
        self.contracts = ContractService(self.store, self.broker)
        self.catalog = TrustedCatalog(self.store)
        self.tasks = TaskService(self.store, self.contracts)
        self.storage = StorageService(self.store)
        self.labels = LabelManager(self.store)
        self.classification = ClassificationProposals(self.store)
        self.authority = RuntimeAuthority(self.store, self.broker, signing_key, harness)
        self.gateway = IntentGateway(self.store, self.broker, self.authority.verify_key, harness)
        self.receiver = SimulatedReceiver(self.store)
        self.dispatcher = Dispatcher(self.store, self.receiver)


def create_phase3_app(runtime, identity_resolver, *, executor_factory=None):
    """Resolver returns authenticated Principal from host context, never from body."""
    if getattr(runtime, "evaluation_only", False): raise ValueError("unsafe evaluation runtime cannot be exposed as a service")
    app = FastAPI(title="AtomicRoot Phase 3", version="0.3.0")

    def identity(request):
        principal = identity_resolver(request)
        if not isinstance(principal, Principal): raise PermissionError("trusted principal required")
        return principal

    @app.exception_handler(PermissionError)
    async def permission_error(request, exc): return JSONResponse({"error": str(exc)}, status_code=403)

    @app.exception_handler(ValueError)
    async def validation_error(request, exc): return JSONResponse({"error": str(exc)}, status_code=422)

    def exact(body, fields):
        if set(body) != set(fields): raise ValueError("unsupported or missing fields")

    @app.get("/registry")
    async def registry(request: Request):
        identity(request)
        return registry_preview()

    @app.get("/schema")
    async def policy_schema(request: Request):
        identity(request)
        return schema()

    @app.get("/tasks/schema")
    async def task_schema(request: Request):
        identity(request)
        from atomicroot.framework.task_spec import task_schema
        return task_schema()

    @app.post("/tasks/validate")
    async def task_validate(body: dict, request: Request):
        return await run_in_threadpool(runtime.tasks.validate, body, identity(request))

    @app.post("/tasks/proposals")
    async def task_propose(body: dict, request: Request):
        return await run_in_threadpool(runtime.tasks.propose, body, identity(request))

    @app.get("/tasks/{task_id}")
    async def task_status(task_id: str, request: Request):
        return await run_in_threadpool(runtime.tasks.status, task_id, identity(request))

    def execute_task(task, run, command, principal):
        principal.require("user", task=task)
        if executor_factory is None: raise ValueError("trusted executor driver not configured")
        workflow = executor_factory(task, principal)
        try:
            if command == "status": return workflow.status(run)
            # Return evidence/status metadata. Worker bytes remain in local
            # checkpoints/ledger rather than the public progress response.
            getattr(workflow, command)(run)
            return workflow.status(run)
        finally: workflow.close()

    @app.get("/tasks/{task}/runs/{run}")
    async def run_status(task: str, run: str, request: Request):
        return await run_in_threadpool(execute_task, task, run, "status", identity(request))

    @app.post("/tasks/{task}/runs/{run}/{command}")
    async def run_command(task: str, run: str, command: str, body: dict, request: Request):
        exact(body, set())
        if command not in {"start", "resume", "recover"}: raise ValueError("unknown run command")
        return await run_in_threadpool(execute_task, task, run, command, identity(request))

    @app.get("/catalog")
    async def catalog_status(request: Request):
        return await run_in_threadpool(runtime.catalog.status, identity(request))

    @app.post("/catalog/destinations")
    async def catalog_destination(body: dict, request: Request):
        await run_in_threadpool(runtime.catalog.set_destination, body, identity(request))
        return {"status": "UPDATED"}

    @app.post("/catalog/entitlements/{task}/{subject}")
    async def catalog_entitlement(task: str, subject: str, body: dict, request: Request):
        await run_in_threadpool(runtime.catalog.set_entitlement, task, subject, body, identity(request))
        return {"status": "UPDATED"}

    @app.post("/contracts/validate")
    async def validate(body: dict, request: Request):
        principal = identity(request)
        principal.require("worker", task=body.get("task_id"))
        return await run_in_threadpool(runtime.contracts.validate, body)

    @app.post("/contracts/proposals")
    async def propose(body: dict, request: Request):
        return await run_in_threadpool(runtime.contracts.propose, body, identity(request))

    @app.post("/contracts/{proposal_id}/activate")
    async def activate(proposal_id: str, body: dict, request: Request):
        exact(body, {"review_id"})
        return await run_in_threadpool(runtime.contracts.activate, proposal_id, body["review_id"], identity(request))

    @app.get("/reviews/{review_id}")
    async def review_status(review_id: str, request: Request):
        return await run_in_threadpool(runtime.broker.status, review_id, identity(request))

    @app.post("/reviews/{review_id}/decide")
    async def decide(review_id: str, body: dict, request: Request):
        exact(body, {"approve"})
        return await run_in_threadpool(runtime.broker.decide, review_id, body["approve"], identity(request))

    @app.post("/storage/{resource}")
    async def ingest(resource: str, body: dict, request: Request):
        exact(body, {"content"})
        return await run_in_threadpool(runtime.storage.ingest, resource, body["content"], identity(request))

    @app.post("/labels/{resource}")
    async def label(resource: str, body: dict, request: Request):
        exact(body, {"digest", "version", "label", "purposes"})
        return await run_in_threadpool(runtime.labels.set_label, resource, body["digest"], body["version"],
                                      body["label"], body["purposes"], identity(request))

    @app.post("/classification/proposals")
    async def classification_begin(body: dict, request: Request):
        exact(body, {"resource", "digest", "content_version", "model_id", "model_version", "criteria_version", "criteria_hash"})
        return await run_in_threadpool(runtime.classification.begin, **body, principal=identity(request))

    @app.post("/classification/proposals/{proposal_id}/result")
    async def classification_result(proposal_id: str, body: dict, request: Request):
        return await run_in_threadpool(runtime.classification.record, proposal_id, body, identity(request))

    @app.get("/classification/proposals/{proposal_id}")
    async def classification_status(proposal_id: str, request: Request):
        return await run_in_threadpool(runtime.classification.status, proposal_id, identity(request))

    @app.post("/classification/proposals/{proposal_id}/accept")
    async def classification_accept(proposal_id: str, body: dict, request: Request):
        exact(body, {"task_id", "purpose"})
        result = await run_in_threadpool(runtime.labels.accept_classification, proposal_id,
                                        body["task_id"], body["purpose"], identity(request))
        return JSONResponse(result, status_code=409 if result["status"] == "STALE" else 200)

    @app.post("/authorize")
    async def authorize(body: dict, request: Request):
        if not set(body) <= {"request", "grant_id"} or "request" not in body: raise ValueError("invalid authorize envelope")
        result = await run_in_threadpool(runtime.authority.authorize, body["request"], identity(request), grant_id=body.get("grant_id"))
        code = {"DENY": 403, "EVALUATION_ERROR": 422, "ESCALATE": 202}.get(result.get("decision"), 200)
        return JSONResponse(result, status_code=code)

    @app.post("/commit")
    async def commit(body: dict, request: Request):
        exact(body, {"ticket", "args"})
        result = await run_in_threadpool(runtime.gateway.commit, body["ticket"], body["args"], identity(request))
        code = {"REJECTED": 403, "STALE_TICKET": 409, "OPERATION_ALREADY_COMMITTED": 409}.get(result["status"], 200)
        return JSONResponse(result, status_code=code)

    @app.get("/operations/{task}/{operation}")
    async def status(task: str, operation: str, digest: str, request: Request):
        return await run_in_threadpool(operation_status, runtime.store, task, operation, digest, identity(request))

    @app.post("/dispatch")
    async def dispatch(request: Request):
        identity(request).require("dispatcher")
        return await run_in_threadpool(runtime.dispatcher.dispatch_once)

    return app
