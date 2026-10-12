"""FastAPI adapter. The host supplies a trusted caller identity resolver."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atomicroot.authority.authority import PolicyAuthority
from atomicroot.gateway.gateway import ToolGateway


def create_app(authority: PolicyAuthority, gateway: ToolGateway,
               identity_resolver: Callable[[Request], str]) -> FastAPI:
    """identity_resolver must verify caller identity outside the request body."""
    app = FastAPI()

    @app.post("/authorize")
    async def authorize(body: dict, request: Request):
        caller = identity_resolver(request)
        result = await run_in_threadpool(authority.authorize, body,
                                         caller_agent_id=caller)
        code = 403 if result.get("decision") == "DENY" else 422 if result.get("decision") == "EVALUATION_ERROR" else 200
        return JSONResponse(result, status_code=code)

    @app.post("/commit")
    async def commit(body: dict, request: Request):
        caller = identity_resolver(request)
        result = await run_in_threadpool(gateway.commit, body.get("ticket", {}),
                                         body.get("args", {}), caller_agent_id=caller)
        code = 409 if result["status"] == "STALE_TICKET" else 403 if result["status"] == "REJECTED" else 200
        return JSONResponse(result, status_code=code)

    return app
