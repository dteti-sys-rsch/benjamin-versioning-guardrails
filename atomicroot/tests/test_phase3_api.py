import pytest
from fastapi.testclient import TestClient

from atomicroot.framework.app import create_phase3_app
from atomicroot.framework.identity import Principal
from atomicroot.tests.phase3_support import System


def client_for(system):
    identities = {"worker-token": system.worker, "reviewer-token": system.approver, "owner-token": system.owner,
                  "dispatcher-token": Principal("dispatcher", frozenset({"dispatcher"}))}
    def resolver(request):
        identity = identities.get(request.headers.get("Authorization"))
        if identity is None: raise PermissionError("invalid fixture authentication")
        return identity
    return TestClient(create_phase3_app(system.runtime, resolver))


def test_api_separates_worker_approver_owner_and_dispatcher(tmp_path):
    s = System(tmp_path / "api.db", label=None, unknown="ESCALATE")
    client = client_for(s)
    worker = {"Authorization": "worker-token"}
    reviewer = {"Authorization": "reviewer-token"}
    assert client.get("/registry").status_code == 403
    assert client.get("/registry", headers=worker).status_code == 200
    assert client.post("/dispatch", headers=worker).status_code == 403
    assert client.post("/storage/d", headers=worker, json={"content": "new"}).status_code == 403
    label = {"digest": s.document["digest"], "version": 1, "label": "PUBLIC", "purposes": ["research"]}
    assert client.post("/labels/d", headers=worker, json=label).status_code == 403
    assert client.post("/facts/budget_used", headers=worker, json={"value": 0, "approved": True}).status_code == 404
    read = client.post("/authorize", headers=worker, json={"request": s.request("read", "read_document")})
    assert read.status_code == 200 and read.json()["decision"] == "ALLOW"
    auth = read.json()
    assert client.post("/commit", headers=worker, json={"ticket": auth["ticket"], "args": auth["commit_args"]}).json()["status"] == "COMMITTED"
    escalation = client.post("/authorize", headers=worker, json={"request": s.request()})
    assert escalation.status_code == 202
    review = escalation.json()["review_id"]
    assert client.post(f"/reviews/{review}/decide", headers=worker, json={"approve": True}).status_code == 403
    assert client.post(f"/reviews/{review}/decide", headers=reviewer, json={"approve": True, "role": "approver"}).status_code == 422
    assert client.post(f"/reviews/{review}/decide", headers=reviewer, json={"approve": True}).json()["status"] == "APPROVED"
    assert client.get(f"/reviews/{review}", headers=reviewer).json()["approver"] == "reviewer"
    auth = client.post("/authorize", headers=worker, json={"request": s.request(), "grant_id": review}).json()
    assert auth["decision"] == "ALLOW"
    assert client.post("/commit", headers=worker, json={"ticket": auth["ticket"], "args": auth["commit_args"]}).json()["delivery"] == "PENDING"
    status = client.get("/operations/t/op", params={"digest": auth["request_digest"]}, headers=worker).json()
    assert status["committed"] and status["delivery"] == "PENDING"
    assert client.post("/dispatch", headers={"Authorization": "dispatcher-token"}).json()["status"] == "RELEASED"


def test_api_contract_preview_review_activation(tmp_path):
    s = System(tmp_path / "contract-api.db")
    client = client_for(s)
    worker, reviewer = {"Authorization": "worker-token"}, {"Authorization": "reviewer-token"}
    proposal = {**s.proposal, "budget_limit": 2_000_000}
    assert client.post("/contracts/validate", headers=worker, json=proposal).json()["valid"]
    draft = client.post("/contracts/proposals", headers=worker, json=proposal).json()
    assert draft["status"] == "DRAFT"
    path = f"/contracts/{draft['proposal_id']}/activate"
    assert client.post(path, headers=worker, json={"review_id": draft["review_id"]}).status_code == 403
    client.post(f"/reviews/{draft['review_id']}/decide", headers=reviewer, json={"approve": True})
    assert client.post(path, headers=reviewer, json={"review_id": draft["review_id"]}).json()["status"] == "ACTIVE"
    assert client.post(path, headers=reviewer, json={"review_id": draft["review_id"]}).status_code == 422
    forged = s.request(agent_id="reviewer")
    assert client.post("/authorize", headers=worker, json={"request": forged}).status_code == 422


def test_operation_status_and_grants_are_bound_to_actual_caller(tmp_path):
    s = System(tmp_path / "caller.db")
    auth = s.execute()
    stranger = Principal("other", frozenset({"worker"}), frozenset({"t"}))
    client = TestClient(create_phase3_app(s.runtime, lambda request: stranger))
    assert client.get("/operations/t/op", params={"digest": auth["request_digest"]}).status_code == 403
    assert client.post("/commit", json={"ticket": auth["ticket"], "args": auth["commit_args"]}).status_code == 403
