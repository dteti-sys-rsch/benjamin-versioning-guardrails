import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace
import pytest

from atomicroot.tests.test_phase35_workflow import Pilot
from atomicroot.integration.memo import InferenceMemo
from atomicroot.integration.providers import Limits, OpenAIModel, FakeModel, ReplayModel
from atomicroot.authority.ticket import args_hash


def test_stale_ticket_reauth_keeps_payload_and_operation_and_is_bounded(tmp_path):
    p = Pilot(tmp_path)
    p.activate()
    original = p.runtime.gateway.commit
    seen = []
    def force_stale(ticket, args, principal, **kwargs):
        seen.append(deepcopy(args))
        with p.runtime.store.transaction() as conn:
            old = p.runtime.store.value(conn, "budget:pilot")[1]
            p.runtime.store.put(conn, "budget:pilot", old + 1)
        return original(ticket, args, principal, **kwargs)
    p.runtime.gateway.commit = force_stale
    request = p.bridge.tools.stage({"tool": "transfer_funds", "args": {"to": "account", "amount": 10}},
        principal=p.principals["executor"], task="pilot", purpose="research", operation="same-op")
    result = p.bridge.tools.execute(request, p.principals["executor"])
    assert result.status == "RETRY_EXHAUSTED"
    assert len(seen) == 3 and all(a == seen[0] for a in seen)
    assert not p.runtime.store.inspect_outbox()


def test_successful_reauth_and_committed_rerun_no_duplicate_effect(tmp_path):
    p = Pilot(tmp_path)
    p.activate()
    original = p.runtime.gateway.commit
    attempts = []
    def once_stale(ticket, args, principal, **kwargs):
        if not attempts:
            with p.runtime.store.transaction() as conn: p.runtime.store.put(conn, "budget:pilot", 1)
        attempts.append(True)
        return original(ticket, args, principal, **kwargs)
    p.runtime.gateway.commit = once_stale
    request = p.bridge.tools.stage({"tool": "transfer_funds", "args": {"to": "account", "amount": 10}},
        principal=p.principals["executor"], task="pilot", purpose="research", operation="same-op")
    first = p.bridge.tools.execute(request, p.principals["executor"])
    second = p.bridge.tools.execute(request, p.principals["executor"])
    assert first.detail["receipt"] == second.detail["receipt"] and len(attempts) == 2
    with p.runtime.store.snapshot() as s: assert s.read("budget:pilot")[1] == 11
    changed = deepcopy(request)
    changed["args"]["amount"] = 11
    assert p.bridge.tools.execute(changed, p.principals["executor"]).status == "EVALUATION_ERROR"
    assert len(p.runtime.store.inspect_outbox()) == 1


def test_unknown_stale_approved_review_requires_new_review(tmp_path):
    p = Pilot(tmp_path, label="UNKNOWN", unknown="ESCALATE")
    f = p.flow()
    first = f.start("run", "Consent workflow")
    p.approve(first)
    pending = f.resume("run")
    old = pending["__interrupt__"][0].value["review_id"]
    p.runtime.broker.decide(old, True, p.approver)
    revision = deepcopy(p.contract)
    revision["budget_limit"] += 1
    r = p.runtime.contracts.propose(revision, p.principals["reader"])
    p.runtime.broker.decide(r["review_id"], True, p.approver)
    p.runtime.contracts.activate(r["proposal_id"], r["review_id"], p.approver)
    new = f.resume("run")
    assert new["__interrupt__"][0].value["review_id"] != old
    p.approve(new)
    result = f.resume("run")
    assert result["status"] == "DONE", result
    assert len([r for r in p.runtime.store.inspect_outbox() if json.loads(r["payload"])["tool"] == "send_email"]) == 1
    f.close()


def test_model_contract_increase_is_reviewed_and_stales_pending_ticket(tmp_path):
    p = Pilot(tmp_path)
    p.contract["budget_limit"] = 500
    def decide(messages):
        d = json.loads(messages[-1]["content"])
        if "user_goal" in d: return {"kind": "contract", "proposal": p.contract, "unsupported": []}
        used = d["read_only_counters"]["spent"]
        if used == 400 and d["approved_contract"]["budget_limit"] == 500:
            rev = deepcopy(p.contract)
            rev["budget_limit"] = 1000
            return {"kind": "contract", "proposal": rev, "unsupported": []}
        if used < 800: return {"kind": "action", "tool": "transfer_funds", "args": {"to": "account", "amount": 400}}
        return {"kind": "done", "summary": "budget done"}
    p.model.responder = decide
    f = p.flow()
    start = f.start("run", "Pay twice; ask to raise cap if needed")
    p.approve(start)
    pause = f.resume("run")
    assert pause["__interrupt__"][0].value["kind"] == "contract"
    with p.runtime.store.snapshot() as s: assert s.read("budget:pilot")[1] == 400
    request = p.bridge.tools.stage({"tool": "send_email", "args": {"to": "alice@corp.id", "body": "summary"}},
        principal=p.principals["executor"], task="pilot", purpose="research", operation="before-revision")
    ticket = p.runtime.authority.authorize(request, p.principals["executor"])
    p.approve(pause)
    result = f.resume("run")
    assert p.runtime.gateway.commit(ticket["ticket"], ticket["commit_args"], p.principals["executor"])["status"] == "STALE_TICKET"
    assert result["status"] == "DONE", result
    with p.runtime.store.snapshot() as s: assert s.read("budget:pilot")[1] == 800
    f.close()


def test_inference_attempts_retry_cap_memo_and_usage(tmp_path):
    p = Pilot(tmp_path)
    memo = InferenceMemo(p.runtime.store)
    calls = []
    async def failure(): calls.append(True); raise TimeoutError("ambiguous")
    limits = Limits(max_calls=2, max_retries=1)
    with pytest.raises(RuntimeError): asyncio.run(memo.run("x", "budget", "JEV", "jev-1.13.0", {}, limits, failure))
    assert len(calls) == 2 and len(memo.attempts()) == 2
    with pytest.raises(ValueError, match="cap"): asyncio.run(memo.run("x", "budget", "JEV", "jev-1.13.0", {}, limits, failure))
    async def success(): return {"output": {}, "usage": {"input_tokens": 1, "output_tokens": 1}}
    first = asyncio.run(memo.run("ok", "other-budget", "LLM", "m", {"scope": "a"}, limits, success))
    assert asyncio.run(memo.run("ok", "other-budget", "LLM", "m", {"scope": "a"}, limits, failure)) == first
    with pytest.raises(ValueError, match="mismatch"): asyncio.run(memo.run("ok", "other-budget", "LLM", "m", {"scope": "b"}, limits, success))


def test_caps_no_unpriced_spend_and_token_limit_before_provider(tmp_path):
    with pytest.raises(ValueError): Limits(spend_cap_usd=.01)
    with pytest.raises(ValueError): Limits(max_calls=13)
    p = Pilot(tmp_path)
    calls = []
    async def invoke(): calls.append(True); return {}
    with pytest.raises(ValueError, match="cap"):
        asyncio.run(p.bridge.memo.run("cap", "budget", "LLM", "m", {"text": "x"*100}, Limits(max_tokens=10, max_output_tokens=1), invoke))
    assert not calls


def test_official_openai_sdk_request_shape_and_replay_offline():
    calls = []
    class SDKFixture:
        def __init__(self, **kwargs):
            assert kwargs["max_retries"] == 0 and kwargs["base_url"] == "https://api.openai.com/v1"
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(model="configured-model-version", choices=[SimpleNamespace(finish_reason="stop", message=SimpleNamespace(
                content='{"kind":"done","summary":"observed"}', refusal=None))], usage=SimpleNamespace(prompt_tokens=50, completion_tokens=8))
    messages = [{"role": "system", "content": "Return JSON"}, {"role": "user", "content": "fixture"}]
    response = asyncio.run(OpenAIModel("configured-model", client_factory=SDKFixture).generate(messages))
    assert response["usage"]["input_tokens"] == 50 and calls[0]["store"] is False
    replay = ReplayModel({args_hash(messages): response["output"]})
    assert asyncio.run(replay.generate(messages))["output"] == response["output"]
    with pytest.raises(ValueError): asyncio.run(replay.generate([]))


def test_concurrent_inference_same_call_is_not_dispatched_twice(tmp_path):
    from atomicroot.integration.memo import InferenceInProgress
    p = Pilot(tmp_path)
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        count = []
        async def invoke():
            count.append(True)
            entered.set()
            await release.wait()
            return {"output": {"kind": "done"}, "usage": None}
        first = asyncio.create_task(p.bridge.memo.run("concurrent", "budget", "LLM", "m", {}, Limits(), invoke))
        await entered.wait()
        try:
            with pytest.raises(InferenceInProgress):
                await p.bridge.memo.run("concurrent", "budget", "LLM", "m", {}, Limits(), invoke)
        finally:
            release.set()
        assert (await first)["output"]["kind"] == "done"
        assert len(count) == 1
    asyncio.run(scenario())
