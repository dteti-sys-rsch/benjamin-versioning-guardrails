"""Generation constraints do not replace the trusted parser or protocol."""
import json
import pytest
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.goals import GoalService
from atomicroot.integration.planning import planner_response_schema, parse_proposal, proposal_schema
from atomicroot.integration.providers import FakeModel
from atomicroot.tests.phase3_support import Clock
from atomicroot.tests.phase55_support import initialize, proposal, GOAL


def test_compact_selection_is_exact_and_cannot_gain_unselected_rights(tmp_path):
    from copy import deepcopy
    from atomicroot.integration.planning import expand_scope_refs
    runtime = FrameworkRuntime(tmp_path / "db", clock=Clock())
    try:
        user, _, _, spec, *_ = initialize(runtime)
        catalog = GoalService(runtime).discover("planning", "write-a", user)
        index = next(i for i, r in enumerate(catalog["scope"]) if r["tool"] == "read_document")
        compact = deepcopy(spec)
        compact.pop("scope"); compact.pop("resources")
        compact["agents"] = [{"id": "writer", "role": "Reader", "scope_refs": [index], "context_resource": None}]
        expanded = expand_scope_refs(compact, catalog)
        assert expanded["scope"] == [catalog["scope"][index]]
        assert expanded["agents"][0]["scope"] == expanded["scope"]
        assert [r["resource"] for r in expanded["resources"]] == ["file"]
        for invalid in ([True], [-1], [len(catalog["scope"])], [index, index]):
            bad = deepcopy(compact); bad["agents"][0]["scope_refs"] = invalid
            with pytest.raises(ValueError): expand_scope_refs(bad, catalog)
        bad = deepcopy(compact); bad["agents"][0]["admin"] = True
        with pytest.raises(ValueError): expand_scope_refs(bad, catalog)
    finally:
        runtime.store.close()


def test_structured_planning_is_budgeted_recorded_and_replayed_without_delegate(tmp_path):
    runtime = FrameworkRuntime(tmp_path / "live.sqlite", clock=Clock())
    replay = FrameworkRuntime(tmp_path / "replay.sqlite", clock=Clock())
    try:
        user, _, _, spec, *_ = initialize(runtime)
        seen = []
        class Model(FakeModel):
            structured_worker_output = True
            async def generate(self, messages, *, response_schema=None):
                seen.append(response_schema)
                context = json.loads(messages[-1]["content"])
                assert response_schema["$defs"]["planner_spec"]["properties"]["task_id"] == {"const": context["target_task"]}
                return await super().generate(messages)
        def respond(messages):
            value = proposal(spec)
            allowed = json.loads(messages[-1]["content"])["allowed_catalog"]["scope"]
            value["spec"].pop("resources"); value["spec"].pop("scope")
            for agent in value["spec"]["agents"]:
                agent["scope_refs"] = [allowed.index(rule) for rule in agent.pop("scope")]
                agent["context_resource"] = None
            return value
        service = GoalService(runtime, Model(respond))
        original_schema = json.dumps(proposal_schema(), sort_keys=True)
        result = service.plan("structured", GOAL, "planning", "write-a", user)
        assert result["status"] == "REVIEW_WAIT", result
        assert len(seen) == 1 and "$ref" in seen[0]
        executable, stopped, unsupported = seen[0]["$defs"]["goal_proposal"]["oneOf"]
        assert executable["properties"]["questions"]["maxItems"] == 0
        assert stopped["properties"]["spec"] == {"type": "null"}
        assert json.dumps(proposal_schema(), sort_keys=True) == original_schema
        with runtime.store.snapshot() as snap:
            reserved = snap._conn.execute("SELECT reserved_tokens FROM inference_attempts").fetchone()[0]
        assert reserved > len(json.dumps(seen[0], separators=(",", ":")))
        artifact = service.export("structured", user)
        assert "scope" in artifact["planning"]["proposal"]["spec"]
        record = next(iter(artifact["planning"]["model_records"].values()))
        assert "scope" not in record["response"]["output"]["spec"]
        replay_user, *_ = initialize(replay)
        assert GoalService(replay).replay(artifact, replay_user)["match"]
        assert len(seen) == 1
    finally:
        runtime.store.close(); replay.store.close()


def test_resource_authority_field_reports_path_and_still_rejects():
    from atomicroot.evaluation.scenarios import write_fixture
    _, spec = write_fixture()
    value = proposal(spec)
    value["spec"]["resources"][0]["label"] = "PUBLIC"
    with pytest.raises(ValueError, match=r"/spec/resources/0: extra=.*label"):
        parse_proposal(value, "write-a", GOAL)


def test_context_declaration_selects_only_exact_catalog_capability(tmp_path):
    from examples.phase55.live_ollama import bootstrap
    from atomicroot.integration.planning import expand_scope_refs
    runtime=FrameworkRuntime(tmp_path/'db',clock=Clock())
    try:
        user,*_=bootstrap(runtime,payment=True)
        catalog=GoalService(runtime).discover('planning','write-a',user)
        payment=next(i for i,r in enumerate(catalog['scope']) if r['tool']=='transfer_funds')
        raw=dict(provider=dict(destination='ollama',model='qwen3:8b'),purpose='research',
            agents=[dict(id='payer',role='Pay',scope_refs=[payment],context_resource='worker-context')])
        result=expand_scope_refs(raw,catalog)
        assert result['scope']==[catalog['scope'][payment],next(r for r in catalog['scope'] if r['tool']=='model_inference')]
        assert all(r in catalog['scope'] for r in result['scope'])
        raw['provider']['destination']='unapproved'
        with pytest.raises(ValueError,match='authorized inference rule'):expand_scope_refs(raw,catalog)
    finally:runtime.store.close()


def test_frozen_revision_replay_runs_the_bound_host_check(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'source.sqlite',clock=Clock())
    replay=FrameworkRuntime(tmp_path/'replay.sqlite',clock=Clock())
    class Check:
        binding={'version':'counter-test'}
        def __init__(self):self.calls=0
        def __call__(self,value):self.calls+=1
    try:
        user,_,_,spec,*_=initialize(runtime)
        model=FakeModel(lambda _:proposal(spec))
        check=Check();service=GoalService(runtime,model,proposal_check=check)
        assert service.plan('frozen',GOAL,'planning','write-a',user)['status']=='REVIEW_WAIT'
        assert service.plan('frozen',GOAL,'planning','write-a',user,replan=True)['status']=='REVIEW_WAIT'
        artifact=service.export('frozen',user)
        replay_user,*_=initialize(replay)
        other_check=Check()
        assert GoalService(replay,proposal_check=other_check).replay(artifact,replay_user)['match']
        assert check.calls==2 and other_check.calls==1 and len(model.calls)==2
    finally:runtime.store.close();replay.store.close()
