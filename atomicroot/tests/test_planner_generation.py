"""Generation constraints do not replace the trusted parser or protocol."""
import json
import pytest
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.goals import GoalService
from atomicroot.integration.planning import planner_response_schema, parse_proposal, proposal_schema
from atomicroot.integration.providers import FakeModel
from atomicroot.tests.phase3_support import Clock
from atomicroot.tests.phase55_support import initialize, proposal, GOAL


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
                assert response_schema["$defs"]["task_spec"]["properties"]["task_id"] == {"const": context["target_task"]}
                return await super().generate(messages)
        service = GoalService(runtime, Model(lambda _: proposal(spec)))
        original_schema = json.dumps(proposal_schema(), sort_keys=True)
        result = service.plan("structured", GOAL, "planning", "write-a", user)
        assert result["status"] == "REVIEW_WAIT", result
        assert len(seen) == 1 and "$ref" in seen[0]
        assert json.dumps(proposal_schema(), sort_keys=True) == original_schema
        with runtime.store.snapshot() as snap:
            reserved = snap._conn.execute("SELECT reserved_tokens FROM inference_attempts").fetchone()[0]
        assert reserved > len(json.dumps(seen[0], separators=(",", ":")))
        artifact = service.export("structured", user)
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
