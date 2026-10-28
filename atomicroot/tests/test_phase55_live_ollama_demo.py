"""Exercise the live-demo harness offline; real calls require explicit CLI flags."""
import json
import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.providers import FakeModel
from examples.phase55 import live_ollama as demo


def test_synthetic_bootstrap_has_no_update_send_payment_or_remote_provider_rights(tmp_path):
    runtime = FrameworkRuntime(tmp_path / "ledger.sqlite")
    try:
        user, _, _, _, config = demo.bootstrap(runtime)
        catalog = demo.GoalService(runtime).discover("planning", "write-a", user)
        assert {r["tool"] for r in catalog["scope"]} == {"read_document", "model_inference"}
        assert {d["endpoint"] for d in catalog["destinations"]} == {"http://localhost:11434/api"}
        assert all(r["destination"] in {None, "ollama"} for r in catalog["scope"])
        state = demo.snapshot(runtime)
        assert state["contract"] is None and state["attempts"] == []
        assert config["max_repairs"] == 1 and demo.CAPS["max_retries"] == 0
    finally:
        runtime.store.close()


@pytest.mark.parametrize("multi", [False, True])
def test_worker_control_records_real_guarded_read_output_and_no_duplicate_on_recover(tmp_path, monkeypatch, multi):
    class Model(FakeModel):
        model = "qwen3:8b"
        structured_worker_output = True
        execution_binding = "offline-live-demo-control"
        async def generate(self, messages, *, response_schema=None):
            return await super().generate(messages)
    def respond(messages):
        observations = json.loads(messages[-1]["content"])["observations"]
        if any(o.get("tool") == "read_document" for o in observations):
            return dict(kind="output", output="result", content="Synthetic summary of delivered source")
        catalog = json.loads(messages[-1]["content"])["catalog"]
        return dict(kind="action", tool="read_document", args={"resource": "file", "digest": catalog[0]["digest"]})
    monkeypatch.setattr(demo, "live_model", lambda *args: Model(respond, provider="ollama"))
    result = demo.worker_control(tmp_path, multi=multi)
    assert result["execution_status"] == "SATISFIED", result
    assert result["recover"] == dict(status="SATISFIED", no_new_outbox=True, no_new_model_call=True)
    assert result["inference_attempts"] == 2
    final = json.loads((tmp_path / ("worker-multi" if multi else "worker-control") / "final-state.json").read_text())
    assert final["document"]["version"] == 1 and len(final["outputs"]) == 1


def test_live_demo_requires_both_explicit_permissions_before_creating_output(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr("sys.argv", ["live_ollama.py", "--output", str(tmp_path / "not-created"), "--authorize-live"])
    with pytest.raises(SystemExit) as error:
        demo.main()
    assert error.value.code == 2 and not (tmp_path / "not-created").exists()
