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


def test_acceptance_error_cannot_be_hidden_by_satisfied_execution(tmp_path,monkeypatch):
    monkeypatch.setattr(demo,"CAPS",dict(demo.CAPS))
    monkeypatch.setattr(demo,"run_case",lambda *args:dict(case="summary",execution_status="SATISFIED",error={"type":"AssertionError"}))
    monkeypatch.setattr("sys.argv",["live_ollama.py","--output",str(tmp_path/"run"),"--authorize-live","--fixture-approve","--case","summary"])
    assert demo.main()==1


def test_budget_fixture_grants_only_explicit_dummy_transfer_and_context(tmp_path):
    runtime=FrameworkRuntime(tmp_path/"db")
    try:
        user,*_=demo.bootstrap(runtime,payment=True)
        catalog=demo.GoalService(runtime).discover("planning","write-a",user)
        assert catalog["budget_limit"]==500
        assert {r["tool"] for r in catalog["scope"]}=={"transfer_funds","model_inference"}
        assert next(r for r in catalog["scope"] if r["tool"]=="transfer_funds")["max_amount"]==500
        assert demo.snapshot(runtime)["contract"] is None
    finally:runtime.store.close()


@pytest.mark.parametrize('repair',[False,True])
def test_weak_generated_policy_is_reported_before_any_payment(tmp_path,monkeypatch,repair):
    from atomicroot.evaluation.scenarios import write_fixture
    from atomicroot.tests.phase55_support import proposal
    _,spec=write_fixture()
    spec.pop("resources");spec.pop("scope")
    spec.update(objective="Pay 175",budget_limit=500,agents=[dict(id="payer",role="Pay",scope_refs=[0,1],context_resource="worker-context")],
        workflow={"nodes":[dict(id="pay",agent="payer",depends_on=[])]},outputs=[],
        acceptance=[dict(kind="receipt",tool="transfer_funds",destination="alice@corp.id")],
        provider=dict(destination="ollama",model="qwen3:8b"),limits=dict(max_steps=4,max_in_flight=1,inference=demo.CAPS))
    value=proposal(spec,demo.GOALS["budget"])
    value["spec"]["policies"][0]["applies_to"]=["model_inference"]
    class Model(FakeModel):model="qwen3:8b"
    def respond(messages):
        from copy import deepcopy
        candidate=deepcopy(value)
        if repair and 'Z3 probe' in json.loads(messages[-1]['content']).get('validation_error',''):
            candidate['spec']['policies'][0]['applies_to']=['transfer_funds']
        return candidate
    model=Model(respond,provider="ollama")
    monkeypatch.setattr(demo,"live_model",lambda *args:model)
    if repair:
        from atomicroot.integration.config_workflow import ConfigWorkflow
        from atomicroot.integration.inference import ModelBridge
        from atomicroot.integration.providers import DisabledClassifier,Limits
        worker=Model(lambda _:dict(kind='action',tool='transfer_funds',args={'to':'alice@corp.id','amount':175}),provider='ollama')
        worker.execution_binding='offline-semantic-repair-worker'
        monkeypatch.setattr(demo,'build_workflow',lambda runtime,path,task,caller,**kwargs:ConfigWorkflow(runtime,path,task=task,caller=caller,
            bridge=ModelBridge(runtime,worker,DisabledClassifier(),llm_limits=Limits(**demo.CAPS))))
    result=demo.run_case(tmp_path,"budget")
    assert result["planning_status"]==('REVIEW_WAIT' if repair else 'INVALID_PROPOSAL'),result
    assert result["business_intents"]==(1 if repair else 0) and result["inference_attempts"]==(3 if repair else 2)
    final=json.loads((tmp_path/"budget/final-state.json").read_text())
    if not repair:assert final["contract"] is None
    else:
        assert result['execution_status']=='SATISFIED' and result['proposal_replay']['match']
        assert result['policy_probe']['negative']=='DENY' and len(model.calls)==2
        artifact=json.loads((tmp_path/'budget/goal-artifact.json').read_text())
        other=FrameworkRuntime(tmp_path/'divergent.sqlite')
        class ChangedCheck:
            binding={'version':'changed'}
            def __call__(self,value):raise AssertionError('must reject before checking/calling model')
        try:
            with pytest.raises(ValueError,match='trusted proposal check divergence'):
                demo.GoalService(other,proposal_check=ChangedCheck()).replay(artifact,None)
        finally:other.store.close()
    evidence=json.loads((tmp_path/"budget/semantic-1.json").read_text())
    assert evidence["observations"][1]["actual"]=="ALLOW"
