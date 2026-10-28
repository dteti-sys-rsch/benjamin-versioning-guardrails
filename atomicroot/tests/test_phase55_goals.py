from copy import deepcopy
import json

import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration.goals import GoalService
from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
from atomicroot.integration.providers import FakeModel
from atomicroot.tests.phase55_support import initialize, proposal, model_for, GOAL
from atomicroot.tests.phase3_support import Clock


@pytest.fixture
def system(tmp_path):
    runtime = FrameworkRuntime(tmp_path / "ledger.sqlite", clock=Clock())
    values = initialize(runtime)
    yield runtime, values, tmp_path
    runtime.store.close()


def plan(system, response=None, goal=GOAL):
    runtime, (user, approver, admin, spec, config, _, _), path = system
    model = FakeModel(lambda _: response if response is not None else proposal(spec, goal))
    service = GoalService(runtime, model)
    return service, model, service.plan("test-goal", goal, "planning", "write-a", user)


def test_goal_preview_policy_review_execution_and_recovery(system):
    runtime, (user, approver, _, spec, _, _, _), path = system
    service, model, result = plan(system)
    assert result["status"] == "REVIEW_WAIT", result
    assert len(model.calls) == 1
    assert runtime.store.get_state("contract3:write-a") is None
    assert service.decide("test-goal", "pause", approver)["status"] == "PAUSED"
    with pytest.raises(ValueError): service.activate("test-goal", approver)
    service.decide("test-goal", "approve", approver); service.activate("test-goal", approver)
    def worker(view):
        if view['node'] == 'read':
            if view['observations']: return {'kind':'done','summary':'Read receipt obtained'}
            return {"kind": "action", "tool": "read_document", "args": {"resource": "file", "digest": spec["resources"][0]["digest"]}}
        receipt = next(o['detail']['receipt']['receipt_id'] for o in view['observations'] if o.get('detail',{}).get('tool') == 'read_document')
        return {"kind": "action", "tool": "update_document", "args": {"resource": "file", "digest": spec["resources"][0]["digest"], "content": "Goal-derived synthetic update", "read_receipt": receipt}}
    class Driver:
        binding = {"fixture": "goal-write-v1"}
        def __call__(self, view): return worker(view)
    factory = lambda task, caller, budget: ConfigWorkflow(runtime, path / 'checkpoint.sqlite', task=task, caller=caller, worker=Driver())
    executed = service.execute('test-goal', user, factory)
    assert executed['status'] == 'SATISFIED', executed
    assert runtime.store.get_state('document:file')['content'] == 'Goal-derived synthetic update'
    before = len(runtime.store.inspect_outbox())
    assert service.execute('test-goal', user, factory, command='recover')['status'] == 'SATISFIED'
    assert len(runtime.store.inspect_outbox()) == before
    assert service.plan('test-goal', GOAL, 'planning', 'write-a', user)['status'] == 'ACTIVE'
    assert len(model.calls) == 1


@pytest.mark.parametrize('attack', ['identity','tool','resource','cycle','fact','operator','label','origin','acceptance','extra'])
def test_invalid_proposals_are_bounded_and_cannot_activate(system, attack):
    runtime, (user, approver, _, spec, _, _, _), _ = system
    value = proposal(spec)
    if attack == 'identity': value['spec']['task_id'] = 'foreign'
    if attack == 'tool': value['spec']['scope'][0]['tool'] = 'shell'
    if attack == 'resource': value['spec']['resources'][0]['resource'] = 'private-file'
    if attack == 'cycle': value['spec']['workflow']['nodes'][0]['depends_on'] = ['write']
    if attack == 'fact': value['spec']['policies'][0]['constraint']['left'] = {'op':'ref','source':'imaginary_balance','id':'task'}
    if attack == 'operator': value['spec']['policies'][0]['constraint'] = {'op':'python','code':'approve()'}
    if attack == 'label': value['spec']['resources'][0]['label'] = 'PUBLIC'
    if attack == 'origin': value['origin'][0]['paths'] = ['/scope','/made_up']
    if attack == 'acceptance': value['spec']['acceptance'] = []
    if attack == 'extra': value['approver'] = 'user approved'
    service, model, result = plan(system, value)
    assert result['status'] == 'INVALID_PROPOSAL', result
    assert len(model.calls) == 2
    assert runtime.store.get_state('contract3:write-a') is None
    with pytest.raises(ValueError): service.activate('test-goal', approver)


@pytest.mark.parametrize('status', ['CLARIFY','UNSUPPORTED'])
def test_ambiguous_or_unsupported_requirements_visible_without_fallback(system, status):
    value = {'status':status,'spec':None,'assumptions':[], 'unsupported':['Unregistered destination or fact'], 'questions':['Which registered recipient?'],'origin':[]}
    _, model, result = plan(system, value)
    assert result['status'] == status and result['proposal']['unsupported']
    assert len(model.calls) == 1


def test_discovery_and_calls_require_actual_intake_and_parent_rights(system):
    runtime, (user, _, admin, spec, config, _, _), _ = system
    model = model_for(spec); service = GoalService(runtime, model)
    stranger = Principal('stranger', user.roles, user.tasks)
    for principal in (stranger, Principal('local-user', frozenset({'worker'}), user.tasks)):
        with pytest.raises(PermissionError): service.plan('blocked', GOAL, 'planning', 'write-a', principal)
    assert model.calls == []
    with pytest.raises(PermissionError): service.register_intake(config, user)
    assert all('content' not in r for r in service.discover('planning','write-a',user)['resources'])
    changed = {**config, 'visible_resources':[]}
    service.register_intake(changed, admin)
    assert service.discover('planning','write-a',user)['resources'] == []


def test_expired_and_revoked_provider_prevent_calls(system):
    runtime, (user, _, admin, spec, config, _, _), _ = system
    service = GoalService(runtime, model_for(spec))
    destination = runtime.store.get_state('destination:openai')
    runtime.catalog.set_destination({**destination,'labels':['PUBLIC']}, admin)
    result = service.plan('blocked', GOAL, 'planning', 'write-a', user)
    assert result['status'] == 'PLANNING_FAILED' and service.model.calls == []
    with runtime.store.transaction() as conn: runtime.store.put(conn, 'goalintake:planning', {**config, 'expires':runtime.store.now()-1})
    with pytest.raises(PermissionError): service.plan('expired', GOAL, 'planning', 'write-a', user)


def test_review_origin_binding_and_superseded_approval_fail_fresh(system):
    runtime, (user, approver, _, _, _, _, _), _ = system
    service, _, old = plan(system)
    service.decide('test-goal','approve',approver)
    new = service.plan('test-goal',GOAL,'planning','write-a',user,replan=True)
    assert new['status'] == 'REVIEW_WAIT', new
    with pytest.raises(ValueError): runtime.contracts.activate(old['preview']['proposal_id'],old['preview']['review_id'],approver)
    with runtime.store.transaction() as conn:
        key='goalproposal:test-goal:1'; data=runtime.store.value(conn,key)[1]
        runtime.store.put(conn,key,{**data,'tampered':True})
    with pytest.raises(ValueError): service.decide('test-goal','approve',approver)


def test_replay_uses_new_key_exact_context_and_no_live_delegate(system, tmp_path):
    runtime, (user, _, _, _, _, _, _), _ = system
    service, _, result = plan(system)
    assert result['status'] == 'REVIEW_WAIT', result
    artifact = service.export('test-goal',user)
    with pytest.raises(ValueError,match='fresh prepared'): service.replay(artifact,user)
    other=FrameworkRuntime(tmp_path/'replay.sqlite',clock=runtime.store._clock)
    try:
        user2,*_=initialize(other)
        assert other.authority.verify_key != runtime.authority.verify_key
        assert GoalService(other).replay(artifact,user2)['match']
        tampered=deepcopy(artifact); tampered['request']['goal']='A changed context'
        with pytest.raises(ValueError): GoalService(other).replay(tampered,user2)
    finally: other.store.close()


def test_replay_rejects_changed_intake_caps_before_any_replayed_call(system,tmp_path):
    runtime,(user,_,_,_,_,_,_),_=system
    service,_,_=plan(system)
    artifact=service.export('test-goal',user)
    other=FrameworkRuntime(tmp_path/'changed-caps.sqlite',clock=Clock())
    try:
        replay_user,approver,_,_,_,_,intake_spec=initialize(other)
        intake_spec['limits']['inference']['max_calls']=11
        preview=other.tasks.propose(intake_spec,replay_user)
        other.broker.decide(preview['review_id'],True,approver)
        other.contracts.activate(preview['proposal_id'],preview['review_id'],approver)
        with pytest.raises(ValueError,match='caps divergence'): GoalService(other).replay(artifact,replay_user)
        assert other.store.inspect_outbox()==[]
    finally: other.store.close()


def test_reject_and_replan_completion_cannot_be_silently_weakened(system):
    runtime, (user, approver, _, spec, _, _, _), _ = system
    service, _, result=plan(system)
    service.decide('test-goal','reject',approver)
    with pytest.raises(ValueError): service.activate('test-goal',approver)
    value=proposal(spec); value['spec']['acceptance']=[{'kind':'read','resource':'file'}]
    service.model=FakeModel(lambda _:value)
    revised=service.plan('test-goal',GOAL,'planning','write-a',user,replan=True)
    assert revised['status']=='INVALID_PROPOSAL',revised


def test_changed_goal_does_not_reuse_old_session_or_memo(system):
    runtime,(user,*_),_=system
    service,model,_=plan(system)
    with pytest.raises(ValueError): service.plan('test-goal','Different goal','planning','write-a',user)
    assert len(model.calls)==1


def test_authorized_context_read_is_exposed_before_planner_and_untrusted(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    model=model_for(spec); service=GoalService(runtime,model)
    result=service.plan('context-goal',GOAL,'planning','write-a',user,context_resources=['file'])
    assert result['status']=='REVIEW_WAIT',result
    assert runtime.store.get_state('exposure:planner-intake')==['PUBLIC']
    prompt=json.loads(model.calls[0][-1]['content'])
    assert prompt['allowed_catalog']['authorized_context'][0]['untrusted_content']=='Synthetic initial file'
    blocked=service.plan('foreign-context',GOAL,'planning','write-a',user,context_resources=['secret'])
    assert blocked['status']=='PLANNING_FAILED' and blocked['error']=='PermissionError'
    assert len(model.calls)==1


def test_intake_expiry_between_authorization_and_commit_has_no_model_call(system):
    runtime,(user,_,admin,spec,config,_,_),_=system
    service=GoalService(runtime,model_for(spec))
    service.register_intake({**config,'expires':runtime.store.now()+1},admin)
    class Hook:
        def checkpoint(self,stage,action):
            if stage=='before_cas': runtime.store._clock.advance(2)
    runtime.authority.harness=runtime.gateway.harness=Hook()
    result=service.plan('expiry',GOAL,'planning','write-a',user)
    assert result['status']=='PLANNING_FAILED'
    assert service.model.calls==[]
    assert runtime.store.inspect_outbox()==[]


def test_real_repair_receives_validation_error_and_records_both_calls(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    responses=iter([{'bad':'shape'},proposal(spec)])
    model=FakeModel(lambda _:next(responses)); service=GoalService(runtime,model)
    result=service.plan('repair',GOAL,'planning','write-a',user)
    assert result['status']=='REVIEW_WAIT' and len(model.calls)==2,result
    assert json.loads(model.calls[1][-1]['content'])['validation_error']
    assert len(result['model_records'])==2 and len(result['calls'])==2


def test_provider_error_is_explicit_recorded_and_never_falls_back_to_fixture(system):
    runtime,(user,_,_,_,_,_,_),_=system
    model=FakeModel(lambda _:RuntimeError('private provider exception body'))
    result=GoalService(runtime,model).plan('error',GOAL,'planning','write-a',user)
    assert result['status']=='PLANNING_FAILED' and len(model.calls)==1
    assert 'private provider exception body' not in json.dumps(result)
    assert next(iter(result['model_records'].values()))['error']=='RuntimeError'


def test_session_call_cap_is_not_reset_by_repairs_or_replans(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    service=GoalService(runtime,model_for(spec))
    first=service.plan('cap',GOAL,'planning','write-a',user)
    assert first['status']=='REVIEW_WAIT'
    # Trusted fixture fills the shared budget with returned attempts, modeling
    # calls already spent by workers. This is not a worker ledger API.
    with runtime.store.transaction() as conn:
        conn.execute("UPDATE inference_attempts SET reserved_tokens=200000 WHERE budget='goal:cap'")
    result=service.plan('cap',GOAL,'planning','write-a',user,replan=True)
    assert result['status']=='PLANNING_FAILED' and len(service.model.calls)==1


def test_two_different_goals_generate_different_plans_without_core_scenario_branch(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    def synthesize(messages):
        context=json.loads(messages[-1]['content']); chosen=deepcopy(spec)
        if context['goal']=='Read the file only':
            chosen['scope']=[r for r in chosen['scope'] if r['tool']=='read_document']
            chosen['agents'][0]['scope']=chosen['scope']
            chosen['workflow']['nodes']=[{'id':'inspect','agent':'writer','depends_on':[]}]
            chosen['acceptance']=[{'kind':'read','resource':'file'}]
        return proposal(chosen,context['goal'])
    service=GoalService(runtime,FakeModel(synthesize))
    first=service.plan('read-only','Read the file only','planning','write-a',user)
    second=service.plan('write',GOAL,'planning','write-a',user)
    assert first['status']==second['status']=='REVIEW_WAIT'
    assert first['proposal']['spec']['workflow']!=second['proposal']['spec']['workflow']


def test_http_goal_identity_review_and_public_redaction(system):
    from fastapi.testclient import TestClient
    from atomicroot.framework.app import create_phase3_app
    runtime,(user,approver,_,spec,_,_,_),_=system
    principals={'user':user,'approver':approver,'worker':Principal('attacker',frozenset({'worker'}),user.tasks)}
    service=GoalService(runtime,model_for(spec))
    app=create_phase3_app(runtime,lambda request:principals[request.headers.get('x-test-role','user')],goal_service=service)
    with TestClient(app) as client:
        body={'session':'api-goal','goal':GOAL,'task':'write-a','intake':'planning','context_resources':[]}
        result=client.post('/goals',json=body)
        assert result.status_code==200 and result.json()['status']=='REVIEW_WAIT'
        assert 'proposal' not in result.json() and GOAL not in result.text
        assert client.post('/goals',json={**body,'agent_id':'approver'}).status_code==422
        assert client.post('/goals/api-goal/decision',json={'decision':'approve'},headers={'x-test-role':'worker'}).status_code==403
        assert client.post('/goals/api-goal/decision',json={'decision':'approve'},headers={'x-test-role':'approver'}).status_code==200
        assert client.get('/goals/api-goal/preview',headers={'x-test-role':'approver'}).json()['request']['goal']==GOAL
        assert client.post('/goals/api-goal/activate',json={},headers={'x-test-role':'approver'}).status_code==200
        assert client.get('/goals/api-goal',headers={'x-test-role':'worker'}).status_code==403


def test_concurrent_same_session_does_not_duplicate_planning_call(system):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    runtime,(user,_,_,spec,_,_,_),_=system
    arrived,release=Event(),Event()
    def respond(_):
        arrived.set(); assert release.wait(5)
        return proposal(spec)
    model=FakeModel(respond); service=GoalService(runtime,model)
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(service.plan,'concurrent',GOAL,'planning','write-a',user)
        assert arrived.wait(5)
        try:
            assert service.plan('concurrent',GOAL,'planning','write-a',user)['status']=='PLANNING'
        finally: release.set()
        assert first.result(5)['status']=='REVIEW_WAIT'
    assert len(model.calls)==1


def test_completed_business_node_carried_across_reviewed_replan_without_duplicate_send(system):
    runtime,(user,approver,_,spec,_,_,_),path=system
    spec=deepcopy(spec)
    send_rule=next(r for r in spec['scope'] if r['tool']=='send_email')
    spec['scope']=[send_rule]; spec['resources']=[]; spec['agents'][0]['scope']=[send_rule]
    spec['workflow']['nodes']=[{'id':'send','agent':'writer','depends_on':[]}]
    spec['acceptance']=[{'kind':'receipt','tool':'send_email','destination':'alice@corp.id'}]
    service=GoalService(runtime,model_for(spec))
    result=service.plan('carry',GOAL,'planning','write-a',user)
    assert result['status']=='REVIEW_WAIT',result
    service.decide('carry','approve',approver); service.activate('carry',approver)
    factory=lambda task,caller,budget:ConfigWorkflow(runtime,path/'carry.sqlite',task=task,caller=caller,
        worker=ScriptedWorker({'send':[{'kind':'action','tool':'send_email','args':{'to':'alice@corp.id','body':'Synthetic message'}}]}))
    assert service.execute('carry',user,factory)['status']=='SATISFIED'
    before=len([r for r in runtime.store.inspect_outbox() if r['task']=='write-a'])
    revised=service.plan('carry',GOAL,'planning','write-a',user,replan=True)
    assert revised['status']=='REVIEW_WAIT',revised
    service.decide('carry','approve',approver); service.activate('carry',approver)
    def crashed_factory(task,caller,budget):
        workflow=factory(task,caller,budget)
        def crash(*args,**kwargs): raise KeyboardInterrupt()
        workflow.graph.invoke=crash
        return workflow
    with pytest.raises(KeyboardInterrupt): service.execute('carry',user,crashed_factory)
    after=service.execute('carry',user,factory,command='recover')
    assert after['status']=='SATISFIED',after
    assert len([r for r in runtime.store.inspect_outbox() if r['task']=='write-a'])==before


def test_frozen_revision_replay_resolves_again_without_replaying_business_effects(system,tmp_path):
    runtime,(user,_,_,_,_,_,_),_=system
    service,_,_=plan(system)
    revised=service.plan('test-goal',GOAL,'planning','write-a',user,replan=True)
    assert revised['status']=='REVIEW_WAIT'
    artifact=service.export('test-goal',user)
    other=FrameworkRuntime(tmp_path/'frozen.sqlite',clock=Clock())
    try:
        replay_user,*_=initialize(other)
        result=GoalService(other).replay(artifact,replay_user)
        assert result['match'] and result['result']['status']=='REVIEW_WAIT'
        assert result['result']['network_calls']==0
        assert other.store.inspect_outbox()==[]
        assert other.store.get_state('contract3:write-a') is None
    finally: other.store.close()


def test_narrower_dynamic_amount_scope_uses_the_existing_z3_subset_resolver(system):
    runtime,(user,_,admin,spec,config,_,_),_=system
    with runtime.store.snapshot() as snap: rights=snap.read('entitlement:write-a:local-user')[1]
    rule={'tool':'transfer_funds','resource':None,'destination':'alice@corp.id','purpose':'research','max_amount':500}
    rights['scope'].append(rule); rights['budget_limit']=500
    runtime.catalog.set_entitlement('write-a','local-user',rights,admin)
    spec=deepcopy(spec); spec['resources']=[]; spec['scope']=[{**rule,'max_amount':175}]; spec['budget_limit']=175
    spec['agents'][0]['scope']=spec['scope']; spec['workflow']['nodes']=[{'id':'pay','agent':'writer','depends_on':[]}]
    spec['acceptance']=[{'kind':'receipt','tool':'transfer_funds','destination':'alice@corp.id'}]
    service=GoalService(runtime,model_for(spec))
    result=service.plan('narrow',GOAL,'planning','write-a',user)
    assert result['status']=='REVIEW_WAIT',result
    assert result['proposal']['spec']['scope'][0]['max_amount']==175


def test_replan_stale_read_requires_new_receipt_and_keeps_old_read_proof(system):
    runtime,(user,approver,_,spec,_,_,_),path=system
    read_spec=deepcopy(spec)
    read_spec['scope']=[r for r in spec['scope'] if r['tool']=='read_document']
    read_spec['agents'][0]['scope']=read_spec['scope']
    read_spec['workflow']['nodes']=[{'id':'read','agent':'writer','depends_on':[]}]
    read_spec['acceptance']=[{'kind':'read','resource':'file'}]
    service=GoalService(runtime,model_for(read_spec))
    assert service.plan('fresh-read',GOAL,'planning','write-a',user)['status']=='REVIEW_WAIT'
    service.decide('fresh-read','approve',approver); service.activate('fresh-read',approver)
    def factory(task,caller,budget):
        active=runtime.tasks.status(task,caller)['resolved']['spec']; ref=active['resources'][0]
        return ConfigWorkflow(runtime,path/'reread.sqlite',task=task,caller=caller,worker=ScriptedWorker({'read':[{'kind':'action','tool':'read_document','args':{'resource':'file','digest':ref['digest']}}]}))
    assert service.execute('fresh-read',user,factory)['status']=='SATISFIED'
    owner=Principal('owner',frozenset({'owner'}),resources=frozenset({'file'}))
    new_ref=runtime.storage.ingest('file','Changed document',owner)
    runtime.labels.set_label('file',new_ref['digest'],new_ref['version'],'PUBLIC',['research'],owner)
    read_spec['resources']=[new_ref]
    service.model=model_for(read_spec)
    assert service.plan('fresh-read',GOAL,'planning','write-a',user,replan=True)['status']=='REVIEW_WAIT'
    service.decide('fresh-read','approve',approver); service.activate('fresh-read',approver)
    assert service.execute('fresh-read',user,factory)['status']=='SATISFIED'
    with runtime.store.snapshot() as snap:
        receipts=[json.loads(r[0])['read_binding'] for r in snap._conn.execute("SELECT receipt FROM receiver_receipts WHERE task='write-a'")]
    assert sorted(r['version'] for r in receipts)==[1,2]


def test_cli_plan_preview_review_execute_recover_and_export(system, capsys):
    from atomicroot_cli import main
    assert main(['artifact-schema'])==0
    assert json.loads(capsys.readouterr().out)['$id']=='urn:atomicroot:goal-replay:1'
    runtime,(_,_,_,spec,_,_,_),path=system
    (path/'signing.key').write_bytes(bytes(runtime.authority._sk))
    config=runtime.store.get_state('goalintake:planning')
    config_path=path/'intake.json'; config_path.write_text(json.dumps(config))
    prefix=['--directory',str(path),'--quiet-progress']
    assert main([*prefix,'register-intake',str(config_path),'--ttl','3600'])==0
    spec=deepcopy(spec); spec['scope']=[r for r in spec['scope'] if r['tool']=='read_document']
    spec['agents'][0]['scope']=spec['scope']; spec['acceptance']=[{'kind':'read','resource':'file'}]
    spec['workflow']['nodes']=[{'id':'inspect','agent':'writer','depends_on':[]}]
    candidate=path/'proposal.json'; candidate.write_text(json.dumps(proposal(spec)))
    responses=path/'responses.json'; responses.write_text(json.dumps({'inspect':[{'kind':'action','tool':'read_document','args':{'resource':'file','digest':spec['resources'][0]['digest']}}]}))
    assert main([*prefix,'--proposal',str(candidate),'plan','cli-goal','planning','write-a','--goal',GOAL])==0
    assert main([*prefix,'preview','cli-goal'])==0
    assert main([*prefix,'decide','cli-goal','pause'])==0
    assert main([*prefix,'activate','cli-goal'])==1
    assert main([*prefix,'decide','cli-goal','approve'])==0
    assert main([*prefix,'activate','cli-goal'])==0
    assert main([*prefix,'execute','cli-goal','--responses',str(responses)])==0
    assert main([*prefix,'execute','cli-goal','--responses',str(responses),'--command','recover'])==0
    artifact=path/'artifact.json'
    assert main([*prefix,'export','cli-goal',str(artifact)])==0
    assert main([*prefix,'export','cli-goal',str(artifact)])==1
    assert 'signing.key' not in artifact.read_text()


def test_reviewed_goal_dsl_is_enforced_by_z3_not_only_schema(system):
    runtime,(user,approver,_,spec,_,_,_),_=system
    value=proposal(spec)
    value['spec']['policies'][0]['applies_to']=['read_document']
    value['spec']['policies'][0]['constraint']={'op':'lt','left':{'op':'ref','fact':'document_version','scope':'document'},'right':{'op':'const','value':1}}
    service,_,result=plan(system,value)
    assert result['status']=='REVIEW_WAIT',result
    service.decide('test-goal','approve',approver); service.activate('test-goal',approver)
    worker=runtime.tasks.principal('write-a','writer',user)
    auth=runtime.authority.authorize({'task_id':'write-a','agent_id':worker.subject,'operation_id':'denied-read','purpose':'research','tool':'read_document',
        'args':{'resource':'file','digest':spec['resources'][0]['digest']}},worker)
    assert auth['decision']=='DENY' and auth['policy']=='goal_amount_limit',auth
    assert not any(r['task']=='write-a' for r in runtime.store.inspect_outbox())


def test_fake_live_driver_cannot_bypass_paid_spend_bound(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    model=model_for(spec); model.live=True
    result=GoalService(runtime,model).plan('live-blocked',GOAL,'planning','write-a',user)
    assert result['status']=='PLANNING_FAILED' and result['error']=='PermissionError'
    assert model.calls==[]


def test_sensitive_context_cannot_egress_to_intake_without_sensitive_permission(system):
    runtime,(user,_,_,spec,_,_,_),_=system
    owner=Principal('owner',frozenset({'owner'}),resources=frozenset({'file'}))
    ref=spec['resources'][0]
    runtime.labels.set_label('file',ref['digest'],ref['version'],'SENSITIVE',['research'],owner)
    model=model_for(spec)
    result=GoalService(runtime,model).plan('sensitive',GOAL,'planning','write-a',user,context_resources=['file'])
    assert result['status']=='PLANNING_FAILED'
    assert model.calls==[] and runtime.store.get_state('exposure:planner-intake')==['SENSITIVE']


def test_planner_crash_after_recorded_response_recovers_without_new_call(system,monkeypatch):
    import atomicroot.integration.goals as goals_module
    runtime,(user,_,_,spec,_,_,_),_=system
    model=model_for(spec); service=GoalService(runtime,model)
    original=goals_module.parse_proposal
    def crash(*args): raise KeyboardInterrupt()
    monkeypatch.setattr(goals_module,'parse_proposal',crash)
    with pytest.raises(KeyboardInterrupt): service.plan('crash-plan',GOAL,'planning','write-a',user)
    assert service.status('crash-plan',user)['status']=='PLANNING' and len(model.calls)==1
    monkeypatch.setattr(goals_module,'parse_proposal',original)
    result=GoalService(runtime,model).plan('crash-plan',GOAL,'planning','write-a',user,recover=True)
    assert result['status']=='REVIEW_WAIT',result
    assert len(model.calls)==1 and len(result['model_records'])==1


def test_llm_and_classifier_share_one_bounded_goal_budget(system):
    import asyncio
    from atomicroot.integration.memo import InferenceMemo
    from atomicroot.integration.providers import Limits
    runtime,_,_=system
    memo=InferenceMemo(runtime.store,aggregate_budget='goal:combined')
    caps=Limits(max_calls=1,max_tokens=10000,max_output_tokens=10)
    called=[]
    async def invoke(): called.append(True); return {'output':'synthetic'}
    asyncio.run(memo.run('planner','goal:combined','LLM','offline',{},caps,invoke))
    with pytest.raises(ValueError,match='cap reached'):
        asyncio.run(memo.run('jev','goal:combined','JEV','offline',{},caps,invoke))
    assert len(called)==1


def test_replan_is_bounded_and_extra_scope_is_visible(system):
    runtime,(user,_,_,_,_,_,_),_=system
    service,_,result=plan(system)
    assert any(type(w) is dict and w['kind']=='EXTRA_SCOPE_REQUIRES_JUSTIFICATION' for w in result['warnings'])
    for _ in range(2): assert service.plan('test-goal',GOAL,'planning','write-a',user,replan=True)['status']=='REVIEW_WAIT'
    with pytest.raises(ValueError,match='bound exhausted'): service.plan('test-goal',GOAL,'planning','write-a',user,replan=True)


def test_model_worker_calls_share_planning_budget_and_checkpoint_recovery(system):
    from atomicroot.integration.inference import ModelBridge
    from atomicroot.integration.providers import DisabledClassifier, Limits
    runtime,(user,approver,admin,spec,config,_,_),path=system
    owner=Principal('owner',frozenset({'owner'}),resources=frozenset({'business-context'}))
    context=runtime.storage.ingest('business-context','Initial context',owner)
    scope=[{'tool':'model_inference','resource':'business-context','destination':'openai','purpose':'research','max_amount':0}]
    with runtime.store.snapshot() as snap: rights=snap.read('entitlement:write-a:local-user')[1]
    rights['scope']+=scope
    runtime.catalog.set_entitlement('write-a','local-user',rights,admin)
    service=GoalService(runtime)
    service.register_intake({**config,'visible_resources':['file','business-context'],'visible_destinations':['alice@corp.id','openai']},admin)
    spec=deepcopy(spec)
    spec['scope']=scope; spec['resources']=[{**context,'binding':'host_context'}]
    spec['provider']={'destination':'openai','model':'offline-script-v1'}
    spec['agents']=[{'id':'author','role':'Produce output','scope':scope}]
    spec['workflow']['nodes']=[{'id':'compose','agent':'author','depends_on':[]}]
    spec['outputs']=[{'id':'result','kind':'summary'}]
    spec['acceptance']=[{'kind':'output','output':'result'}]
    spec['limits']['inference']={'max_calls':12,'max_tokens':200000,'max_output_tokens':4096,'max_retries':0,'timeout':30}
    service.model=model_for(spec)
    assert service.plan('model-goal',GOAL,'planning','write-a',user)['status']=='REVIEW_WAIT'
    service.decide('model-goal','approve',approver); service.activate('model-goal',approver)
    def respond(messages):
        view=json.loads(messages[-1]['content'])
        if any(o.get('status')=='OUTPUT_STORED' for o in view['observations']): return {'kind':'done','summary':'Output complete'}
        return {'kind':'output','output':'result','content':'Synthetic model result'}
    model=FakeModel(respond)
    model.execution_binding='synthetic-model-worker-v1'
    def factory(task,caller,budget):
        bridge=ModelBridge(runtime,model,DisabledClassifier(),llm_limits=Limits(**spec['limits']['inference']),budget=budget)
        return ConfigWorkflow(runtime,path/'model.sqlite',task=task,caller=caller,bridge=bridge)
    result=service.execute('model-goal',user,factory)
    assert result['status']=='SATISFIED',result
    assert service.execute('model-goal',user,factory,command='recover')['status']=='SATISFIED'
    with runtime.store.snapshot() as snap:
        budgets=[r[0] for r in snap._conn.execute('SELECT budget FROM inference_attempts')]
    assert budgets==['goal:model-goal']*3 and len(model.calls)==2
    model.live=True  # Host driver stub; it must be blocked before any paid call.
    with pytest.raises(PermissionError,match='paid live execution'):
        service.execute('model-goal',user,factory,command='recover')
    assert len(model.calls)==2
