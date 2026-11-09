"""Arbitrary user configurations exercise the real resolver/review/executor offline."""
from copy import deepcopy
import json

import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.environment import prepare_environment, initialize_environment, activate_intake, local_identities
from atomicroot.integration.goals import GoalService
from atomicroot.integration.providers import FakeModel, DisabledClassifier, Limits
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.config_workflow import ConfigWorkflow


def environment(task='arbitrary-analysis', recipient=None):
    scope = [dict(tool='transfer_funds', resource=None, destination=recipient, purpose='user-purpose', max_amount=600)] if recipient else [
        dict(tool=tool, resource='user-notes', destination='openai' if tool == 'model_inference' else None,
             purpose='user-purpose', max_amount=0) for tool in ('read_document', 'model_inference')]
    return dict(schema_version=1, task_id=task, purpose='user-purpose',
        resources=[] if recipient else [dict(resource='user-notes', content='User supplied synthetic notes', label='PUBLIC', purposes=['user-purpose'])],
        destinations=[dict(destination='openai', kind='provider', purposes=['user-purpose'], models=['offline-script-v1'],
            labels=['PUBLIC', 'UNKNOWN'], endpoint='https://api.openai.com/v1'), *([dict(destination=recipient, kind='recipient',
            purposes=['user-purpose'], models=[], labels=[], endpoint=None)] if recipient else [])],
        scope=scope, budget_limit=600 if recipient else 0, max_agents=1,
        limits=dict(max_steps=8, max_in_flight=1, inference=dict(max_calls=8, max_tokens=200000,
            max_output_tokens=3072, max_retries=0, timeout=30)), provider=dict(destination='openai',model='offline-script-v1'),
        planning=dict(ttl=3600,max_repairs=1,max_replans=2))


def ready(runtime, value):
    prepared=prepare_environment(value)
    record=initialize_environment(runtime,value,prepared['digest'])
    user, approver=local_identities(runtime)
    assert runtime.store.get_state('goalintake:planning') is None
    with pytest.raises(ValueError): activate_intake(runtime,approver)
    runtime.broker.decide(record['preview']['review_id'],True,approver)
    activate_intake(runtime,approver)
    return user,approver


def candidate(runtime, value, user, goal):
    catalog=GoalService(runtime).discover('planning',value['task_id'],user)
    refs=[{k:r[k] for k in ('resource','digest','version')} for r in catalog['resources']]
    for ref in refs:
        if ref['resource'].startswith('worker-'): ref['binding']='host_context'
    spec=dict(schema_version=1,task_id=value['task_id'],objective='User-selected workflow',purpose=value['purpose'],
        resources=refs, scope=catalog['scope'],budget_limit=value['budget_limit'],
        agents=[dict(id='user-worker',role='Perform only reviewed user work',scope=catalog['scope'])],policies=[],
        workflow=dict(nodes=[dict(id='work',agent='user-worker',depends_on=[])]),outputs=[],
        acceptance=[dict(kind='receipt',tool='transfer_funds',destination=value['scope'][0]['destination'])] if value['budget_limit'] else [dict(kind='read',resource='user-notes')],
        provider=value['provider'],classifier=dict(mode='disabled'),limits=value['limits'],unknown_release='DENY')
    return dict(status='PROPOSAL',spec=spec,assumptions=[],unsupported=[],questions=[],
        origin=[dict(requirement=goal,paths=['/resources','/scope','/agents','/workflow','/policies','/budget_limit','/acceptance'],reason='User goal mapped to proposed workflow')])


@pytest.mark.parametrize('task,recipient', [('new-analysis-job',None),('new-payment-job','new-person@example.net')])
def test_dynamic_environment_goal_review_execution_recover(tmp_path,task,recipient):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(task,recipient); user,approver=ready(runtime,value)
        goal='Transfer 237 to '+recipient if recipient else 'Read my user-notes resource'
        proposal=candidate(runtime,value,user,goal)
        model=FakeModel(lambda _:proposal)
        service=GoalService(runtime,model)
        result=service.plan('user-goal',goal,'planning',task,user)
        assert result['status']=='REVIEW_WAIT',result
        assert runtime.store.get_state('contract3:'+task) is None
        service.decide('user-goal','pause',approver)
        with pytest.raises(ValueError): service.activate('user-goal',approver)
        service.decide('user-goal','approve',approver); service.activate('user-goal',approver)
        def respond(messages):
            view=json.loads(messages[-1]['content'])
            if view['observations']: return dict(kind='done',summary='Receipt obtained')
            return dict(kind='action',tool='transfer_funds' if recipient else 'read_document',
                args=dict(to=recipient,amount=237) if recipient else dict(resource='user-notes',digest=proposal['spec']['resources'][0]['digest']))
        worker=FakeModel(respond)
        worker.execution_binding='user-environment-test-v1'
        def factory(task,caller,budget):
            bridge=ModelBridge(runtime,worker,DisabledClassifier(),llm_limits=Limits(**value['limits']['inference']),budget=budget)
            return ConfigWorkflow(runtime,tmp_path/'checkpoint.sqlite',task=task,caller=caller,bridge=bridge)
        output=service.execute('user-goal',user,factory)
        assert output['status']=='SATISFIED',output
        before=runtime.store.inspect_outbox()
        assert service.execute('user-goal',user,factory,command='recover')['status']=='SATISFIED'
        assert runtime.store.inspect_outbox()==before
        if recipient:
            assert runtime.store.get_state('budget:'+task)==237
        else: assert runtime.store.get_state('document:user-notes')['content']=='User supplied synthetic notes'
    finally: runtime.store.close()


def test_reject_proposal_and_undeclared_recipient_do_not_commit(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(recipient='chosen@example.net'); user,approver=ready(runtime,value)
        goal='Transfer only to chosen recipient'
        proposal=candidate(runtime,value,user,goal)
        service=GoalService(runtime,FakeModel(lambda _:proposal))
        assert service.plan('reject',goal,'planning',value['task_id'],user)['status']=='REVIEW_WAIT'
        service.decide('reject','reject',approver)
        with pytest.raises(ValueError): service.activate('reject',approver)
        bad=deepcopy(proposal)
        for scope in (bad['spec']['scope'],bad['spec']['agents'][0]['scope']):
            for rule in scope:
                if rule['tool']=='transfer_funds': rule['destination']='unapproved@example.net'
        bad['spec']['acceptance'][0]['destination']='unapproved@example.net'
        service.model=FakeModel(lambda _:bad)
        assert service.plan('excess',goal,'planning',value['task_id'],user)['status']=='INVALID_PROPOSAL'
        assert runtime.store.get_state('contract3:'+value['task_id']) is None
        assert not [row for row in runtime.store.inspect_outbox() if row['task']==value['task_id']]
        assert runtime.store.get_state('budget:'+value['task_id']) is None
    finally: runtime.store.close()


@pytest.mark.parametrize('change', ['schema','tool','destination','label','caps','purpose'])
def test_environment_preflight_rejects_invalid_input(change):
    value=environment()
    if change=='schema': value['schema_version']=True
    elif change=='tool': value['scope'][0]['tool']='shell'
    elif change=='destination': value['destinations'][0]['endpoint']='https://untrusted.example'
    elif change=='label': value['resources'][0]['label']='SAFE'
    elif change=='caps': value['limits']['inference']['max_calls']=999
    else: value['scope'][0]['purpose']='foreign'
    with pytest.raises(ValueError): prepare_environment(value)


def test_exact_environment_approval_and_no_reinitialization(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment()
        with pytest.raises(PermissionError): initialize_environment(runtime,value,'sha256:wrong')
        assert runtime.store.get_state('document:user-notes') is None
        ready(runtime,value)
        with pytest.raises(ValueError): initialize_environment(runtime,value,prepare_environment(value)['digest'])
    finally: runtime.store.close()


def test_cli_environment_setup_requires_intake_review(tmp_path,capsys):
    from atomicroot_cli import main
    path=tmp_path/'environment.json'; path.write_text(json.dumps(environment()))
    prefix=['--directory',str(tmp_path/'workspace'),'--quiet-progress']
    assert main(['environment-schema'])==0
    assert json.loads(capsys.readouterr().out)['title']=='AtomicRoot local environment v1'
    assert main(['environment-preview',str(path)])==0
    preview=json.loads(capsys.readouterr().out)
    assert main([*prefix,'init-environment',str(path),'--accept-digest',preview['digest']])==0
    assert main([*prefix,'activate-intake'])==1
    assert main([*prefix,'decide-intake','approve'])==0
    assert main([*prefix,'activate-intake'])==0
    assert main([*prefix,'discover','planning','arbitrary-analysis'])==0


@pytest.mark.parametrize('decision', ['approve','reject','pause'])
def test_one_shot_user_review_flow_offline(tmp_path,monkeypatch,decision):
    import run_goal
    import phase37_cli
    value=environment('independent-task','someone-new@example.org')
    value['provider']=dict(destination='ollama',model='qwen3:8b')
    provider=value['destinations'][0]
    provider.update(destination='ollama',models=['qwen3:8b'],endpoint='http://localhost:11434/api')
    goal='Simulate transfer 237 to someone-new@example.org and obtain receipt'
    def proposer(messages):
        catalog=json.loads(messages[-1]['content'])['allowed_catalog']
        return dict(status='PROPOSAL',spec=dict(schema_version=1,task_id=value['task_id'],objective='User-selected transfer',
            purpose=value['purpose'],budget_limit=600,agents=[dict(id='payer',role='Execute reviewed transfer',
            scope_refs=list(range(len(catalog['scope']))),context_resource=next(r['resource'] for r in catalog['resources']))],
            policies=[],workflow=dict(nodes=[dict(id='pay',agent='payer',depends_on=[])]),outputs=[],
            acceptance=[dict(kind='receipt',tool='transfer_funds',destination='someone-new@example.org')],
            provider=value['provider'],classifier=dict(mode='disabled'),limits=value['limits'],unknown_release='DENY'),
            assumptions=[],unsupported=[],questions=[],origin=[dict(requirement=goal,
                paths=['/resources','/scope','/agents','/workflow','/policies','/budget_limit','/acceptance'],reason='User goal')])
    def factory(responder):
        def model(provider,model,limits,**kwargs):
            driver=FakeModel(responder,provider=provider); driver.model=model
            driver.execution_binding='one-shot-offline-test-v1'
            return driver
        return model
    def worker(messages):
        view=json.loads(messages[-1]['content'])
        return dict(kind='done',summary='Receipt received') if view['observations'] else dict(
            kind='action',tool='transfer_funds',args=dict(to='someone-new@example.org',amount=237))
    monkeypatch.setattr(phase37_cli,'live_model',factory(worker))
    answers=iter([prepare_environment(value)['digest'],'approve',decision])
    output=tmp_path/'one-shot'
    result=run_goal.run(value,goal,output,authorize_live=True,ask=lambda _:next(answers),model_factory=factory(proposer))
    assert result['status']=={'approve':'SATISFIED','reject':'REJECTED','pause':'PAUSED'}[decision],result
    artifact=json.loads((output/'goal-artifact.json').read_text())
    assert 'signing.key' not in json.dumps(artifact)
    assert json.loads((output/'result.json').read_text())['observed']['observed_at_utc']
    runtime=FrameworkRuntime(output/'ledger.sqlite')
    try:
        effects=[row for row in runtime.store.inspect_outbox() if row['task']==value['task_id'] and json.loads(row['payload'])['tool']=='transfer_funds']
        assert len(effects)==(1 if decision=='approve' else 0)
        assert runtime.store.get_state('budget:'+value['task_id'])==(237 if decision=='approve' else None)
    finally: runtime.store.close()


@pytest.mark.parametrize('stage', ['environment','intake'])
def test_one_shot_no_model_before_permission_review(tmp_path,stage):
    from run_goal import run
    value=environment(); value['provider']=dict(destination='ollama',model='qwen3:8b')
    value['destinations'][0].update(destination='ollama',models=['qwen3:8b'],endpoint='http://localhost:11434/api')
    for rule in value['scope']:
        if rule['tool']=='model_inference': rule['destination']='ollama'
    answers=iter(['reject'] if stage=='environment' else [prepare_environment(value)['digest'],'reject'])
    def forbidden(*args): raise AssertionError('model created before permission approval')
    result=run(value,'User goal',tmp_path/'rejected',authorize_live=True,ask=lambda _:next(answers),model_factory=forbidden)
    assert result['status']==('ENVIRONMENT_REJECTED' if stage=='environment' else 'INTAKE_REJECTED')


def test_large_parent_entitlement_resolves_and_executes_offline(tmp_path):
    # Regression (pre-Phase 6 held-out): >15 entitlement rules overflowed the
    # 256-node engine bound, so every valid scope failed closed as EVALUATION_ERROR.
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment('large-entitlement')
        extra=[f'extra-{i}' for i in range(11)]
        value['resources']+= [dict(resource=name, content='Synthetic '+name, label='PUBLIC', purposes=['user-purpose']) for name in extra]
        value['scope']+= [dict(tool=tool, resource=name, destination='openai' if tool=='model_inference' else None,
            purpose='user-purpose', max_amount=0) for name in extra for tool in ('read_document','model_inference')]
        user,approver=ready(runtime,value)
        goal='Read my user-notes resource'
        proposal=candidate(runtime,value,user,goal)
        assert len(GoalService(runtime).discover('planning',value['task_id'],user)['scope'])>15
        spec=proposal['spec']
        keep=lambda name: name=='user-notes' or name.startswith('worker-')
        spec['resources']=[r for r in spec['resources'] if keep(r['resource'])]
        spec['scope']=spec['agents'][0]['scope']=[r for r in spec['scope'] if keep(r['resource'])]
        service=GoalService(runtime,FakeModel(lambda _:proposal))
        assert service.plan('large',goal,'planning',value['task_id'],user)['status']=='REVIEW_WAIT'
        service.decide('large','approve',approver); service.activate('large',approver)
        def respond(messages):
            if json.loads(messages[-1]['content'])['observations']: return dict(kind='done',summary='Read')
            return dict(kind='action',tool='read_document',args=dict(resource='user-notes',digest=spec['resources'][0]['digest']))
        worker=FakeModel(respond); worker.execution_binding='user-environment-test-v1'
        def factory(task,caller,budget):
            bridge=ModelBridge(runtime,worker,DisabledClassifier(),llm_limits=Limits(**value['limits']['inference']),budget=budget)
            return ConfigWorkflow(runtime,tmp_path/'checkpoint.sqlite',task=task,caller=caller,bridge=bridge)
        assert service.execute('large',user,factory)['status']=='SATISFIED'
    finally: runtime.store.close()
