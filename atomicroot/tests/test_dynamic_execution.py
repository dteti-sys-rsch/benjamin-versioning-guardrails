"""Dynamic protocol integration uses real services with offline model responses.

These cases pin the archived v4 wire; current v5 coverage is test_dynamic_proposal_v5.
"""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json

import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration import dynamic_proposal_v4 as protocol
from atomicroot.integration.goals import GoalService
from atomicroot.integration.config_workflow import ConfigWorkflow
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.providers import FakeModel, DisabledClassifier, Limits
from atomicroot.tests.test_user_environment import environment, ready
from atomicroot.tests.test_dynamic_proposal import proposal


def test_new_resource_is_owner_bound_atomic_and_stale_bundle_rejected(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,approver=ready(runtime,value);raw=proposal(runtime,value,user)
        raw['permission_requests']=[dict(kind='resource',reference='new-source',reason='User selected new source')]
        for rule in raw['proposal']['spec']['agents'][0]['capabilities']:rule['resource']='new-source'
        raw['proposal']['spec']['acceptance']=[dict(kind='read',resource='new-source')]
        inputs={'new-source':dict(resource='new-source',content='User-supplied synthetic input',label='PUBLIC',purposes=[value['purpose']])}
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol,resource_inputs=inputs)
        result=service.plan('new-resource','Perform user task','planning',value['task_id'],user)
        assert result['status']=='REVIEW_WAIT',result
        assert runtime.store.get_state('document:new-source') is None
        service.decide('new-resource','approve',approver)
        with runtime.store.transaction() as conn:
            key='catalog:destinations';runtime.store.put(conn,key,runtime.store.value(conn,key)[1])
        operator=Principal(approver.subject,approver.roles|{'admin','owner'},approver.tasks,frozenset(inputs))
        with pytest.raises(ValueError,match='stale'):service.activate('new-resource',operator)
        assert runtime.store.get_state('document:new-source') is None
        # A fresh proposal/review, never rebasing an old grant.
        result=service.plan('new-resource','Perform user task','planning',value['task_id'],user,replan=True)
        assert result['status']=='REVIEW_WAIT',result
        service.decide('new-resource','approve',approver);service.activate('new-resource',operator)
        assert runtime.store.get_state('document:new-source')['content']==inputs['new-source']['content']
        assert runtime.store.get_state('label:new-source')['label']=='PUBLIC'
    finally:runtime.store.close()


def test_dynamic_replay_preserves_requirements_and_named_response(tmp_path):
    source=FrameworkRuntime(tmp_path/'source.sqlite');replay=FrameworkRuntime(tmp_path/'replay.sqlite')
    try:
        value=environment();user,approver=ready(source,value);other,_=ready(replay,value)
        raw=proposal(source,value,user)
        required=deepcopy(raw['requirements']);required['required_reads']=['user-notes'];raw['requirements']=required
        driver=FakeModel(lambda _:raw);service=GoalService(source,driver,protocol=protocol)
        assert service.plan('replay','Perform user task','planning',value['task_id'],user,requirements=required)['status']=='REVIEW_WAIT'
        artifact=service.export('replay',user)
        # Preserve original intake expiry; keys and protocol tickets remain new.
        GoalService(replay).register_intake(artifact['planning']['intake'],Principal('admin',frozenset({'admin'})))
        result=GoalService(replay).replay(artifact,other)
        assert result['match'] and result['result']['dynamic_proposal']==raw
        assert len(driver.calls)==1
    finally:source.store.close();replay.store.close()


def test_dynamic_parallel_workers_join_and_recover(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();value['max_agents']=3;value['limits']['max_in_flight']=2
        second=deepcopy(value['resources'][0]);second.update(resource='other-notes',content='Second synthetic source')
        value['resources'].append(second)
        for r in deepcopy(value['scope']):r['resource']='other-notes';value['scope'].append(r)
        user,approver=ready(runtime,value);raw=proposal(runtime,value,user)
        raw['proposal']['spec']['agents']=[]
        for name,resource in [('left','user-notes'),('right','other-notes'),('join',None)]:
            caps=[r for r in value['scope'] if r['resource']==resource]
            if resource is None:
                # Join has no business effects; an existing source inference capability is explicit.
                caps=[r for r in value['scope'] if r['tool']=='model_inference']
            raw['proposal']['spec']['agents'].append(dict(id=name,role='Process assigned source' if resource else 'Join verified observations',capabilities=caps))
        raw['proposal']['spec']['workflow']=dict(nodes=[dict(id='left',agent='left',depends_on=[]),
            dict(id='right',agent='right',depends_on=[]),dict(id='join',agent='join',depends_on=['left','right'])])
        raw['proposal']['spec'].update(outputs=[dict(id='result',kind='summary')],acceptance=[dict(kind='read',resource='user-notes'),
            dict(kind='read',resource='other-notes'),dict(kind='output',output='result')])
        raw['requirements'].update(required_outputs=['result'],required_reads=['user-notes','other-notes'])
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        result=service.plan('parallel','Perform user task','planning',value['task_id'],user)
        assert result['status']=='REVIEW_WAIT',result
        service.decide('parallel','approve',approver);service.activate('parallel',approver)
        barrier=Barrier(2);seen=[]
        refs={r['resource']:r for r in result['proposal']['spec']['resources']}
        def respond(messages):
            view=json.loads(messages[-1]['content']);node=view['node'];seen.append(node)
            if node in {'left','right'}:
                barrier.wait(timeout=15)
                resource='user-notes' if node=='left' else 'other-notes'
                return dict(kind='action',tool='read_document',args=dict(resource=resource,digest=refs[resource]['digest']))
            if any(o.get('status')=='OUTPUT_STORED' for o in view['observations']):return dict(kind='done',summary='Joined output stored')
            return dict(kind='output',output='result',content='Joined verified synthetic source observations')
        model=FakeModel(respond);model.execution_binding='parallel-dynamic-v2-test'
        def factory(task,caller,budget):
            bridge=ModelBridge(runtime,model,DisabledClassifier(),llm_limits=Limits(**value['limits']['inference']),budget=budget)
            return ConfigWorkflow(runtime,tmp_path/'checkpoint.sqlite',task=task,caller=caller,bridge=bridge)
        executed=service.execute('parallel',user,factory)
        assert executed['status']=='SATISFIED',executed
        assert seen[:2] in (['left','right'],['right','left']) and seen[-1]=='join'
        before=len(runtime.store.inspect_outbox());calls=len(model.calls)
        assert service.execute('parallel',user,factory,command='recover')['status']=='SATISFIED'
        assert len(runtime.store.inspect_outbox())==before and len(model.calls)==calls
    finally:runtime.store.close()


def test_dynamic_two_initial_allow_cas_and_unrelated_key(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    second=FrameworkRuntime(tmp_path/'ledger.sqlite',signing_key=runtime.authority._sk)
    try:
        value=environment(recipient='budget@example.net');value['max_agents']=2;value['limits']['max_in_flight']=2
        user,approver=ready(runtime,value);raw=proposal(runtime,value,user)
        first=raw['proposal']['spec']['agents'][0];first.pop('context_resource')
        first['capabilities']=[r for r in first['capabilities'] if r['tool']=='transfer_funds']
        other=deepcopy(first);other['id']='second-payer';raw['proposal']['spec']['agents'].append(other)
        raw['proposal']['spec']['workflow']['nodes'].append(dict(id='other-payment',agent='second-payer',depends_on=[]))
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        assert service.plan('race','Perform user task','planning',value['task_id'],user)['status']=='REVIEW_WAIT'
        service.decide('race','approve',approver);service.activate('race',approver)
        actors=[runtime.tasks.principal(value['task_id'],name,user) for name in (first['id'],other['id'])]
        barrier=Barrier(2)
        def authorize(index):
            request=dict(task_id=value['task_id'],agent_id=actors[index].subject,operation_id='payment-'+str(index),
                tool='transfer_funds',purpose=value['purpose'],args=dict(to='budget@example.net',amount=400))
            result=(runtime if index==0 else second).authority.authorize(request,actors[index])
            barrier.wait(timeout=10)
            return result
        with ThreadPoolExecutor(2) as pool:auth=list(pool.map(authorize,[0,1]))
        assert [r['decision'] for r in auth]==['ALLOW','ALLOW']
        owner=Principal('owner',frozenset({'owner'}),resources=frozenset({'unrelated'}))
        runtime.storage.ingest('unrelated','Independent mutation',owner)
        first_result=runtime.gateway.commit(auth[0]['ticket'],auth[0]['commit_args'],actors[0])
        stale=second.gateway.commit(auth[1]['ticket'],auth[1]['commit_args'],actors[1])
        assert first_result['status']=='COMMITTED'
        assert stale['status']=='STALE_TICKET',stale
        assert runtime.store.get_state('reserved:'+value['task_id'])==400
        assert len([r for r in runtime.store.inspect_outbox() if r['task']==value['task_id']])==1
    finally:second.store.close();runtime.store.close()


def test_tool_spec_approval_never_activates_executable(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,approver=ready(runtime,value);raw=proposal(runtime,value,user)
        raw['capability_requests']=[dict(name='whatsapp',purpose='Requested delivery',input_schema={},output_schema={},
            effects='Message delivery',data_access=['recipient','body'],permissions=['send'],idempotency='Not verified',facts=[],updaters=[])]
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        assert service.plan('tool','Perform user task','planning',value['task_id'],user)['status']=='NEEDS_CAPABILITY'
        result=service.decide('tool','approve',approver)
        assert result['execution_authorized'] is False
        with pytest.raises(ValueError):service.activate('tool',approver)
        assert service.status('tool',user)['status']=='NEEDS_CAPABILITY'
        assert runtime.store.get_state('contract3:'+value['task_id']) is None
    finally:runtime.store.close()


def test_workspace_bootstrap_rolls_back_and_can_retry_without_reset(tmp_path,monkeypatch):
    from atomicroot.integration.environment import initialize_environment,prepare_environment
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();digest=prepare_environment(value)['digest']
        original=runtime.labels.set_label
        def crash(*args,**kwargs):raise RuntimeError('bootstrap fault')
        monkeypatch.setattr(runtime.labels,'set_label',crash)
        with pytest.raises(RuntimeError,match='bootstrap fault'):initialize_environment(runtime,value,digest)
        with runtime.store.snapshot() as snap:assert snap._conn.execute('SELECT count(*) FROM conflict_keys').fetchone()[0]==0
        assert runtime.store.inspect_outbox()==[]
        monkeypatch.setattr(runtime.labels,'set_label',original)
        assert initialize_environment(runtime,value,digest)['status']=='INTAKE_REVIEW_WAIT'
        with pytest.raises(ValueError):initialize_environment(runtime,value,digest)
    finally:runtime.store.close()


def test_pure_output_requires_only_allocated_host_capability(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,_=ready(runtime,value);raw=proposal(runtime,value,user)
        agent=raw['proposal']['spec']['agents'][0];agent.pop('context_resource');agent['capabilities']=[]
        raw['proposal']['spec'].update(outputs=[dict(id='result',kind='artifact')],acceptance=[dict(kind='output',output='result')])
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        result=service.plan('output','Perform user task','planning',value['task_id'],user)
        assert result['status']=='REVIEW_WAIT',result
        assert [r['tool'] for r in result['proposal']['spec']['scope']]==['model_inference']
    finally:runtime.store.close()


def test_large_failed_candidate_has_explicit_bounded_context_terminal(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,_=ready(runtime,value);raw=proposal(runtime,value,user)
        # Invalid registered capability requests are recorded, then repaired only within the context bound.
        raw['capability_requests']=[dict(name='read_document',purpose='x'*256,input_schema={},output_schema={},effects='x'*256,
            data_access=['x'*256]*16,permissions=[],idempotency='x'*256,facts=[],updaters=[]) for _ in range(2)]
        model=FakeModel(lambda _:raw);service=GoalService(runtime,model,protocol=protocol)
        result=service.plan('bounded','Perform user task','planning',value['task_id'],user)
        assert result['status']=='CONTEXT_LIMIT',result
        assert len(model.calls)==1
        assert runtime.store.get_state('contract3:'+value['task_id']) is None
    finally:runtime.store.close()


def test_output_only_workspace_has_valid_contextual_purpose_schema():
    from atomicroot.integration.workspace import task_environment
    from atomicroot.integration.environment import prepare_environment
    value=environment();workspace={k:v for k,v in value.items() if k not in {'task_id','scope'}}
    workspace.update(schema_version=2,resources=[],enabled_tools=['model_inference'])
    first=task_environment(workspace,'Write a poem');second=task_environment(workspace,'Draft a checklist')
    assert first['scope']==second['scope']==[] and first['task_id']!=second['task_id']
    prepared=prepare_environment(first)
    scope=prepared['catalog']['entitlements'][0]['rights']['scope']
    catalog=dict(scope=scope,resources=[],host_contexts=[r['resource'] for r in scope],destinations=workspace['destinations'],
        max_agents=1,budget_limit=0,planning_constraints=dict(limits=first['limits']['inference']))
    schema=protocol.response_schema(protocol.messages('Write a poem',first['task_id'],catalog))
    assert schema['$defs']['planner_spec']['properties']['purpose']=={'enum':[first['purpose']]}


def test_bundle_preserves_model_narrower_existing_scope(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(recipient='existing@example.net');user,approver=ready(runtime,value);raw=proposal(runtime,value,user)
        agent=raw['proposal']['spec']['agents'][0]
        old=next(r for r in agent['capabilities'] if r['tool']=='transfer_funds');old['max_amount']=137
        added=deepcopy(old);added.update(destination='new@example.net',max_amount=200)
        agent['capabilities'].append(added)
        raw['permission_requests']=[dict(kind='recipient',reference='new@example.net',reason='User requested new destination')]
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        result=service.plan('mixed','Perform user task','planning',value['task_id'],user)
        assert result['status']=='REVIEW_WAIT',result
        service.decide('mixed','approve',approver)
        service.activate('mixed',Principal(approver.subject,approver.roles|{'admin'},approver.tasks))
        actor=runtime.tasks.principal(value['task_id'],agent['id'],user)
        denied=runtime.authority.authorize(dict(task_id=value['task_id'],agent_id=actor.subject,operation_id='too-much',
            tool='transfer_funds',purpose=value['purpose'],args=dict(to='existing@example.net',amount=138)),actor)
        assert denied['decision']=='DENY'
        scope=runtime.tasks.status(value['task_id'],user)['resolved']['spec']['scope']
        assert next(r['max_amount'] for r in scope if r['destination']=='existing@example.net')==137
    finally:runtime.store.close()
