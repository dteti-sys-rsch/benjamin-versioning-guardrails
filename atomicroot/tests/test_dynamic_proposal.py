from copy import deepcopy
import json

import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.dynamic_proposal_v4 import parse_dynamic_proposal, capability_catalog
from atomicroot.integration.goals import GoalService
from atomicroot.tests.test_user_environment import environment, ready, candidate


def proposal(runtime, value, user):
    goal='Perform user task'
    original=candidate(runtime,value,user,goal)
    for agent in original['spec']['agents']:
        agent['context_resource']=next(r['resource'] for r in original['spec']['resources'] if r.get('binding')=='host_context')
        agent['capabilities']=[r for r in agent.pop('scope') if r['resource']!=agent['context_resource']]
    original['spec'].pop('scope');original['spec'].pop('resources')
    return dict(schema_version=2,proposal=original,requirements=dict(required_outputs=[],required_reads=[],required_receipts=[],
        max_amount=None,allowed_recipients=None,external_release=True),permission_requests=[],capability_requests=[])


@pytest.mark.parametrize('recipient',[None,'dynamic@example.net'])
def test_named_capabilities_ignore_catalog_order_and_preserve_raw(tmp_path,recipient):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(recipient=recipient);user,_=ready(runtime,value)
        raw=proposal(runtime,value,user);before=deepcopy(raw)
        catalog=GoalService(runtime).discover('planning',value['task_id'],user)
        first=parse_dynamic_proposal(raw,value['task_id'],'Perform user task',catalog)
        catalog['scope'].reverse();catalog['resources'].reverse()
        second=parse_dynamic_proposal(raw,value['task_id'],'Perform user task',catalog)
        assert first==second and raw==before
        assert runtime.store.get_state('contract3:'+value['task_id']) is None
    finally:runtime.store.close()


def test_requirement_mismatch_and_scope_escalation_rejected(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(recipient='dynamic@example.net');user,_=ready(runtime,value)
        raw=proposal(runtime,value,user);catalog=GoalService(runtime).discover('planning',value['task_id'],user)
        raw['requirements']['required_outputs']=['result']
        with pytest.raises(ValueError,match='missing required acceptance'):
            parse_dynamic_proposal(raw,value['task_id'],'Perform user task',catalog)
        raw['requirements']['required_outputs']=[]
        raw['requirements']['max_amount']=137
        raw['proposal']['spec']['agents'][0]['capabilities'][0]['max_amount']=137
        result=parse_dynamic_proposal(raw,value['task_id'],'Perform user task',catalog)
        assert any(r['max_amount']==137 for r in result['proposal']['spec']['scope'])
        raw['proposal']['spec']['agents'][0]['capabilities'][0]['max_amount']=601
        with pytest.raises(ValueError,match='unavailable'):
            parse_dynamic_proposal(raw,value['task_id'],'Perform user task',catalog)
    finally:runtime.store.close()


def test_unregistered_tool_spec_is_blocked_not_executable(tmp_path):
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,_=ready(runtime,value);raw=proposal(runtime,value,user)
        raw['capability_requests']=[dict(name='new_adapter',purpose='User requested capability',input_schema={},output_schema={},
            effects='External effect',data_access=[],permissions=[],idempotency='Unverified',facts=[],updaters=[])]
        result=parse_dynamic_proposal(raw,value['task_id'],'Perform user task',{})
        assert result['status']=='NEEDS_CAPABILITY'
        assert not runtime.store.get_state('contract3:'+value['task_id'])
        assert runtime.store.inspect_outbox()==[]
    finally:runtime.store.close()


def test_registry_catalog_is_json_serializable():
    value=capability_catalog()
    assert json.loads(json.dumps(value))==value


def test_dynamic_service_review_activation_and_requirement_binding(tmp_path):
    from atomicroot.integration import dynamic_proposal_v4 as protocol
    from atomicroot.integration.providers import FakeModel
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment();user,approver=ready(runtime,value)
        raw=proposal(runtime,value,user)
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        planned=service.plan('dynamic','Perform user task','planning',value['task_id'],user)
        assert planned['status']=='REVIEW_WAIT',planned
        assert planned['prompt_version']==protocol.VERSION
        assert planned['dynamic_proposal']==raw
        assert runtime.store.get_state('goalrequirements:'+value['task_id']) is None
        service.decide('dynamic','approve',approver)
        service.activate('dynamic',approver)
        assert runtime.store.get_state('goalrequirements:'+value['task_id'])==raw['requirements']
        assert service.status('dynamic',user)['status']=='ACTIVE'
    finally:runtime.store.close()


@pytest.mark.parametrize('fault',[False,True])
def test_new_recipient_bundle_is_atomic_and_requires_operator(tmp_path,monkeypatch,fault):
    from atomicroot.integration import dynamic_proposal_v4 as protocol
    from atomicroot.integration.providers import FakeModel
    from atomicroot.framework.identity import Principal
    runtime=FrameworkRuntime(tmp_path/'ledger.sqlite')
    observer=FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value=environment(recipient='original@example.net');user,approver=ready(runtime,value)
        raw=proposal(runtime,value,user)
        raw['permission_requests']=[dict(kind='recipient',reference='new@example.net',reason='Explicit goal recipient')]
        for rule in raw['proposal']['spec']['agents'][0]['capabilities']:
            if rule['tool']=='transfer_funds':rule['destination']='new@example.net'
        raw['proposal']['spec']['acceptance'][0]['destination']='new@example.net'
        service=GoalService(runtime,FakeModel(lambda _:raw),protocol=protocol)
        result=service.plan('bundle','Perform user task','planning',value['task_id'],user)
        assert result['status']=='REVIEW_WAIT',result
        assert observer.store.get_state('destination:new@example.net') is None
        service.decide('bundle','approve',approver)
        with pytest.raises(PermissionError):service.activate('bundle',approver)
        assert observer.store.get_state('destination:new@example.net') is None
        operator=Principal(approver.subject,approver.roles|{'admin'},approver.tasks)
        original=runtime.contracts.activate_in_transaction
        if fault:
            def crash(*args):
                original(*args)
                raise RuntimeError('crash after contract write')
            monkeypatch.setattr(runtime.contracts,'activate_in_transaction',crash)
            with pytest.raises(RuntimeError,match='crash after contract'):service.activate('bundle',operator)
            assert observer.store.get_state('destination:new@example.net') is None
            assert observer.store.get_state('contract3:'+value['task_id']) is None
            assert service.status('bundle',user)['status']=='REVIEW_WAIT'
            monkeypatch.setattr(runtime.contracts,'activate_in_transaction',original)
        service.activate('bundle',operator)
        assert observer.store.get_state('destination:new@example.net')['kind']=='recipient'
        assert observer.store.get_state('contract3:'+value['task_id']) is not None
        assert service.status('bundle',user)['status']=='ACTIVE'
        assert runtime.store.inspect_outbox()[-1]['task']!=value['task_id']
    finally:observer.store.close();runtime.store.close()
