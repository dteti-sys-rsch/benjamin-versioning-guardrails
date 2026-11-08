"""Current dynamic planner protocol (v8 on wire v3): one requirement statement, selections
expanded to run-time dependencies, least privilege, real services, offline models."""
from copy import deepcopy
from pathlib import Path
from threading import Barrier
import json

import pytest

from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.framework.storage import dumps
from atomicroot.integration import dynamic_proposal as protocol
from atomicroot.integration.config_workflow import ConfigWorkflow
from atomicroot.integration.goals import GoalService
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.providers import FakeModel, DisabledClassifier, Limits
from atomicroot.tests.test_user_environment import environment, ready

GOAL = 'Perform user task'
WORKSPACE = Path(__file__).parents[2]/'examples/workspace/workspace-v2.json'


def discover(runtime, value, user):
    return GoalService(runtime, protocol=protocol).discover('planning', value['task_id'], user)


def wire(value, caps, **requirements):
    requirement = dict(required_outputs=[], required_reads=[], required_receipts=[], max_amount=None,
                       allowed_recipients=None, external_release=False)
    requirement.update(requirements)
    spec = dict(agents=[dict(id='worker', role='Perform reviewed work', capabilities=[
                    dict(tool=t, resource=r, destination=d, purpose=value['purpose']) for t, r, d in caps])],
                workflow=dict(nodes=[dict(id='work', agent='worker', depends_on=[])]), policies=[],
                budget_limit=value['budget_limit'], provider=value['provider'])
    return dict(schema_version=3, requirements=requirement, capability_requests=[], permission_requests=[],
                proposal=dict(assumptions=[], unsupported=[], questions=[], status='PROPOSAL', spec=spec))


def tools(spec):
    """Business/source scope; host context buffers are runtime-allocated."""
    hosts = {r['resource'] for r in spec['resources'] if r.get('binding') == 'host_context'}
    return sorted((r['tool'], r['resource'], r['destination'], r['max_amount']) for r in spec['scope'] if r['resource'] not in hosts)


def workspace(goal, **changes):
    from atomicroot.integration.workspace import task_environment
    value = json.loads(WORKSPACE.read_text(encoding='utf-8')); value.update(changes)
    return task_environment(value, goal)


def test_read_expands_to_source_inference_and_derives_acceptance(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); user, _ = ready(runtime, value)
        raw = wire(value, [('read_document', 'user-notes', None)], required_outputs=['result'], required_reads=['user-notes'])
        before = deepcopy(raw); catalog = discover(runtime, value, user)
        first = protocol.parse_dynamic_proposal(raw, value['task_id'], GOAL, catalog)
        catalog['scope'].reverse(); catalog['resources'].reverse()
        assert protocol.parse_dynamic_proposal(raw, value['task_id'], GOAL, catalog) == first and raw == before
        spec = first['proposal']['spec']
        assert ('model_inference', 'user-notes', 'openai', 0) in tools(spec) and ('read_document', 'user-notes', None, 0) in tools(spec)
        assert spec['outputs'] == [dict(id='result', kind='artifact')]
        assert spec['acceptance'] == [dict(kind='output', output='result'), dict(kind='read', resource='user-notes')]
        assert spec['limits']['inference']['max_calls'] == catalog['limits']['max_calls']
        assert runtime.store.get_state('contract3:' + value['task_id']) is None
    finally: runtime.store.close()


def test_diagnostics_and_least_privilege_never_edit_the_plan(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); user, _ = ready(runtime, value)
        catalog = discover(runtime, value, user)
        def rejects(raw, message):
            with pytest.raises(ValueError, match=message): protocol.parse_dynamic_proposal(raw, value['task_id'], GOAL, catalog)
        rejects(wire(value, [], required_reads=['user-notes']), 'read_document.*select catalog rule')
        rejects(wire(value, [('read_document', 'missing-notes', None)], required_reads=['missing-notes']), 'unavailable')
        rejects(wire(value, [('send_whatsapp', None, '+62')]), 'not registered; specify it in capability_requests')
        rejects(wire(value, [('read_document', 'user-notes', None)]), 'not a stated read; if the goal needs it add "user-notes"')
        for tool, message in [('send_whatsapp', 'capability_requests'), ('read_document', 'required_reads'),
                              ('model_inference', 'host-managed')]:
            rejects(wire(value, [], required_receipts=[dict(tool=tool, destination=None)]), message)
        raw = wire(value, [('read_document', 'user-notes', None)], required_reads=['user-notes'])
        raw['proposal']['spec']['agents'][0]['capabilities'][0]['max_amount'] = 0
        rejects(raw, 'unknown or missing fields')
    finally: runtime.store.close()


def test_spending_ceiling_comes_from_requirement(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(recipient='pay@example.net'); user, _ = ready(runtime, value)
        catalog = discover(runtime, value, user)
        receipt = [dict(tool='transfer_funds', destination='pay@example.net')]
        def raw(**changes):
            return wire(value, [('transfer_funds', None, 'pay@example.net')], **{**dict(required_receipts=receipt,
                max_amount=137, allowed_recipients=['pay@example.net'], external_release=True), **changes})
        spec = protocol.parse_dynamic_proposal(raw(), value['task_id'], GOAL, catalog)['proposal']['spec']
        assert tools(spec) == [('transfer_funds', None, 'pay@example.net', 137)] and spec['outputs'] == []
        with pytest.raises(ValueError, match='state the single-operation ceiling'):
            protocol.parse_dynamic_proposal(raw(max_amount=None), value['task_id'], GOAL, catalog)
        with pytest.raises(ValueError, match='prohibits external'):
            protocol.parse_dynamic_proposal(raw(external_release=False), value['task_id'], GOAL, catalog)
        low = raw(); low['proposal']['spec']['budget_limit'] = 100
        with pytest.raises(ValueError, match='below requirements.max_amount'):
            protocol.parse_dynamic_proposal(low, value['task_id'], GOAL, catalog)
        with pytest.raises(ValueError, match=r'not a stated effect; if the goal requests it add \{"destination":"pay@example.net","tool":"transfer_funds"\}'
                                             r' to requirements.required_receipts and set requirements.external_release=true'):
            protocol.parse_dynamic_proposal(raw(required_receipts=[]), value['task_id'], GOAL, catalog)
        system = protocol.messages(GOAL, value['task_id'], catalog)[0]['content']
        assert 'update_document: {tool:update_document,destination:null}' in system
        assert 'send_email: {tool:send_email,destination:<destination>}' in system
    finally: runtime.store.close()


def test_update_expands_to_its_required_read(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment()
        value['scope'].append(dict(tool='update_document', resource='user-notes', destination=None, purpose=value['purpose'], max_amount=0))
        user, _ = ready(runtime, value)
        raw = wire(value, [('update_document', 'user-notes', None)], required_receipts=[dict(tool='update_document', destination=None)])
        service = GoalService(runtime, FakeModel(lambda _: raw), protocol=protocol)
        planned = service.plan('update', GOAL, 'planning', value['task_id'], user)
        assert planned['status'] == 'REVIEW_WAIT', planned
        assert [t[:2] for t in tools(planned['proposal']['spec'])] == [
            ('model_inference', 'user-notes'), ('read_document', 'user-notes'), ('update_document', 'user-notes')]
    finally: runtime.store.close()


def test_send_email_use_case_from_workspace_without_code_change(tmp_path):
    goal = 'Read notes-a and email a short summary to research@example.net.'
    value = workspace(goal, enabled_tools=['read_document', 'send_email', 'model_inference'])
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        user, _ = ready(runtime, value)
        raw = wire(value, [('read_document', 'notes-a', None), ('send_email', None, 'research@example.net')],
                   required_reads=['notes-a'], required_receipts=[dict(tool='send_email', destination='research@example.net')],
                   allowed_recipients=['research@example.net'], external_release=True)
        raw['proposal']['spec']['provider'] = dict(destination='ollama', model='qwen3:8b')
        planner = FakeModel(lambda _: raw, provider='ollama'); planner.model = 'qwen3:8b'
        planned = GoalService(runtime, planner, protocol=protocol).plan('email', goal, 'planning', value['task_id'], user)
        assert planned['status'] == 'REVIEW_WAIT', planned
        assert dict(kind='receipt', tool='send_email', destination='research@example.net') in planned['proposal']['spec']['acceptance']
    finally: runtime.store.close()


def test_parallel_join_receives_derived_source_inference_and_executes(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); value['max_agents'] = 3; value['limits']['max_in_flight'] = 2
        second = deepcopy(value['resources'][0]); second.update(resource='other-notes', content='Second synthetic source')
        value['resources'].append(second)
        for r in deepcopy(value['scope']): r['resource'] = 'other-notes'; value['scope'].append(r)
        user, approver = ready(runtime, value)
        raw = wire(value, [], required_outputs=['result'], required_reads=['user-notes', 'other-notes'])
        spec = raw['proposal']['spec']
        spec['agents'] = [dict(id='left', role='Read first source', capabilities=[dict(tool='read_document', resource='user-notes', destination=None, purpose=value['purpose'])]),
                          dict(id='right', role='Read second source', capabilities=[dict(tool='read_document', resource='other-notes', destination=None, purpose=value['purpose'])]),
                          dict(id='join', role='Join observations', capabilities=[])]
        spec['workflow'] = dict(nodes=[dict(id='left', agent='left', depends_on=[]), dict(id='right', agent='right', depends_on=[]),
                                       dict(id='join', agent='join', depends_on=['left', 'right'])])
        service = GoalService(runtime, FakeModel(lambda _: raw), protocol=protocol)
        result = service.plan('parallel', GOAL, 'planning', value['task_id'], user)
        assert result['status'] == 'REVIEW_WAIT', result
        join = next(a for a in result['proposal']['spec']['agents'] if a['id'] == 'join')
        assert sorted(r['resource'] for r in join['scope'] if r['tool'] == 'model_inference' and not r['resource'].startswith('worker-')) == ['other-notes', 'user-notes']
        service.decide('parallel', 'approve', approver); service.activate('parallel', approver)
        barrier = Barrier(2); seen = []
        refs = {r['resource']: r for r in result['proposal']['spec']['resources']}
        def respond(messages):
            view = json.loads(messages[-1]['content']); node = view['node']; seen.append(node)
            if node in {'left', 'right'}:
                barrier.wait(timeout=15)
                resource = 'user-notes' if node == 'left' else 'other-notes'
                return dict(kind='action', tool='read_document', args=dict(resource=resource, digest=refs[resource]['digest']))
            if any(o.get('status') == 'OUTPUT_STORED' for o in view['observations']): return dict(kind='done', summary='Joined')
            return dict(kind='output', output='result', content='Joined synthetic observations')
        model = FakeModel(respond); model.execution_binding = 'parallel-dynamic-v8-test'
        def factory(task, caller, budget):
            bridge = ModelBridge(runtime, model, DisabledClassifier(), llm_limits=Limits(**value['limits']['inference']), budget=budget)
            return ConfigWorkflow(runtime, tmp_path/'checkpoint.sqlite', task=task, caller=caller, bridge=bridge)
        assert service.execute('parallel', user, factory)['status'] == 'SATISFIED'
        assert seen[:2] in (['left', 'right'], ['right', 'left']) and seen[-1] == 'join'
    finally: runtime.store.close()


def test_plan_review_activate_execute_recover_and_replay(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite'); replay = FrameworkRuntime(tmp_path/'replay.sqlite')
    try:
        value = environment(); user, approver = ready(runtime, value); other, _ = ready(replay, value)
        raw = wire(value, [('read_document', 'user-notes', None)], required_outputs=['result'], required_reads=['user-notes'])
        planner = FakeModel(lambda _: raw)
        service = GoalService(runtime, planner, protocol=protocol)
        planned = service.plan('goal', GOAL, 'planning', value['task_id'], user)
        assert planned['status'] == 'REVIEW_WAIT', planned
        assert planned['prompt_version'] == protocol.VERSION and planned['dynamic_proposal'] == raw
        artifact = service.export('goal', user)
        service.decide('goal', 'approve', approver); service.activate('goal', approver)
        assert runtime.store.get_state('goalrequirements:' + value['task_id']) == raw['requirements']
        ref = next(r for r in planned['proposal']['spec']['resources'] if r['resource'] == 'user-notes')
        def respond(messages):
            observations = json.loads(messages[-1]['content'])['observations']
            if not observations: return dict(kind='action', tool='read_document', args=dict(resource='user-notes', digest=ref['digest']))
            if any(o.get('status') == 'OUTPUT_STORED' for o in observations): return dict(kind='done', summary='Output stored')
            return dict(kind='output', output='result', content='Synthetic summary of user notes')
        worker = FakeModel(respond); worker.execution_binding = 'dynamic-v8-test'
        def factory(task, caller, budget):
            bridge = ModelBridge(runtime, worker, DisabledClassifier(), llm_limits=Limits(**value['limits']['inference']), budget=budget)
            return ConfigWorkflow(runtime, tmp_path/'checkpoint.sqlite', task=task, caller=caller, bridge=bridge)
        assert service.execute('goal', user, factory)['status'] == 'SATISFIED'
        outbox, calls = len(runtime.store.inspect_outbox()), len(worker.calls)
        assert service.execute('goal', user, factory, command='recover')['status'] == 'SATISFIED'
        assert len(runtime.store.inspect_outbox()) == outbox and len(worker.calls) == calls
        GoalService(replay).register_intake(artifact['planning']['intake'], Principal('admin', frozenset({'admin'})))
        result = GoalService(replay).replay(artifact, other)
        assert result['match'] and result['result']['dynamic_proposal'] == raw and len(planner.calls) == 1
    finally: runtime.store.close(); replay.store.close()


def test_repair_turn_fits_context_bound_and_provider_grammar(tmp_path):
    goal = 'Read notes-a and produce a short summary as output result.'
    value = workspace(goal)
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        user, _ = ready(runtime, value)
        raw = wire(value, [('read_document', 'notes-a', None)], required_outputs=['result'], required_reads=['notes-a'])
        raw['proposal']['spec']['policies'] = [dict(policy_id='no-spend', version=1, scope='task', applies_to=['read_document'],
            when=dict(op='const', value=True), constraint=dict(op='le', left=dict(op='amount'), right=dict(op='const', value=0)),
            on_violation='DENY')]
        invalid = deepcopy(raw)
        invalid['proposal']['spec']['agents'][0]['capabilities'].append(dict(tool='read_document', resource='notes-b', destination=None, purpose='research'))
        responses = [invalid, raw]
        planner = FakeModel(lambda _: responses.pop(0), provider='ollama'); planner.model = 'qwen3:8b'
        result = GoalService(runtime, planner, protocol=protocol).plan('repair', goal, 'planning', value['task_id'], user)
        assert result['status'] == 'REVIEW_WAIT', result
        assert len(planner.calls) == 2 and 'required_reads' in result['validation_errors'][0]['error'], result['validation_errors']
        system, context, diagnostic = planner.calls[1]
        repair = json.loads(diagnostic['content'])
        assert diagnostic['role'] == 'user' and repair['invalid_draft'] == invalid and 'required_reads' in repair['validation_error']
        assert json.loads(context['content'])['protocol'] == protocol.VERSION and planner.calls[0] == [system, context]
        assert len(dumps(planner.calls[1]).encode('utf-8')) < 8192
        from atomicroot.integration.planning import planner_response_schema
        schema = planner_response_schema(planner.calls[1])['$defs']['planner_spec']['properties']
        assert schema['provider'] == {'oneOf': [{'type': 'null'}, dict(type='object', additionalProperties=False, required=['destination', 'model'],
            properties=dict(destination={'const': 'ollama'}, model={'enum': ['qwen3:8b']}))]}
        assert all('max_amount' not in v['properties'] for v in schema['agents']['items']['properties']['capabilities']['items']['oneOf'])
    finally: runtime.store.close()


def test_registered_tool_in_capability_requests_points_to_agent_capability(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); user, _ = ready(runtime, value)
        raw = wire(value, [('read_document', 'user-notes', None)], required_reads=['user-notes'])
        raw['capability_requests'] = [dict(name='read_document', purpose='Read notes', input_schema={}, output_schema={},
            effects='read', data_access=[], permissions=[], idempotency='n/a', facts=[], updaters=[])]
        with pytest.raises(ValueError, match='already registered; remove it.*agents'):
            protocol.parse_dynamic_proposal(raw, value['task_id'], GOAL, discover(runtime, value, user))
        order = protocol.proposal_schema()['$defs']['dynamic_proposal']['required']
        assert order[-1] == 'capability_requests' and order.index('requirements') < order.index('proposal')
    finally: runtime.store.close()


def test_missing_adapter_is_needs_capability_without_contract(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); user, approver = ready(runtime, value)
        raw = wire(value, [], required_receipts=[dict(tool='send_whatsapp', destination='+620000')], external_release=True)
        raw['capability_requests'] = [dict(name='send_whatsapp', purpose='Mandatory WhatsApp delivery', input_schema={},
            output_schema={}, effects='External message', data_access=['body'], permissions=['send'], idempotency='Unverified',
            facts=[], updaters=[])]
        raw['proposal'].update(status='UNSUPPORTED', spec=None, unsupported=['send_whatsapp adapter is not registered'])
        service = GoalService(runtime, FakeModel(lambda _: raw), protocol=protocol)
        assert service.plan('tool', GOAL, 'planning', value['task_id'], user)['status'] == 'NEEDS_CAPABILITY'
        assert service.decide('tool', 'approve', approver)['execution_authorized'] is False
        assert runtime.store.get_state('contract3:' + value['task_id']) is None
    finally: runtime.store.close()


def test_stopped_proposal_with_permission_request_is_a_stop_not_a_crash(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(); user, _ = ready(runtime, value)
        raw = wire(value, [])
        raw['permission_requests'] = [dict(kind='recipient', reference='whatsapp@example.com', reason='Live v9b response shape')]
        raw['proposal'].update(status='CLARIFY', spec=None, questions=['Which delivery channel is registered?'])
        model = FakeModel(lambda _: raw)
        planned = GoalService(runtime, model, protocol=protocol).plan('stop', GOAL, 'planning', value['task_id'], user)
        assert planned['status'] == 'NEEDS_PERMISSION' and 'validation_errors' not in planned, planned
        assert len(model.calls) == 1 and runtime.store.get_state('destination:whatsapp@example.com') is None
    finally: runtime.store.close()


def test_new_recipient_bundle_binds_expanded_rules(tmp_path):
    runtime = FrameworkRuntime(tmp_path/'ledger.sqlite')
    try:
        value = environment(recipient='old@example.net'); user, approver = ready(runtime, value)
        raw = wire(value, [('transfer_funds', None, 'new@example.net')], required_receipts=[dict(tool='transfer_funds', destination='new@example.net')],
                   max_amount=137, allowed_recipients=['new@example.net'], external_release=True)
        raw['permission_requests'] = [dict(kind='recipient', reference='new@example.net', reason='Goal names this recipient')]
        service = GoalService(runtime, FakeModel(lambda _: raw), protocol=protocol)
        assert service.plan('bundle', GOAL, 'planning', value['task_id'], user)['status'] == 'REVIEW_WAIT'
        assert runtime.store.get_state('destination:new@example.net') is None
        service.decide('bundle', 'approve', approver)
        service.activate('bundle', Principal(approver.subject, approver.roles | {'admin'}, approver.tasks))
        assert runtime.store.get_state('destination:new@example.net')['kind'] == 'recipient'
        scope = runtime.tasks.status(value['task_id'], user)['resolved']['spec']['scope']
        assert [r['max_amount'] for r in scope if r['tool'] == 'transfer_funds'] == [137]
        assert service.status('bundle', user)['status'] == 'ACTIVE'
    finally: runtime.store.close()
