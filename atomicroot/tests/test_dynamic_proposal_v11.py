"""Planner protocol v11: CLARIFY is a real question, recipients are grounded in the goal. Offline."""
from atomicroot.authority.ticket import args_hash
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration import dynamic_proposal_v11 as v11
from atomicroot.integration import dynamic_proposal_v10 as v10
from atomicroot.integration.goals import GoalService
from atomicroot.integration.planning import protocol_for_digest, protocol_for_version
from atomicroot.integration.providers import FakeModel
from atomicroot.tests.test_dynamic_planner import discover, wire
from atomicroot.tests.test_user_environment import environment, ready


def transfer(value, to, amount):
    return wire(value, [('transfer_funds', None, to)], required_receipts=[dict(tool='transfer_funds', destination=to)],
                max_amount=amount, allowed_recipients=[to], external_release=True)


def scripted(*responses):
    calls = []
    def respond(_):
        calls.append(1)
        return responses[min(len(calls), len(responses)) - 1]
    return FakeModel(respond), calls


def test_versions_are_distinct_and_v10_stays_replayable():
    assert v11.VERSION == 'dynamic-proposal-v11' and protocol_for_version('dynamic-proposal-v10') is v10
    assert protocol_for_version('dynamic-proposal-v11') is v11
    assert args_hash(v11.proposal_schema()) != args_hash(v10.proposal_schema())
    assert protocol_for_digest(args_hash(v11.proposal_schema())) is v11
    assert protocol_for_digest(args_hash(v10.proposal_schema())) is v10
    assert 'my manager' in v11.INSTRUCTION and 'op:"and"' in v11.INSTRUCTION and 'my manager' not in v10.INSTRUCTION


def test_clarify_without_question_is_rejected_even_with_permission_request(tmp_path):
    runtime = FrameworkRuntime(tmp_path / 'ledger.sqlite')
    try:
        value = environment(recipient='old@example.net'); user, _ = ready(runtime, value)
        goal = 'Transfer 40 (simulated) to new@example.net.'
        raw = transfer(value, 'new@example.net', 40)
        raw['permission_requests'] = [dict(kind='recipient', reference='new@example.net', reason='absent from catalog')]
        raw['proposal'].update(status='CLARIFY', spec=None, questions=[])
        catalog = discover(runtime, value, user)
        # v10 (frozen, replayable) accepted this shape as a stop; v11 asks for the reviewable bundle instead.
        assert v10.parse_dynamic_proposal(raw, value['task_id'], goal, catalog)['status'] == 'NEEDS_PERMISSION'
        model, calls = scripted(raw)
        planned = GoalService(runtime, model, protocol=v11).plan('s', goal, 'planning', value['task_id'], user)
        assert planned['status'] == 'INVALID_PROPOSAL' and len(calls) == 2
        assert all('CLARIFY requires at least one question' in e['error'] for e in planned['validation_errors'])
    finally: runtime.store.close()


def test_named_absent_recipient_reaches_the_reviewed_permission_bundle(tmp_path):
    runtime = FrameworkRuntime(tmp_path / 'ledger.sqlite')
    try:
        value = environment(recipient='old@example.net'); user, approver = ready(runtime, value)
        goal = 'Transfer 137 (simulated) to new@example.net.'
        raw = transfer(value, 'new@example.net', 137)
        raw['permission_requests'] = [dict(kind='recipient', reference='new@example.net', reason='Goal names this recipient')]
        service = GoalService(runtime, FakeModel(lambda _: raw), protocol=v11)
        assert service.plan('b', goal, 'planning', value['task_id'], user)['status'] == 'REVIEW_WAIT'
        assert runtime.store.get_state('destination:new@example.net') is None   # nothing granted before review
        service.decide('b', 'approve', approver)
        service.activate('b', Principal(approver.subject, approver.roles | {'admin'}, approver.tasks))
        assert runtime.store.get_state('destination:new@example.net')['kind'] == 'recipient'
    finally: runtime.store.close()


def test_role_described_recipient_must_clarify_and_clarification_grounds_it(tmp_path):
    runtime = FrameworkRuntime(tmp_path / 'ledger.sqlite')
    try:
        value = environment(recipient='old@example.net'); user, _ = ready(runtime, value)
        goal = 'Transfer 40 (simulated) to my manager.'
        guess = transfer(value, 'old@example.net', 40)
        ask = wire(value, [])
        ask['proposal'].update(status='CLARIFY', spec=None, questions=['What is the exact recipient address of your manager?'])
        model, calls = scripted(guess, ask)
        planned = GoalService(runtime, model, protocol=v11).plan('m', goal, 'planning', value['task_id'], user)
        assert planned['status'] == 'CLARIFY' and len(calls) == 2, planned
        assert 'is not named in the goal' in planned['validation_errors'][0]['error']
        catalog = discover(runtime, value, user)
        # The user's own clarification grounds the address; the same plan is then valid.
        grounded = dict(catalog, clarifications=['My manager is old@example.net'])
        assert v11.parse_dynamic_proposal(guess, value['task_id'], goal, grounded)['proposal']['status'] == 'PROPOSAL'
        assert v10.parse_dynamic_proposal(guess, value['task_id'], goal, catalog)['proposal']['status'] == 'PROPOSAL'
    finally: runtime.store.close()
