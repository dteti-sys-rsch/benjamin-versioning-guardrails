"""Planner protocol v12: every grammar-valid free-text string passes the byte validators. Offline."""
from copy import deepcopy

import pytest

from atomicroot.authority.ticket import args_hash
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration import dynamic_proposal as v12
from atomicroot.integration import dynamic_proposal_v11 as v11
from atomicroot.integration.planning import protocol_for_digest, protocol_for_version
from atomicroot.tests.test_dynamic_planner import discover, wire
from atomicroot.tests.test_user_environment import environment, ready

WORST = '\U0001F600'   # 4 UTF-8 bytes, the per-character maximum
GOAL = 'Read user-notes and write a summary as output result.'


def bound(schema, key, parent=None):
    found = []
    def walk(node, k=None, p=None):
        if isinstance(node, dict):
            if node.get('type') == 'string' and (k == key if parent is None else (k == 'items' and p == parent)):
                found.append(node.get('maxLength'))
            for kk, vv in node.items(): walk(vv, kk, k)
        elif isinstance(node, list):
            for vv in node: walk(vv, k, p)
    walk(schema)
    assert found and len(set(found)) == 1, (key, parent, found)
    return found[0]


def test_v12_is_registered_and_v11_stays_replayable():
    assert protocol_for_version('dynamic-proposal-v11') is v11 and protocol_for_version('dynamic-proposal-v12') is v12
    assert protocol_for_digest(args_hash(v12.proposal_schema())) is v12
    assert protocol_for_digest(args_hash(v11.proposal_schema())) is v11
    # Identifier fields keep the inherited bound; only free text is tightened.
    schema = v12.response_schema()
    assert bound(schema, 'items', 'allowed_recipients') == 256 and bound(schema, 'reference') == 256
    assert bound(v11.response_schema(), 'reason') == 256 and bound(schema, 'reason') == 64


@pytest.mark.parametrize('field', ['origin.reason', 'assumptions', 'role', 'questions', 'unsupported'])
def test_grammar_maximum_worst_case_text_is_accepted(tmp_path, field):
    runtime = FrameworkRuntime(tmp_path / 'ledger.sqlite')
    try:
        value = environment(); user, _ = ready(runtime, value); catalog = discover(runtime, value, user)
        schema = v12.response_schema()
        key, parent = {'origin.reason': ('reason', None), 'role': ('role', None)}.get(field, ('items', field))
        text = WORST * bound(schema, key, parent)
        assert len(text.encode('utf-8')) <= 256
        raw = wire(value, [('read_document', 'user-notes', None)], required_outputs=['result'], required_reads=['user-notes'])
        raw['proposal']['origin'] = [dict(requirement=GOAL, paths=['/agents'], reason='ok')]
        if field in {'questions', 'unsupported'}:
            raw['proposal'].update(status='CLARIFY' if field == 'questions' else 'UNSUPPORTED', spec=None, origin=[], **{field: [text]})
        elif field == 'origin.reason': raw['proposal']['origin'][0]['reason'] = text
        elif field == 'assumptions': raw['proposal']['assumptions'] = [text]
        else: raw['proposal']['spec']['agents'][0]['role'] = text
        v12.parse_dynamic_proposal(deepcopy(raw), value['task_id'], GOAL, catalog)
        if field == 'origin.reason':
            # The v11 failure: 256 characters allowed by its grammar, 260 bytes rejected by the validator.
            raw['proposal']['origin'][0]['reason'] = 'a' * 252 + 'é' * 4
            with pytest.raises(ValueError, match='bounded nonempty text'):
                v11.parse_dynamic_proposal(raw, value['task_id'], GOAL, catalog)
    finally: runtime.store.close()
