"""Versioned named-capability proposals; structural checks confer no authority.

v9 keeps the v8 wire, expansion and least-privilege check. In the v8 live batch
qwen3:8b selected update_document/send_email capabilities but left
required_receipts empty, so the check rejected them. v9 states the receipt shape
of every registered effect tool (generated from the registry, not per use case)
and names the exact requirement entry in the diagnostic. The check is unchanged:
an effect the requirements do not state is still rejected, never accepted.
"""
import json

from atomicroot.framework.registry import TOOLS
from atomicroot.framework.storage import dumps
from atomicroot.integration import dynamic_proposal_v7 as v7
from atomicroot.integration import dynamic_proposal_v8 as v8
from atomicroot.integration.dynamic_proposal_v8 import (REQUIREMENT_FIELDS, CAPABILITY_FIELDS, WIRE_VERSION,  # noqa: F401
    HOST_MANAGED, capability_catalog, validate_requirements, check_requirements, catalog_for_prompt, expand)

VERSION = 'dynamic-proposal-v9'
DYNAMIC = True
PLANNER_VERSION = VERSION
EFFECTS = [t for t in TOOLS.values() if t.name != 'read_document' and t.effect_class not in HOST_MANAGED]


def justify(spec, requirement):
    selections = [(agent.get('id'), s) for agent in spec['agents'] for s in agent['capabilities']]
    receipted = {s['resource'] for _, s in selections if 'read_receipt' in TOOLS[s['tool']].required and s['resource']}
    readable = set(requirement['required_reads']) | receipted
    for agent, selection in selections:
        tool = TOOLS[selection['tool']]
        where = f'/proposal/spec/agents/{agent}/capabilities: {tool.name}({selection["resource"] or selection["destination"]})'
        if tool.name == 'read_document' or tool.effect_class in HOST_MANAGED:
            if selection['resource'] not in readable:
                raise ValueError(f'{where} is not a stated read; if the goal needs it add "{selection["resource"]}" to '
                                 'requirements.required_reads, otherwise remove this capability')
        elif not any(r['tool'] == tool.name and r['destination'] == selection['destination'] for r in requirement['required_receipts']):
            entry = dumps(dict(tool=tool.name, destination=selection['destination']))
            release = ' and set requirements.external_release=true' if tool.external else ''
            raise ValueError(f'{where} is not a stated effect; if the goal requests it add {entry} to '
                             f'requirements.required_receipts{release}, otherwise remove this capability')


def parse_dynamic_proposal(value, task, goal, catalog, *, approved_requirements=None, permissions_resolved=False):
    return v8.parse_dynamic_proposal(value, task, goal, catalog, approved_requirements=approved_requirements,
                                     permissions_resolved=permissions_resolved, check=justify)


def parse_proposal(value, task, goal, catalog=None):
    resolved = parse_dynamic_proposal(value, task, goal, catalog)
    if resolved['status'] in {'NEEDS_PERMISSION', 'NEEDS_CAPABILITY'}: return resolved
    return resolved['proposal']


def proposal_schema():
    result = v8.proposal_schema()
    result['title'] = 'AtomicRoot dynamic proposal wire v3, planner v9'
    return result


def response_schema(messages=None):
    return v7.response_schema(messages, base=proposal_schema())


def _instruction():
    shapes = ', '.join(f'{t.name}: {{tool:{t.name},destination:{"<destination>" if t.external else "null"}}}' for t in EFFECTS)
    external = ', '.join(t.name for t in EFFECTS if t.external)
    text = v8.INSTRUCTION.replace('dynamic-proposal-v8', VERSION)
    for old, new in [
            ('required_receipts = [{tool,destination}] for each requested effect (send, transfer, update, deploy); never for reads or model inference. ',
             'required_receipts = one {tool,destination} per side effect the goal asks for, shaped as ' + shapes +
             '; never for reads or model inference. Every effect tool selected in spec needs its entry here. '),
            ('external_release = true only if the goal requests an external send/transfer/deploy. ',
             'external_release = true exactly when a required receipt uses an external tool (' + external + '). ')]:
        if old not in text: raise RuntimeError('v8 instruction changed; v9 derivation would be stale')
        text = text.replace(old, new)
    return text


INSTRUCTION = _instruction()


def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
    result = v8.messages(goal, task, catalog, previous=previous, error=error, draft=draft)
    context = json.loads(result[1]['content']); context['protocol'] = VERSION
    result[0] = dict(role='system', content=result[0]['content'].replace(v8.INSTRUCTION, INSTRUCTION, 1))
    result[1] = dict(role='user', content=dumps(context))
    return result

