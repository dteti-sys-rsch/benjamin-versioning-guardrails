"""Versioned named-capability proposals; structural checks confer no authority.

v7 keeps the v6 wire, ordering and lowering. Two changes follow the v6 live
batch: (1) the grammar restricts `provider` to provider destinations/models in
the discovered catalog (qwen3:8b chose a payment recipient as its provider);
(2) repair is a separate user turn quoting the draft and diagnostic, instead
of fields inside the context JSON, where qwen3:8b at temperature 0 returned an
identical draft. messages[1] stays the bound planning context.
"""
import json

from atomicroot.framework.storage import dumps
from atomicroot.integration import dynamic_proposal_v5 as v5
from atomicroot.integration import dynamic_proposal_v6 as v6
from atomicroot.integration.dynamic_proposal_v6 import (REQUIREMENT_FIELDS, CAPABILITY_FIELDS, WIRE_VERSION,  # noqa: F401
    capability_catalog, validate_requirements, check_requirements, catalog_for_prompt, lower,
    parse_dynamic_proposal, parse_proposal)

VERSION = 'dynamic-proposal-v7'
DYNAMIC = True
PLANNER_VERSION = VERSION


def proposal_schema():
    result = v6.proposal_schema()
    result['title'] = 'AtomicRoot dynamic proposal wire v3, planner v7'
    return result


def response_schema(messages=None, *, base=None):
    result = v5.response_schema(messages[:2] if messages is not None else None, base=base or proposal_schema())
    if messages is not None:
        catalog = json.loads(messages[1]['content'])['allowed_catalog']
        providers = [dict(type='object', additionalProperties=False, required=['destination', 'model'],
                          properties=dict(destination={'const': d['destination']}, model={'enum': d['models']}))
                     for d in catalog['destinations'] if d['kind'] == 'provider' and d['models']]
        result['$defs']['planner_spec']['properties']['provider'] = {'oneOf': [{'type': 'null'}, *providers]}
    return result


def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
    base = v6.messages(goal, task, catalog, previous=previous)
    instruction = base[0]['content'].replace('dynamic-proposal-v6', VERSION).replace(
        'If validation_error is present, return a corrected complete envelope. ', '')
    context = json.loads(base[1]['content']); context['protocol'] = VERSION
    result = [dict(role='system', content=instruction), dict(role='user', content=dumps(context))]
    # Egress admits only system/user roles; the draft is quoted data in the repair turn.
    if error or draft:
        result.append(dict(role='user', content=dumps(dict(invalid_draft=draft, validation_error=error,
            instruction='Your previous envelope (invalid_draft) failed validation. Change what validation_error names, '
                        'keep every requirement, and return the corrected complete envelope.'))))
    return result
