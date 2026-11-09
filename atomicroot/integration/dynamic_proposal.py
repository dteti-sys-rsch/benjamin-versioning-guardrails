"""Versioned named-capability proposals; structural checks confer no authority.

v11 builds on v10. Each change answers a failure observed in the pre-Phase-6 runs
(docs/REPORTS/PRE_PHASE6_READINESS_REPORT.md §6-§9); none grants authority:

1. CLARIFY is a real question to the user. v10 accepted CLARIFY with no question when
   permission_requests were present, so a goal naming a recipient absent from the
   catalog stopped at NEEDS_PERMISSION with no reviewable plan (h-permission-base 3/3).
   v11 requires >= 1 question for every CLARIFY and tells the planner that a missing,
   explicitly named recipient/resource is a PROPOSAL with spec plus permission_requests
   (the existing reviewed permission-bundle path), not CLARIFY.
2. External-effect recipients must be grounded in the user's own words. Every
   destination in requirements.required_receipts for send_email/transfer_funds/deploy
   must appear in the goal or in user clarifications. This is a host check, not model
   judgement: a role such as "my manager" can no longer be mapped to a catalog address
   (a-ambiguous-recipient delivered such a guess under blind review). It only rejects.
3. The policy example shows a conjunctive constraint (amount and recipient), because
   the v10 example showed only an amount ceiling and multi-predicate rules lost the
   recipient predicate (h-policy2-base/-alt).
4. Contradictory goals must CLARIFY instead of silently dropping one side.
"""
from atomicroot.framework.registry import TOOLS
from atomicroot.integration import dynamic_proposal_v10 as v10
from atomicroot.integration.dynamic_proposal_v8 import (REQUIREMENT_FIELDS, CAPABILITY_FIELDS, WIRE_VERSION,  # noqa: F401
    HOST_MANAGED, SELECTION_FIELDS, _ancestors, capability_catalog, validate_requirements, check_requirements)
from atomicroot.framework.storage import dumps

VERSION = 'dynamic-proposal-v11'
DYNAMIC = True
PLANNER_VERSION = VERSION
EFFECTS = v10.EFFECTS
ORIGIN_PATHS = v10.ORIGIN_PATHS
catalog_for_prompt = v10.catalog_for_prompt
expand = v10.expand
scope_breakdown = v10.scope_breakdown
EXTERNAL_EFFECTS = frozenset(t.name for t in TOOLS.values() if t.external and t.effect_class not in HOST_MANAGED)


def _grounding(goal, catalog):
    clarifications = catalog.get('clarifications', []) if type(catalog) is dict and type(catalog.get('clarifications')) is list else []
    return (goal + ' ' + ' '.join(str(c) for c in clarifications)).lower()


def parse_dynamic_proposal(value, task, goal, catalog, *, approved_requirements=None, permissions_resolved=False):
    raw_prop = value.get('proposal') if type(value) is dict else None
    if type(raw_prop) is dict and raw_prop.get('status') == 'CLARIFY' and not raw_prop.get('questions'):
        raise ValueError('/proposal/questions: CLARIFY requires at least one question to the user in proposal.questions. '
                         'If the goal explicitly names a recipient/resource that is absent from allowed_catalog, return '
                         'proposal.status="PROPOSAL" with the complete spec using it, and list it in permission_requests')
    # 'Perform user task' is the fixed goal of the legacy offline fixtures (same exemption as v10).
    if type(value) is dict and type(value.get('requirements')) is dict and catalog is not None and goal != 'Perform user task':
        grounding = _grounding(goal, catalog)
        for receipt in validate_requirements(value['requirements'])['required_receipts']:
            destination = receipt.get('destination')
            if receipt.get('tool') in EXTERNAL_EFFECTS and type(destination) is str and destination.lower() not in grounding:
                raise ValueError(f'/requirements/required_receipts: destination "{destination}" is not named in the goal; never '
                                 'map a person, role or description to a catalog destination. Return proposal.status="CLARIFY", '
                                 'spec=null, required_receipts=[], and ask the user for the exact recipient in proposal.questions')
    return v10.parse_dynamic_proposal(value, task, goal, catalog, approved_requirements=approved_requirements,
                                      permissions_resolved=permissions_resolved)


def parse_proposal(value, task, goal, catalog=None):
    resolved = parse_dynamic_proposal(value, task, goal, catalog)
    if resolved['status'] in {'NEEDS_PERMISSION', 'NEEDS_CAPABILITY'}:
        return resolved
    return resolved['proposal']


def proposal_schema():
    # A distinct title gives v11 its own schema digest, so planning contexts bind to v11.
    result = v10.proposal_schema()
    result['title'] = 'AtomicRoot dynamic proposal wire v3, planner v11'
    return result


def response_schema(messages=None):
    result = v10.response_schema(messages)
    result['title'] = proposal_schema()['title']
    return result


def _instruction():
    text = v10.INSTRUCTION.replace(v10.VERSION, VERSION)
    old_status = ('2) proposal: PROPOSAL with spec when registered tools and allowed_catalog cover every requirement; '
                  'CLARIFY or UNSUPPORTED with spec=null and questions or unsupported reasons otherwise. ')
    new_status = ('2) proposal: PROPOSAL with spec when registered tools cover every requirement. If the goal explicitly names '
                  'a recipient/resource absent from allowed_catalog, still return PROPOSAL with the complete spec using it and '
                  'list it in permission_requests; this is not CLARIFY. CLARIFY (spec=null, at least one question to the user) '
                  'only when the goal itself is ambiguous or contradictory: a recipient given as a person, role or description '
                  '(e.g. "my manager") instead of the exact address or name, or a goal that both requests and forbids the same '
                  'effect. Never map a described person to a catalog destination and never resolve a contradiction by dropping '
                  'one side. UNSUPPORTED (spec=null, reasons) when a needed tool is not registered. ')
    old_pol = ('constraint:{op:"le",left:{op:"amount"},right:{op:"const",value:N}},on_violation:"DENY"}. ')
    new_pol = ('constraint:{op:"le",left:{op:"amount"},right:{op:"const",value:N}},on_violation:"DENY"}. '
               'When the rule has several conditions, put every condition in one constraint: '
               '{op:"and",children:[{op:"le",left:{op:"amount"},right:{op:"const",value:N}},'
               '{op:"eq",left:{op:"request",name:"recipient"},right:{op:"const",value:"<recipient>"}}]}. ')
    if old_status not in text or old_pol not in text:
        raise RuntimeError('v10 instruction changed; v11 derivation would be stale')
    return text.replace(old_status, new_status, 1).replace(old_pol, new_pol, 1)


INSTRUCTION = _instruction()


def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
    import json
    result = v10.messages(goal, task, catalog, previous=previous, error=error, draft=draft)
    context = json.loads(result[1]['content'])
    context['protocol'] = VERSION
    result[0] = dict(role='system', content=result[0]['content'].replace(v10.INSTRUCTION, INSTRUCTION, 1))
    result[1] = dict(role='user', content=dumps(context))
    return result
