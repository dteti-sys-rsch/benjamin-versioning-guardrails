"""Versioned named-capability proposals; structural checks confer no authority.

v10 builds on v9:
1. Restores model-supplied `origin` in `proposal` (validated against the goal,
   with host-derived paths appended only for host-expanded `/resources`,
   `/scope`, `/acceptance`).
2. Rejects `required_outputs` IDs that collide with existing catalog resources
   (preventing update goals from authoring a colliding output artifact).
3. Rejects hallucinated `permission_requests` whose reference is absent from
   the user goal/clarifications (preventing silent tool substitution such as
   WhatsApp -> send_email to an invented address).
4. Enforces policy DSL synthesis when the goal explicitly requests a policy or
   constraint rule, while allowing scope ceilings to remain at `budget_limit`
   when a custom spending policy is synthesized so Z3 evaluates the policy rule.
"""
from copy import deepcopy
import json

from atomicroot.authority.ticket import freeze_json
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.storage import dumps
from atomicroot.framework.task_spec import exact, sequence, text
from atomicroot.integration import dynamic_proposal_v4 as v4
from atomicroot.integration import dynamic_proposal_v5 as v5
from atomicroot.integration import dynamic_proposal_v7 as v7
from atomicroot.integration import dynamic_proposal_v8 as v8
from atomicroot.integration import dynamic_proposal_v9 as v9
from atomicroot.integration.dynamic_proposal_v8 import (REQUIREMENT_FIELDS, CAPABILITY_FIELDS, WIRE_VERSION,  # noqa: F401
    HOST_MANAGED, SELECTION_FIELDS, _ancestors, capability_catalog, validate_requirements, check_requirements)

VERSION = 'dynamic-proposal-v10'
DYNAMIC = True
PLANNER_VERSION = VERSION
EFFECTS = v9.EFFECTS
ORIGIN_PATHS = v5.ORIGIN_PATHS


def catalog_for_prompt(catalog):
    result = v5.catalog_for_prompt(catalog)
    result.pop('clarifications', None)
    return result


expand = v8.expand


def scope_breakdown(raw_value, resolved_spec):
    """Classify resolved TaskSpec scope rules into model-selected vs host-derived."""
    proposal = raw_value.get('proposal') if type(raw_value) is dict else None
    raw_spec = proposal.get('spec') if type(proposal) is dict else None
    raw_agents = raw_spec.get('agents', []) if type(raw_spec) is dict else []
    selected_keys = {(s.get('tool'), s.get('resource'), s.get('destination'), s.get('purpose'))
                     for a in raw_agents if type(a) is dict for s in a.get('capabilities', []) if type(s) is dict}
    hosts = {r['resource'] for r in resolved_spec.get('resources', []) if r.get('binding') == 'host_context'}
    selected, derived, host_egress = [], [], []
    for r in resolved_spec.get('scope', []):
        if r['resource'] in hosts:
            host_egress.append(r)
        elif (r['tool'], r['resource'], r['destination'], r['purpose']) in selected_keys:
            selected.append(r)
        else:
            derived.append(r)
    return dict(selected_by_model=selected, derived_by_host=derived, host_context_egress=host_egress)


def _normalize_origin(raw_origin, goal):
    if not raw_origin:
        return [dict(requirement=goal, paths=list(ORIGIN_PATHS),
                     reason='host-lowered whole-goal provenance; requirement interpretation is reviewed separately')]
    normalized = []
    covered = set()
    for item in sequence(raw_origin, 32, nonempty=True):
        exact(item, {'requirement', 'paths', 'reason'})
        text(item['requirement'], 2048)
        text(item['reason'])
        req = item['requirement'] if item['requirement'] in goal else goal
        paths = []
        for p in sequence(item['paths'], 16, nonempty=True):
            text(p)
            if p not in ORIGIN_PATHS:
                raise ValueError(f'/proposal/origin: unsupported path {p}; use paths from {ORIGIN_PATHS}')
            paths.append(p)
            covered.add(p)
        normalized.append(dict(requirement=req, paths=paths, reason=item['reason']))
    missing = [p for p in ORIGIN_PATHS if p not in covered]
    if missing:
        normalized.append(dict(requirement=goal, paths=missing,
                               reason='host-derived resolution and expansion paths'))
    return normalized


def lower(value, task, goal, catalog, *, permissions_resolved=False):
    value = freeze_json(value, max_bytes=49152)
    exact(value, {'schema_version', 'requirements', 'capability_requests', 'permission_requests', 'proposal'})
    if type(value['schema_version']) is not int or value['schema_version'] != WIRE_VERSION:
        raise ValueError('unsupported dynamic proposal version')
    requirement = validate_requirements(value['requirements'])
    proposal = deepcopy(value['proposal'])
    raw_origin = proposal.pop('origin', None) if type(proposal) is dict and 'origin' in proposal else None
    exact(proposal, {'status', 'spec', 'assumptions', 'unsupported', 'questions'})
    if proposal['status'] == 'UNSUPPORTED' and not proposal['unsupported'] and value['capability_requests']:
        proposal['unsupported'] = [f"{c.get('name', 'tool')} is not registered" for c in value['capability_requests'] if type(c) is dict]
    proposal['origin'] = []
    blocked = value['capability_requests'] or (value['permission_requests'] and not permissions_resolved)
    if proposal['status'] == 'PROPOSAL' and not blocked:
        spec = proposal['spec']
        exact(spec, set(v5.SPEC_FIELDS))
        v5.diagnose(spec, requirement, catalog)
        purposes = ({r.get('purpose') for a in spec['agents'] for r in a['capabilities']}
                    or {r['purpose'] for r in catalog['scope']})
        if len(purposes) != 1:
            raise ValueError('/proposal/spec/agents: selected capabilities must share one catalog purpose')
        limits = catalog['limits']
        proposal['spec'] = dict(spec, schema_version=1, task_id=task, objective=v5.objective(goal), purpose=purposes.pop(),
            outputs=[dict(id=name, kind='artifact') for name in requirement['required_outputs']],
            acceptance=v5.acceptance(requirement), classifier={'mode': 'disabled'}, unknown_release='DENY',
            limits=dict(inference={k: limits[k] for k in v5.LIMIT_FIELDS},
                        max_in_flight=limits['max_in_flight'], max_steps=limits['max_steps']))
        proposal['origin'] = _normalize_origin(raw_origin, goal)
    return dict(schema_version=2, proposal=proposal, requirements=requirement,
                permission_requests=value['permission_requests'], capability_requests=value['capability_requests'])


def parse_dynamic_proposal(value, task, goal, catalog, *, approved_requirements=None, permissions_resolved=False):
    value = freeze_json(value, max_bytes=49152)
    requests = value.get('capability_requests') if type(value) is dict else None
    for request in sequence(requests) if type(requests) is list else []:
        name = request.get('name') if type(request) is dict else None
        if name in TOOLS:
            raise ValueError(f'/capability_requests: {name} is already registered; remove it from capability_requests and '
                             'select its allowed_catalog.scope rule in proposal.spec.agents[].capabilities (or if the goal '
                             'requires an unregistered tool, set capability_requests[].name to that unregistered tool name)')
    if type(value) is dict and type(value.get('requirements')) is dict and catalog is not None:
        req = validate_requirements(value['requirements'])
        hosts = set(catalog.get('host_contexts', []))
        existing_resources = {r['resource'] for r in catalog.get('resources', []) if r['resource'] not in hosts}
        for out_id in req['required_outputs']:
            if out_id in existing_resources:
                raise ValueError(f'/requirements/required_outputs: "{out_id}" is an existing catalog resource, not a newly authored '
                                 f'output; remove "{out_id}" from required_outputs and use required_receipts '
                                 '[{"tool":"update_document","destination":null}] when modifying a document')
    if type(value) is dict and goal != 'Perform user task' and catalog is not None:
        clarifications = catalog.get('clarifications', []) if type(catalog.get('clarifications')) is list else []
        grounding = (goal + ' ' + ' '.join(str(c) for c in clarifications)).lower()
        for perm in sequence(value.get('permission_requests', [])) if type(value.get('permission_requests')) is list else []:
            ref = perm.get('reference') if type(perm) is dict else None
            if type(ref) is str and ref.lower() not in grounding:
                raise ValueError(f'/permission_requests: reference "{ref}" is not mentioned in the goal; never invent a '
                                 'recipient/resource or substitute another tool (such as send_email) for an unregistered '
                                 'capability. If the goal requires an unregistered tool, set permission_requests=[], '
                                 'required_receipts=[], proposal.status="UNSUPPORTED", proposal.unsupported=[reason], '
                                 'and specify the missing tool in capability_requests')
    raw_prop = value.get('proposal') if type(value) is dict else None
    if type(raw_prop) is dict and raw_prop.get('status') in {'CLARIFY', 'UNSUPPORTED'}:
        if raw_prop['status'] == 'CLARIFY' and catalog is not None and catalog.get('clarifications'):
            raise ValueError('/proposal/status: user clarifications are already provided in allowed_catalog.clarifications; '
                             'use them to resolve the ambiguity and return proposal.status="PROPOSAL" with a complete spec')
        if raw_prop['status'] == 'CLARIFY' and not raw_prop.get('questions') and not value.get('permission_requests'):
            raise ValueError('/proposal/questions: CLARIFY requires at least one question in proposal.questions')
        if raw_prop['status'] == 'UNSUPPORTED' and not raw_prop.get('unsupported') and not value.get('capability_requests'):
            raise ValueError('/proposal/unsupported: UNSUPPORTED requires at least one reason in proposal.unsupported or capability_requests')
    if (type(raw_prop) is dict and raw_prop.get('status') == 'PROPOSAL' and type(raw_prop.get('spec')) is dict
            and catalog is not None and catalog.get('host_contexts') and raw_prop['spec'].get('provider') is None):
        providers = [dict(destination=d['destination'], model=d['models'][0])
                     for d in catalog.get('destinations', []) if d.get('kind') == 'provider' and d.get('models')]
        if providers:
            raise ValueError('/proposal/spec/provider: provider cannot be null for model-executed workflows; '
                             f'set proposal.spec.provider to {dumps(providers[0])}')
    expanded = expand(value)
    proposal = expanded.get('proposal')
    blocked = expanded.get('capability_requests') or (expanded.get('permission_requests') and not permissions_resolved)
    if type(proposal) is dict and proposal.get('status') == 'PROPOSAL' and not blocked:
        requirement = validate_requirements(expanded['requirements'])
        exact(proposal['spec'], set(v5.SPEC_FIELDS))
        v5.diagnose(proposal['spec'], requirement, catalog)
        v9.justify(value['proposal']['spec'], requirement)
        budget = proposal['spec']['budget_limit']
        if requirement['max_amount'] is not None and type(budget) is int and budget < requirement['max_amount'] and any(
                TOOLS[r['tool']].spending for a in proposal['spec']['agents'] for r in a['capabilities']):
            raise ValueError(f'/proposal/spec/budget_limit: {budget} is below requirements.max_amount {requirement["max_amount"]}')
        if goal != 'Perform user task' and any(w in goal.lower() for w in ('policy', 'constraint rule', 'dsl')) and not proposal['spec'].get('policies'):
            raise ValueError('/proposal/spec/policies: the goal requests an explicit policy rule, but policies is []; '
                             'add a policy object {policy_id,version:1,scope:"task",applies_to:[tool],when:{op:"const",value:true},'
                             'constraint:{op:"le",left:{op:"amount"},right:{op:"const",value:N}},on_violation:"DENY"}')
    lowered = lower(expanded, task, goal, catalog, permissions_resolved=permissions_resolved)
    result = v4.parse_dynamic_proposal(lowered, task, goal, catalog, approved_requirements=approved_requirements,
                                       permissions_resolved=permissions_resolved)
    if result['status'] in {'NEEDS_PERMISSION', 'NEEDS_CAPABILITY'}:
        result['proposal'] = deepcopy(value['proposal'])
    elif result.get('proposal', {}).get('spec'):
        result['scope_breakdown'] = scope_breakdown(value, result['proposal']['spec'])
    return result


def parse_proposal(value, task, goal, catalog=None):
    resolved = parse_dynamic_proposal(value, task, goal, catalog)
    if resolved['status'] in {'NEEDS_PERMISSION', 'NEEDS_CAPABILITY'}:
        return resolved
    return resolved['proposal']


def proposal_schema():
    result = v8.proposal_schema()
    origin_def = v4.proposal_schema()['$defs']['goal_proposal']['properties']['origin']
    origin_def = deepcopy(origin_def)
    origin_def['items']['properties']['paths']['items'] = {'enum': list(ORIGIN_PATHS)}
    goal_def = result['$defs']['goal_proposal']
    goal_def['properties']['origin'] = origin_def
    if 'origin' not in goal_def['required']:
        goal_def['required'] = [*goal_def['required'], 'origin']
    result['title'] = 'AtomicRoot dynamic proposal wire v3, planner v10'
    return result


def response_schema(messages=None):
    result = v7.response_schema(messages, base=proposal_schema())
    branches = result['$defs']['dynamic_proposal']['oneOf']
    exec_origin = branches[0]['properties']['proposal']['properties']['origin']
    exec_origin['minItems'] = 1
    exec_origin['maxItems'] = 8
    if messages is not None:
        context = json.loads(messages[1]['content'])
        exec_origin['items']['properties']['requirement'] = {'const': context['goal']}
    branches[1]['properties']['proposal']['properties']['origin']['maxItems'] = 0
    return result


def _instruction():
    text = v9.INSTRUCTION.replace('dynamic-proposal-v9', VERSION)
    old_out = ('required_outputs = IDs of outputs the goal asks to author, '
               'spelled exactly as the goal names them (e.g. "as output X" gives "X"); [] if no authored output is requested. '
               'A receipt or tool result is never an output. ')
    new_out = ('required_outputs = IDs of new outputs the goal explicitly asks to author '
               '(e.g. "as output result" -> ["result"]); [] when no new output is requested. '
               'Never put a catalog resource name (e.g. notes-a, notes-b) in required_outputs; updating a document uses required_receipts only. ')
    old_pol = ('policies: goal-specific rules in the policy DSL, may be []; constraint states what is ALLOWED, on_violation=DENY, Z3 '
               'evaluates. Ceiling N on a spending tool: when=const true, constraint=le(amount,const N), applies_to that tool. ')
    new_pol = ('policies: goal-specific DSL rules (include whenever the goal states a policy/ceiling rule, else []), shaped as '
               '{policy_id:<id>,version:1,scope:"task",applies_to:[<tool>],when:{op:"const",value:true},'
               'constraint:{op:"le",left:{op:"amount"},right:{op:"const",value:N}},on_violation:"DENY"}. '
               'Always set spec.provider={destination,model} to the provider in allowed_catalog.destinations (never null when a provider destination is present). '
               'origin=[{requirement:<goal>,paths:["/agents","/workflow","/policies","/budget_limit"],reason:<why>}] for PROPOSAL, [] otherwise. '
               'For update_document(X), use a single agent/node with update_document(X) (host adds read_document(X) to that same agent). ')
    if old_out not in text or old_pol not in text:
        raise RuntimeError('v9 instruction changed; v10 derivation would be stale')
    return text.replace(old_out, new_out, 1).replace(old_pol, new_pol, 1)


INSTRUCTION = _instruction()


def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
    result = v8.messages(goal, task, catalog, previous=previous, error=error, draft=draft)
    context = json.loads(result[1]['content'])
    context['protocol'] = VERSION
    if type(catalog) is dict and catalog.get('clarifications'):
        context['clarifications'] = list(catalog['clarifications'])
    result[0] = dict(role='system', content=result[0]['content'].replace(v8.INSTRUCTION, INSTRUCTION, 1))
    result[1] = dict(role='user', content=dumps(context))
    return result
