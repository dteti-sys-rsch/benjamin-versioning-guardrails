"""Versioned named-capability proposals; structural checks confer no authority."""
from copy import deepcopy
from dataclasses import asdict

from atomicroot.authority.policy_engine import money_integer
from atomicroot.authority.ticket import freeze_json
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.task_spec import exact, sequence, text, rules
from atomicroot.integration.planning import parse_proposal as legacy_parse_proposal

VERSION = 'dynamic-proposal-v2'
DYNAMIC = True
PLANNER_VERSION = VERSION
REQUIREMENT_FIELDS = {'required_outputs', 'required_reads', 'required_receipts',
                      'max_amount', 'allowed_recipients', 'external_release'}
CAPABILITY_FIELDS = {'name', 'purpose', 'input_schema', 'output_schema', 'effects',
                     'data_access', 'permissions', 'idempotency', 'facts', 'updaters'}


def capability_catalog():
    """Descriptions derive from executable registry, never a use-case switch."""
    return [{**asdict(tool), 'required': sorted(tool.required),
             'writes': list(tool.writes),
             'read_facts': list(tool.read_facts),
             'authority': 'registered adapter only; proposal cannot install executable'}
            for tool in TOOLS.values()]


def validate_requirements(value):
    value = freeze_json(value); exact(value, REQUIREMENT_FIELDS)
    for field in ('required_outputs', 'required_reads'):
        for item in sequence(value[field]): text(item)
        if len(set(value[field])) != len(value[field]): raise ValueError('duplicate requirement: ' + field)
    for item in sequence(value['required_receipts']):
        exact(item, {'tool', 'destination'}); text(item['tool'])
        if item['destination'] is not None: text(item['destination'])
    if value['max_amount'] is not None: money_integer(value['max_amount'])
    if value['allowed_recipients'] is not None:
        for item in sequence(value['allowed_recipients']): text(item)
    if type(value['external_release']) is not bool: raise ValueError('external_release must be boolean')
    return value


def check_requirements(spec, value):
    """Check typed requirements against the plan, not arbitrary policy evaluation.

    Business rule ceilings are later enforced by the existing Z3 scope compiler.
    No missing requirement is silently added to a model-generated plan.
    """
    requirement = validate_requirements(value)
    acceptance = spec['acceptance']
    expected = ([dict(kind='output', output=name) for name in requirement['required_outputs']]
                + [dict(kind='read', resource=name) for name in requirement['required_reads']]
                + [dict(kind='receipt', **item) for item in requirement['required_receipts']])
    for criterion in expected:
        if criterion not in acceptance: raise ValueError('missing required acceptance: ' + str(criterion))
    for rule in spec['scope']:
        tool = TOOLS[rule['tool']]
        if tool.spending and requirement['max_amount'] is not None and rule['max_amount'] > requirement['max_amount']:
            raise ValueError('scope exceeds required operation ceiling')
        business_release = tool.external and tool.effect_class not in {'inference', 'classification'}
        if business_release:
            if not requirement['external_release']: raise ValueError('requirement prohibits external business release')
            if requirement['allowed_recipients'] is not None and rule['destination'] not in requirement['allowed_recipients']:
                raise ValueError('recipient outside reviewed requirement')


def parse_dynamic_proposal(value, task, goal, catalog, *, approved_requirements=None, permissions_resolved=False):
    """Lower named selections through v1 parser without changing catalog rights.

    New destinations/resources are retained as permission requests, not installed.
    This parser alone is not an activation or review service.
    """
    value = freeze_json(value, max_bytes=49152)
    exact(value, {'schema_version', 'proposal', 'requirements', 'permission_requests', 'capability_requests'})
    if type(value['schema_version']) is not int or value['schema_version'] != 2: raise ValueError('unsupported dynamic proposal version')
    requirement = validate_requirements(value['requirements'])
    if approved_requirements is not None and requirement != validate_requirements(approved_requirements):
        raise ValueError('approved requirements changed; new user review required')
    permissions = sequence(value['permission_requests'])
    for request in permissions:
        exact(request, {'kind', 'reference', 'reason'})
        if request['kind'] not in {'resource', 'recipient', 'scope'}: raise ValueError('unsupported permission request kind')
        for field in ('reference', 'reason'): text(request[field])
    capability_requests = sequence(value['capability_requests'])
    for request in capability_requests:
        exact(request, CAPABILITY_FIELDS)
        for field in ('name', 'purpose', 'effects', 'idempotency'): text(request[field])
        for field in ('input_schema', 'output_schema'):
            if type(request[field]) is not dict: raise ValueError('tool schema must be an object')
        for field in ('data_access', 'permissions', 'facts', 'updaters'):
            for item in sequence(request[field]): text(item)
        if request['name'] in TOOLS: raise ValueError('capability already registered; select the existing adapter')
    if capability_requests:
        return dict(status='NEEDS_CAPABILITY', **{k: deepcopy(value[k]) for k in
            ('requirements', 'permission_requests', 'capability_requests', 'proposal')})
    if permissions and not permissions_resolved:
        return dict(status='NEEDS_PERMISSION', **{k: deepcopy(value[k]) for k in
            ('requirements', 'permission_requests', 'capability_requests', 'proposal')})
    proposal = deepcopy(value['proposal'])
    if proposal.get('status') == 'PROPOSAL':
        resolved_catalog = deepcopy(catalog)
        spec = proposal['spec']
        if 'scope' in spec or 'resources' in spec: raise ValueError('dynamic spec uses named capabilities, not canonical scope overrides')
        contexts = list(catalog.get('host_contexts',[]))
        assigned = {a['context_resource'] for a in spec['agents'] if a.get('context_resource') is not None}
        for agent in sequence(spec['agents'], nonempty=True):
            if 'context_resource' not in agent:
                available=sorted(set(contexts)-assigned)
                if not available:raise ValueError('no separately authorized host context for agent '+str(agent.get('id')))
                agent['context_resource']=available[0];assigned.add(available[0])
            elif contexts and agent['context_resource'] not in contexts:
                raise ValueError('context is not an authorized host buffer')
            exact(agent, {'id', 'role', 'capabilities', 'context_resource'})
            selections = rules(agent.pop('capabilities'))
            if any(r['resource'] in contexts for r in selections):
                raise ValueError('host contexts are allocated by runtime; select business/source capabilities only')
            if not selections: raise ValueError('explicit named capability selection required')
            indices = []
            for selection in selections:
                matches = [rule for rule in catalog['scope'] if
                    all(rule[k] == selection[k] for k in ('tool', 'resource', 'destination', 'purpose'))
                    and rule['max_amount'] >= selection['max_amount']]
                if len(matches) != 1: raise ValueError('capability unavailable or ambiguous: ' + str(selection))
                if selection not in resolved_catalog['scope']: resolved_catalog['scope'].append(selection)
                indices.append(resolved_catalog['scope'].index(selection))
            agent['scope_refs'] = indices
        canonical = legacy_parse_proposal(proposal, task, goal, resolved_catalog)
        check_requirements(canonical['spec'], requirement)
    else:
        canonical = legacy_parse_proposal(proposal, task, goal, catalog)
    return dict(status=canonical['status'], proposal=canonical, requirements=requirement,
                permission_requests=[], capability_requests=[])


def proposal_schema():
    from atomicroot.integration.planning import proposal_schema as legacy_schema
    result = deepcopy(legacy_schema())
    compact = result['$defs']['planner_spec']
    agent = compact['properties']['agents']['items']
    agent['properties'].pop('scope_refs')
    agent['properties']['capabilities'] = deepcopy(result['$defs']['task_spec']['properties']['scope'])
    agent['properties'].pop('context_resource')
    agent['required'] = ['id', 'role', 'capabilities']
    def obj(properties):
        return dict(type='object', properties=properties, required=list(properties), additionalProperties=False)
    string = dict(type='string', maxLength=256)
    strings = dict(type='array', maxItems=16, items=string)
    req = obj(dict(required_outputs=strings, required_reads=strings,
        required_receipts=dict(type='array', maxItems=16, items=obj(dict(tool=string, destination=dict(type=['string','null'])))),
        max_amount=dict(type=['integer','null'],minimum=0),allowed_recipients=dict(type=['array','null'],maxItems=16,items=string),
        external_release=dict(type='boolean')))
    request = obj(dict(kind=dict(enum=['resource','recipient','scope']),reference=string,reason=string))
    capability = obj({**{k:string for k in ('name','purpose','effects','idempotency')},
        **{k:dict(type='object') for k in ('input_schema','output_schema')},
        **{k:strings for k in ('data_access','permissions','facts','updaters')}})
    result['$defs']['goal_proposal']['properties']['spec'] = dict(oneOf=[{'$ref':'#/$defs/planner_spec'},dict(type='null')])
    result['$defs']['dynamic_proposal'] = obj(dict(schema_version=dict(const=2),proposal={'$ref':'#/$defs/goal_proposal'},
        requirements=req,permission_requests=dict(type='array',maxItems=16,items=request),
        capability_requests=dict(type='array',maxItems=16,items=capability)))
    result['oneOf'] = [{'$ref':'#/$defs/dynamic_proposal'}]
    result['title'] = 'AtomicRoot dynamic proposal v2'
    return result


def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
    from atomicroot.framework.storage import dumps
    from atomicroot.integration.planning import previous_context
    context = dict(protocol=VERSION,goal=goal,target_task=task,allowed_catalog=catalog)
    if previous is not None: context['previous'] = previous_context(previous)
    if error: context['validation_error'] = error
    if draft: context['invalid_draft_for_repair'] = draft
    descriptions = [{k:v for k,v in tool.items() if k in ('name','required','effect_class','resource','external','spending')}
                    for tool in capability_catalog()]
    instruction = (
        'Return a dynamic-proposal-v2 JSON envelope: schema_version=2, proposal, requirements, permission_requests, capability_requests. '
        'proposal={status:PROPOSAL|CLARIFY|UNSUPPORTED,spec,assumptions:[],unsupported:[],questions:[],origin:[]}. '
        'For PROPOSAL use compact TaskSpec fields except scope/resources; agent={id,role,capabilities:[full named catalog rules]}. '
        'Choose business capabilities by tool/resource/destination/purpose/max_amount, never numeric indices. '
        'Host allocates a separate already-authorized context per worker. Do not select host context rules as business capabilities. Reading source content requires read_document plus source inference permission. '
        'Plan reads now; the worker reads actual source during execution. Tool schemas/receipts are provided by the host. '
        'Represent every requested output and operation in acceptance. Preserve literal user output identifiers. '
        'requirements={required_outputs:[],required_reads:[],required_receipts:[{tool,destination}],max_amount:null|integer,allowed_recipients:null|[string],external_release:boolean}. '
        'Requirements are proposed interpretations for user review, never permission grants. '
        'For a missing destination/resource/permission add {kind,reference,reason} to permission_requests. '
        'For a missing executable capability add its specification to capability_requests; never invent an installed tool. '
        'A stopped proposal has spec=null and explicit questions or unsupported reasons. '
        'Use dependency-ready independent nodes for parallel work, with an explicit join node when required. '
        'A join worker receiving ancestor source content needs explicit source inference capabilities for all those sources. '
        'Never drop requirements or narrow requested work to make validation pass. Policy constraints express allowed conditions; Z3 evaluates them. '
        'Use registered fact/operator names from the schema. origin quotes the goal and covers /resources,/scope,/agents,/workflow,/policies,/budget_limit,/acceptance. '
        'Host tool metadata: ' + dumps(descriptions))
    return [dict(role='system',content=instruction),dict(role='user',content=dumps(context))]


def parse_proposal(value, task, goal, catalog=None):
    resolved = parse_dynamic_proposal(value,task,goal,catalog)
    if resolved['status'] in {'NEEDS_PERMISSION','NEEDS_CAPABILITY'}: return resolved
    return resolved['proposal']


def response_schema():
    value = proposal_schema()
    def refs(node):
        if isinstance(node,dict):
            for key,item in node.items():
                if key=='$ref': yield item.rsplit('/',1)[-1]
                else: yield from refs(item)
        elif isinstance(node,list):
            for item in node: yield from refs(item)
    needed={'dynamic_proposal'}
    while True:
        expanded=needed|{r for name in needed for r in refs(value['$defs'][name])}
        if expanded==needed:break
        needed=expanded
    return {'$defs':{name:value['$defs'][name] for name in sorted(needed)},'$ref':'#/$defs/dynamic_proposal'}
