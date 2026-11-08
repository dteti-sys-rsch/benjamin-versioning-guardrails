"""Workspace inventory and ceilings, independent of a particular goal or workflow."""
from copy import deepcopy
from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.task_spec import exact, sequence


def workspace_schema():
    from atomicroot.integration.environment import environment_schema
    value=environment_schema()
    for field in ('task_id','scope'):
        value['properties'].pop(field);value['required'].remove(field)
    value['properties']['schema_version']={'const':2}
    value['properties']['enabled_tools']=dict(type='array',minItems=1,maxItems=len(TOOLS),uniqueItems=True,items=dict(enum=list(TOOLS)))
    value['required'].append('enabled_tools')
    value['title']='AtomicRoot workspace inventory v2'
    return value


def task_environment(value, goal):
    """Instantiate trusted parent permissions from inventory, never from goal keywords."""
    value=freeze_json(value,max_bytes=32768)
    exact(value,{'schema_version','purpose','resources','destinations','provider','enabled_tools','budget_limit','max_agents','limits','planning'})
    if type(value['schema_version']) is not int or value['schema_version']!=2:raise ValueError('workspace schema version must be 2')
    enabled=sequence(value['enabled_tools'],len(TOOLS),nonempty=True)
    if len(set(enabled))!=len(enabled) or not set(enabled)<=set(TOOLS):raise ValueError('invalid enabled tool inventory')
    scope=[]
    for name in enabled:
        tool=TOOLS[name]
        if tool.effect_class=='classification':raise ValueError('classification requires the existing explicit classifier configuration path')
        resources=[r['resource'] for r in value['resources']] if tool.resource else [None]
        destinations=([d['destination'] for d in value['destinations'] if d['kind']==('provider' if tool.effect_class=='inference' else 'recipient')]
                      if tool.external else [None])
        for resource in resources:
            for destination in destinations:
                if tool.effect_class=='inference' and destination!=value['provider']['destination']:continue
                scope.append(dict(tool=name,resource=resource,destination=destination,purpose=value['purpose'],
                                  max_amount=value['budget_limit'] if tool.spending else 0))
    sequence(scope,64)
    result={k:deepcopy(value[k]) for k in ('purpose','resources','destinations','provider','budget_limit','max_agents','limits','planning')}
    result.update(schema_version=1,task_id='task-'+args_hash(dict(workspace=value,goal=goal))[7:31],scope=scope)
    return result
