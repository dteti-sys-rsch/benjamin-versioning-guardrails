"""Reviewed permission projection and atomic activation via existing trusted services."""
from copy import deepcopy
from tempfile import TemporaryDirectory
from pathlib import Path

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.framework.task_spec import rules, exact
from atomicroot.framework.storage import dumps


def _changes(runtime, raw, task, intake, user, resource_inputs):
    request_refs = {r['reference'] for r in raw['permission_requests']}
    with runtime.store.snapshot() as snap:
        entitlement = snap.read(f'entitlement:{task}:{user.subject}')[1]
        config = snap.read('goalintake:' + intake)[1]
        changes = dict(resources=[],destinations=[],entitlement=deepcopy(entitlement),intake=deepcopy(config))
        import json
        selected = rules([json.loads(r) for r in sorted({dumps(r) for a in raw['proposal']['spec']['agents'] for r in a['capabilities']})])
        for rule in selected:
            if rule['max_amount'] > entitlement['budget_limit']: raise ValueError('requested operation exceeds workspace budget ceiling')
            if rule['purpose'] != config['purpose']: raise ValueError('permission request changes intake purpose')
            resource, destination = rule['resource'], rule['destination']
            if resource and snap.read('document:' + resource)[1] is None:
                if resource not in request_refs or resource not in resource_inputs:
                    raise ValueError('new resource requires explicit operator content/label input: ' + resource)
                item = freeze_json(resource_inputs[resource]); exact(item,{'resource','content','label','purposes'})
                if item['resource'] != resource: raise ValueError('resource input identity mismatch')
                if item not in changes['resources']: changes['resources'].append(item)
            if destination and snap.read('destination:' + destination)[1] is None:
                if destination not in request_refs: raise ValueError('new destination must be explicitly requested')
                if rule['tool'] in {'model_inference','classify_document'}:
                    raise ValueError('new provider requires a separately authorized intake')
                item = dict(destination=destination,kind='recipient',purposes=[rule['purpose']],endpoint=None,models=[],labels=[])
                if item not in changes['destinations']: changes['destinations'].append(item)
            covered=any(all(parent[k]==rule[k] for k in ('tool','resource','destination','purpose'))
                        and parent['max_amount']>=rule['max_amount'] for parent in changes['entitlement']['scope'])
            if not covered:
                if not {resource,destination,rule['tool']} & request_refs:
                    raise ValueError('new scope requires an explicit permission request')
                changes['entitlement']['scope'].append(rule)
            if resource and resource not in changes['intake']['visible_resources']:
                changes['intake']['visible_resources'].append(resource)
            if destination and destination not in changes['intake']['visible_destinations']:
                changes['intake']['visible_destinations'].append(destination)
    return changes


def _apply(runtime, changes, task, user, operator):
    operator.require('admin')
    for item in changes['resources']:
        ref = runtime.storage.ingest(item['resource'],item['content'],operator)
        runtime.labels.set_label(ref['resource'],ref['digest'],ref['version'],item['label'],item['purposes'],operator)
    for item in changes['destinations']: runtime.catalog.set_destination(item,operator)
    runtime.catalog.set_entitlement(task,user.subject,changes['entitlement'],operator)
    with runtime.store.transaction() as conn:
        runtime.store.put(conn,'goalintake:' + changes['intake']['id'],changes['intake'])
        runtime.store.audit(conn,'BUNDLE_PERMISSIONS_APPLIED',operator.subject,dict(task=task,digest=args_hash(changes)))


def preview(runtime, raw, session, revision, goal, intake, task, user, *, resource_inputs=None, requirements=None, protocol=None):
    from atomicroot.integration.goals import GoalService
    from atomicroot.integration import dynamic_proposal
    protocol = protocol or dynamic_proposal
    with TemporaryDirectory(prefix='atomicroot-projection-') as directory:
        # Same clock as the main runtime: intake/review expiry must not differ in projection.
        projected = FrameworkRuntime(Path(directory)/'projection.sqlite', clock=runtime.store._clock)
        try:
            with runtime.store._lock: runtime.store._conn.backup(projected.store._conn)
            with projected.store.snapshot() as snap:
                initial_versions = dict(snap._conn.execute('SELECT key,version FROM conflict_keys'))
            # Protocols that expand selections bind permissions to the expanded rules.
            selected = protocol.expand(raw) if hasattr(protocol,'expand') else raw
            changes = _changes(projected,selected,task,intake,user,resource_inputs or {})
            operator = Principal('projection-operator',frozenset({'admin','owner'}),user.tasks,
                                 frozenset(item['resource'] for item in changes['resources']))
            with projected.store.composed_transaction(): _apply(projected,changes,task,user,operator)
            catalog = GoalService(projected,protocol=protocol).discover(intake,task,user)
            resolved = protocol.parse_dynamic_proposal(raw,task,goal,catalog,approved_requirements=requirements,permissions_resolved=True)
            if resolved['status'] != 'PROPOSAL': raise ValueError('permission bundle requires an executable proposal')
            validation = projected.tasks.validate(resolved['proposal']['spec'],user)
            if not validation['valid']: raise ValueError('; '.join(validation['unsupported']))
            projected_task = validation['resolved']
        finally: projected.store.close()
    keys = set(projected_task['basis']) | {'catalog:destinations','goalintake:'+intake,
        'goalhead:'+session,'goalexecuting:'+task,'hostcontexts:'+task}
    keys.update('destination:'+v['destination'] for v in changes['destinations'])
    for item in changes['resources']: keys.update({'document:'+item['resource'],'label:'+item['resource']})
    basis = {key:initial_versions.get(key,0) for key in keys}
    payload = dict(schema_version=1,raw=raw,changes=changes,proposal=resolved['proposal'],
        requirements=raw['requirements'],contract=projected_task['contract'],basis=basis,
        provenance='operator-reviewed projection; no permission installed in main database')
    digest = args_hash(payload)
    key = f'goalproposal:{session}:{revision}:bundle'
    with runtime.store.transaction() as conn:
        if runtime.store.stale(conn,basis): raise ValueError('bundle preview basis changed')
        runtime.store.put(conn,key,payload)
        footprint = {**basis,key:runtime.store.value(conn,key)[0]}
        review = runtime.broker.create(conn,'bundle',task,dict(digest=digest,footprint=footprint,
            preview=payload,agent_id=user.subject))
    return dict(proposal=resolved['proposal'],bundle=dict(key=key,digest=digest,task=task),
        preview=dict(proposal_id=key,review_id=review,digest=digest,status='DRAFT',preview=payload))


def activate(runtime, bundle, review_id, user, operator):
    """Caller owns composed transaction, including final goal state update."""
    operator.require('admin'); operator.require('approver',task=bundle['task'])
    with runtime.store.snapshot() as snap: payload=snap.read(bundle['key'])[1]
    if not payload or args_hash(payload)!=bundle['digest']: raise ValueError('bundle payload changed')
    runtime.broker.validate_grant(runtime.store._conn,review_id,'bundle',bundle['task'],bundle['digest'])
    _apply(runtime,payload['changes'],bundle['task'],user,operator)
    child=runtime.tasks.propose(payload['proposal']['spec'],user,
        review_bindings={bundle['key']:args_hash(payload)})
    resolved=child['preview']['resolved_task']
    if resolved['spec']!=payload['proposal']['spec'] or resolved['contract']!=payload['contract']:
        raise ValueError('fresh resolution differs from reviewed projection')
    # One operator decision authorizes this exact bound bundle, not arbitrary child contracts.
    runtime.broker.decide(child['review_id'],True,operator)
    result=runtime.contracts.activate_in_transaction(runtime.store._conn,child['proposal_id'],child['review_id'],operator)
    runtime.broker.consume(runtime.store._conn,review_id)
    return result
