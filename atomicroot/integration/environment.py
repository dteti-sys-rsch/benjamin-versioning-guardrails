"""User-authored local workspace configuration, independent of experiment fixtures."""
from copy import deepcopy

from atomicroot.authority.policy_engine import valid_identity, money_integer
from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.identity import Principal
from atomicroot.framework.labels import content_digest
from atomicroot.framework.task_spec import TaskSpec, exact, sequence, text, rules, task_schema
from atomicroot.framework.tasks import TrustedCatalog
from atomicroot.integration.goals import GoalService
from atomicroot.observability import point


def install_catalog(runtime, data):
    """Explicit local operator action; unavailable to planner/worker tools."""
    exact(data, {"resources", "destinations", "entitlements"})
    admin = Principal("local-admin", frozenset({"admin"}))
    for resource in sequence(data["resources"]):
        exact(resource, {"resource", "content", "label", "purposes"})
        owner = Principal("local-owner", frozenset({"owner"}), resources=frozenset({resource["resource"]}))
        with runtime.store.snapshot() as snap: previous = snap.read("document:" + resource["resource"])[1]
        if previous is not None: raise ValueError("resource exists; use official owner API for changes")
        ref = runtime.storage.ingest(resource["resource"], resource["content"], owner)
        runtime.labels.set_label(ref["resource"], ref["digest"], ref["version"], resource["label"], resource["purposes"], owner)
    for destination in sequence(data["destinations"]): runtime.catalog.set_destination(destination, admin)
    for entitlement in sequence(data["entitlements"]):
        exact(entitlement, {"task", "subject", "rights"})
        runtime.catalog.set_entitlement(entitlement["task"], entitlement["subject"], entitlement["rights"], admin)


def local_identities(runtime):
    # Local CLI is an explicitly trusted operator boundary, not network authentication.
    with runtime.store.snapshot() as snap:
        tasks = frozenset(key.split(":")[1] for (key,) in snap._conn.execute(
            "SELECT key FROM conflict_keys WHERE key LIKE 'entitlement:%:local-user'"))
    return (Principal("local-user", frozenset({"user"}), tasks),
            Principal("local-human", frozenset({"approver"}), tasks))


FIELDS = {"schema_version", "task_id", "purpose", "resources", "destinations", "scope",
          "budget_limit", "max_agents", "limits", "provider", "planning"}


def environment_schema():
    spec = task_schema()
    properties = spec["$defs"]["task_spec"]["properties"]
    def obj(properties):
        return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}
    strings = {"type": "array", "maxItems": 16, "uniqueItems": True, "items": {"type": "string"}}
    array = lambda item: {"type": "array", "maxItems": 16, "items": item}
    result = obj({k: deepcopy(properties[k]) for k in FIELDS if k in properties})
    result["properties"].update(
        provider={"type": "object", "required": ["destination", "model"], "additionalProperties": False,
                  "properties": {"destination": {"type": "string"}, "model": {"type": "string"}}},
        resources=array(obj({"resource": {"type": "string"}, "content": {"type": "string"},
            "label": {"enum": ["PUBLIC", "SENSITIVE", "UNKNOWN"]}, "purposes": strings})),
        destinations=array(obj({"destination": {"type": "string"}, "kind": {"enum": ["provider", "recipient"]},
            "purposes": strings, "models": strings, "labels": strings, "endpoint": {"type": ["string", "null"]}})),
        max_agents={"type": "integer", "minimum": 1, "maximum": 12},
        planning=obj({"ttl": {"type": "integer", "minimum": 1, "maximum": 86400},
            "max_repairs": {"type": "integer", "minimum": 0, "maximum": 1},
            "max_replans": {"type": "integer", "minimum": 0, "maximum": 2}}))
    result.update(title="AtomicRoot local environment v1", required=sorted(FIELDS),
                  **{"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": spec["$defs"]})
    return result


def prepare_environment(value):
    """Compile environment permissions only; never generate a business workflow/policy."""
    data = freeze_json(value, max_bytes=32768); exact(data, FIELDS)
    if type(data["schema_version"]) is not int or data["schema_version"] != 1: raise ValueError("unsupported environment schema")
    valid_identity(data["task_id"]); text(data["purpose"]); money_integer(data["budget_limit"])
    count = data["max_agents"]
    if type(count) is not int or not 1 <= count <= 12: raise ValueError("max_agents must be in [1,12]")
    planning = data["planning"]; exact(planning, {"ttl", "max_repairs", "max_replans"})
    for name, minimum, maximum in (("ttl", 1, 86400), ("max_repairs", 0, 1), ("max_replans", 0, 2)):
        if type(planning[name]) is not int or not minimum <= planning[name] <= maximum: raise ValueError("invalid planning bound: " + name)
    exact(data["provider"], {"destination", "model"})
    for item in data["provider"].values(): text(item)
    resources = sequence(data["resources"], 16)
    for item in resources:
        exact(item, {"resource", "content", "label", "purposes"}); valid_identity(item["resource"])
        if type(item["content"]) is not str: raise ValueError("resource content must be text")
        content_digest(item['content'])
        if item["label"] not in {"PUBLIC", "SENSITIVE", "UNKNOWN"}: raise ValueError("invalid resource label")
        for purpose in sequence(item["purposes"], nonempty=True): text(purpose)
    if len({r['resource'] for r in resources}) != len(resources): raise ValueError("duplicate resource")
    destinations = sequence(data["destinations"], nonempty=True)
    for destination in destinations: TrustedCatalog.validate_destination(destination)
    if len({d['destination'] for d in destinations}) != len(destinations): raise ValueError("duplicate destination")
    suffix = args_hash(data).split(":")[-1][:16]
    intake_task, context = "intake-" + suffix, "goal-" + suffix
    contexts = ["worker-" + suffix + "-" + str(i) for i in range(count)]
    if {context, *contexts} & {r['resource'] for r in resources}: raise ValueError("reserved context collision")
    provider, purpose = data["provider"], data["purpose"]
    rule = lambda resource: dict(tool="model_inference", resource=resource,
        destination=provider["destination"], purpose=purpose, max_amount=0)
    business_scope = rules([*data["scope"], *(rule(name) for name in contexts)],limit=64)
    if any(r['purpose'] != purpose or r['max_amount'] > data['budget_limit'] for r in business_scope):
        raise ValueError("scope exceeds environment purpose/budget")
    if any(r['resource'] is not None and r['resource'] not in {v['resource'] for v in resources} | set(contexts) for r in business_scope):
        raise ValueError("scope references an undeclared resource")
    if any(r['destination'] is not None and r['destination'] not in {d['destination'] for d in destinations} for r in business_scope):
        raise ValueError("scope references an undeclared destination")
    all_resources = [*deepcopy(resources), *(dict(resource=name, content="", label="UNKNOWN", purposes=[purpose]) for name in [context, *contexts])]
    sequence(all_resources)  # Keep catalog/context bounds compatible with TaskSpec and storage.
    intake_scope = [rule(context)]
    intake = TaskSpec.parse(dict(schema_version=1, task_id=intake_task, objective="Authorize bounded goal planning",
        purpose=purpose, resources=[dict(resource=context, digest=content_digest(""), version=1, binding="host_context")],
        scope=intake_scope, budget_limit=0, agents=[dict(id="planner", role="Propose plans without business authority", scope=intake_scope)],
        policies=[], workflow=dict(nodes=[dict(id="plan", agent="planner", depends_on=[])]),
        outputs=[dict(id="proposal", kind="artifact")], acceptance=[dict(kind="output", output="proposal")],
        provider=provider, classifier=dict(mode="disabled"), limits=data["limits"], unknown_release="DENY")).data
    limits = intake["limits"]
    flat = {k: limits['inference'][k] for k in ('max_calls','max_tokens','max_output_tokens','max_retries','timeout')}
    flat.update({k: limits[k] for k in ('max_steps','max_in_flight')})
    if any(type(v) is not int for v in flat.values()): raise ValueError("integer environment limits required")
    catalog = dict(resources=all_resources, destinations=destinations, entitlements=[
        dict(task=data['task_id'], subject='local-user', rights=dict(scope=business_scope, budget_limit=data['budget_limit'], max_agents=count, limits=flat)),
        dict(task=intake_task, subject='local-user', rights=dict(scope=intake_scope, budget_limit=0, max_agents=1, limits=flat))])
    for entitlement in catalog['entitlements']:
        TrustedCatalog.validate_entitlement(entitlement['task'], entitlement['subject'], entitlement['rights'])
    selected = next((d for d in destinations if d['destination'] == provider['destination']), None)
    if not selected or selected['kind'] != 'provider' or provider['model'] not in selected['models'] or purpose not in selected['purposes']:
        raise ValueError("provider/model/purpose is not declared")
    if 'UNKNOWN' not in selected['labels']: raise ValueError("explicit UNKNOWN permission required for user goal/context egress")
    config = dict(id="planning", intake_task=intake_task, agent="planner", context_resource=context,
        provider=provider['destination'], model=provider['model'], purpose=purpose, subject="local-user", targets=[data['task_id']],
        visible_resources=[r['resource'] for r in resources] + contexts, visible_destinations=[d['destination'] for d in destinations],
        max_repairs=planning['max_repairs'], max_replans=planning['max_replans'])
    return dict(schema_version=1, digest=args_hash(data), environment=data, catalog=catalog, intake_spec=intake,
        intake_permission=config, identity_mode="TRUSTED_LOCAL_OPERATOR", business_effects="SIMULATED")


def initialize_environment(runtime, value, accepted_digest):
    prepared = prepare_environment(value)
    if accepted_digest != prepared['digest']: raise PermissionError("accept the exact environment-preview digest")
    with runtime.store.composed_transaction() as conn:
        if runtime.store.value(conn,'workspace:environment')[1] is not None:
            raise ValueError('environment already initialized; use a new workspace')
        if conn.execute('SELECT 1 FROM conflict_keys LIMIT 1').fetchone():
            raise ValueError('environment requires an empty workspace')
        install_catalog(runtime, prepared['catalog'])
        source_ids={r['resource'] for r in prepared['environment']['resources']}
        with runtime.store.transaction() as conn:
            runtime.store.put(conn,'hostcontexts:'+prepared['environment']['task_id'],
                [name for name in prepared['intake_permission']['visible_resources'] if name not in source_ids])
        user, _ = local_identities(runtime)
        preview = runtime.tasks.propose(prepared['intake_spec'], user)
        record = dict(status='INTAKE_REVIEW_WAIT', prepared=prepared, preview=preview, observed=point())
        with runtime.store.transaction() as conn: runtime.store.put(conn, 'workspace:environment', record)
    return record


def activate_intake(runtime, principal):
    # Construct schema-owning service before opening the composed transaction.
    service=GoalService(runtime)
    with runtime.store.composed_transaction():
        record = runtime.store.get_state('workspace:environment')
        if not record or record['status'] != 'INTAKE_REVIEW_WAIT': raise ValueError('intake is not awaiting activation')
        prepared, preview = record['prepared'], record['preview']
        runtime.contracts.activate(preview['proposal_id'], preview['review_id'], principal)
        config = dict(prepared['intake_permission'], expires=runtime.store.now() + prepared['environment']['planning']['ttl'])
        result = service.register_intake(config, Principal('local-admin', frozenset({'admin'})))
        record.update(status='READY', observed=point())
        with runtime.store.transaction() as conn: runtime.store.put(conn, 'workspace:environment', record)
    return dict(status='READY', intake=result['id'], task=prepared['environment']['task_id'], observed=point())
