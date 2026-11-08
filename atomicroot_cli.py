"""AtomicRoot B: goal -> proposed DSL/plan -> trusted review -> executor A."""
import argparse
import json
from pathlib import Path

from nacl.signing import SigningKey
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.integration.goals import GoalService
from atomicroot.integration.planning import PLANNER_VERSION, proposal_schema, artifact_schema
from atomicroot.integration.progress import Progress
from atomicroot.integration.providers import FakeModel, Limits, live_model
from atomicroot.sim.model_tape import ModelTape
from atomicroot.integration.environment import (local_identities, environment_schema, prepare_environment,
    initialize_environment, activate_intake)
from atomicroot.observability import point
from phase36_cli import load, init_fixture
from phase37_cli import build_workflow


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('.runs/goals'))
    parser.add_argument('--planner-mode', choices=('fake','replay','live'))
    parser.add_argument('--proposal', help='explicit offline response fixture; not live synthesis')
    parser.add_argument('--records', help='exact ModelTape records')
    parser.add_argument('--authorize-live', action='store_true')
    parser.add_argument('--quiet-progress', action='store_true')
    parser.add_argument('--proposal-protocol',choices=('legacy','dynamic'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('schema')
    sub.add_parser('dynamic-schema')
    sub.add_parser('workspace-schema')
    sub.add_parser('capabilities')
    sub.add_parser('artifact-schema')
    sub.add_parser('environment-schema')
    sub.add_parser('environment-preview').add_argument('file')
    setup=sub.add_parser('init-environment'); setup.add_argument('file'); setup.add_argument('--accept-digest',required=True)
    sub.add_parser('intake-preview')
    intake_decision=sub.add_parser('decide-intake'); intake_decision.add_argument('decision',choices=('approve','reject'))
    sub.add_parser('activate-intake')
    sub.add_parser('init-fixture').add_argument('file')
    registration=sub.add_parser('register-intake'); registration.add_argument('file'); registration.add_argument('--ttl',type=int,help='explicit local admin renewal in seconds, maximum 86400')
    discover = sub.add_parser('discover'); discover.add_argument('intake'); discover.add_argument('task')
    plan = sub.add_parser('plan'); plan.add_argument('session'); plan.add_argument('intake'); plan.add_argument('task'); plan.add_argument('--goal',required=True); plan.add_argument('--context',action='append',default=[]);plan.add_argument('--requirements')
    for name in ('status','preview','replan','recover-plan','activate'):
        entry=sub.add_parser(name);entry.add_argument('session')
        if name=='replan':
            entry.add_argument('--requirements')
            entry.add_argument('--clarification')
    decide = sub.add_parser('decide'); decide.add_argument('session'); decide.add_argument('decision',choices=('approve','reject','pause'))
    export = sub.add_parser('export'); export.add_argument('session'); export.add_argument('output',type=Path)
    replay = sub.add_parser('replay'); replay.add_argument('file')
    execute = sub.add_parser('execute'); execute.add_argument('session'); execute.add_argument('--command',dest='execution_command',choices=('start','recover','resume','status'),default='start'); execute.add_argument('--worker-mode',choices=('scripted','fake','replay','live')); execute.add_argument('--responses'); execute.add_argument('--worker-records'); execute.add_argument('--classifier-mode',choices=('disabled','fake','jev'),default='disabled')
    args = parser.parse_args(argv)
    if args.command=='capabilities':
        from atomicroot.integration.dynamic_proposal import capability_catalog
        print(json.dumps(capability_catalog(),indent=2));return 0
    if args.command=='dynamic-schema':
        from atomicroot.integration.dynamic_proposal import proposal_schema as dynamic_schema
        print(json.dumps(dynamic_schema(),indent=2));return 0
    if args.command=='workspace-schema':
        from atomicroot.integration.workspace import workspace_schema
        print(json.dumps(workspace_schema(),indent=2));return 0
    if args.command in {'schema','artifact-schema'}:
        print(json.dumps(proposal_schema() if args.command=='schema' else artifact_schema(),indent=2)); return 0
    if args.command == 'environment-schema':
        print(json.dumps(environment_schema(),indent=2)); return 0
    if args.command == 'environment-preview':
        try:
            print(json.dumps(dict(prepare_environment(load(args.file)), observed=point()),indent=2,ensure_ascii=False)); return 0
        except (ValueError, KeyError, TypeError) as exc:
            print(json.dumps(dict(status='REJECTED',reason=str(exc)[:256],observed=point()))); return 1
    args.directory.mkdir(parents=True,exist_ok=True)
    key_path = args.directory/'signing.key'
    if not key_path.exists():
        if args.command not in {'init-fixture','init-environment'}: parser.error('initialize a user environment with init-environment first')
        key_path.write_bytes(bytes(SigningKey.generate())); key_path.chmod(0o600)
    runtime = FrameworkRuntime(str(args.directory/'ledger.sqlite'),signing_key=SigningKey(key_path.read_bytes()))
    try:
        user, approver = local_identities(runtime)
        configured = runtime.store.get_state('workspace:environment') is not None
        args.planner_mode = args.planner_mode or ('fake' if args.proposal else 'live' if configured else 'fake')
        if args.command == 'execute':
            args.worker_mode = args.worker_mode or ('scripted' if args.responses else 'live' if configured else 'scripted')
        progress=Progress(args.directory/'progress.jsonl',quiet=args.quiet_progress)
        from atomicroot.integration import planning as protocol
        if args.proposal_protocol=='dynamic':
            from atomicroot.integration import dynamic_proposal as protocol
        elif hasattr(args,'session'):
            try:
                version=GoalService(runtime)._revision(args.session)['prompt_version']
                from atomicroot.integration.planning import protocol_for_version
                protocol=protocol_for_version(version)
            except ValueError:pass
        model=None
        if args.command in {'plan','replan','recover-plan'}:
            intake=args.intake if args.command=='plan' else GoalService(runtime)._session(args.session,user)['intake']
            with runtime.store.snapshot() as snap: config=snap.read('goalintake:'+intake)[1]
            if not config: raise ValueError('register an authorized intake before planning')
            if args.planner_mode=='fake':
                if not args.proposal: raise ValueError('fake planner needs explicit --proposal fixture')
                value=load(args.proposal); model=FakeModel(lambda _:value,provider=config['provider'])
                if model.model!=config['model']: raise ValueError('fake planner model must match approved intake')
            elif args.planner_mode=='replay':
                if not args.records: raise ValueError('exact --records required')
                model=ModelTape(provider=config['provider'],model=config['model'],prompt_version=protocol.PLANNER_VERSION,records=load(args.records))
            else:
                if not args.authorize_live: raise PermissionError('live planning requires explicit --authorize-live')
                caps=runtime.tasks.status(config['intake_task'],user)['resolved']['spec']['limits']['inference']
                limits=Limits(**caps)
                if config['provider']!='ollama' and limits.spend_cap_usd is None: raise ValueError('paid live planning requires verified pricing and an explicit spend cap')
                model=live_model(config['provider'],config['model'],limits)
        service=GoalService(runtime,model,progress=progress,protocol=protocol)
        if args.command=='init-environment': result=initialize_environment(runtime,load(args.file),args.accept_digest)
        elif args.command in {'intake-preview','decide-intake','activate-intake'}:
            record=runtime.store.get_state('workspace:environment')
            if not record or 'preview' not in record: raise ValueError('no environment intake preview')
            if args.command=='intake-preview': result=record
            elif args.command=='decide-intake': result=runtime.broker.decide(record['preview']['review_id'],args.decision=='approve',approver)
            else: result=activate_intake(runtime,approver)
        elif args.command=='init-fixture': result=init_fixture(runtime,load(args.file))
        elif args.command=='register-intake':
            config=load(args.file)
            if args.ttl is not None:
                if not 0<args.ttl<=86400: raise ValueError('TTL must be in (0,86400]')
                config={**config,'expires':runtime.store.now()+args.ttl}
            result=service.register_intake(config,Principal('local-admin',frozenset({'admin'})))
        elif args.command=='discover': result=service.discover(args.intake,args.task,user)
        elif args.command=='plan':
            service.plan(args.session,args.goal,args.intake,args.task,user,context_resources=args.context,
                         requirements=load(args.requirements) if args.requirements else None)
            result=service.status(args.session,user)
        elif args.command in {'replan','recover-plan'}:
            record=service._session(args.session,user)
            service.plan(args.session,record['data']['goal'],record['intake'],record['task'],user,context_resources=record['data']['context_resources'],
                replan=args.command=='replan',recover=args.command=='recover-plan',
                requirements=load(args.requirements) if getattr(args,'requirements',None) else None,
                clarification=getattr(args,'clarification',None))
            result=service.status(args.session,user)
        elif args.command in {'status','preview'}: result=service.status(args.session,user,private=args.command=='preview')
        elif args.command=='decide': result=service.decide(args.session,args.decision,approver)
        elif args.command=='activate':
            data=service._revision(args.session)
            if data.get('bundle'):
                resources=frozenset(r['resource'] for r in data['preview']['preview']['changes']['resources'])
                approver=Principal(approver.subject,approver.roles|{'admin','owner'},approver.tasks,resources)
            result=service.activate(args.session,approver)
        elif args.command=='export':
            # Explicit local private export. Do not overwrite older evidence.
            args.output.parent.mkdir(parents=True,exist_ok=True)
            with args.output.open('x',encoding='utf-8') as stream: json.dump(service.export(args.session,user),stream,indent=2)
            args.output.chmod(0o600); result={'status':'EXPORTED','path':str(args.output)}
        elif args.command=='replay':
            raw=Path(args.file).read_bytes()
            if len(raw)>4*1024*1024: raise ValueError('artifact exceeds byte bound')
            report=service.replay(json.loads(raw),user)
            result={'match':report['match'],'preview':report['result'].get('preview'),'scope':report['result'].get('scope','initial intake/proposal replay')}
        else:
            def factory(task,caller,budget):
                flow=build_workflow(runtime,args.directory/'executor.sqlite',task,caller,mode=args.worker_mode,
                    responses=load(args.responses) if args.responses else None,replay=load(args.worker_records) if args.worker_records else None,
                    authorize_live=args.authorize_live,classifier_mode=args.classifier_mode,progress=progress)
                if flow.bridge: flow.bridge.budget=budget
                return flow
            result=service.execute(args.session,user,factory,command=args.execution_command)
        print(json.dumps(dict(result, observed=point()),indent=2,ensure_ascii=False))
        if args.command=='execute': return 0 if result.get('status') in {'SATISFIED','REVIEW_WAIT','DELIVERY_UNKNOWN'} else 1
        return 1 if result.get('match') is False or result.get('status') in {'INVALID_PROPOSAL','PLANNING_FAILED','UNSUPPORTED','CONTEXT_LIMIT','NEEDS_CAPABILITY','NEEDS_PERMISSION'} else 0
    except Exception as exc:
        print(json.dumps({'status':'REJECTED','error':type(exc).__name__,'reason':str(exc)[:256],'observed':point()})); return 1
    finally: runtime.store.close()


if __name__=='__main__': raise SystemExit(main())
