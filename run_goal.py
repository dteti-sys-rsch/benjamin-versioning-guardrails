"""Interactive System B: user environment and goal, live proposal, review, execution."""
import argparse
import json
from pathlib import Path

from nacl.signing import SigningKey
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.environment import prepare_environment, initialize_environment, activate_intake, local_identities
from atomicroot.integration.goals import GoalService
from atomicroot.integration.providers import Limits, live_model
from atomicroot.integration.progress import Progress
from atomicroot.observability import point
from phase36_cli import load
from phase37_cli import build_workflow


def run(environment, goal, directory, *, authorize_live, ask=input, model_factory=live_model,
        protocol=None, requirements=None, resource_inputs=None):
    """CLI operator owns configuration/review. No model can answer these prompts."""
    if not authorize_live: raise PermissionError('explicit --authorize-live required')
    from atomicroot.integration import dynamic_proposal, planning
    workspace_mode=environment.get('schema_version')==2
    if workspace_mode:
        from atomicroot.integration.workspace import task_environment
        environment=task_environment(environment,goal)
        protocol=protocol or dynamic_proposal
    protocol=protocol or planning
    prepared=prepare_environment(environment)
    limits=Limits(**prepared['intake_spec']['limits']['inference'])
    provider=environment['provider']
    if provider['destination'] != 'ollama' and limits.spend_cap_usd is None:
        raise PermissionError('paid live planning requires verified pricing and explicit spend cap')
    directory=Path(directory)
    if directory.exists(): raise ValueError('output already exists; use atomicroot_cli.py to resume the existing workspace')
    directory.mkdir(parents=True)
    def save(name, value):
        path=directory/name
        path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8'); path.chmod(0o600)
    save('invocation.json',dict(entrypoint='run_goal.py',goal=goal,output=str(directory),
        environment_digest=prepared['digest'],authorize_live=authorize_live,observed=point()))
    save('environment-preview.json',dict(prepared,observed=point()))
    print(json.dumps(dict(prepared,observed=point()),indent=2,ensure_ascii=False))
    if ask('Accept environment permissions? Type the displayed digest, or reject: ').strip() != prepared['digest']:
        result=dict(status='ENVIRONMENT_REJECTED',observed=point()); save('result.json',result); return result
    key=SigningKey.generate()
    key_path=directory/'signing.key'; key_path.write_bytes(bytes(key)); key_path.chmod(0o600)
    runtime=FrameworkRuntime(str(directory/'ledger.sqlite'),signing_key=key)
    service=None
    try:
        setup=initialize_environment(runtime,environment,prepared['digest'])
        save('intake-preview.json',setup)
        print(json.dumps(setup['preview'],indent=2,ensure_ascii=False))
        user,approver=local_identities(runtime)
        # Workspace digest approval above includes the deterministic intake spec.
        approved=workspace_mode or ask('Approve this exact intake/provider preview? approve/reject: ').strip()=='approve'
        runtime.broker.decide(setup['preview']['review_id'],approved,approver)
        if not approved:
            result=dict(status='INTAKE_REJECTED',observed=point()); save('result.json',result); return result
        activate_intake(runtime,approver)
        model=model_factory(provider['destination'],provider['model'],limits)
        progress=Progress(directory/'progress.jsonl')
        service=GoalService(runtime,model,progress=progress,protocol=protocol,resource_inputs=resource_inputs)
        service.plan('goal',goal,'planning',environment['task_id'],user,requirements=requirements)
        preview=service.status('goal',user,private=True)
        save('proposal-preview.json',preview)
        save('goal-artifact.json',service.export('goal',user))
        print(json.dumps(preview,indent=2,ensure_ascii=False))
        if preview['status']=='NEEDS_CAPABILITY':
            decision=ask('Review capability specification only; execution stays blocked. approve/reject/pause: ').strip()
            service.decide('goal',decision if decision in {'approve','reject','pause'} else 'pause',approver)
            result=dict(status='NEEDS_CAPABILITY',execution_authorized=False,observed=point())
            save('goal-artifact.json',service.export('goal',user));save('result.json',result);return result
        if preview['status'] != 'REVIEW_WAIT':
            result=dict(status=preview['status'],observed=point()); save('result.json',result); return result
        decision=ask('Approve this exact business proposal? approve/reject/pause: ').strip()
        if decision not in {'approve','reject','pause'}: decision='pause'
        service.decide('goal',decision,approver)
        if decision != 'approve':
            result=dict(status='REJECTED' if decision=='reject' else 'PAUSED',observed=point())
        else:
            if preview.get('bundle'):
                from atomicroot.framework.identity import Principal
                operator=Principal(approver.subject,approver.roles|{'admin','owner'},approver.tasks,frozenset(resource_inputs or {}))
            else:operator=approver
            service.activate('goal',operator)
            def factory(task,caller,budget):
                flow=build_workflow(runtime,directory/'executor.sqlite',task,caller,mode='live',authorize_live=True,progress=progress)
                if flow.bridge: flow.bridge.budget=budget
                return flow
            result=dict(service.execute('goal',user,factory),observed=point())
        save('goal-artifact.json',service.export('goal',user)); save('result.json',result)
        return result
    except Exception as exc:
        result=dict(status='FAILED',error=type(exc).__name__,reason=str(exc)[:256],observed=point())
        save('result.json',result)
        if service:
            try: save('goal-artifact.json',service.export('goal',user))
            except (ValueError,PermissionError): pass
        raise
    finally: runtime.store.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment',required=True)
    parser.add_argument('--goal',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--authorize-live',action='store_true')
    parser.add_argument('--requirements',help='operator-authored typed requirements JSON')
    parser.add_argument('--resource-inputs',help='operator-supplied new resource records keyed by resource ID')
    args=parser.parse_args(argv)
    try:
        result=run(load(args.environment),args.goal,args.output,authorize_live=args.authorize_live,
            requirements=load(args.requirements) if args.requirements else None,
            resource_inputs=load(args.resource_inputs) if args.resource_inputs else None)
        print(json.dumps(result,indent=2,ensure_ascii=False))
        return 0 if result['status'] in {'SATISFIED','PAUSED','REVIEW_WAIT','DELIVERY_UNKNOWN'} else 1
    except Exception as exc:
        print(json.dumps(dict(status='INVOCATION_FAILED',error=type(exc).__name__,reason=str(exc)[:256],observed=point()))); return 1


if __name__=='__main__': raise SystemExit(main())
