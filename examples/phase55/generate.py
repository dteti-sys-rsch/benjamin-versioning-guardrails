"""Two synthetic B goals, reviewed execution A and fresh-key offline proposal replay."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.integration.config_workflow import ConfigWorkflow
from atomicroot.integration.goals import GoalService
from atomicroot.integration.providers import FakeModel
from atomicroot.integration.planning import proposal_schema, artifact_schema
from atomicroot.observability import Stopwatch, point
from atomicroot.tests.phase3_support import Clock
from atomicroot.tests.phase55_support import initialize, proposal, GOAL


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    timer=Stopwatch(); results=[]
    for index,goal in enumerate(('Read the file only.',GOAL)):
        directory=output/('goal-'+str(index+1)); directory.mkdir()
        # Runtime ledgers/checkpoints are local; signing keys stay in memory.
        clock=Clock(); clock.value=datetime.now(timezone.utc)
        runtime=FrameworkRuntime(directory/'ledger.sqlite',clock=clock)
        try:
            user,approver,_,spec,config,fixture,intake_spec=initialize(runtime)
            if index==0:
                spec['scope']=[r for r in spec['scope'] if r['tool']=='read_document']
                spec['agents'][0]['scope']=spec['scope']
                spec['workflow']['nodes']=[{'id':'inspect','agent':'writer','depends_on':[]}]
                spec['acceptance']=[{'kind':'read','resource':'file'}]
            value=proposal(spec,goal)
            service=GoalService(runtime,FakeModel(lambda _:deepcopy(value)))
            plan=service.plan('example',goal,'planning','write-a',user)
            if plan['status']!='REVIEW_WAIT': raise AssertionError(plan)
            # Explicit trusted synthetic fixture review; never a worker right.
            service.decide('example','pause',approver)
            service.decide('example','approve',approver); service.activate('example',approver)
            ref=spec['resources'][0]
            class Driver:
                binding={'fixture':'phase55-synthetic-worker-v1','spec':spec}
                def __call__(self,view):
                    if view['node'] in {'inspect','read'}:
                        if view['observations']: return {'kind':'done','summary':'Read receipt observed'}
                        return {'kind':'action','tool':'read_document','args':{'resource':'file','digest':ref['digest']}}
                    receipt=next(o['detail']['receipt']['receipt_id'] for o in view['observations'] if o.get('detail',{}).get('tool')=='read_document')
                    return {'kind':'action','tool':'update_document','args':{'resource':'file','digest':ref['digest'],'content':'Synthetic B output','read_receipt':receipt}}
            factory=lambda task,caller,budget:ConfigWorkflow(runtime,directory/'executor.sqlite',task=task,caller=caller,worker=Driver())
            execution=service.execute('example',user,factory)
            if execution['status']!='SATISFIED': raise AssertionError(execution)
            count=len(runtime.store.inspect_outbox())
            if service.execute('example',user,factory,command='recover')['status']!='SATISFIED': raise AssertionError('recover failed')
            if len(runtime.store.inspect_outbox())!=count: raise AssertionError('duplicate effect after recover')
            # Export was recorded before writes changed the catalog: replay binds
            # the original discovery, not a reconstructed current business state.
            artifact=service.export('example',user)
            replay_clock=Clock(); replay_clock.value=clock.value
            replay_runtime=FrameworkRuntime(directory/'replay.sqlite',clock=replay_clock)
            try:
                replay_user,*_=initialize(replay_runtime)
                repeated=GoalService(replay_runtime).replay(artifact,replay_user)
                if not repeated['match']: raise AssertionError(repeated)
            finally: replay_runtime.store.close()
            save(directory/'proposal-fixture.json',value)
            save(directory/'goal-artifact.json',artifact)
            save(directory/'execution.json',execution)
            if index==0:
                save(output/'trusted-fixture.json',fixture); save(output/'intake-spec.json',intake_spec); save(output/'intake-permission.json',config)
            results.append({'goal':goal,'status':execution['status'],'proposal_replay':True,'checkpoint_recover':True,
                'business_effects':'SIMULATED','model_origin':'OFFLINE_FAKE_PREBUILT_PROPOSAL','live_synthesis':'NOT RUN'})
        finally: runtime.store.close()
    negatives=[]
    for name in ('unsupported','forged-authority','stale-review'):
        directory=output/name; directory.mkdir()
        clock=Clock(); clock.value=datetime.now(timezone.utc)
        runtime=FrameworkRuntime(directory/'ledger.sqlite',clock=clock)
        try:
            user,approver,_,spec,*_=initialize(runtime)
            value=proposal(spec)
            if name=='unsupported': value={'status':'UNSUPPORTED','spec':None,'assumptions':[], 'unsupported':['No registered adapter/fact for this requirement'],'questions':[],'origin':[]}
            if name=='forged-authority': value['approved_by']='user approved'
            service=GoalService(runtime,FakeModel(lambda _:value))
            result=service.plan(name,GOAL,'planning','write-a',user)
            reason=None
            if name=='stale-review':
                from atomicroot.framework.identity import Principal
                owner=Principal('fixture-owner',frozenset({'owner'}),resources=frozenset({'file'}))
                runtime.storage.ingest('file','Trusted owner mutation before review',owner)
                try: service.decide(name,'approve',approver)
                except ValueError: reason='STALE_REVIEW_REJECTED'
                if reason is None: raise AssertionError('stale approval accepted')
            if runtime.store.get_state('contract3:write-a') is not None: raise AssertionError('negative case activated business authority')
            if any(r['task']=='write-a' for r in runtime.store.inspect_outbox()): raise AssertionError('negative business effect')
            save(directory/'goal-artifact.json',service.export(name,user))
            negatives.append({'scenario':name,'status':result['status'],'rejection':reason,'business_intents':0,
                'fixture_actor':'trusted owner mutation' if name=='stale-review' else 'untrusted proposal'})
        finally: runtime.store.close()
    save(output/'proposal-schema-v1.json',proposal_schema())
    save(output/'goal-replay-schema-v1.json',artifact_schema())
    report={'schema_version':1,'command':[sys.executable,str(Path(__file__).resolve()),*(sys.argv[1:] if argv is None else argv)],
        'runs':results,'negative_cases':negatives,'live_validation':'NOT RUN','live_calls':0,'observed_timing':timer.finish(),'generated':point(),
        'scope':'Fase 5.5 finite offline B; no Phase 6 benchmark'}
    save(output/'validation.json',report)
    print(json.dumps({'goals':len(results),'satisfied':len(results),'fresh_key_proposal_replays':2,'directory':str(output)}))


if __name__=='__main__': main()
