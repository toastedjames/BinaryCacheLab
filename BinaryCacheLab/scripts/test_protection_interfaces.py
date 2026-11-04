"""Final real CLI/TUI gate plus read-only replay of accepted prevention controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import project
import test_protection_native as native
import verify_workflow_report


def main(args=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--existing',type=Path,required=True)
    parser.add_argument('--pin',type=Path,required=True)
    opts=parser.parse_args(args)
    previous=opts.existing.resolve(strict=True)
    summary=project.read(previous/'result.json')
    if summary.get('status')!='PROTECTED_NATIVE_PIPELINE_AND_PREVENTION_EXPECTATIONS_MET':raise RuntimeError('Missing accepted prevention result')
    app=Path(__file__).resolve().parent.parent
    root=Path(tempfile.mkdtemp(prefix='protection-final-',dir=app/'experiments'))
    verified=[]
    for index,row in enumerate(summary['results']):
        run=Path(row['run']).resolve(strict=True)
        if not run.is_relative_to(previous):raise RuntimeError('Evidence run outside accepted experiment')
        integrity=verify_workflow_report.verify(run)
        report=project.read(run/'report.json')
        if row['kind']=='ORIGINAL_ALREADY_DISTINGUISHES':
            if report.get('protection',{}).get('published') or (run/'protected/program').exists():raise RuntimeError('Negative control was published')
            if not any(item['status']=='ORIGINAL_ALREADY_DISTINGUISHES' for item in report['protection'].get('original_pairs',[])):raise RuntimeError('Negative control lacks original-distinction evidence')
        else:
            target=root/('approval-replay-'+str(index)+'.json')
            subprocess.run([os.environ.get('JAVA','java'),'-jar',str(app/'binarycachelab.jar'),'approve-transform',
                            str(run/'validation/protection/approval.json'),'--report',str(target)],check=True,stdout=subprocess.DEVNULL)
            replay=project.read(target)
            if not replay.get('bounded_transformation_approved') or replay['candidate_sha256']!=report['protection']['sha256']:
                raise RuntimeError('Accepted protected binary did not pass current exact-byte approval')
            for pair in report['security_assessment']['secret_pairs']:
                outcomes=pair['by_variant']
                if not outcomes['original']['equal_across_secrets'] or not outcomes['transformed']['equal_across_secrets']:raise RuntimeError('Accepted source/protected equality differs')
                if row['kind']=='CONTROLLED_PREVENTION' and outcomes['baseline']['equal_across_secrets']:raise RuntimeError('Controlled introduced distinction missing')
        verified.append({'kind':row['kind'],'integrity':integrity['status'],'run':str(run)})
    if {row['kind'] for row in verified}!={'NATIVE_ELF_PROTECTED_BUILD','CONTROLLED_PREVENTION','ORIGINAL_ALREADY_DISTINGUISHES'}:
        raise RuntimeError('Positive, prevention and negative controls are all required')
    for name in ('bcl.toml','contract.json','tables.asm'):shutil.copyfile(app/'examples/protection'/name,root/name)
    config=root/'bcl.toml';text=config.read_text(encoding='utf-8')
    text=re.sub(r'^pin = .*$', 'pin = '+json.dumps(str(opts.pin.resolve())),text,flags=re.M)
    config.write_text(text,encoding='utf-8')
    subprocess.run(['nasm','-f','elf64',str(root/'tables.asm'),'-o',str(root/'original.o')],check=True)
    subprocess.run(['ld','-m','elf_x86_64','-e','_start',str(root/'original.o'),'-o',str(root/'original')],check=True)
    cli=native.run_case(config,root/'original')
    subprocess.run([sys.executable,str(app/'scripts/test_dashboard_native.py'),'--saved','--config',str(config),
                    '--input',str(root/'original'),'--expect-protected'],check=True,cwd=app)
    result={'schema':'bcl-stage3-final-acceptance-1','status':'STAGE3_DECLARED_SCOPE_ACCEPTANCE_MET',
            'scope':'Explicit finite static integer entry/input contracts, declared literal data regions and ordered 64-byte virtual data lines',
            'cli':cli,'tui':'NATIVE_SAVED_PROTECTED_REPORT_VERIFIED','accepted_control_replays':verified,
            'jar_sha256':hashlib.sha256((app/'binarycachelab.jar').read_bytes()).hexdigest(),
            'source_inputs':project.read(app/'test-inputs.json'),
            'universal_asm_support':False,'physical_cache_or_timing_guarantee':False}
    project.save(root/'final-acceptance.json',result)
    if os.environ.get('BCL_NATIVE_EXPORT'):
        destination=Path(os.environ['BCL_NATIVE_EXPORT']).resolve();destination.mkdir(parents=True,exist_ok=True)
        export=Path(tempfile.mkdtemp(prefix='native-stage3-final-',dir=destination))
        shutil.copytree(root,export/'current')
        shutil.copytree(previous,export/'accepted-controls')
        shutil.copyfile(app/'native-dashboard.log',export/'native-dashboard.log')
        shutil.copyfile(app/'python-tests.log',export/'python-tests.log')
        result['exported_evidence']=str(export)
        project.save(export/'final-acceptance.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='source_inputs'},indent=2),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
