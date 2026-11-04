"""One small real loop/branch/call protected build, reusing accepted CLI/TUI evidence."""
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
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--existing',type=Path,required=True);parser.add_argument('--pin',type=Path,required=True)
    opts=parser.parse_args(args);previous=opts.existing.resolve(strict=True)
    accepted=project.read(previous/'final-acceptance.json')
    if accepted.get('status')!='STAGE3_DECLARED_SCOPE_ACCEPTANCE_MET':raise RuntimeError('Missing accepted CLI/TUI gate')
    app=Path(__file__).resolve().parent.parent
    if hashlib.sha256((app/'binarycachelab.jar').read_bytes()).hexdigest()!=accepted['jar_sha256']:raise RuntimeError('Accepted checker JAR differs')
    oldrun=previous/'runs'/Path(accepted['cli']['run']).name
    verify_workflow_report.verify(oldrun)
    root=Path(tempfile.mkdtemp(prefix='protection-constructs-',dir=app/'experiments'))
    for name in ('bcl.toml','loop-contract.json','tables_loop.asm'):shutil.copyfile(app/'examples/protection'/name,root/name)
    config=root/'bcl.toml';text=config.read_text(encoding='utf-8').replace('approval_profile = "contract.json"','approval_profile = "loop-contract.json"')
    text=re.sub(r'^pin = .*$','pin = '+json.dumps(str(opts.pin.resolve())),text,flags=re.M);config.write_text(text,encoding='utf-8')
    subprocess.run(['nasm','-f','elf64',str(root/'tables_loop.asm'),'-o',str(root/'original.o')],check=True)
    subprocess.run(['ld','-m','elf_x86_64','-e','_start',str(root/'original.o'),'-o',str(root/'original')],check=True)
    subprocess.run([sys.executable,str(app/'scripts/test_dashboard_native.py'),'--config',str(config),
                    '--input',str(root/'original'),'--expect-protected'],check=True,cwd=app)
    runs=list((root/'runs').glob('*'))
    if len(runs)!=1:raise RuntimeError('Expected one TUI-launched protected loop build')
    run=runs[0];certificate=project.read(run/'validation/protection/certified-occurrences.json')
    if certificate.get('status')!='EXHAUSTIVE_REFERENCE_SEQUENCES_BOUND':raise RuntimeError('Repeated-access certificate missing')
    for variant in ('original','baseline','transformed'):
        for events in certificate['sequences'][variant].values():
            if len(events)!=4 or len({row['ip'] for row in events})!=2:raise RuntimeError('Fixture did not exercise repeated memory sites')
    report=project.read(run/'report.json')
    if report['comparison']['unmatched_events'] or report['checks']['event_correspondence']['status']!='PASS':raise RuntimeError('Repeated native access correspondence incomplete')
    for secret in ('0','1'):
        subprocess.run([str(run/'protected/program'),secret],check=True,capture_output=True,timeout=10)
    result={'status':report['overall_verdict'],'run':str(run),'protected_executable':str(run/'protected/program'),
            'events':{v:row['events'] for v,row in report['event_statistics'].items()},'entrypoint':'TUI Run analysis',
            'integrity':verify_workflow_report.verify(run)['status']}
    final={'schema':'bcl-stage3-supported-constructs-1','status':'STAGE3_SUPPORTED_CONSTRUCTS_ACCEPTANCE_MET',
           'native_loop_call_build':result,'prior_cli_tui_acceptance':str(previous),
           'tested_native_constructs':['loop','conditional branch','function call','repeated memory site','indexed addressing','RIP-relative address','REX registers','two data regions'],
           'scope':accepted['scope'],'jar_sha256':accepted['jar_sha256'],'source_inputs':project.read(app/'test-inputs.json')}
    project.save(root/'constructs-acceptance.json',final)
    if os.environ.get('BCL_NATIVE_EXPORT'):
        destination=Path(os.environ['BCL_NATIVE_EXPORT']).resolve();destination.mkdir(parents=True,exist_ok=True)
        export=Path(tempfile.mkdtemp(prefix='native-stage3-constructs-',dir=destination))
        shutil.copytree(root,export/'constructs');shutil.copytree(previous,export/'prior-interfaces')
        shutil.copyfile(app/'python-tests.log',export/'python-tests.log')
        shutil.copyfile(app/'native-dashboard.log',export/'native-dashboard.log')
        final['exported_evidence']=str(export);project.save(export/'constructs-acceptance.json',final)
    print(json.dumps({k:v for k,v in final.items() if k!='source_inputs'},indent=2),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
