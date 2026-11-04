"""Native required-reference and finite security gates, including a leakage control."""
import json
from pathlib import Path
import subprocess
import sys
import verify_workflow_report


def main():
    app=Path(__file__).resolve().parent.parent;example=app/'examples/workflow';results=[]
    cases=[('secret_line.asm','COMPROMISED')] if sys.argv[1:]==['--control-only'] else [('sample1.asm','PASS'),('secret_line.asm','COMPROMISED')]
    if sys.argv[1:] not in ([], ['--control-only']):raise ValueError('Expected no arguments or --control-only')
    for source,expected in cases:
        before=set((example/'runs').glob('*')) if (example/'runs').exists() else set()
        print('Checking '+source+'; expected '+expected,flush=True)
        command=[sys.executable,str(app/'scripts/test_dashboard_native.py')] if expected=='PASS' else [str(app/'bcl'),str(example/source),'--config',str(example/'bcl.toml')]
        process=subprocess.run(command,cwd=example)
        if process.returncode != (0 if expected=='PASS' else 5):raise RuntimeError('Unexpected workflow exit for '+source+': '+str(process.returncode))
        runs=set((example/'runs').glob('*'))-before
        if len(runs)!=1:raise RuntimeError('Expected one new run for '+source)
        run=runs.pop();report=json.loads((run/'report.json').read_text())
        if report['overall_verdict']!=expected:raise RuntimeError('Unexpected verdict')
        if report['configuration']['execution']['repetitions']!=1:raise RuntimeError('Default workflow repeated an input')
        if report['checks']['repeat_stability']['status']!='NOT_REQUESTED':raise RuntimeError('Single-run default claimed repeat stability')
        text=(run/'comparisons/trace_diff.txt').read_text()
        if 'G1: secret0' not in text or 'Repetition:' in text or 'COMPARISON 20' in text:raise RuntimeError('Human report is not grouped by secret inputs')
        if 'FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED' not in text:raise RuntimeError('Human report omitted combined findings')
        if 'Unique access comparisons: 6\n' not in text:raise RuntimeError('Fixture must show six unique build-access pairs, not duplicate classification rows')
        if len(report['security_assessment'].get('secret_pairs',[]))!=1:raise RuntimeError('Expected one secret decision group for two keys')
        if report['checks']['references']['status']!='PASS' or not report['checks']['references']['required']:raise RuntimeError('Required reference check did not pass')
        if report['security_assessment']['status']=='NOT_ASSESSED':raise RuntimeError('Security test was skipped')
        reference=json.loads((run/'validation/reference_checks.json').read_text())
        if reference.get('verified') is not True or len(reference['pairs'])!=3:raise RuntimeError('Missing three-way reference correspondence')
        if expected=='COMPROMISED' and report['security_assessment']['difference_origin']!='PRESENT_IN_ORIGINAL':raise RuntimeError('Existing leakage incorrectly attributed to rebuilding')
        verified=verify_workflow_report.verify(run)
        results.append({'input':source,'verdict':expected,'references':'PASS','security':report['security_assessment']['status'],'run':str(run),'integrity':verified['status']})
    print(json.dumps({'status':'REFERENCE_SECURITY_EXPECTATIONS_MET','results':results,'scope':'Byte-verified declared lookup-kernel contract and finite configured secret pairs; no whole-program or physical-cache proof'},indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
