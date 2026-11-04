"""Native checks for ordinary ASM; real NASM, FoxDec and PIN are required."""
import json
import os
import math
from pathlib import Path
import subprocess
import sys
import verify_workflow_report


def main():
    root=Path(__file__).resolve().parent.parent;config=root/'examples/workflow/bcl.toml';runs=config.parent/'runs';results=[]
    if sys.argv[1:] not in ([],['--prime-only']):raise ValueError('Expected --prime-only or no arguments')
    sources=('prime_numbers.asm',) if sys.argv[1:] else ('hello_start.asm','hello_main.asm','prime_numbers.asm','control_loop.asm','control_nested.asm','control_indirect.asm','control_recursive.asm')
    for source in sources:
        before=set(runs.glob('*')) if runs.exists() else set()
        process=subprocess.run([str(root/'bcl'),str(root/'examples/programs'/source),'--config',str(config)],cwd=root)
        fresh=set(runs.glob('*'))-before
        if len(fresh)!=1:raise RuntimeError('Expected one retained program run')
        run=fresh.pop();report=json.loads((run/'report.json').read_text())
        if process.returncode!=0 or report['overall_verdict']!='PASS':
            logs=sorted((p for p in (run/'logs').glob('*.log') if p.name[:1].isdigit()),key=lambda p:p.name)
            if logs:
                print('Last command log: '+str(logs[-1]),flush=True)
                print('\n'.join(logs[-1].read_text(errors='replace').splitlines()[-80:]),flush=True)
            raise RuntimeError('Program check failed: '+source+'; report '+str(run/'report.json'))
        if report['configuration'].get('mode')!='program' or report['security_assessment']['status']!='NOT_CONFIGURED':raise RuntimeError('Program run made an undeclared security claim')
        if set(report['artifacts'])!={'original','baseline'}:raise RuntimeError('Unexpected transformed program')
        if report['configuration']['execution']['repetitions']!=1:raise RuntimeError('Program default repeated an input')
        if report['checks']['stage_6']['required'] or report['checks']['stage_7']['required']:raise RuntimeError('Unrequested transform marked required')
        expected=(('\n'.join(str(n) for n in range(2,1001) if all(n%d for d in range(2,math.isqrt(n)+1)))+'\n').encode() if source=='prime_numbers.asm' else {'control_loop.asm':b'OK\n','control_nested.asm':b'NESTED\n','control_indirect.asm':b'INDIRECT\n','control_recursive.asm':b'720\n'}.get(source,b'Hello, World\n'))
        for variant in ('original','baseline'):
            for repeat in range(report['configuration']['execution']['repetitions']):
                for mode in ('native','pin'):
                    if (run/'raw'/variant/'default'/str(repeat)/(mode+'.stdout')).read_bytes()!=expected:raise RuntimeError('Wrong output for '+source)
        if source=='hello_start.asm' and report['event_statistics']['original']['events']!=0:raise RuntimeError('Unexpected data access in syscall-only original')
        result=verify_workflow_report.verify(run)
        results.append({'input':source,'status':'PASS','events':{v:s['events'] for v,s in report['event_statistics'].items()},'security':'NOT_CONFIGURED','integrity':result['status'],'run':str(run)})
    print(json.dumps({'status':'GENERAL_PROGRAM_NATIVE_EXPECTATIONS_MET','programs':results},indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
