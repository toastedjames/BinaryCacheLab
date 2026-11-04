"""Drive the real Java TUI and verify its displayed result against its real run report."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import verify_workflow_report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--saved',action='store_true');parser.add_argument('--expect',choices=('PASS','COMPROMISED'),default='PASS')
    parser.add_argument('--config',type=Path);parser.add_argument('--input',type=Path);parser.add_argument('--expect-protected',action='store_true');args=parser.parse_args()
    app = Path(__file__).resolve().parent.parent
    example = args.config.resolve().parent if args.config else app/'examples/workflow'
    log = app/'native-dashboard.log'
    before = set((example/'runs').glob('*')) if (example/'runs').exists() else set()
    command = [str(app/'bcl'), 'tui', '--config', str(args.config or example/'bcl.toml'), '--input', str(args.input or example/'sample1.asm')]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    ready = threading.Event(); internal_text = threading.Event(); failure = []; observed = []
    def consume():
        try:
            with log.open('w') as stream:
                for line in process.stdout:
                    stream.write(line);stream.flush()
                    # Screens are bounded. Raw subprocess output stays in its own log.
                    if len(observed)<2000: observed.append(line)
                    if 'Structured text report' in line: internal_text.set();ready.set()
                    if 'VERDICT:' in line or 'Analysis Complete' in line: ready.set()
        except Exception as error: failure.append(str(error));ready.set()
    reader=threading.Thread(target=consume,daemon=True);reader.start()
    try:
        process.stdin.write('A\nO\nB\nB\nC\nB\n'+('V\n' if args.saved else 'R\n'));process.stdin.flush()
        if not ready.wait(900): raise RuntimeError('Native TUI workflow timed out; inspect '+str(log))
        if failure: raise RuntimeError(failure[0])
        process.stdin.write(('B\n' if internal_text.is_set() else '')+'V\nB\nD\nB\nM\nQ\n');process.stdin.flush()
        process.wait(timeout=45);reader.join(timeout=5)
        if process.returncode != 0: raise RuntimeError('TUI exited '+str(process.returncode))
        runs=set((example/'runs').glob('*'))-before
        if args.saved:
            candidates=[p for p in before if (p/'report.json').is_file()]
            if not candidates: raise RuntimeError('No saved report found')
            run=max(candidates,key=lambda p:p.stat().st_mtime)
            if runs: raise RuntimeError('Saved-report viewing unexpectedly started a run')
        else:
            if len(runs)!=1: raise RuntimeError('Expected exactly one TUI-launched run')
            run=runs.pop()
        report=json.loads((run/'report.json').read_text())
        screen=''.join(observed)
        if ('BUILD / TRACE RESULT: ' if report['configuration'].get('mode')=='program' else 'VERDICT: ')+report['overall_verdict'] not in screen: raise RuntimeError('TUI verdict differs from report')
        for variant,stats in report['event_statistics'].items():
            if variant+' events: '+str(stats['events']) not in screen: raise RuntimeError('TUI event count differs: '+variant)
        if report['overall_verdict']!=args.expect:
            errors=[name+': '+row['status']+' - '+row['detail'] for name,row in report['checks'].items() if row.get('required') and row['status']!='PASS']
            raise RuntimeError('Unexpected native verdict: '+report['overall_verdict']+'\n'+'\n'.join(errors)+'\nReport: '+str(run/'report.json'))
        if args.expect_protected:
            if not report.get('protection',{}).get('published') or 'Protected build: PROTECTED_BUILD_APPROVED_WITHIN_BOUNDS' not in screen:
                raise RuntimeError('TUI did not expose the verified protected build')
        for expected in ('[R] Run analysis','[A] Advanced tools','Instruction correspondence','Observer','Configuration',('Secret comparisons' if report.get('presentation',{}).get('schema')=='bcl-readable-decisions-2' else 'Trace comparisons' if report['configuration'].get('mode')=='program' else 'Trace differences')):
            if expected not in screen: raise RuntimeError('Navigation screen missing: '+expected)
        if report['configuration'].get('mode')!='program' and not args.saved and 'FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED' not in (run/'comparisons/trace_diff.txt').read_text():
            raise RuntimeError('TUI did not show all findings for the changed access')
        result=verify_workflow_report.verify(run)
        result.update(status='NATIVE_TUI_SAVED_REPORT_EXPECTATIONS_MET' if args.saved else 'NATIVE_TUI_EXPECTATIONS_MET',run=str(run),screen_log=str(log),verdict=report['overall_verdict'])
        print(json.dumps(result,indent=2))
        return 0
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=45)
            except subprocess.TimeoutExpired: process.kill();process.wait()
        if process.stdin: process.stdin.close()
        if process.stdout: process.stdout.close()


if __name__=='__main__': raise SystemExit(main())
