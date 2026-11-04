"""Small real FoxDec/NASM/ld/PIN protection integration and prevention controls.

At most 20,000 operands per capture, 12 captures per successful case. The
controlled case injects 12 real data bytes into lifted NASM before rebuilding;
it never modifies recorded results or represents that shift as a FoxDec bug.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

import project
import workflow
import workflow_events
import verify_workflow_report

ROOT = Path(__file__).resolve().parent.parent


class ControlledWorkflow(workflow.Workflow):
    def lift(self):
        super().lift()
        build = self.root / 'build'
        assembly = build / 'lifted.asm'
        before = assembly.read_bytes()
        shutil.copyfile(assembly, build / 'foxdec-unmodified.asm')
        text = before.decode('utf-8')
        pattern = r'^(section\s+\.data[^\n]*\n)'
        if len(re.findall(pattern, text, re.M | re.I)) != 1:
            raise RuntimeError('Controlled fixture requires one data section')
        text = re.sub(pattern, lambda m: m.group(0) + 'times 12 db 0 ; deliberate development control\n', text, count=1, flags=re.M | re.I)
        assembly.write_text(text, encoding='utf-8')
        self.runner.command('controlled-baseline-assemble', ['nasm', '-f', 'elf64', assembly, '-o', build / 'baseline.o'])
        self.runner.command('controlled-baseline-link', [str(x).replace('{object}', str(build / 'baseline.o')).replace('{output}', str(build / 'baseline')) for x in self.link])
        self.report['artifacts']['baseline'] = self.elf(build / 'baseline')
        self.report['development_control'] = {'kind': 'DELIBERATE_LIFTED_DATA_PREFIX', 'bytes': 12,
                'unmodified_foxdec_assembly_sha256': hashlib.sha256(before).hexdigest(),
                'ordinary_control_assembly_sha256': workflow_events.sha(assembly),
                'not_a_natural_foxdec_failure': True}


def run_case(config, input_path, controlled=False):
    if controlled:
        instance = ControlledWorkflow(input_path, config)
        report = instance.run()
    else:
        output=config.parent/'runs';before=set(output.glob('*')) if output.exists() else set()
        code=subprocess.run([str(ROOT/'bcl'),'protect',str(input_path),'--config',str(config)],cwd=ROOT).returncode
        fresh=set(output.glob('*'))-before
        if len(fresh)!=1:raise RuntimeError('CLI protected build did not retain exactly one run')
        run=fresh.pop();report=project.read(run/'report.json');instance=SimpleNamespace(root=run)
        if code!=0:print('Protected CLI exit:',code,flush=True)
    if report['overall_verdict'] != 'PASS' or not report.get('protection', {}).get('published'):
        logs = sorted((p for p in (instance.root / 'logs').glob('*.log') if p.name[:1].isdigit()))
        for path in logs[-2:]:
            print(path, '\n', path.read_text(errors='replace')[-12000:], flush=True)
        raise RuntimeError('Protected native case failed: ' + str(instance.root / 'report.json'))
    if report['checks']['functional']['status'] != 'PASS':
        raise RuntimeError('Functional verification did not pass')
    pairs = report['security_assessment']['secret_pairs']
    for pair in pairs:
        outcomes = pair['by_variant']
        if not outcomes['original']['equal_across_secrets'] or not outcomes['transformed']['equal_across_secrets']:
            raise RuntimeError('Original/protected equality not established')
        if controlled and outcomes['baseline']['equal_across_secrets']:
            raise RuntimeError('Controlled ordinary rebuild did not exercise an introduced distinction')
        if pair['preservation']['transformed']!='SATISFIED_FOR_TESTED_PAIR':
            raise RuntimeError('Protected preservation condition was not satisfied')
        if controlled and pair['preservation']['baseline']!='CANDIDATE_PRESERVATION_VIOLATION':
            raise RuntimeError('Controlled introduced violation was not classified correctly')
    check = verify_workflow_report.verify(instance.root)
    # The protected binary is actually executed independently after publication.
    for secret in ('0', '1'):
        result = subprocess.run([str(instance.root / 'protected/program'), secret], capture_output=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError('Published executable does not pass its native result oracle')
    return {'kind': 'CONTROLLED_PREVENTION' if controlled else 'NATIVE_ELF_PROTECTED_BUILD',
            'status': 'PASS', 'run': str(instance.root), 'protected_executable': str(instance.root / 'protected/program'),
            'original_equal': True, 'ordinary_equal': pairs[0]['by_variant']['baseline']['equal_across_secrets'],
            'protected_equal': True, 'integrity': check['status'], 'events': check['trace_events']}


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', type=Path, required=True)
    opts = parser.parse_args(args)
    root = Path(tempfile.mkdtemp(prefix='protection-native-', dir=ROOT / 'experiments'))
    for name in ('bcl.toml', 'contract.json', 'tables.asm'):
        shutil.copyfile(ROOT / 'examples/protection' / name, root / name)
    config = root / 'bcl.toml'
    text = config.read_text(encoding='utf-8')
    text = re.sub(r'^pin = .*$', 'pin = ' + json.dumps(str(opts.pin.resolve())), text, flags=re.M)
    config.write_text(text, encoding='utf-8')
    subprocess.run(['nasm', '-f', 'elf64', str(root / 'tables.asm'), '-o', str(root / 'original.o')], check=True)
    subprocess.run(['ld', '-m', 'elf_x86_64', '-e', '_start', str(root / 'original.o'), '-o', str(root / 'original')], check=True)
    results = [run_case(config, root / 'original'), run_case(config, root / 'original', controlled=True)]
    subprocess.run([os.environ.get('BCL_PYTHON',__import__('sys').executable),str(ROOT/'scripts/test_dashboard_native.py'),
                    '--saved','--config',str(config),'--input',str(root/'original'),'--expect-protected'],check=True,cwd=ROOT)
    # Negative control: this source already separates the selected secrets.
    source = root / 'already-leaking.asm'
    source.write_text((root / 'tables.asm').read_text().replace('times 48 db 0', 'times 60 db 0'), encoding='utf-8')
    rejected = workflow.Workflow(source, config)
    report = rejected.run()
    if report.get('protection', {}).get('published') or (rejected.root / 'protected/program').exists():
        raise RuntimeError('Already-distinguishing control was incorrectly published as protected')
    if not any(row['status'] == 'ORIGINAL_ALREADY_DISTINGUISHES' for row in report['protection'].get('original_pairs', [])):
        raise RuntimeError('Original distinction was not identified in negative control')
    results.append({'kind': 'ORIGINAL_ALREADY_DISTINGUISHES', 'status': 'REJECTED_AS_PROTECTED', 'run': str(rejected.root)})
    result = {'status': 'PROTECTED_NATIVE_PIPELINE_AND_PREVENTION_EXPECTATIONS_MET', 'results': results,
              'scope': 'Declared lookup entry/input contract, two data regions, real native/PIN checks; controlled ordinary shift is explicitly injected'}
    project.save(root / 'result.json', result)
    if os.environ.get('BCL_NATIVE_EXPORT'):
        destination=Path(os.environ['BCL_NATIVE_EXPORT']).resolve();destination.mkdir(parents=True,exist_ok=True)
        export=Path(tempfile.mkdtemp(prefix='native-protection-',dir=destination))
        shutil.copytree(root,export/'experiment')
        result['exported_evidence']=str(export/'experiment')
        project.save(export/'result.json',result)
    print(json.dumps(result, indent=2), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
