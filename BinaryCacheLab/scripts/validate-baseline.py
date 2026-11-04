#!/usr/bin/env python3
"""Validate an existing baseline; preserve sealed build evidence and collect separately."""
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def agree(python, java, python_exit, java_exit):
    require(python.get('schema') == java.get('schema') == 'whole-comparison-1', 'Invalid comparison schema')
    require(python_exit == java_exit == python.get('exit_code') == java.get('exit_code'), 'Checker exit disagreement')
    for key in ('verdict', 'functional_checks', 'repeat_stability', 'comparisons', 'runs', 'manifest_sha256'):
        require(key in python and key in java and python[key] == java[key], 'Python/Java disagreement: ' + key)
    for report in (python, java):
        observer = report.get('observer', {})
        require(observer.get('line_size_bytes') == 64 and observer.get('addresses') == 'raw-virtual'
                and observer.get('repetitions') == 'retained', 'Unsupported observation policy')
        require(observer.get('order') in ('event order; ascending touched lines within each event',
                                         'event order; ascending touched lines within event'), 'Unsupported observation ordering')
    for key in ('excluded',):
        require(python['observer'].get(key) == java['observer'].get(key), 'Observer policy disagreement')
    require(python.get('functional_checks') is True, 'Functional comparison failed')
    require(python.get('repeat_stability') is True, 'Repeated observations are unstable')
    require(python_exit in (0, 3, 5), 'Invalid or incomplete scientific result')
    return python['verdict']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--check-only', action='store_true', help='Verify saved evidence; do not execute native binaries or PIN')
    args = parser.parse_args()
    result = None
    try:
        app, evidence = args.app.resolve(strict=True), args.evidence.resolve(strict=True)
        summary = read(evidence / 'summary.json')
        require(summary.get('status') == 'BASELINE_METADATA_CHECKED' and summary.get('workflow_mode') == 'BASELINE_REBUILD_ONLY', 'Expected successful baseline-only rebuild evidence')
        config = read(evidence / 'resolved-config.json')
        repetitions = config.get('experiment.repetitions')
        timeout = config.get('experiment.timeout')
        require(type(repetitions) is int and 2 <= repetitions <= 20, 'Unsupported repetition count')
        require(type(timeout) is int and 1 <= timeout <= 86400, 'Unsupported run timeout')
        jar = app / 'binarycachelab.jar'
        require(jar.is_file(), 'Application JAR missing')
        result = Path(tempfile.mkdtemp(prefix='baseline-validation-', dir=evidence.parent))
        print('Validation: ' + str(result), flush=True)
        commands = []

        def run(name, argv, allowed, seconds, visible=False):
            commands.append({'stage': name, 'argv': list(map(str, argv))})
            print('STAGE ' + name, flush=True)
            if visible:
                code = execute(argv, seconds)
            else:
                with (result / (name + '.log')).open('x', encoding='utf-8') as log:
                    code = execute(argv, seconds, log)
            commands[-1]['exit_code'] = code
            require(code in allowed, name + ' failed: exit ' + str(code) + '; see ' + str(result))
            return code

        # These commands validate the manifest and bind the declared instruction rows to ELF bytes.
        run('linked-references', ['java', '-jar', str(jar), 'verify-references', str(evidence), '--report', str(result / 'references.json')], {0}, 300)
        run('reference-assessment', ['java', '-jar', str(jar), 'assess-references', str(evidence), '--report', str(result / 'assessment.json')], {6, 7}, 300)
        # Read again after integrity validation. Never turn the safety rejection into authorization.
        summary = read(evidence / 'summary.json')
        require(summary.get('status') == 'BASELINE_METADATA_CHECKED', 'Baseline status changed')
        callbacks = read(result / 'assessment.json')['callback_metadata_comparisons']['baseline']
        require(callbacks.get('differences') == [], 'Callback metadata still differs across builds')
        require(read(evidence / 'baseline-callback-link-check.json').get('status') == 'CALLBACK_ENTRY_MAPPING_CHECKED', 'Missing linked callback check')
        record = {'schema': 'bcl-baseline-validation-1', 'build_evidence': str(evidence),
                  'build_manifest_sha256': digest(evidence / 'SHA256SUMS'), 'commands': commands,
                  'automatic_rewrite_allowed': False, 'whole_program_safety_proved': False}
        if args.check_only:
            record.update(status='STATIC_CHECKS_COMPLETE', observation_verdict='NOT_COLLECTED')
            write(result / 'summary.json', record)
            print('STATIC_CHECKS_COMPLETE; no native execution; ' + str(result))
            return 0
        require(sys.platform.startswith('linux'), 'Native collection requires Linux')
        pin = Path(config['tools.pin'])
        require(digest(pin) == read(evidence / 'input-provenance.json')['pin']['sha256'], 'PIN changed since baseline rebuild')
        backend = evidence / 'inputs/backend'
        collect = [sys.executable, str(backend / 'collect_whole.py'), '--original', str(evidence / 'inputs/original'),
                   '--rebuilt', str(evidence / 'baseline/program'), '--pin', str(pin), '--tool', str(evidence / 'inputs/tracer.so'),
                   '--tool-source', str(evidence / 'inputs/tracer.cpp'), '--secret-0', '0', '--secret-1', '1',
                   '--repetitions', str(repetitions), '--timeout', str(timeout), '--output-parent', str(result)]
        if config.get('experiment.eager_binding') is True:
            collect.append('--eager-binding')
        run('four-run-collection', collect, {0}, timeout * repetitions * 8 + 180, visible=True)
        batches = list(result.glob('whole-collection-*'))
        require(len(batches) == 1 and batches[0].is_dir(), 'Expected one collection batch')
        batch = str(batches[0])
        py_exit = run('python-comparison', [sys.executable, str(backend / 'whole_trace_check.py'), batch, '--repetitions', str(repetitions), '--line-size', '64', '--report', str(result / 'python-comparison.json')], {0, 2, 3, 4, 5}, 300)
        java_exit = run('java-comparison', ['java', '-jar', str(jar), 'pin-check-java', batch, '--repetitions', str(repetitions), '--report', str(result / 'java-comparison.json')], {0, 2, 3, 4, 5}, 300)
        verdict = agree(read(result / 'python-comparison.json'), read(result / 'java-comparison.json'), py_exit, java_exit)
        record.update(status='COMPARISON_COMPLETE', observation_verdict=verdict, checker_exit=java_exit,
                      scope='Baseline only, secrets 0/1, fixed declared public inputs, ordered 64-byte virtual data lines; finite runs')
        write(result / 'summary.json', record)
        print('COMPARISON_COMPLETE: ' + verdict + '\nEvidence: ' + str(result), flush=True)
        return java_exit
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        if result is not None:
            write(result / 'failure.json', {'status': 'FAILED', 'error': str(error), 'automatic_rewrite_allowed': False})
        print('FAILED: ' + str(error), file=sys.stderr)
        return 2


def execute(argv, seconds, log=None):
    process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT if log else None,
                               start_new_session=sys.platform.startswith('linux'))
    try:
        return process.wait(timeout=seconds)
    except BaseException:
        try:
            if sys.platform.startswith('linux'):
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait()
        raise


if __name__ == '__main__':
    sys.exit(main())
