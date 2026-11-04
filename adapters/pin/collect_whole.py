#!/usr/bin/env python3
"""Collect controlled single-thread whole-2 PIN experiments on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile

from whole_trace_check import Collection, load

def execution_environment(root, eager_binding=False):
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC',
                   'HOME': str(root / 'home')}
    if eager_binding:
        environment['LD_BIND_NOW'] = '1'
    return environment

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def execute(command, directory, environment, prefix, timeout, stdin_path=None):
    prefix.with_suffix('.command.json').write_text(json.dumps(command, indent=2) + '\n')
    # GNU timeout bounds the process group, including ordinary PIN descendants.
    bounded = ['/usr/bin/timeout', '--kill-after=5s', str(timeout) + 's', *command]
    with prefix.with_suffix('.stdout').open('xb') as stdout, \
            prefix.with_suffix('.stderr').open('xb') as stderr, open(stdin_path if stdin_path is not None else os.devnull, 'rb') as stdin:
        result = subprocess.run(bounded, cwd=directory, env=environment,
                                stdin=stdin, stdout=stdout, stderr=stderr)
    prefix.with_suffix('.exit').write_text(str(result.returncode) + '\n')
    if result.returncode != 0:
        raise RuntimeError(f'{prefix}: nonzero execution exit {result.returncode}')

def manifest(root):
    files = sorted(p for p in root.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
    (root / 'SHA256SUMS').write_text(''.join(
        f'{digest(p)}  ./{p.relative_to(root).as_posix()}\n' for p in files))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', required=True, type=Path)
    parser.add_argument('--rebuilt', required=True, type=Path)
    parser.add_argument('--pin', required=True, type=Path)
    parser.add_argument('--tool', required=True, type=Path)
    parser.add_argument('--tool-source', required=True, type=Path)
    parser.add_argument('--output-parent', required=True, type=Path)
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--secret-0', default='0')
    parser.add_argument('--secret-1', default='1')
    parser.add_argument('--public-before', action='append', default=[], help='Fixed argv token before the secret (repeatable)')
    parser.add_argument('--public-after', action='append', default=[], help='Fixed argv token after the secret (repeatable)')
    parser.add_argument('--stdin-file', type=Path, help='Fixed public stdin, copied into collection evidence')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--max-events', type=int, default=2000000)
    parser.add_argument('--max-snapshots', type=int, default=4096)
    parser.add_argument('--eager-binding', action='store_true',
                        help='Set LD_BIND_NOW=1 for both binaries, native and PIN; changes execution conditions')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('This collector supports Linux x86_64 only')
    if (args.repetitions < 2 or args.timeout < 1 or args.max_events < 1
            or args.max_snapshots < 1 or args.secret_0 == args.secret_1):
        parser.error('Invalid repetition/limit settings or identical secrets')
    sources = {}
    for name in ('original', 'rebuilt', 'pin', 'tool', 'tool_source'):
        path = getattr(args, name).resolve(strict=True)
        if not path.is_file():
            parser.error(f'Not a regular file: {path}')
        sources[name] = path
    for name in ('original', 'rebuilt', 'pin'):
        if not os.access(sources[name], os.X_OK):
            parser.error(f'Not executable: {sources[name]}')
    setarch = shutil.which('setarch')
    if not setarch or not Path('/usr/bin/timeout').is_file():
        parser.error('setarch and /usr/bin/timeout are required')
    args.output_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='whole-collection-', dir=args.output_parent.resolve()))
    print(f'Batch: {root}', flush=True)
    state = {'schema': 'whole-collection-1', 'status': 'incomplete',
             'reason': 'collection-in-progress'}
    status_path = root / 'collection.json'
    status_path.write_text(json.dumps(state, indent=2) + '\n')
    try:
        for name in ('binaries', 'tool', 'home'):
            (root / name).mkdir()
        copies = {'original': 'binaries/original', 'rebuilt': 'binaries/rebuilt',
                  'tool': 'tool/WholeProgramMemoryTracer.so',
                  'tool_source': 'tool/WholeProgramMemoryTracer.cpp'}
        provenance = {}
        for name, target in copies.items():
            dest = root / target
            shutil.copy2(sources[name], dest)
            if digest(dest) != digest(sources[name]):
                raise RuntimeError(f'Copy verification failed: {name}')
            provenance[name] = {'source': str(sources[name]), 'sha256': digest(dest)}
        stdin_path = None
        if args.stdin_file is not None:
            stdin_path = root / 'public-stdin.bin'
            shutil.copyfile(args.stdin_file.resolve(strict=True), stdin_path)
        environment = execution_environment(root, args.eager_binding)
        configuration = dict(schema='whole-collection-1', repetitions=args.repetitions,
            secrets=[args.secret_0, args.secret_1], input_transport='single-argv-secret' if not (args.public_before or args.public_after) else 'argv-secret-with-fixed-public-arguments',
            public_inputs={'stdin': 'empty' if stdin_path is None else 'snapshot:public-stdin.bin',
                           'other_arguments': args.public_before + args.public_after},
            environment=environment, cwd=str(root), aslr_request='setarch x86_64 -R',
            binding_request='eager' if args.eager_binding else 'loader-default',
            timeout_seconds=args.timeout, max_events=args.max_events,
            max_snapshots=args.max_snapshots, sources=provenance,
            pin={'path': str(sources['pin']), 'sha256': digest(sources['pin'])},
            platform=platform.platform(),
            scope='Single-argument benchmarks; finite controlled runs, not a security proof.')
        (root/'experiment.json').write_text(json.dumps(configuration, indent=2) + '\n')
        if args.public_before or args.public_after:
            configuration['secret_argv_index'] = len(args.public_before) + 1
            configuration['public_argv_before'] = args.public_before
            configuration['public_argv_after'] = args.public_after
            (root/'experiment.json').write_text(json.dumps(configuration, indent=2) + '\n')
        control = [setarch, 'x86_64', '-R']
        execute(control + ['/bin/true'], root, environment, root/'aslr-probe', args.timeout)
        for repeat in range(args.repetitions):
            for version in ('original', 'rebuilt'):
                for secret, value in enumerate((args.secret_0, args.secret_1)):
                    run = root / f'repeat-{repeat}/{version}-{secret}'
                    run.mkdir(parents=True)
                    binary = str(root / copies[version])
                    benchmark_args = [*args.public_before, value, *args.public_after]
                    execute(control + [binary, *benchmark_args], root, environment,
                            run/'native', args.timeout, stdin_path)
                    command = control + [str(sources['pin']), '-t', str(root/copies['tool']),
                        '-o', str(run/'trace.csv'), '-images', str(run/'images.csv'),
                        '-maps', str(run/'maps.log'), '-meta', str(run/'trace.properties'),
                        '-max_events', str(args.max_events),
                        '-max_snapshots', str(args.max_snapshots), '--', binary, *benchmark_args]
                    execute(command, root, environment, run/'pin', args.timeout, stdin_path)
                    for suffix in ('stdout', 'stderr'):
                        if (run/f'native.{suffix}').read_bytes() != (run/f'pin.{suffix}').read_bytes():
                            raise RuntimeError(f'{run}: native/PIN {suffix} mismatch')
                        if version == 'rebuilt':
                            original = root/f'repeat-{repeat}/original-{secret}/native.{suffix}'
                            if original.read_bytes() != (run/f'native.{suffix}').read_bytes():
                                raise RuntimeError(f'{run}: original/rebuilt {suffix} mismatch')
                    print(f'COLLECTED: repeat={repeat} binary={version} secret-slot={secret}', flush=True)
        manifest(root)
        collection = Collection(root)
        for repeat in range(args.repetitions):
            for version in ('original', 'rebuilt'):
                for secret in (0, 1):
                    load(collection, f'repeat-{repeat}/{version}-{secret}', 64)
        state.update(status='complete', reason='collection-and-trace-validation-passed',
                     preservation_verdict='NOT_EVALUATED')
        status_path.write_text(json.dumps(state, indent=2) + '\n')
        manifest(root)
        print(f'COMPLETE: {root}\nRun whole_trace_check.py separately for the verdict.')
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        state.update(status='incomplete', reason=str(error))
        status_path.write_text(json.dumps(state, indent=2) + '\n')
        print(f'FAILED: {error}\nArtifacts retained: {root}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
