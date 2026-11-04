#!/usr/bin/env python3
"""Finite-run, raw-virtual-line comparison for whole-2 PIN collections."""
import argparse
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

HEADER = ['sequence', 'thread_id', 'instruction_address', 'memory_address',
          'access_size_bytes', 'access_type', 'source_backend']
REQUIRED = dict(status='complete', reason='normal-exit', tracer_version='whole-2',
                application_threads='1', main_images='1', application_exit='0',
                backend='PIN', address_space='raw-virtual', observation_filter='none',
                normalization='none', scope='pin-instrumented-user-space',
                event_semantics='before-instruction-pin-predication',
                read_modify_write='separate-read-then-write',
                kernel_memory_accesses='excluded', instruction_fetches='excluded')

class Invalid(ValueError):
    pass

class Collection:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.hashes = {}
        manifest = self.root / 'SHA256SUMS'
        if manifest.is_symlink():
            raise Invalid('Symlink manifest')
        for line in manifest.read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  (\./.+)', line)
            if not match:
                raise Invalid('Invalid SHA256SUMS entry')
            digest, name = match.groups()
            name = name[2:]
            if name in self.hashes:
                raise Invalid('Duplicate manifest entry')
            self.path(name)
            self.hashes[name] = digest
        if not self.hashes:
            raise Invalid('Empty manifest')
        # Verify every listed artifact, and require coverage for every consumed file.
        for name in self.hashes:
            self.read(name)

    def path(self, name):
        if not name or '\\' in name or ':' in name or any(
                part in ('', '.', '..') for part in name.split('/')):
            raise Invalid('Unsafe artifact path')
        path = self.root
        for part in name.split('/'):
            path = path / part
            if path.is_symlink():
                raise Invalid('Symlink artifact')
        if not path.is_file():
            raise Invalid(f'Missing artifact: {name}')
        return path

    def read(self, name):
        if name not in self.hashes:
            raise Invalid(f'Artifact not covered by manifest: {name}')
        data = self.path(name).read_bytes()
        if hashlib.sha256(data).hexdigest() != self.hashes[name]:
            raise Invalid(f'Checksum mismatch: {name}')
        return data

def load(collection, prefix, line_size):
    def read(name):
        return collection.read(prefix + '/' + name)
    meta = {}
    for line in read('trace.properties').decode().splitlines():
        if not line:
            continue
        key, value = line.split('=', 1)
        if key in meta:
            raise Invalid('Duplicate metadata key')
        meta[key] = value
    for key, value in REQUIRED.items():
        if meta.get(key) != value:
            raise Invalid(f'{prefix}: unsupported/incomplete metadata {key}')
    if int(meta['mapping_snapshots']) <= 0:
        raise Invalid('No mapping snapshots declared')
    rows = csv.reader(io.StringIO(read('trace.csv').decode()))
    if next(rows, None) != HEADER:
        raise Invalid('Invalid CSV header')
    events, tokens, threads = [], [], set()
    for index, row in enumerate(rows):
        if len(row) != 7:
            raise Invalid('Invalid CSV row width')
        seq, thread, ip, address, size, kind, backend = row
        seq, thread, size = int(seq), int(thread), int(size)
        ip, address = int(ip, 16), int(address, 16)
        if (seq != index or thread < 0 or not 0 <= ip < 2**64
                or size <= 0 or address < 0 or address + size > 2**64
                or kind not in ('READ', 'WRITE') or backend != 'PIN'):
            raise Invalid('Invalid memory event')
        first, last = address // line_size, (address + size - 1) // line_size
        if last - first > 65535:
            raise Invalid('Access exceeds supported projection limit')
        threads.add(thread)
        events.append((ip, address, size, kind, thread))
        tokens.extend((line, index) for line in range(first, last + 1))
    if not events or len(events) != int(meta['events']) or len(threads) != 1:
        raise Invalid('Empty/count/thread mismatch')
    outputs = tuple((read(mode + '.stdout'), read(mode + '.stderr'),
                     int(read(mode + '.exit'))) for mode in ('native', 'pin'))
    return events, tokens, outputs

def witness(data, index):
    if index >= len(data[1]):
        return {'end_of_observation': True}
    line, event = data[1][index]
    ip, address, size, kind, thread = data[0][event]
    return dict(line=line, event=event, csv_row=event + 2, ip=hex(ip),
                address=hex(address), size=size, access_type=kind, thread=thread)

def evaluate(root, variant='rebuilt', repetitions=3, line_size=64):
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', variant) or variant == 'original':
        raise Invalid('Invalid variant name')
    if repetitions < 2 or line_size < 1 or line_size & (line_size - 1):
        raise Invalid('Need at least two repetitions and a power-of-two line size')
    collection = Collection(root)
    versions = ('original', variant)
    runs, summaries, equalities = {}, [], {}
    for version in versions:
        for repeat in range(repetitions):
            for secret in (0, 1):
                prefix = f'repeat-{repeat}/{version}-{secret}'
                data = load(collection, prefix, line_size)
                runs[version, repeat, secret] = data
                summaries.append(dict(run=prefix, events=len(data[0]),
                    line_tokens=len(data[1]), outputs=[dict(mode=mode,
                        stdout_sha256=hashlib.sha256(output[0]).hexdigest(),
                        stderr_sha256=hashlib.sha256(output[1]).hexdigest(),
                        stdout_bytes=len(output[0]), stderr_bytes=len(output[1]),
                        exit=output[2]) for mode, output in zip(('native', 'pin'), data[2])]))
    stable = all(runs[v, r, s][0] == runs[v, 0, s][0]
                 and runs[v, r, s][2] == runs[v, 0, s][2]
                 for v in versions for r in range(1, repetitions) for s in (0, 1))
    functional = all(d[2][0] == d[2][1] and d[2][0][2] == 0 for d in runs.values())
    functional &= all(runs['original', r, s][2][0] == runs[variant, r, s][2][0]
                      for r in range(repetitions) for s in (0, 1))
    comparisons = []
    for version in versions:
        equalities[version] = []
        for repeat in range(repetitions):
            left, right = (runs[version, repeat, s] for s in (0, 1))
            a, b = ([t[0] for t in d[1]] for d in (left, right))
            equalities[version].append(a == b)
            entry = dict(binary=version, repeat=repeat, equal=a == b)
            if a != b:
                index = next(i for i in range(max(len(a), len(b)))
                             if i >= len(a) or i >= len(b) or a[i] != b[i])
                entry['first_difference'] = dict(token_index=index,
                    secret_0=witness(left, index), secret_1=witness(right, index))
            comparisons.append(entry)
    if not stable:
        verdict, code = 'INCONCLUSIVE_UNSTABLE_REPETITIONS', 2
    elif not functional:
        verdict, code = 'FUNCTIONAL_OUTPUT_MISMATCH', 4
    elif not all(equalities['original']):
        verdict, code = 'ORIGINAL_OBSERVATIONS_DIFFER', 5
    elif not all(equalities[variant]):
        verdict, code = 'CANDIDATE_PRESERVATION_VIOLATION', 3
    else:
        verdict, code = 'SATISFIED_FOR_TESTED_PAIR', 0
    return dict(schema='whole-comparison-1', batch=str(collection.root),
        variant=variant, verdict=verdict, exit_code=code,
        functional_checks=functional, repeat_stability=stable,
        observer=dict(line_size_bytes=line_size, addresses='raw-virtual',
            order='event order; ascending touched lines within each event',
            repetitions='retained', excluded=['access types', 'event boundaries',
            'instruction addresses', 'instruction fetches', 'kernel accesses']),
        layout_handling='Compare secrets within each build, not addresses across builds.',
        conditions='Execution controls are collector declarations, not verified by this checker.',
        scope='Finite recorded runs only; no hardware-cache measurement or formal proof.',
        manifest_sha256=hashlib.sha256((collection.root/'SHA256SUMS').read_bytes()).hexdigest(),
        runs=summaries, comparisons=comparisons), code

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('batch')
    parser.add_argument('--variant', default='rebuilt')
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--line-size', type=int, default=64)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.report and (args.report.resolve() == Path(args.batch).resolve()
                       or Path(args.batch).resolve() in args.report.resolve().parents):
        parser.error('Place the report outside the checksummed batch')
    try:
        report, code = evaluate(args.batch, args.variant, args.repetitions, args.line_size)
    except (OSError, ValueError, KeyError, csv.Error) as error:
        report, code = dict(verdict='INVALID_OR_INCOMPLETE', error=str(error), exit_code=2), 2
    text = json.dumps(report, indent=2)
    if args.report:
        try:
            with args.report.open('x', encoding='utf-8') as stream:
                stream.write(text + '\n')
        except OSError as error:
            print(f'Report not written: {error}', file=sys.stderr)
            return 2
    print(text)
    return code

if __name__ == '__main__':
    sys.exit(main())
