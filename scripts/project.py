#!/usr/bin/env python3
"""General ELF-pair projects. Finite observations and restricted analyses stay separate."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import runpy
import shutil
import struct
import sys
import tempfile
import uuid
sys.dont_write_bytecode = True
import easy

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def elf_inventory(path):
    """Read ELF64 little-endian x86-64 sections and defined object/function symbols."""
    blob = Path(path).read_bytes()
    require(len(blob) >= 64 and blob[:6] == b'\x7fELF\x02\x01', 'Require ELF64 little-endian input')
    kind, machine = struct.unpack_from('<HH', blob, 16)
    require(machine == 62 and kind in (2, 3), 'Require x86-64 executable or PIE/shared ELF')
    entry, = struct.unpack_from('<Q', blob, 24)
    offset, = struct.unpack_from('<Q', blob, 40)
    width, count, strings = struct.unpack_from('<HHH', blob, 58)
    require(width == 64 and 0 < count <= 65535 and strings < count, 'Unsupported ELF section table')
    require(offset + count * width <= len(blob), 'Truncated ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', blob, offset + n * width) for n in range(count)]

    def data(section):
        start, size = section[4:6]
        require(start <= len(blob) and size <= len(blob) - start, 'ELF section outside file')
        return blob[start:start + size]

    def string(table, at):
        require(at < len(table), 'ELF string outside string table')
        end = table.find(b'\0', at)
        require(end >= 0, 'Unterminated ELF string')
        return table[at:end].decode('utf-8', errors='replace')

    names = data(sections[strings])
    objects, functions, seen, dependencies = [], [], set(), []
    for section in sections:
        if section[1] == 6:
            require(section[6] < count and section[5] % 16 == 0, 'Invalid dynamic table')
            dynamic, table = data(section), data(sections[section[6]])
            for at in range(0, len(dynamic), 16):
                tag, value = struct.unpack_from('<qQ', dynamic, at)
                if tag == 0:
                    break
                if tag == 1:
                    dependencies.append(string(table, value))
        if section[1] not in (2, 11):
            continue
        require(section[9] == 24 and section[5] % 24 == 0 and section[6] < count, 'Invalid ELF symbols')
        symbols, table = data(section), data(sections[section[6]])
        for at in range(0, len(symbols), 24):
            name_at, info, other, index, address, size = struct.unpack_from('<IBBHQQ', symbols, at)
            if not 0 < index < count or info & 15 not in (1, 2) or not size:
                continue
            owner = sections[index]
            if not owner[2] & 2:
                continue
            require(address >= owner[3] and size <= owner[5] and address - owner[3] <= owner[5] - size,
                    'Symbol extends outside its section')
            name = string(table, name_at)
            key = (name, address, size, info & 15)
            if key in seen:
                continue
            seen.add(key)
            row = {'name': name, 'address': address, 'size': size, 'section': string(names, owner[0]),
                   'writable': bool(owner[2] & 1), 'file_backed': owner[1] != 8}
            (objects if info & 15 == 1 else functions).append(row)
    return {'schema': 'bcl-elf-inventory-1', 'sha256': easy.sha(path), 'elf_type': kind, 'entry': entry,
            'objects': sorted(objects, key=lambda r: (r['address'], r['name'])),
            'functions': sorted(functions, key=lambda r: (r['address'], r['name'])),
            'external_libraries': dependencies,
            'tls_sections': [string(names, s[0]) for s in sections if s[2] & 0x400],
            'discovery_complete': False,
            'scope': 'Defined ELF symbols only; stripped objects, aliases, pointer uses and lifetimes are not inferred.'}


def profile(path):
    path = Path(path).resolve(strict=True)
    doc = read(path)
    require(doc.get('schema') == 'bcl-project-1', 'Expected bcl-project-1')
    allowed = {'schema', 'original', 'rebuilt', 'output', 'secrets', 'repetitions', 'timeout',
               'contracts', 'regions', 'transform', 'build_jobs', 'public_before', 'public_after', 'stdin_file', 'lift', 'inputs', 'analysis', 'correspondence', 'approval'}
    require(not set(doc) - allowed, 'Unknown project fields: ' + str(sorted(set(doc) - allowed)))
    for key in ('original', 'rebuilt', 'output'):
        require(isinstance(doc.get(key), str) and doc[key], 'Missing path: ' + key)
    secrets = doc.get('secrets', ['0', '1'])
    require(isinstance(secrets, list) and len(secrets) == 2 and all(isinstance(s, str) and '\0' not in s for s in secrets)
            and secrets[0] != secrets[1], 'Require two distinct secret argv tokens')
    for key, default, lo, hi in [('repetitions', 3, 2, 20), ('timeout', 120, 1, 86400)]:
        value = doc.setdefault(key, default)
        require(type(value) is int and lo <= value <= hi, 'Invalid ' + key)
    doc['secrets'] = secrets
    for key in ('public_before', 'public_after'):
        require(isinstance(doc.get(key, []), list) and all(isinstance(a, str) and '\0' not in a for a in doc.get(key, [])),
                key + ' requires fixed argv tokens')
    require(isinstance(doc.get('contracts', {}), dict) and not set(doc.get('contracts', {})) - {'original', 'rebuilt'},
            'Contracts must map original/rebuilt to closure profile paths')
    return path, doc


def resolve(base, value):
    require(isinstance(value, str) and value, 'Expected nonempty path')
    return (base / value).resolve()


def symbol_contract(inventory, analysis):
    require(isinstance(analysis, dict) and set(analysis) <= {'entries', 'regions'}, 'Analysis supports entries/regions symbol-name arrays')
    def select(kind, names):
        require(isinstance(names, list) and 0 < len(names) <= 128 and all(isinstance(n, str) for n in names), 'Require 1..128 analysis symbols')
        result = []
        for name in names:
            matches = [r for r in inventory[kind] if r['name'] == name]
            require(len(matches) == 1, 'Missing or ambiguous ' + kind + ' symbol: ' + name)
            result.append(matches[0])
        return result
    entries = select('functions', analysis.get('entries'))
    regions = select('objects', analysis.get('regions'))
    require(all(r['file_backed'] for r in regions), 'Symbol contracts currently require file-backed region bytes')
    return {'schema': 'bcl-closure-1', 'entries': [r['address'] for r in entries],
            'regions': [{'name': r['name'], 'address': r['address'], 'size': r['size'], 'immutable': False} for r in regions],
            'initial_registers': {'rsp': 'stack'}, 'stack_disjoint_from_regions': False,
            'observed_return_registers': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                                          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'],
            'external_contracts': []}


def seal(root):
    files = sorted(p for p in root.rglob('*') if p.is_file() and p != root / 'SHA256SUMS')
    require(not any(p.is_symlink() for p in root.rglob('*')), 'Evidence contains symlink')
    (root / 'SHA256SUMS').write_text(''.join(easy.sha(p) + '  ' + p.relative_to(root).as_posix() + '\n' for p in files))


def verify_manifest(root):
    root = Path(root).resolve(strict=True)
    require(not any(p.is_symlink() for p in root.rglob('*')), 'Evidence contains symlink')
    declared = set()
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        p = root / name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and p.resolve().is_relative_to(root), 'Unsafe manifest path')
        require(name not in declared and p.is_file() and easy.sha(p) == digest, 'Changed or missing evidence: ' + name)
        declared.add(name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p != root / 'SHA256SUMS'}
    require(actual == declared, 'Evidence contains unmanifested files')
    return len(declared)


def restore_tmc_alias(assembly, symbols, original=None):
    """Restore a dropped CRT alias only at an explicitly emitted original address."""
    text = assembly.read_text(encoding='utf-8')
    if not re.search(r'\b__TMC_END__\b', text) or re.search(r'^\s*__TMC_END__\s*(?::|equ\b)', text, re.M | re.I):
        return False
    addresses = {int(m.group(1), 16) for m in re.finditer(r'^([0-9a-fA-F]+)\s+[A-Za-z]\s+__TMC_END__\s*$', symbols, re.M)}
    require(len(addresses) == 1, 'Cannot restore __TMC_END__: missing/ambiguous original symbol')
    address = addresses.pop()
    labels = [m.group(1) for m in re.finditer(r'^\s*(L_\.[A-Za-z0-9_]+_0x([0-9a-fA-F]+)):\s*$', text, re.M) if int(m.group(2), 16) == address]
    if len(labels) == 1:
        text += '\n; Original ELF CRT alias, rebound to the emitted address label.\n__TMC_END__ equ ' + labels[0] + '\n'
    else:
        require(not labels and original is not None, 'Cannot restore __TMC_END__: no unique emitted label at its original address')
        # FoxDec sometimes drops an alias inside a byte-emitted section. Locate
        # that position only after checking every emitted byte against the ELF.
        blob = Path(original).read_bytes()
        require(blob[:6] == b'\x7fELF\x02\x01' and len(blob) >= 64, 'Unsupported alias source ELF')
        offset, = struct.unpack_from('<Q', blob, 40)
        width, count, strings = struct.unpack_from('<HHH', blob, 58)
        require(width == 64 and strings < count and offset + count * width <= len(blob), 'Invalid alias source sections')
        sections = [struct.unpack_from('<IIQQQQIIQQ', blob, offset+i*width) for i in range(count)]
        names_section = sections[strings]; names = blob[names_section[4]:names_section[4]+names_section[5]]
        candidates = []
        lines = text.splitlines(keepends=True)
        for start,line in enumerate(lines):
            match = re.fullmatch(r'\s*section\s+(\.data|\.bss)\s+align=\d+\s*;\s*@([0-9a-fA-F]+)\s*', line, re.I)
            if not match: continue
            name, base = match.group(1), int(match.group(2),16)
            owners = [s for s in sections if names[s[0]:].split(b'\0',1)[0].decode('ascii') == name and s[3] == base and base <= address <= base+s[5]]
            if len(owners) != 1: continue
            owner = owners[0]
            require(owner[5] <= 16777216, 'CRT alias section exceeds supported byte-map limit')
            emitted = bytearray(); insertion = None; valid = True
            for index in range(start+1,len(lines)):
                body = lines[index].split(';',1)[0].strip()
                if re.match(r'section\b',body,re.I): break
                if base+len(emitted) == address and insertion is None: insertion = index
                if not body or re.fullmatch(r'[A-Za-z_.$][\w.$]*:',body): continue
                byte = re.fullmatch(r'db\s+(?:0x([0-9a-fA-F]{1,3})|([0-9a-fA-F]{1,3})h|([0-9]{1,3}))',body,re.I)
                reserve = re.fullmatch(r'resb\s+([0-9]+)',body,re.I)
                if byte and owner[1] == 1:
                    value = int(byte.group(1) or byte.group(2),16) if byte.group(1) or byte.group(2) else int(byte.group(3))
                    if value > 255: valid=False;break
                    emitted.append(value)
                elif reserve and owner[1] == 8 and int(reserve.group(1)) <= owner[5]-len(emitted):
                    # An alias inside a reservation needs splitting; reject it.
                    emitted.extend(bytes(int(reserve.group(1))))
                else: valid=False;break
                if len(emitted) > owner[5]: valid=False;break
            expected = bytes(owner[5]) if owner[1] == 8 else blob[owner[4]:owner[4]+owner[5]]
            if valid and insertion is not None and len(emitted) == owner[5] and emitted == expected:
                candidates.append(insertion)
        require(len(candidates) == 1, 'Cannot restore __TMC_END__: emitted section is not an exact supported ELF byte mapping')
        lines.insert(candidates[0], '__TMC_END__:\n')
        text = ''.join(lines)
    assembly.write_text(text, encoding='utf-8')
    return True


def lift_original(root, options, runner, command, base, configuration_values=None, static_syscalls=False):
    require(isinstance(options, dict) and set(options) <= {'image', 'timeout', 'extra_link_args', 'entry_symbols'}, 'Invalid lift settings')
    timeout = options.get('timeout', 7200)
    require(type(timeout) is int and 1 <= timeout <= 86400, 'Invalid lift timeout')
    extras = options.get('extra_link_args', [])
    require(isinstance(extras, list) and all(isinstance(a, str) for a in extras), 'extra_link_args requires a string array')
    runner.command('callback-plan', [*command, 'callback-plan', root / 'original', '--report', root / 'callback-plan.json'])
    callback = read(root / 'callback-plan.json')
    inputs, artifacts = root / 'lift-input', root / 'lift-artifacts'
    inputs.mkdir()
    artifacts.mkdir()
    require(':' not in str(root)[len(root.drive):] and ',' not in str(root), 'Unsupported Docker bind path')
    shutil.copy2(root / 'original', inputs / 'program')
    roots={r['original_entry'] for r in callback['required_roots']}
    entries=options.get('entry_symbols',[])
    require(isinstance(entries,list) and all(isinstance(n,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',n) for n in entries),'Invalid explicit lift entry symbols')
    if entries:
        symbols,_=runner.command('original-lift-entry-symbols',['nm','-an','--defined-only',root/'original'])
        for entry in entries:
            matches={int(parts[0],16) for line in symbols.splitlines() if len(parts:=line.split())==3 and parts[1] in ('T','t','W','w') and parts[2]==entry}
            require(len(matches)==1,'Missing/ambiguous executable lift entry: '+entry)
            roots.update(matches)
    (inputs / 'program.entry').write_text(''.join(hex(address)+'\n' for address in sorted(roots)))
    runner.docker_access()
    values = easy.config_values() if configuration_values is None else dict(configuration_values)
    if 'image' in options:
        values['lift.image'] = options['image']
    image = runner.foxdec(values)
    text, _ = runner.command('image-identity', [*runner.docker, 'image', 'inspect', image, '--format', '{{.Id}}'])
    identity = text.strip()
    require(identity.startswith('sha256:') and len(identity) == 71 and all(c in '0123456789abcdef' for c in identity[7:]), 'Invalid image identity')
    save(root / 'lift-image.json', {'image': image, 'identity': identity})
    syscall_setup = ''
    syscall_mount = []
    if static_syscalls:
        import syscall_lift
        from syscall_cfg import disassemble
        disassembly = disassemble(root/'original',runner,'syscall-instruction-inventory')
        syscall_doc = syscall_lift.prepare(root / 'original', root / 'syscall-extension', disassembly=disassembly)
        roots.update(syscall_doc.get('function_entries', []))
        (inputs / 'program.entry').write_text(''.join(hex(address)+'\n' for address in sorted(roots)))
        syscall_setup = syscall_lift.container_setup()
        syscall_mount = ['-v', str(root / 'syscall-extension') + ':/bcl-syscall:ro']
    script = ('set -euo pipefail; cd /FoxDec/foxdec_v0.7; ' + syscall_setup + 'WORK=$(mktemp -d ./examples/bcl-XXXXXXXX); '
              'cp /binary/program /binary/program.entry "$WORK/"; '
              'cabal run foxdec-exe -- -c ./config/config.dhall -d "$WORK/" -n program '
              '-i BINARY --Gmetrics --Gcallgraph --Gfuncs --GNASM; '
              'cp -R --no-preserve=mode,ownership "$WORK/." /artifacts/; chmod -R a+rX /artifacts/')
    container = 'bcl-project-' + uuid.uuid4().hex
    try:
        runner.command('foxdec-lift', [*runner.docker, 'run', '--rm', '--name', container, '--entrypoint', '/bin/bash',
            '-v', str(inputs) + ':/binary:ro', '-v', str(artifacts) + ':/artifacts', *syscall_mount, identity, '-c', script], seconds=timeout)
    finally:
        runner.capture([*runner.docker, 'rm', '-f', container])
    assembly, helper = artifacts / 'nasm/program.asm', artifacts / 'nasm/__gmon_start__.c'
    for file in (assembly, helper, artifacts / 'nasm/program.asm.json', artifacts / 'program.metrics.txt'):
        require(file.is_file() and file.stat().st_size > 0, 'Incomplete FoxDec output: ' + str(file))
    # Container artifacts may be root-owned and read-only. Preserve them as
    # evidence and apply host repairs only to a newly created user-owned file.
    host_assembly = root / 'lifted-host.asm'
    with host_assembly.open('xb') as destination:
        destination.write(assembly.read_bytes())
    assembly = host_assembly
    runner.command('lifted-callback-definitions', [*command, 'callback-plan', root / 'original', '--assembly', assembly])
    symbols, _ = runner.command('original-crt-symbols', ['nm', '-an', '--defined-only', root / 'original'])
    restore_tmc_alias(assembly, symbols, root / 'original')
    runner.command('compile-helper', ['gcc', '-c', helper, '-o', root / 'helper.o'])
    return assembly, ['gcc', '-g', '-m64', '-nostartfiles', '-fgnu-tm', '-o', '{output}', '{object}', str(root / 'helper.o'),
                      *callback['linker_arguments'], *extras]


def run_project(path, check_only=False):
    path, doc = profile(path)
    base = path.parent
    require(sys.platform.startswith('linux') or check_only, 'Native project execution requires Linux x86-64; static checks are portable')
    output = resolve(base, doc['output'])
    output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='project-', dir=output))
    runner = easy.Runner()
    # Logs are part of this experiment, not a separate mutable session directory.
    runner.logs = root / 'logs'
    runner.logs.mkdir()
    save(root / 'project.json', doc)
    shutil.copy2(ROOT / 'binarycachelab.jar', root / 'toolkit.jar')
    backend = root / 'backend'
    backend.mkdir()
    for name in ('collect_whole.py', 'whole_trace_check.py'):
        shutil.copy2(ROOT / 'backend' / name, backend / name)
    java = os.environ.get('JAVA', 'java')
    command = [java, '-jar', root / 'toolkit.jar']
    result = {'schema': 'bcl-project-result-1', 'status': 'RUNNING', 'automatic_rewrite_allowed': False,
              'scope': 'Selected ELF pair; finite observations and declared-region checks, not whole-program equivalence.'}
    print('Project evidence: ' + str(root), flush=True)
    try:
        inputs = doc.get('inputs', {})
        require(isinstance(inputs, dict) and len(inputs) <= 256, 'inputs must map names to source paths')
        if inputs:
            (root / 'inputs').mkdir()
        substitutions = {'{work}': str(root)}
        for name, source in inputs.items():
            require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in ('.', '..'), 'Invalid input name')
            shutil.copy2(resolve(base, source), root / 'inputs' / name)
            substitutions['{input:' + name + '}'] = str(root / 'inputs' / name)
        def expand(text):
            for token, value in substitutions.items():
                text = text.replace(token, value)
            require(not re.search(r'\{(?:work|input:)[^}]*\}', text), 'Unknown build placeholder')
            return text
        jobs = doc.get('build_jobs', [])
        require(isinstance(jobs, list) and len(jobs) <= 32, 'Require at most 32 build jobs')
        for n, job in enumerate(jobs):
            require(isinstance(job, dict) and set(job) <= {'argv', 'cwd', 'timeout'}, 'Invalid build job')
            argv = job.get('argv')
            require(isinstance(argv, list) and argv and all(isinstance(a, str) and '\0' not in a for a in argv), 'Build argv must be a nonempty string array')
            require(not check_only, '--check-only does not execute build recipes; supply existing binaries')
            seconds = job.get('timeout', doc['timeout'])
            require(type(seconds) is int and 1 <= seconds <= 86400, 'Invalid build timeout')
            runner.command('build-' + str(n), [expand(a) for a in argv], seconds=seconds, cwd=resolve(base, expand(job.get('cwd', '.'))))
        original = root / 'original'
        shutil.copy2(resolve(base, expand(doc['original'])), original)
        original.chmod(0o755)
        save(root / 'original-inventory.json', elf_inventory(original))
        lifted, link_argv = None, None
        if 'lift' in doc:
            require(not check_only, '--check-only cannot perform a FoxDec lift')
            lifted, link_argv = lift_original(root, doc['lift'], runner, command, base)
        if 'transform' in doc:
            require(not check_only, '--check-only cannot build a transformation')
            transform = doc['transform']
            require(isinstance(transform, dict) and set(transform) == {'regions', 'link_argv'}, 'Transform needs regions and link_argv')
            region_file = resolve(base, transform['regions'])
            region_doc = read(region_file)
            shutil.copy2(lifted or resolve(region_file.parent, region_doc['assembly']), root / 'source.asm')
            region_doc['assembly'] = str(root / 'source.asm')
            save(root / 'regions.json', region_doc)
            runner.command('apply-regions', [*command, 'apply-regions', root / 'regions.json', '--output', root / 'candidate.asm', '--report', root / 'plan.json'])
            runner.command('assemble', ['nasm', '-f', 'elf64', root / 'candidate.asm', '-o', root / 'candidate.o'])
            argv = transform['link_argv'] or link_argv
            require(isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv), 'link_argv requires a string array')
            require(any('{object}' in a for a in argv) and any('{output}' in a for a in argv), 'link_argv must contain {object} and {output}')
            runner.command('link', [a.replace('{object}', str(root / 'candidate.o')).replace('{output}', str(root / 'rebuilt')) for a in argv], seconds=doc['timeout'], cwd=base)
        elif lifted is not None:
            shutil.copy2(lifted, root / 'candidate.asm')
            runner.command('assemble', ['nasm', '-f', 'elf64', root / 'candidate.asm', '-o', root / 'candidate.o'])
            runner.command('link', [a.replace('{object}', str(root / 'candidate.o')).replace('{output}', str(root / 'rebuilt')) for a in link_argv], seconds=doc['timeout'], cwd=base)
        else:
            shutil.copy2(resolve(base, expand(doc['rebuilt'])), root / 'rebuilt')
            if 'regions' in doc:
                shutil.copy2(resolve(base, doc['regions']), root / 'regions.json')
        rebuilt = root / 'rebuilt'
        rebuilt.chmod(0o755)
        save(root / 'rebuilt-inventory.json', elf_inventory(rebuilt))
        if lifted is not None:
            runner.command('callback-link-check', [*command, 'callback-check', original, '--rebuilt', rebuilt, '--report', root / 'callbacks.json'])
            result['callback_mapping_checked'] = True
        if (root / 'regions.json').exists():
            runner.command('linked-regions', [*command, 'verify-regions', root / 'regions.json', '--original', original, '--rebuilt', rebuilt, '--report', root / 'layout.json'])
        contracts = {label: read(resolve(base, source)) for label, source in doc.get('contracts', {}).items()}
        if 'analysis' in doc:
            require(not contracts, 'Use either analysis symbols or explicit contracts')
            contracts = {label: symbol_contract(read(root / (label + '-inventory.json')), doc['analysis']) for label in ('original', 'rebuilt')}
        for label, contract in contracts.items():
            bounded = contract.get('schema') == 'bcl-bounded-references-1'
            if bounded:
                contract['binary'] = label
            else:
                disassembly = root / (label + '.objdump')
                text, _ = runner.command('disassemble-' + label, ['objdump', '-d', '-w', '-Mintel', root / label])
                disassembly.write_text(text)
                contract.update(binary=str(root / label), disassembly=str(disassembly))
            save(root / (label + '-contract.json'), contract)
            runner.command('closure-' + label, [*command, 'bounded-references' if bounded else 'closure', root / (label + '-contract.json'), '--report', root / (label + '-closure.json')], allowed=(0, 7) if bounded else (0, 6))
        result['reference_status'] = {label: read(root / (label + '-closure.json'))['status'] for label in contracts}
        approval = None
        if 'approval' in doc:
            approval_source = resolve(base, doc['approval'])
            approval = read(approval_source)
            require(approval.get('schema') == 'bcl-bounded-transformation-1', 'Expected bounded transformation policy')
            source = resolve(approval_source.parent, approval['correspondence'])
            if 'correspondence' in doc:
                require(source == resolve(base, doc['correspondence']), 'Approval and project must use the same correspondence')
        elif 'correspondence' in doc:
            source = resolve(base, doc['correspondence'])
        if 'correspondence' in doc or approval is not None:
            pair = read(source)
            require(pair.get('schema') == 'bcl-bounded-correspondence-1', 'Expected bounded correspondence profile')
            for label in ('original', 'rebuilt'):
                bounded = read(resolve(source.parent, pair[label]))
                bounded['binary'] = label
                target = 'correspondence-' + label + '.json'
                save(root / target, bounded)
                pair[label] = target
            save(root / 'correspondence.json', pair)
            runner.command('program-correspondence', [*command, 'correspondence', root / 'correspondence.json', '--report', root / 'correspondence-report.json'], allowed=(0, 3, 7))
            pair_result = read(root / 'correspondence-report.json')
            result['correspondence_status'] = pair_result['status']
            require(pair_result.get('correspondence_established') is True, 'Program correspondence failed: ' + pair_result['status'] + '; see ' + str(root / 'correspondence-report.json'))
        if approval is not None:
            approval['correspondence'] = 'correspondence.json'
            save(root / 'approval.json', approval)
            runner.command('transformation-approval', [*command, 'approve-transform', root / 'approval.json', '--report', root / 'approval-report.json'], allowed=(0, 3, 7))
            approval_result = read(root / 'approval-report.json')
            result['approval_status'] = approval_result['status']
            result['bounded_transformation_approved'] = approval_result.get('bounded_transformation_approved') is True
            require(result['bounded_transformation_approved'], 'Transformation rejected: ' + approval_result['status'])
        result['safety_decision'] = 'INCONCLUSIVE_WHOLE_PROGRAM_OBLIGATIONS'
        if result.get('bounded_transformation_approved'):
            result['safety_decision'] = 'APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS'
        assessment = {'schema': 'bcl-project-assessment-1', 'decision': result['safety_decision'],
            'automatic_rewrite_allowed': False, 'declared_layout_checked': (root / 'layout.json').exists(),
            'callback_mapping_checked': result.get('callback_mapping_checked', False),
            'bounded_transformation_approved': result.get('bounded_transformation_approved', False),
            'bounded_correspondence_status': result.get('correspondence_status', 'NOT_REQUESTED'),
            'reference_status': result['reference_status'],
            'external_libraries': {role: read(root / (role + '-inventory.json'))['external_libraries'] for role in ('original', 'rebuilt')},
            'unestablished_obligations': ['COMPLETE_ENTRY_AND_REFERENCE_COVERAGE', 'ORIGINAL_REBUILT_INSTRUCTION_AND_ABI_CORRESPONDENCE',
                'LOADER_EXTERNAL_AND_ASYNCHRONOUS_BEHAVIOR', 'OUTSIDE_OBJECT_INTERACTIONS', 'GENERAL_FUNCTIONAL_EQUIVALENCE']}
        save(root / 'assessment.json', assessment)
        if check_only:
            result['status'] = 'STATIC_CHECKS_COMPLETED'
            result['verdict'] = 'NO_OBSERVATION_VERDICT'
        else:
            tools = easy.config_values()
            public = ['--public-before=' + arg for arg in doc.get('public_before', [])] + ['--public-after=' + arg for arg in doc.get('public_after', [])]
            if 'stdin_file' in doc:
                shutil.copyfile(resolve(base, doc['stdin_file']), root / 'public-stdin.bin')
                public += ['--stdin-file', root / 'public-stdin.bin']
            runner.command('collect', [sys.executable, backend / 'collect_whole.py', '--original', original, '--rebuilt', rebuilt,
                '--pin', easy.resolve(tools.get('tools.pin', '')), '--tool', easy.resolve(tools.get('tools.tracer', '')),
                '--tool-source', easy.resolve(tools.get('tools.tracer_source', '')), '--output-parent', root,
                '--repetitions', str(doc['repetitions']), '--timeout', str(doc['timeout']),
                '--secret-0=' + doc['secrets'][0], '--secret-1=' + doc['secrets'][1], *public], seconds=doc['timeout'] * doc['repetitions'] * 8 + 120)
            batches = list(root.glob('whole-collection-*'))
            require(len(batches) == 1, 'Expected one collected batch')
            _, pc = runner.command('python-comparison', [sys.executable, backend / 'whole_trace_check.py', batches[0], '--repetitions', str(doc['repetitions']), '--report', root / 'python-comparison.json'], allowed=(0, 2, 3, 4, 5))
            _, jc = runner.command('java-comparison', [*command, 'pin-check-java', batches[0], '--repetitions', str(doc['repetitions']), '--report', root / 'java-comparison.json'], allowed=(0, 2, 3, 4, 5))
            agree = runpy.run_path(str(ROOT / 'scripts/validate-baseline.py'))['agree']
            result['verdict'] = agree(read(root / 'python-comparison.json'), read(root / 'java-comparison.json'), pc, jc)
            result['python_java_agreement'] = True
            result['status'] = 'COMPARISON_COMPLETE'
    except BaseException as error:
        result.update(status='FAILED', error=str(error))
        raise
    finally:
        save(root / 'summary.json', result)
        seal(root)
    print(render_result(result), flush=True)
    return root


def render_result(data):
    return '\n'.join(['Project result', '==============', 'Status: ' + data['status'],
        'Observation: ' + data.get('verdict', 'unavailable'),
        'References: ' + json.dumps(data.get('reference_status', {})),
        'Exact bounded candidate approved: ' + str(data.get('bounded_transformation_approved', False)),
        'Bounded correspondence: ' + data.get('correspondence_status', 'not requested'),
        'General safe rewriting: not established', 'Evidence retains binaries, inputs, logs and reports.'])


def replay_project(evidence):
    root = Path(evidence).resolve(strict=True)
    count = verify_manifest(root)
    summary = read(root / 'summary.json')
    require(summary.get('schema') == 'bcl-project-result-1' and summary.get('status') in
            ('STATIC_CHECKS_COMPLETED', 'COMPARISON_COMPLETE'), 'Cannot qualify a failed or incomplete project')
    doc = read(root / 'project.json')
    require(summary.get('automatic_rewrite_allowed') is False, 'Project must not claim automatic rewrite authorization')
    if summary['status'] == 'STATIC_CHECKS_COMPLETED':
        require(summary.get('verdict') == 'NO_OBSERVATION_VERDICT', 'Static checks cannot establish an observation verdict')
    runner = easy.Runner()
    command = [os.environ.get('JAVA', 'java'), '-jar', ROOT / 'binarycachelab.jar']
    for label in ('original', 'rebuilt'):
        require(elf_inventory(root / label) == read(root / (label + '-inventory.json')), 'ELF inventory disagreement')
        if (root / (label + '-contract.json')).exists():
            contract = read(root / (label + '-contract.json'))
            bounded = contract.get('schema') == 'bcl-bounded-references-1'
            if bounded:
                require(contract['binary'] == label, 'Bounded contract must bind the snapshotted binary')
                profile_path = root / (label + '-contract.json')
            else:
                contract.update(binary=str(root / label), disassembly=str(root / (label + '.objdump')))
                profile_path = runner.logs / (label + '-contract.json')
                save(profile_path, contract)
            report = runner.logs / (label + '-closure.json')
            runner.command('replay-closure-' + label, [*command, 'bounded-references' if bounded else 'closure', profile_path, '--report', report], allowed=(0, 7) if bounded else (0, 6))
            require(read(report) == read(root / (label + '-closure.json')), 'Reference analysis replay disagreement')
            require(summary.get('reference_status', {}).get(label) == read(report)['status'], 'Summary reference status differs from replay')
    if summary.get('bounded_transformation_approved') or (root / 'approval.json').exists():
        require((root / 'approval.json').is_file() and (root / 'approval-report.json').is_file(), 'Missing approval evidence')
        require(read(root / 'approval.json').get('correspondence') == 'correspondence.json', 'Approval correspondence binding changed')
        approval_report = runner.logs / 'approval-report.json'
        runner.command('replay-approval', [*command, 'approve-transform', root / 'approval.json', '--report', approval_report])
        approved = read(approval_report)
        require(approved == read(root / 'approval-report.json'), 'Approval replay disagreement')
        require(approved.get('bounded_transformation_approved') is True and summary.get('bounded_transformation_approved') is True and summary.get('approval_status') == approved['status'], 'Summary approval differs from replay')
    if (root / 'correspondence.json').exists():
        pair = read(root / 'correspondence.json')
        for label in ('original', 'rebuilt'):
            expected = 'correspondence-' + label + '.json'
            require(pair[label] == expected and read(root / expected)['binary'] == label, 'Correspondence must bind the sealed original/rebuilt binaries')
        report = runner.logs / 'correspondence-report.json'
        runner.command('replay-correspondence', [*command, 'correspondence', root / 'correspondence.json', '--report', report])
        require(read(report) == read(root / 'correspondence-report.json'), 'Program correspondence replay disagreement')
        require(read(report)['correspondence_established'] is True and summary.get('correspondence_status') == read(report)['status'], 'Summary correspondence status differs from replay')
    if (root / 'regions.json').exists():
        report = runner.logs / 'layout.json'
        runner.command('replay-layout', [*command, 'verify-regions', root / 'regions.json', '--original', root / 'original', '--rebuilt', root / 'rebuilt', '--report', report])
        require(read(report) == read(root / 'layout.json'), 'Linked layout replay disagreement')
    if (root / 'callbacks.json').exists():
        report = runner.logs / 'callbacks.json'
        runner.command('replay-callbacks', [*command, 'callback-check', root / 'original', '--rebuilt', root / 'rebuilt', '--report', report])
        require(read(report) == read(root / 'callbacks.json'), 'Callback mapping replay disagreement')
    if summary['status'] == 'COMPARISON_COMPLETE':
        batches = list(root.glob('whole-collection-*'))
        require(len(batches) == 1, 'Expected one bound collection')
        batch = batches[0]
        settings = read(batch / 'experiment.json')
        require(settings.get('secrets') == doc.get('secrets') and settings.get('repetitions') == doc.get('repetitions'),
                'Collection input contract differs from the project')
        require(settings.get('public_inputs', {}).get('other_arguments') == doc.get('public_before', []) + doc.get('public_after', []),
                'Collection public arguments differ from the project')
        require(settings.get('public_argv_before', []) == doc.get('public_before', []) and
                settings.get('public_argv_after', []) == doc.get('public_after', []), 'Public argument ordering differs')
        if 'stdin_file' in doc:
            require(easy.sha(root / 'public-stdin.bin') == easy.sha(batch / 'public-stdin.bin'), 'Collection stdin differs from project snapshot')
        else:
            require(settings.get('public_inputs', {}).get('stdin') == 'empty', 'Unexpected collection stdin')
        for label in ('original', 'rebuilt'):
            require(easy.sha(root / label) == easy.sha(batch / 'binaries' / label), 'Collection binary differs from analyzed ELF')
        py_report, java_report = runner.logs / 'python-comparison.json', runner.logs / 'java-comparison.json'
        _, pc = runner.command('replay-python', [sys.executable, ROOT / 'backend/whole_trace_check.py', batch,
            '--repetitions', str(doc['repetitions']), '--report', py_report], allowed=(0, 2, 3, 4, 5))
        _, jc = runner.command('replay-java', [*command, 'pin-check-java', batch, '--repetitions', str(doc['repetitions']),
            '--report', java_report], allowed=(0, 2, 3, 4, 5))
        agree = runpy.run_path(str(ROOT / 'scripts/validate-baseline.py'))['agree']
        verdict = agree(read(py_report), read(java_report), pc, jc)
        require(verdict == summary.get('verdict'), 'Recorded observation verdict differs from replay')
        for current, saved in ((py_report, root / 'python-comparison.json'), (java_report, root / 'java-comparison.json')):
            actual, expected = read(current), read(saved)
            actual.pop('batch', None)
            expected.pop('batch', None)
            require(actual == expected, 'Recorded result differs from replay')
    print('Replayed project evidence: ' + str(count) + ' files checked.\n' + render_result(summary))
    return count


def qualify_references(output, bounded=False, correspondence=False, approval=False):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='reference-qualification-', dir=output))
    classes = root / 'classes'
    classes.mkdir()
    runner = easy.Runner()
    runner.logs = root / 'logs'
    runner.logs.mkdir()
    java = os.environ.get('JAVA', 'java')
    javac = os.environ.get('JAVAC', 'javac')
    test_class = 'BoundedTransformationTest' if approval else 'BoundedCorrespondenceTest' if correspondence else 'BoundedReferencesTest' if bounded else 'ReferenceClosureTest'
    source = ROOT / ('src/test/java/org/binarycachelab/analysis/' + test_class + '.java')
    jar = root / 'binarycachelab.jar'
    shutil.copy2(ROOT / 'binarycachelab.jar', jar)
    shutil.copy2(source, root / source.name)
    sources = [root / source.name]
    if correspondence or approval:
        helper = ROOT / 'src/test/java/org/binarycachelab/analysis/BoundedReferencesTest.java'
        shutil.copy2(helper, root / helper.name)
        sources.append(root / helper.name)
    if approval:
        helper = ROOT / 'src/test/java/org/binarycachelab/analysis/BoundedCorrespondenceTest.java'
        shutil.copy2(helper, root / helper.name)
        sources.append(root / helper.name)
    runner.command('compile-reference-tests', [javac, '--release', '17', '-cp', jar, '-d', classes, *sources])
    runner.command('reference-analysis-tests', [java, '-cp', str(jar) + os.pathsep + str(classes),
                    'org.binarycachelab.analysis.' + test_class, root / 'cases'])
    result = read(root / 'cases/summary.json')
    require(result['status'] == ('APPROVAL_QUALIFICATION_EXPECTATIONS_MET' if approval else 'CORRESPONDENCE_QUALIFICATION_EXPECTATIONS_MET' if correspondence else 'BOUNDED_QUALIFICATION_EXPECTATIONS_MET' if bounded else 'REFERENCE_QUALIFICATION_EXPECTATIONS_MET'), 'Reference qualification did not complete')
    save(root / 'summary.json', result)
    seal(root)
    print('Bounded transformation approval qualification\n=============================================' if approval else 'Bounded correspondence qualification\n====================================' if correspondence else 'Reference analysis qualification\n================================')
    print('Checks passed: ' + str(result['checks']))
    print('Evidence: ' + str(root))
    print('Scope: ' + result['scope'])
    return root


def project_tui(path):
    path, doc = profile(path)
    latest = None
    while True:
        print('\nBinaryCacheLab project\n======================')
        print('Profile: ' + str(path))
        print('Original: ' + doc['original'])
        print('Rebuild: ' + ('fresh FoxDec lift' if 'lift' in doc else doc['rebuilt']))
        print('Secrets: ' + repr(doc['secrets']) + '; repeats: ' + str(doc['repetitions']))
        print('[r] run  [s] static checks  [v] verify latest  [q] quit')
        try:
            choice = input('> ').strip().lower()
            if choice == 'q':
                return 0
            if choice in ('r', 's'):
                latest = run_project(path, choice == 's')
            elif choice == 'v':
                require(latest is not None, 'No completed project run in this session')
                replay_project(latest)
            else:
                print('Choose r, s, v or q. Ctrl+C cancels an active run.')
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print('\nCancelled; any partial evidence is retained.')
        except (OSError, ValueError, RuntimeError) as error:
            print('ERROR: ' + str(error))


def qualify(output, lift=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='project-qualification-', dir=output))
    record = {'schema': 'bcl-project-qualification-1', 'status': 'RUNNING', 'fresh_lifting': lift,
              'automatic_rewrite_allowed': False, 'cases': []}
    print('Qualification evidence: ' + str(root), flush=True)
    cases = [('equal_line', 'SATISFIED_FOR_TESTED_PAIR'), ('multiple_regions', 'SATISFIED_FOR_TESTED_PAIR'),
             ('secret_line', 'ORIGINAL_OBSERVATIONS_DIFFER'), ('crossing_lines', 'ORIGINAL_OBSERVATIONS_DIFFER')]
    try:
        for name, expected in cases:
            source = ROOT / 'examples/benchmarks' / (name + '.c')
            doc = {'schema': 'bcl-project-1', 'original': '{work}/original-built', 'rebuilt': '{work}/rebuilt-built',
                'output': str(root / name), 'inputs': {name + '.c': str(source),
                    'fixture.h': str(source.parent / 'fixture.h')},
                'build_jobs': [{'argv': ['gcc', '-O1', '-fPIE', '-pie', '{input:' + name + '.c}', '-o', '{work}/original-built']}],
                'secrets': ['0', '1'], 'repetitions': 3, 'timeout': 120, 'contracts': {}}
            if lift:
                doc['lift'] = {}
            else:
                doc['build_jobs'].append({'argv': ['gcc', '-O2', '-fPIE', '-pie', '{input:' + name + '.c}', '-o', '{work}/rebuilt-built']})
            profile_path = root / (name + '.json')
            save(profile_path, doc)
            evidence = run_project(profile_path)
            replay_project(evidence)
            summary = read(evidence / 'summary.json')
            passed = summary.get('status') == 'COMPARISON_COMPLETE' and summary.get('verdict') == expected
            record['cases'].append({'name': name, 'expected': expected, 'actual': summary.get('verdict'),
                'evidence': str(evidence), 'expectations_met': passed})
            require(passed, 'Qualification expectation failed for ' + name)
        record['status'] = 'PROJECT_QUALIFICATION_EXPECTATIONS_MET'
    except BaseException as error:
        record.update(status='FAILED', error=str(error))
        raise
    finally:
        save(root / 'qualification.json', record)
        seal(root)
    print('PROJECT_QUALIFICATION_EXPECTATIONS_MET: ' + str(root), flush=True)
    return root


def main(args=None, raw=False):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--original', required=True, type=Path)
    choice = init.add_mutually_exclusive_group(required=True)
    choice.add_argument('--rebuilt', type=Path)
    choice.add_argument('--lift', action='store_true', help='Fresh FoxDec lift and baseline rebuild of the original')
    init.add_argument('--output', required=True, type=Path, help='New project JSON file')
    init.add_argument('--entry', action='append', default=[], help='Function symbol for automatic contract addresses (repeatable)')
    init.add_argument('--region', action='append', default=[], help='Object symbol for automatic contract regions (repeatable)')
    discover = sub.add_parser('discover')
    discover.add_argument('binary', type=Path)
    discover.add_argument('--report', type=Path)
    run = sub.add_parser('run')
    run.add_argument('profile', type=Path)
    run.add_argument('--check-only', action='store_true')
    tui = sub.add_parser('tui')
    tui.add_argument('profile', type=Path)
    verify = sub.add_parser('verify')
    verify.add_argument('evidence', type=Path)
    verify.add_argument('--integrity-only', action='store_true', help='Check files without analysis/trace replay')
    publish = sub.add_parser('publish', help='Replay evidence and publish only its exact approved bounded candidate')
    publish.add_argument('evidence', type=Path)
    publish.add_argument('--output', required=True, type=Path)
    qualification = sub.add_parser('qualify')
    qualification.add_argument('--output', type=Path, default=ROOT / 'experiments')
    qualification_mode = qualification.add_mutually_exclusive_group()
    qualification_mode.add_argument('--lift', action='store_true', help='Use fresh FoxDec rebuilding for all four benchmarks')
    qualification_mode.add_argument('--references', action='store_true', help='Run encoded ELF pointer, alias, entry and indirect-control qualification')
    qualification_mode.add_argument('--bounded-references', action='store_true', help='Run exhaustive bounded machine-model qualification')
    qualification_mode.add_argument('--approval', action='store_true', help='Qualify exact bounded transformation approval and publication')
    qualification_mode.add_argument('--correspondence', action='store_true', help='Run bounded functionality, ABI, control-flow and runtime qualification')
    opts = parser.parse_args(args)
    if opts.action == 'discover':
        inventory = elf_inventory(opts.binary)
        if opts.report:
            require(not opts.report.exists(), 'Report already exists')
            save(opts.report, inventory)
        if raw:
            print(json.dumps(inventory, indent=2))
        else:
            print('ELF inventory\n=============\nEntry: ' + hex(inventory['entry']))
            print('Defined data objects: ' + str(len(inventory['objects'])))
            for row in inventory['objects'][:40]:
                print('  ' + hex(row['address']) + '  ' + str(row['size']) + ' bytes  ' + row['name'])
            if len(inventory['objects']) > 40:
                print('  Additional objects are available with --json or --report FILE.')
            print('Defined functions: ' + str(len(inventory['functions'])) + '\nSymbol discovery does not establish reference coverage.')
    elif opts.action == 'init':
        require(not opts.output.exists(), 'Project file already exists')
        original = opts.original.resolve(strict=True)
        rebuilt = opts.rebuilt.resolve(strict=True) if opts.rebuilt else original
        elf_inventory(original)
        elf_inventory(rebuilt)
        doc = {'schema': 'bcl-project-1', 'original': str(original), 'rebuilt': str(rebuilt),
             'output': 'experiments', 'secrets': ['0', '1'], 'repetitions': 3, 'timeout': 120, 'contracts': {}}
        if opts.lift:
            doc['lift'] = {}
        if opts.entry or opts.region:
            require(opts.entry and opts.region, '--entry and --region must be supplied together')
            doc['analysis'] = {'entries': opts.entry, 'regions': opts.region}
            symbol_contract(elf_inventory(original), doc['analysis'])
        save(opts.output, doc)
        print('Created ' + str(opts.output) + '\nRun: ./bcl project run ' + str(opts.output))
    elif opts.action == 'run':
        run_project(opts.profile, opts.check_only)
    elif opts.action == 'tui':
        return project_tui(opts.profile)
    elif opts.action == 'publish':
        replay_project(opts.evidence)
        root = opts.evidence.resolve(strict=True)
        require(read(root / 'summary.json').get('bounded_transformation_approved') is True, 'Evidence has no bounded transformation approval')
        runner = easy.Runner()
        text, _ = runner.command('publish-approved-candidate', [os.environ.get('JAVA', 'java'), '-jar', ROOT / 'binarycachelab.jar', 'publish-transform', root / 'approval.json', '--output', opts.output])
        result = json.loads(text)
        require(result.get('bounded_transformation_approved') is True and 'publication' in result, 'Publication refused')
        print('Published exact bounded candidate: ' + result['publication']['output'])
    elif opts.action == 'qualify':
        if opts.references or opts.bounded_references or opts.correspondence or opts.approval:
            qualify_references(opts.output, opts.bounded_references, opts.correspondence, opts.approval)
        else:
            qualify(opts.output, opts.lift)
    else:
        if opts.integrity_only:
            count = verify_manifest(opts.evidence)
            print('Integrity checked: ' + str(count) + ' files. This is not execution attestation.\n' + render_result(read(opts.evidence / 'summary.json')))
        else:
            replay_project(opts.evidence)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(2)
