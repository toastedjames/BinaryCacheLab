"""Restore declared data boundaries using exact original ELF/assembly bytes.

FoxDec may retain an original alias instead of its address-derived spelling.
An alias is established only after checking the complete emitted literal section.
"""
from pathlib import Path
import re
import struct

import project


def require(value, detail):
    if not value: raise ValueError(detail)


def sections(binary):
    raw = Path(binary).read_bytes()
    require(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01', 'Region binding requires ELF64 little endian')
    start = struct.unpack_from('<Q', raw, 40)[0]
    width, count, strings = struct.unpack_from('<HHH', raw, 58)
    require(width == 64 and 0 < count <= 4096 and strings < count and 64 <= start <= len(raw) - 64 * count,
            'Unsupported section inventory for protected region binding')
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, start + i * 64) for i in range(count)]
    def content(row):
        require(row[4] <= len(raw) and row[5] <= len(raw) - row[4], 'Section bytes outside original ELF')
        return raw[row[4]:row[4] + row[5]]
    names = content(rows[strings])
    result = []
    for row in rows:
        if row[1] != 1 or not row[2] & 2 or row[2] & 4: continue
        require(row[0] < len(names) and b'\0' in names[row[0]:], 'Invalid original section name')
        result.append({'name': names[row[0]:].split(b'\0', 1)[0].decode('ascii'),
                       'address': row[3], 'size': row[5], 'bytes': content(row)})
    return result


def literal(code):
    match = re.fullmatch(r'(?i)(db|dw|dd|dq)\s+(.+)', code)
    require(match is not None, 'Unsupported emitted data statement in protected literal section: ' + code)
    width = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8}[match[1].lower()]
    result = bytearray()
    for item in match[2].split(','):
        value = item.strip()
        if re.fullmatch(r'(?i)0x[0-9a-f]+', value): number = int(value, 16)
        elif re.fullmatch(r'(?i)[0-9][0-9a-f]*h', value): number = int(value[:-1], 16)
        elif re.fullmatch(r'-?[0-9]+', value): number = int(value)
        else: raise ValueError('Nonliteral or relocation-bearing data cannot be rebound as literal bytes: ' + value)
        require(-(1 << (8 * width - 1)) <= number < (1 << (8 * width)), 'Data literal outside operand width')
        result.extend((number % (1 << (8 * width))).to_bytes(width, 'little'))
    return bytes(result)


def restore(assembly, binary, declarations):
    path = Path(assembly)
    before_raw = path.read_bytes()
    before = before_raw.decode('utf-8')
    lines = before.splitlines()
    owners = sections(binary)
    requests = {}
    for row in declarations:
        address, size = row['address'], row['size']
        hits = [owner for owner in owners if owner['address'] <= address and address + size <= owner['address'] + owner['size']]
        require(len(hits) == 1, 'Protected literal region must occupy one allocated nonexecutable file-backed section')
        owner = hits[0]
        for name, point in ((row['start_label'], address), (row['end_label'], address + size)):
            require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.$]*', name), 'Invalid protected data alias')
            require(name not in requests or requests[name] == (owner['name'], point), 'One alias requests different data boundaries')
            requests[name] = (owner['name'], point)
    replacements, established, used_sections, original_labels = [], {}, set(), set()
    starts = [i for i, line in enumerate(lines) if re.match(r'(?i)^\s*(section|segment)\s+', line)]
    for first, stop in zip(starts, starts[1:] + [len(lines)]):
        header = re.match(r'(?i)^\s*(?:section|segment)\s+(\.[\w.]+).*;\s*@(?:0x)?([0-9a-f]+)\s*$', lines[first])
        if not header or not any(section == header[1] for section, _ in requests.values()): continue
        name, address = header[1], int(header[2], 16)
        hits = [owner for owner in owners if owner['name'] == name and owner['address'] == address]
        require(len(hits) == 1 and name not in used_sections, 'Emitted data section has no unique original address binding')
        owner = hits[0]; used_sections.add(name)
        emitted = bytearray(); labels = {}
        for line in lines[first + 1:stop]:
            code = line.split(';', 1)[0].strip()
            if not code: continue
            match = re.match(r'^([A-Za-z_][\w.$]*):\s*(.*)$', code)
            if match:
                label = match[1]
                require(label not in labels, 'Duplicate emitted data label')
                labels[label] = address + len(emitted); code = match[2]
            if code: emitted.extend(literal(code))
            require(len(emitted) <= owner['size'], 'Emitted data exceeds original section')
        require(bytes(emitted) == owner['bytes'], 'Emitted section differs from original ELF; cannot establish aliases')
        original_labels.update(labels)
        all_labels = dict(labels)
        for label, (section, point) in requests.items():
            if section != name: continue
            require(label not in labels or labels[label] == point, 'Existing data alias is at the wrong original offset')
            all_labels[label] = point
            established[label] = point
        body = [lines[first]]
        for offset in range(len(emitted) + 1):
            body.extend(label + ':' for label, point in all_labels.items() if point == address + offset)
            if offset < len(emitted): body.append('db 0x%02x' % emitted[offset])
        replacements.append((first, stop, body))
    require(set(established) == set(requests), 'No exact emitted section available for every protected data boundary')
    # Any same-named label outside its proven section is ambiguous, not guessed.
    for label in established:
        count = sum(bool(re.match(r'^\s*' + re.escape(label) + r':', line)) for line in lines)
        require(count <= 1 and (count == 0 or label in original_labels), 'Duplicate or out-of-section protected boundary alias in assembly')
    for first, stop, body in reversed(replacements): lines[first:stop] = body
    after = '\n'.join(lines) + '\n'
    path.write_text(after, encoding='utf-8', newline='\n')
    return {'schema': 'bcl-exact-data-boundaries-1', 'status': 'ORIGINAL_ELF_BYTES_AND_BOUNDARIES_VERIFIED',
            'aliases': established, 'original_elf_sha256': project.easy.sha(binary),
            'source_assembly_sha256': __import__('hashlib').sha256(before_raw).hexdigest(),
            'bound_assembly_sha256': project.easy.sha(path), 'section_bytes_preserved': True}


def materialize(workflow, assembly):
    options = workflow.doc['transform']
    require('profile' not in options, 'Automatic boundary binding requires the declared region-name/end-symbol configuration')
    names = options.get('region_names', [])
    ends = options.get('end_symbols', [])
    require(len(names) == len(ends) and names, 'Protection needs region boundary declarations')
    original = {row['name']: row for row in workflow.regions['original']}
    configured = {row['name']: row for row in workflow.doc['regions']}
    declarations = []
    for name, end in zip(names, ends):
        require('symbol' in configured[name]['baseline'] and 'symbol' in configured[name]['transformed'], 'Protected final region boundaries require symbolic bindings')
        for variant in ('baseline', 'transformed'):
            declarations.append({**original[name], 'start_label': workflow.label(configured[name][variant]['symbol'], name),
                                 'end_label': workflow.label(end, name)})
    result = restore(assembly, workflow.root / 'build/original', declarations)
    project.save(workflow.root / 'validation/data-boundary-bindings.json', result)
