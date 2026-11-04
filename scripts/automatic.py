"""Automatic, fail-closed literal-region relocation in the exhaustive bounded model."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import project
import easy

SCHEMA = 'bcl-automatic-rewrite-1'
MAX_ATTEMPTS = 32


def require(value, detail):
    project.require(value, detail)


def load_elf(raw):
    require(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01', 'Only little-endian ELF64 is supported')
    require(struct.unpack_from('<HH', raw, 16) == (2, 62), 'Only fixed-address x86-64 ET_EXEC is supported')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    width, count = struct.unpack_from('<HH', raw, 54)
    require(width == 56 and 0 < count <= 256 and 64 <= offset <= len(raw) - count * width, 'Invalid program headers')
    segments = []
    for i in range(count):
        kind, flags, file, address, _, size, memory, _ = struct.unpack_from('<IIQQQQQQ', raw, offset + i * width)
        require(kind not in (2, 3, 7), 'Dynamic loader, libraries and TLS are outside the automatic runtime model')
        if kind == 1:
            require(file <= len(raw) and size <= len(raw) - file and size <= memory, 'Invalid load extent')
            segments.append((address, size, file, flags))
    return segments


def file_at(segments, address, size, executable=False):
    hits = [(offset + address - start, flags) for start, length, offset, flags in segments
            if start <= address and 0 < size <= length and address - start <= length - size]
    require(len(hits) == 1, 'Address must have one complete file-backed mapping')
    offset, flags = hits[0]
    require(flags & 4 and (flags & 1 if executable else flags & 2 and not flags & 1),
            'Expected executable code' if executable else 'Regions require readable writable nonexecutable file-backed data')
    return offset


def validate(policy):
    require(isinstance(policy, dict) and set(policy) == {'schema', 'original', 'regions', 'destinations', 'secret_inputs', 'register_outputs'},
            'Automatic policy requires schema, original, regions, destinations, secret_inputs and register_outputs only')
    require(policy['schema'] == SCHEMA, 'Expected ' + SCHEMA)
    regions = policy['regions']
    require(isinstance(regions, list) and 1 <= len(regions) <= 32, 'Declare 1..32 literal regions')
    names = set()
    for region in regions:
        require(isinstance(region, dict) and set(region) == {'name', 'address', 'size', 'alignment'}, 'Invalid literal region')
        require(isinstance(region['name'], str) and region['name'] and region['name'] not in names, 'Region names must be unique')
        names.add(region['name'])
        require(all(type(region[k]) is int for k in ('address', 'size', 'alignment')), 'Region fields must be integers')
        a, size, alignment = region['address'], region['size'], region['alignment']
        require(0 <= a < 2**47 and 0 < size <= 1024*1024 and a + size < 2**47, 'Invalid region extent')
        require(0 < alignment <= 1024*1024 and alignment & (alignment-1) == 0 and a % alignment == 0, 'Invalid original alignment')
    ordered = sorted(regions, key=lambda r: r['address'])
    require(all(a['address'] + a['size'] <= b['address'] for a, b in zip(ordered, ordered[1:])), 'Overlapping regions are unsupported')
    require(sum(r['size'] for r in regions) <= 4*1024*1024, 'Selected literal bytes exceed 4 MiB')
    destinations = policy['destinations']
    require(isinstance(destinations, list) and 1 <= len(destinations) <= MAX_ATTEMPTS and
            all(type(a) is int and 0 <= a < 2**47 for a in destinations) and len(set(destinations)) == len(destinations),
            'Declare 1..32 distinct candidate addresses for the first region')
    return ordered


def candidate(raw, analysis, regions, destination):
    segments = load_elf(raw)
    delta = destination - regions[0]['address']
    period = max(64, *(r['alignment'] for r in regions))
    require(delta != 0 and delta % period == 0, 'Placement must move data and preserve 64-byte residue and all alignments')
    source_spans, target_spans = [], []
    for r in regions:
        start, size = r['address'], r['size']
        old = file_at(segments, start, size)
        new = file_at(segments, start + delta, size)
        require(not any(raw[new:new+size]), 'Destination is not unused zero file storage')
        source_spans.append((old, size))
        target_spans.append((new, size))
    require(all(a+n <= b or b+m <= a for a,n in source_spans for b,m in target_spans), 'Destinations overlap selected source bytes')
    patched = bytearray(raw)
    changes = []
    for instruction in analysis['instruction_coverage']:
        encoded = bytes.fromhex(instruction['bytes'])
        # B8+rd: MOV r32,imm32 zero extends; REX.W selects MOVABS r64,imm64.
        prefix = 1 if encoded and 0x40 <= encoded[0] <= 0x4f else 0
        if len(encoded) <= prefix or not 0xb8 <= encoded[prefix] <= 0xbf:
            continue
        width = 8 if prefix and encoded[0] & 8 else 4
        immediate = prefix + 1
        if len(encoded) != immediate + width:
            continue
        value = int.from_bytes(encoded[immediate:], 'little')
        matches = [r for r in regions if r['address'] <= value < r['address'] + r['size']]
        if not matches:
            continue
        where = file_at(segments, instruction['ip'], len(encoded), True)
        require(raw[where:where+len(encoded)] == encoded, 'Instruction bytes disagree with exhaustive analysis')
        replacement = value + delta
        require(0 <= replacement < 2**47, 'Rebound pointer outside supported address space')
        require(replacement < 1 << (8*width), 'Rebound pointer cannot be represented by the original immediate width')
        patched[where+immediate:where+immediate+width] = replacement.to_bytes(width, 'little')
        changes.append({'ip': instruction['ip'], 'file_offset': where+immediate, 'instruction_offset': where, 'width': width, 'old': value, 'new': replacement, 'region': matches[0]['name']})
    require(changes, 'No supported executed MOVABS/MOV-immediate region-address loads; no automatic rewrite is available')
    # Reject overlapping alternate instruction entries that could change meaning underneath another decode.
    for instruction in analysis['instruction_coverage']:
        start = file_at(segments, instruction['ip'], len(bytes.fromhex(instruction['bytes'])), True)
        for patch in changes:
            if start != patch['instruction_offset']:
                require(start+len(bytes.fromhex(instruction['bytes'])) <= patch['file_offset'] or patch['file_offset']+patch['width'] <= start,
                        'Address patch overlaps an alternate executed instruction decoding')
    for (old,size),(new,_) in zip(source_spans,target_spans):
        patched[old:old+size] = bytes(size)
        patched[new:new+size] = raw[old:old+size]
    # Keep any declared section view consistent with the rewritten PT_LOAD bytes.
    section_offset = struct.unpack_from('<Q',raw,40)[0]
    section_width, section_count = struct.unpack_from('<HH',raw,58)
    if section_count:
        require(section_width == 64 and 0 <= section_offset <= len(raw)-64*section_count, 'Invalid section inventory')
        for index in range(section_count):
            at = section_offset + 64*index
            kind, flags, address, offset, size = struct.unpack_from('<IQQQQ',raw,at+4)
            require(kind not in (2,11), 'Automatic symbol-table rebinding is unsupported')
            for region in regions:
                if flags & 2 and address < region['address']+region['size'] and region['address'] < address+size:
                    require(kind == 1 and address == region['address'] and size == region['size'],
                            'Selected region must exactly occupy its allocated section; sectionless ELF is also supported')
                    target = file_at(segments,address+delta,size)
                    struct.pack_into('<QQ',patched,at+16,address+delta,target)
    return bytes(patched), delta, changes


def contracts(original, analysis, regions, delta, policy):
    require(all(set(i) == {'register','values'} for i in original['inputs']), 'Automatic rewriting currently supports scalar register inputs only')
    require(not original['machine'].get('initial_registers'), 'Automatic rewriting requires zero initial register defaults')
    rebuilt = copy.deepcopy(original)
    rebuilt['binary'] = 'candidate.elf'
    rebuilt['regions'] = [{'name': r['name'], 'address': r['address']+delta, 'size': r['size']} for r in regions]
    pair = {'schema': 'bcl-bounded-correspondence-1', 'abi': 'sysv-amd64-integer',
            'original': '../original.json', 'rebuilt': 'rebuilt.json',
            'entries': [{'original': a, 'rebuilt': a} for a in original['entries']],
            'control_map': [{'original': i['ip'], 'rebuilt': i['ip']} for i in analysis['instruction_coverage']],
            'memory_maps': [{'name': r['name'], 'original': r['address'], 'rebuilt': r['address']+delta, 'size': r['size']} for r in regions],
            'input_map': [{'original': i, 'rebuilt': i, 'encoding': 'scalar'} for i in range(len(original['inputs']))],
            'register_outputs': policy['register_outputs']}
    approval = {'schema': 'bcl-bounded-transformation-1', 'correspondence': 'correspondence.json',
                'observer': {'policy': 'ordered-raw-virtual-lines', 'line_bytes': 64},
                'secret_inputs': policy['secret_inputs'], 'require_nonvacuous': True,
                'layout': {'policy': 'preserve-byte-line-partition',
                           'regions': [{'name': r['name'], 'alignment': r['alignment']} for r in regions]}}
    return rebuilt, pair, approval


def verify_rebinding(result, regions, delta):
    correspondence=result['correspondence']
    for pair in correspondence['cases']:
        a=correspondence['original_analysis']['executions'][pair['original_case']]['references']
        b=correspondence['rebuilt_analysis']['executions'][pair['rebuilt_case']]['references']
        require(len(a)==len(b),'Executed reference count changed during automatic rebinding')
        for old,new in zip(a,b):
            require(all(old[k]==new[k] for k in ('ip','width','write')),'Executed reference-site correspondence changed')
            address,width=old['address'],old['width']
            overlaps=[r for r in regions if address<r['address']+r['size'] and r['address']<address+width]
            expected=address
            if overlaps:
                require(len(overlaps)==1 and overlaps[0]['address']<=address and address+width<=overlaps[0]['address']+overlaps[0]['size'],
                        'Cross-region or outside-object access unsupported by automatic rebinding')
                expected+=delta
            require(new['address']==expected,'Not every executed region reference was rebound correctly')


def execute(root, policy):
    regions = validate(policy)
    runner = easy.Runner()
    runner.logs = root / 'logs'
    runner.logs.mkdir(exist_ok=True)
    command = [os.environ.get('JAVA','java'), '-jar', root/'toolkit.jar']
    def analyze(name, command_name, profile, report, allowed=(0,3,7)):
        runner.command(name, [*command, command_name, profile, '--report', report], allowed=allowed)
        return project.read(report)
    summary = {'schema':'bcl-automatic-rewrite-report-1','status':'AUTO_REWRITE_REJECTED',
               'bounded_transformation_approved':False,'automatic_rewrite_allowed':False,'attempts':[],
               'scope':'Exact generated candidate and exhaustive finite closed machine contract; no arbitrary-program authorization'}
    original = project.read(root/'original.json')
    require(original.get('schema') == 'bcl-bounded-references-1' and original['binary'] == 'original.elf', 'Invalid original snapshot binding')
    raw = (root/'original.elf').read_bytes()
    summary['original_sha256'] = hashlib.sha256(raw).hexdigest()
    analysis = analyze('original-analysis','bounded-references',root/'original.json',root/'original-analysis.json')
    if not analysis.get('exhaustive'):
        summary['rejection'] = 'Original execution is unsupported or exceeds declared bounds'
        return summary
    require(analysis['binary_sha256'] == summary['original_sha256'], 'Original changed during analysis')
    for index,destination in enumerate(policy['destinations']):
        attempt = root / ('attempt-%02d'%index)
        attempt.mkdir()
        record = {'index':index,'destination':destination,'status':'REJECTED'}
        summary['attempts'].append(record)
        try:
            rewritten,delta,changes = candidate(raw,analysis,regions,destination)
            rebuilt,pair,approval = contracts(original,analysis,regions,delta,policy)
            (attempt/'candidate.elf').write_bytes(rewritten)
            (attempt/'candidate.elf').chmod(0o755)
            project.save(attempt/'rebuilt.json',rebuilt)
            project.save(attempt/'correspondence.json',pair)
            project.save(attempt/'approval.json',approval)
            manifest = {'schema':'bcl-automatic-transform-manifest-1','policy':'preserve-byte-line-partition',
                        'original_sha256':summary['original_sha256'],'candidate_sha256':hashlib.sha256(rewritten).hexdigest(),
                        'delta':delta,'address_patches':changes,'regions':regions,'cleared_original_region_bytes':True,
                        'selection_reason':'One common aligned displacement preserves every selected relative offset and shared-line class; exhaustive approval is mandatory'}
            project.save(attempt/'transformation.json',manifest)
            result = analyze('approve-%02d'%index,'approve-transform',attempt/'approval.json',attempt/'approval-report.json')
            record['decision'] = result['status']
            if not result.get('bounded_transformation_approved'):
                record['reason'] = result.get('rejection',{})
                continue
            verify_rebinding(result,regions,delta)
            manifest['executed_reference_rebinding_verified']=True
            project.save(attempt/'transformation.json',manifest)
            # Recompute approval again inside publication; never copy an unapproved candidate to the final name.
            runner.command('publish-%02d'%index,[*command,'publish-transform',attempt/'approval.json','--output',root/'protected.elf','--report',attempt/'publication.json'])
            record['status']='APPROVED'
            summary.update(status='AUTO_REWRITE_APPROVED_WITHIN_BOUNDS',bounded_transformation_approved=True,
                           selected_attempt=index,candidate_sha256=manifest['candidate_sha256'],publication='protected.elf')
            return summary
        except (ValueError,RuntimeError) as error:
            record['reason']=str(error).replace(str(root),'<evidence>')
    summary['rejection']='No proposed placement passed rewriting and exhaustive approval'
    return summary


def run(profile, output):
    source = Path(profile).resolve(strict=True)
    policy = project.read(source)
    validate(policy)
    original_path = project.resolve(source.parent,policy['original'])
    original = project.read(original_path)
    binary = project.resolve(original_path.parent,original['binary'])
    require(binary.stat().st_size <= 64*1024*1024, 'Original exceeds 64 MiB')
    root = Path(output).absolute()
    require(not root.exists() and not any(p.is_symlink() for p in (root,*root.parents)), 'Use a new nonsymlink evidence directory')
    root.mkdir(parents=True)
    policy['original']='original.json'
    original['binary']='original.elf'
    project.save(root/'policy.json',policy)
    project.save(root/'original.json',original)
    shutil.copy2(binary,root/'original.elf')
    shutil.copy2(project.ROOT/'binarycachelab.jar',root/'toolkit.jar')
    try:
        result=execute(root,policy)
    except (ValueError,RuntimeError,OSError) as error:
        result={'schema':'bcl-automatic-rewrite-report-1','status':'AUTO_REWRITE_REJECTED',
                'bounded_transformation_approved':False,'automatic_rewrite_allowed':False,'rejection':str(error).replace(str(root),'<evidence>')}
    project.save(root/'summary.json',result)
    project.seal(root)
    return result


def verify(evidence):
    root=Path(evidence).resolve(strict=True)
    project.verify_manifest(root)
    policy=project.read(root/'policy.json')
    require(policy['original']=='original.json','Policy snapshot binding changed')
    expected=project.read(root/'summary.json')
    require((root/'protected.elf').exists()==bool(expected.get('bounded_transformation_approved')), 'Publication presence disagrees with the decision')
    # Rebuild every decision from the sealed original/profile, using the sealed toolkit.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='bcl-auto-replay-',dir=root.parent) as directory:
        scratch=Path(directory)
        for name in ('policy.json','original.json','original.elf','toolkit.jar'):
            shutil.copy2(root/name,scratch/name)
        try:
            actual=execute(scratch,policy)
        except (ValueError,RuntimeError,OSError) as error:
            actual={'schema':'bcl-automatic-rewrite-report-1','status':'AUTO_REWRITE_REJECTED',
                    'bounded_transformation_approved':False,'automatic_rewrite_allowed':False,
                    'rejection':str(error).replace(str(scratch),'<evidence>')}
        require(actual==expected,'Automatic decision differs from replay')
        for file in scratch.rglob('*'):
            if file.is_file() and file.relative_to(scratch).parts[0]!='logs':
                counterpart=root/file.relative_to(scratch)
                if file.name=='publication.json':
                    a,b=project.read(file),project.read(counterpart)
                    a['publication']['output']=b['publication']['output']
                    require(a==b,'Publication approval differs from replay')
                else:
                    require(counterpart.is_file(),'Missing rewritten artifact: '+str(file.relative_to(scratch)))
                    same = project.read(file)==project.read(counterpart) if file.suffix=='.json' else file.read_bytes()==counterpart.read_bytes()
                    require(same,'Rewritten artifact differs from replay: '+str(file.relative_to(scratch)))
    return expected


def main(args=None,raw=False):
    args=list(sys.argv[1:] if args is None else args)
    if args and args[0]=='qualify':
        parser=argparse.ArgumentParser(description='Qualify automatic rewriting with real encoded ELF programs')
        parser.add_argument('--output',required=True,type=Path)
        opts=parser.parse_args(args[1:])
        from qualify_automatic import qualify
        result=qualify(opts.output)
    elif args and args[0]=='verify':
        require(len(args)==2,'Usage: rewrite verify EVIDENCE')
        result=verify(args[1])
    else:
        parser=argparse.ArgumentParser(description=__doc__)
        parser.add_argument('profile',type=Path)
        parser.add_argument('--output',type=Path,required=True)
        opts=parser.parse_args(args)
        result=run(opts.profile,opts.output)
    if raw:
        print(json.dumps(result,indent=2))
    else:
        print('Automatic transformation decision\n=================================')
        print('Status: '+result['status'])
        for attempt in result.get('attempts',[]):
            print('  Placement '+hex(attempt['destination'])+': '+attempt['status']+'; '+str(attempt.get('reason') or attempt.get('decision','')))
        if result.get('rejection'):print('Reason: '+str(result['rejection']))
        if result.get('publication'):print('Approved output: '+result['publication'])
        print('Scope: exact generated bytes and declared exhaustive bounded contract')
    return 0 if result.get('bounded_transformation_approved') or result['status']=='AUTOMATIC_QUALIFICATION_EXPECTATIONS_MET' else 7

