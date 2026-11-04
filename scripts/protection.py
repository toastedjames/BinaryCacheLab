"""Mandatory protection gate for the actual lift/plan/link workflow.

Publication requires BOTH native checks and exhaustive, exact-byte approval of
the declared finite entry contract. Sampled PIN traces alone never authorize it.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import project


SCHEMA = 'bcl-protected-build-1'


def planner_input(profile, directory):
    """Give adjacent regions unique zero-byte end aliases for the existing planner."""
    profile = copy.deepcopy(profile)
    text = Path(profile['assembly']).read_text(encoding='utf-8')
    starts = {row['name'] for row in profile['regions']}
    changes = []
    for index, row in enumerate(profile['regions']):
        if row['end_label'] not in starts:
            continue
        label = row['end_label']
        alias = 'BCL_PROTECTION_END_' + str(index)
        require(not re.search(r'^\s*' + re.escape(alias) + r':', text, re.M), 'Reserved protection end alias already defined')
        pattern = r'^(\s*)' + re.escape(label) + r':\s*(?:;[^\n]*)?$'
        require(len(re.findall(pattern, text, re.M)) == 1, 'Missing/ambiguous adjacent-region boundary label')
        text = re.sub(pattern, lambda m: alias + ':\n' + m.group(0), text, count=1, flags=re.M)
        changes.append({'region': row['name'], 'boundary_label': label, 'zero_byte_alias': alias})
        row['end_label'] = alias
    path = directory / 'protection-input.asm'
    with path.open('x', encoding='utf-8', newline='\n') as stream: stream.write(text)
    profile['assembly'] = str(path)
    project.save(directory / 'protection-boundary-aliases.json', changes)
    return profile


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_config(doc):
    """No optional-check or capture-only fallback is allowed in protection mode."""
    settings = doc.get('protection')
    require(isinstance(settings, dict) and set(settings) == {'approval_profile'},
            'Protection requires only approval_profile; no sampled-only approval mode exists')
    require(isinstance(settings['approval_profile'], str) and settings['approval_profile'].strip(),
            'Protection requires an explicit finite entry/input approval contract')
    require(doc.get('mode') != 'program', 'Protection cannot fall back to general capture-only mode')
    require(doc.get('lift', {}).get('adapter') == 'foxdec', 'Protection requires an actual FoxDec lift')
    require(doc.get('transform', {}).get('adapter') == 'regions', 'Protection requires automatic region planning')
    require(doc.get('regions'), 'Protection requires explicit original and rebuilt regions')
    require(not doc.get('reference_analysis') and not doc.get('reference_profiles'),
            'Protection supplies its own exhaustive references; remove sampled/local reference adapters')
    require(doc['comparison']['line_bytes'] == 64, 'Exhaustive protection currently requires 64-byte lines')
    require(doc['execution']['repetitions'] >= 2, 'Protection requires repeated native/PIN validation')
    require(all(doc['checks'].get(key) is True for key in
                ('functional', 'references', 'layout', 'event_correspondence')),
            'Protection cannot disable functional, reference, layout or correspondence checks')
    security = doc.get('security', {})
    require(security.get('enabled') is True and security.get('variant') == 'transformed',
            'Protection requires explicit original/transformed secret-pair testing')
    require(set(security.get('cases', [])) == {case['id'] for case in doc['execution']['cases']},
            'Protection must test every configured input case')
    # Derive source-to-final obligations instead of trusting optional rules
    # comparing only an already-damaged baseline with its successor.
    mandatory = [
        {'id': 'PROTECTION-CONTENTS', 'kind': 'contents', 'source': 'original', 'target': 'transformed'},
        {'id': 'PROTECTION-LINES', 'kind': 'line_partition', 'source': 'original', 'target': 'transformed'},
        {'id': 'PROTECTION-NONOVERLAP', 'kind': 'non_overlap', 'variants': ['original', 'transformed']}]
    constraints = doc.setdefault('layout_constraints', [])
    for rule in mandatory:
        existing = [row for row in constraints if row.get('id') == rule['id']]
        require(not existing or existing == [rule], 'Cannot override mandatory protection constraint: ' + rule['id'])
        if not existing:
            constraints.append(rule)
    return doc


def _read(path):
    require(path.is_file() and path.stat().st_size <= 1024 * 1024, 'Missing or oversized approval input: ' + str(path))
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), 'Approval inputs must be JSON objects')
    return value


def snapshot_contract(source, target, binaries, regions):
    """Bind all approval layers to the actual final binaries, never profile binaries.

    Numeric control maps remain explicit obligations. A map that no longer
    describes the FoxDec output is rejected by exhaustive correspondence.
    """
    source = Path(source).resolve()
    approval = _read(source)
    require(approval.get('schema') == 'bcl-bounded-transformation-1', 'Expected bounded transformation approval contract')
    require(approval.get('observer') == {'policy': 'ordered-raw-virtual-lines', 'line_bytes': 64},
            'Protection approval must use ordered 64-byte virtual data lines')
    require(approval.get('require_nonvacuous') is True, 'A vacuous preservation implication cannot authorize publication')
    pair_source = project.resolve(source.parent, approval['correspondence'])
    pair = _read(pair_source)
    require(pair.get('schema') == 'bcl-bounded-correspondence-1', 'Expected bounded correspondence contract')
    maps = pair.get('memory_maps', [])
    require(maps and len({row['name'] for row in maps}) == len(maps), 'Memory maps must have distinct region names')
    by_variant = {variant: {row['name']: row for row in regions[variant]} for variant in ('original', 'transformed')}
    require(set(by_variant['original']) == set(by_variant['transformed']), 'Final region inventory differs from original')
    require(set(by_variant['original']) <= {row['name'] for row in maps}, 'Approval omits a transformed region')
    selected = approval.get('layout', {}).get('regions', [])
    require({row['name'] for row in selected} == set(by_variant['original']), 'Approval layout must cover all transformed regions')
    for row in maps:
        if row['name'] in by_variant['original']:
            old, new = by_variant['original'][row['name']], by_variant['transformed'][row['name']]
            require(old['size'] == new['size'] == row['size'], 'Approval region size does not match final ELF')
            require(row['original'] == old['address'] and row['rebuilt'] == new['address'],
                    'Approval region addresses do not match the actual linked executables')
    target.mkdir()
    for field, variant in (('original', 'original'), ('rebuilt', 'transformed')):
        contract = _read(project.resolve(pair_source.parent, pair[field]))
        require(contract.get('schema') == 'bcl-bounded-references-1', 'Protection requires exhaustive finite reference contracts')
        binary = Path(binaries[variant]).resolve()
        # Copies isolate the checker from stale profile paths and later builds.
        shutil.copyfile(binary, target / (field + '.elf'))
        contract['binary'] = field + '.elf'
        project.save(target / (field + '.json'), contract)
        pair[field] = field + '.json'
    project.save(target / 'correspondence.json', pair)
    approval['correspondence'] = 'correspondence.json'
    project.save(target / 'approval.json', approval)
    return target / 'approval.json'


def native_gate(report):
    checks = report['checks']
    for name, row in checks.items():
        if row.get('required') and name not in ('stage_8', 'protection'):
            require(row.get('status') == 'PASS', 'Protected publication blocked by required check ' + name)
    for name in ('functional', 'references', 'layout', 'event_correspondence', 'repeat_stability', 'observations'):
        require(checks.get(name, {}).get('status') == 'PASS', 'Protected publication blocked by ' + name)
    require(all(checks.get('stage_' + str(i), {}).get('status') == 'PASS' for i in range(1, 8)),
            'Every build, validation and capture stage must finish before protected publication')
    require(all(report.get('event_statistics', {}).get(v, {}).get('incomplete_traces', 0) == 0
                for v in ('original', 'baseline', 'transformed')), 'Incomplete traces block protected publication')
    configuration = report['configuration']
    repetitions = configuration['execution']['repetitions']
    case_ids = configuration['security']['cases']
    expected_runs = len(configuration['execution']['cases']) * repetitions
    require(all(report.get('event_statistics', {}).get(v, {}).get('runs') == expected_runs
                for v in ('original', 'baseline', 'transformed')), 'Missing required native/PIN runs')
    assessment = report.get('security_assessment', {})
    pairs = assessment.get('secret_pairs', [])
    require(pairs, 'Missing within-build secret-pair evidence')
    from itertools import combinations
    require(len(pairs) == len(case_ids) * (len(case_ids) - 1) // 2 and
            {frozenset(pair['cases']) for pair in pairs} == {frozenset(pair) for pair in combinations(case_ids, 2)},
            'Missing or duplicate configured secret-pair decisions')
    require(assessment.get('repeat_stability_tested') is True, 'Secret observation stability was not tested')
    for pair in pairs:
        for variant in ('original', 'transformed'):
            row = pair['by_variant'][variant]
            require(row.get('assessed') is True and row.get('stable') is True,
                    'Unassessed or unstable secret pair cannot authorize protection')
            require(row.get('evidence') and all(item.get('equal') is True for item in row['evidence']) == row.get('equal_across_secrets'),
                    'Secret-pair summary disagrees with underlying observations')
            require(len(row['evidence']) == repetitions, 'Missing secret-pair repetition evidence')
        # A protected output is not advertised as resistant if it already
        # distinguishes the configured secrets, even when the premise is false.
        require(pair['by_variant']['original']['equal_across_secrets'] is True,
                'Original already distinguishes this configured pair; cannot certify it as leakage-resistant')
        require(pair['by_variant']['transformed']['equal_across_secrets'] is True,
                'Protected candidate splits an original-equal secret pair')


def inspect_original(workflow):
    """Record source distinctions even if a later gate rejects the rebuild."""
    from itertools import combinations
    import workflow_compare
    settings = workflow.doc['comparison']
    rows = []
    for left, right in combinations(workflow.doc['security']['cases'], 2):
        comparisons = [workflow_compare.token_compare(workflow.runs['original', left, repeat],
                        workflow.runs['original', right, repeat], settings['line_identity'], settings['scope'])
                       for repeat in range(workflow.doc['execution']['repetitions'])]
        stable = all(workflow_compare.token_compare(workflow.runs['original', case, 0], workflow.runs['original', case, repeat],
                      settings['line_identity'], settings['scope'])['equal'] and
                     workflow.native_outputs['original', case, 0] == workflow.native_outputs['original', case, repeat]
                     for case in (left, right) for repeat in range(1, workflow.doc['execution']['repetitions']))
        equal = all(row['equal'] for row in comparisons)
        rows.append({'cases': [left, right], 'status': 'INCONCLUSIVE' if not stable else
                     'ORIGINAL_EQUAL_FOR_CONFIGURED_PAIR' if equal else 'ORIGINAL_ALREADY_DISTINGUISHES',
                     'stable': stable, 'equal': equal, 'evidence': comparisons})
    workflow.report['protection']['original_pairs'] = rows
    project.save(workflow.root / 'validation/protection-original-pairs.json', rows)


def enforce(workflow):
    """Called inside the real workflow after comparisons and before final sealing."""
    report = workflow.report
    original_pairs = report.get('protection', {}).get('original_pairs', [])
    decision = {'schema': SCHEMA, 'status': 'PROTECTED_BUILD_REJECTED', 'published': False,
                'scope': 'Exact final bytes and declared exhaustive finite entry/input contract; native checks cover configured cases',
                'whole_program_security_proven': False, 'original_pairs': original_pairs}
    report['protection'] = decision
    evidence = ['validation/protection/approval-report.json', 'validation/protection/final-approval-report.json']
    owns_publication_directory = False
    try:
        validate_config(workflow.doc)
        native_gate(report)
        binaries = {v: workflow.root / 'build' / v for v in ('original', 'transformed')}
        before = {v: hashlib.sha256(path.read_bytes()).hexdigest() for v, path in binaries.items()}
        require(all(before[v] == report['artifacts'][v]['sha256'] for v in before), 'Executable changed after native validation')
        directory = workflow.root / 'validation/protection'
        require(hasattr(workflow, 'protection_profile'), 'Pre-execution exhaustive protection approval did not run')
        profile = workflow.protection_profile
        workflow.java('approve-transform', profile, '--report', directory / 'final-approval-report.json', allowed=(0, 3, 7))
        approval = _read_report(directory / 'final-approval-report.json')
        require(approval.get('bounded_transformation_approved') is True, 'Exhaustive protection approval rejected: ' + approval.get('status', 'missing status'))
        require(approval.get('original_sha256') == before['original'] and approval.get('candidate_sha256') == before['transformed'],
                'Exhaustive approval did not bind the native-tested executable bytes')
        require(approval.get('correspondence', {}).get('correspondence_established') is True,
                'Exhaustive functional/ABI correspondence was not established')
        require(approval.get('observation', {}).get('preservation_holds') is True and
                approval.get('observation', {}).get('nonvacuous') is True, 'No nonvacuous exhaustive preservation approval')
        require(all(hashlib.sha256(path.read_bytes()).hexdigest() == before[v] for v, path in binaries.items()),
                'Final build changed during protection approval')
        # Publisher independently reruns exact-byte approval. It never copies a
        # candidate merely because a report contained PASS.
        output_dir = workflow.root / 'protected'
        output_dir.mkdir()
        owns_publication_directory = True
        output = output_dir / 'program'
        workflow.java('publish-transform', profile, '--output', output, allowed=(0, 3, 7))
        require(output.is_file() and hashlib.sha256(output.read_bytes()).hexdigest() == before['transformed'],
                'Published bytes differ from the approved native-tested candidate')
        output.chmod(0o755)
        decision.update(status='PROTECTED_BUILD_APPROVED_WITHIN_BOUNDS', published=True,
                        executable='protected/program', sha256=before['transformed'],
                        original_sha256=before['original'], approval='validation/protection/final-approval-report.json',
                        contract='validation/protection/approval.json')
        report['checks']['protection'] = {'status': 'PASS', 'required': True,
                'detail': 'Automatic layout, native checks and exhaustive exact-candidate approval passed; protected/program published', 'evidence': evidence}
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, IndexError, OverflowError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        # A publication failure must leave no executable advertised as protected.
        output = workflow.root / 'protected/program'
        if owns_publication_directory and not output.parent.is_symlink() and output.is_file() and not output.is_symlink():
            output.unlink()
        decision['reason'] = str(error)
        report['checks']['protection'] = {'status': 'FAIL', 'required': True, 'detail': str(error), 'evidence': evidence}
        if isinstance(error, KeyboardInterrupt):
            project.save(workflow.root / 'validation/protection-decision.json', decision)
            raise
    project.save(workflow.root / 'validation/protection-decision.json', decision)


def _read_report(path):
    # Exhaustive result files can exceed the 1 MiB input-profile limit.
    return project.read(path)


def revoke(workflow, reason):
    """Remove only this run's published output if finalization cannot complete."""
    decision = workflow.report.get('protection', {})
    if not decision.get('published'):
        return
    output = workflow.root / 'protected/program'
    require(not output.parent.is_symlink() and not output.is_symlink(), 'Publication path changed during finalization')
    if output.is_file():
        output.unlink()
    decision.update(status='PROTECTED_BUILD_REJECTED', published=False, reason=reason)
    decision.pop('executable', None)
    workflow.report['checks']['protection'] = {'status': 'FAIL', 'required': True,
                'detail': reason, 'evidence': ['validation/protection-decision.json']}
    project.save(workflow.root / 'validation/protection-decision.json', decision)


def propose_control_map(original, rebuilt, entry_pairs):
    """Derive a bijective candidate map from ALL finite execution transfers.

    This is a proposal, not authorization: independent Java correspondence and
    transformation approval must replay the actual bytes and reject bad maps.
    It supports repeated transfers (loops/recursion), not only straight lines.
    """
    forward, reverse = {}, {}
    def bind(a, b):
        require(a not in forward or forward[a] == b, 'Ambiguous original control-site correspondence')
        require(b not in reverse or reverse[b] == a, 'Ambiguous rebuilt control-site correspondence')
        forward[a] = b
        reverse[b] = a
    roots = dict(entry_pairs)
    for a, b in entry_pairs:
        bind(a, b)
    def cases(analysis, source):
        result = {}
        for execution in analysis['executions']:
            entry = execution['entry'] if source else reverse_root[execution['entry']]
            key = (entry, json.dumps(execution['inputs'], sort_keys=True))
            require(key not in result, 'Duplicate finite logical execution')
            result[key] = execution
        return result
    reverse_root = {b: a for a, b in roots.items()}
    require(len(reverse_root) == len(roots), 'Entry correspondence is not bijective')
    left, right = cases(original, True), cases(rebuilt, False)
    require(left and set(left) == set(right), 'Finite original/rebuilt execution domains differ')
    for key in left:
        a = left[key]['correspondence']['transfers']
        b = right[key]['correspondence']['transfers']
        require(len(a) == len(b), 'Control transfer structure changed; automatic correspondence unavailable')
        for x, y in zip(a, b):
            require(x['kind'] == y['kind'], 'Control transfer kinds differ')
            bind(x['from'], y['from'])
            if x['kind'] != 'entry-return':
                bind(x['to'], y['to'])
    return [{'original': a, 'rebuilt': b} for a, b in sorted(forward.items())]


def derive_contract(workflow, source, directory, target_variant='transformed'):
    """Bind symbolic entries, derive finite control maps and check actual ELFs."""
    settings = _read(source)
    required={'schema', 'machine', 'inputs', 'bounds', 'entries', 'regions', 'secret_inputs', 'register_outputs'}
    require(required<=set(settings)<=required|{'native_cases'},
            'Invalid symbolic protection contract fields')
    entries = settings['entries']
    require(isinstance(entries, list) and entries and all(isinstance(row, dict) and set(row) == {'original', 'transformed'} for row in entries),
            'Declare symbolic original/transformed entry pairs')
    require(settings['inputs'] and all(set(row) == {'register', 'values'} for row in settings['inputs']),
            'Automatic protection contract currently requires scalar register inputs')
    selected = settings['regions']
    require(isinstance(selected, list) and selected and all(set(row) == {'name', 'alignment'} for row in selected),
            'Declare region names and alignments')
    expected = {row['name'] for row in workflow.regions['original']}
    require(len(selected) == len(expected) and {row['name'] for row in selected} == expected,
            'Protection contract must cover all declared transformed regions exactly once')
    directory.mkdir()
    roots, analyses = {}, {}
    for field, variant in (('original', 'original'), ('rebuilt', target_variant)):
        binary = workflow.root / 'build' / variant
        text, _ = workflow.runner.command('protection-symbols-' + variant, ['nm', '-an', '--defined-only', binary])
        symbols = {}
        for line in text.splitlines():
            words = line.split()
            if len(words) == 3 and words[1] in ('t', 'T', 'w', 'W'):
                symbols.setdefault(words[2], set()).add(int(words[0], 16))
        roots[field] = []
        for row in entries:
            label=row['transformed' if variant=='baseline' else variant]
            values = symbols.get(label, set())
            require(len(values) == 1, 'Missing/ambiguous executable protection entry: ' + str(label))
            roots[field].append(next(iter(values)))
        require(len(set(roots[field])) == len(roots[field]), 'Duplicate protection entries')
        shutil.copyfile(binary, directory / (field + '.elf'))
        profile = {'schema': 'bcl-bounded-references-1', 'binary': field + '.elf',
                   'entries': roots[field], 'regions': copy.deepcopy(workflow.regions[variant]),
                   'machine': settings['machine'], 'inputs': settings['inputs'], 'bounds': settings['bounds']}
        # Region records passed to the machine schema contain no runtime fields.
        profile['regions'] = [{k: row[k] for k in ('name', 'address', 'size')} for row in profile['regions']]
        project.save(directory / (field + '.json'), profile)
        report = directory / (field + '-analysis.json')
        workflow.java('bounded-control', directory / (field + '.json'), '--report', report, allowed=(0, 7))
        analyses[field] = _read_report(report)
        require(analyses[field].get('exhaustive') is True, 'Unsupported execution or exhausted bounds for ' + variant)
        require(analyses[field]['binary_sha256'] == workflow.report['artifacts'][variant]['sha256'],
                'Reference analysis did not bind the actual final executable')
    entry_pairs = list(zip(roots['original'], roots['rebuilt']))
    maps = propose_control_map(analyses['original'], analyses['rebuilt'], entry_pairs)
    region_maps = []
    old = {row['name']: row for row in workflow.regions['original']}
    new = {row['name']: row for row in workflow.regions[target_variant]}
    require(set(old) == set(new), 'Final region names differ')
    for name, row in old.items():
        require(row['size'] == new[name]['size'], 'Final region extent changed')
        region_maps.append({'name': name, 'original': row['address'], 'rebuilt': new[name]['address'], 'size': row['size']})
    pair = {'schema': 'bcl-bounded-correspondence-1', 'abi': 'sysv-amd64-integer',
            'original': 'original.json', 'rebuilt': 'rebuilt.json',
            'entries': [{'original': a, 'rebuilt': b} for a, b in entry_pairs], 'control_map': maps,
            'memory_maps': region_maps, 'input_map': [{'original': i, 'rebuilt': i, 'encoding': 'scalar'} for i in range(len(settings['inputs']))],
            'register_outputs': settings['register_outputs']}
    project.save(directory / 'correspondence.json', pair)
    approval = {'schema': 'bcl-bounded-transformation-1', 'correspondence': 'correspondence.json',
                'observer': {'policy': 'ordered-raw-virtual-lines', 'line_bytes': 64},
                'secret_inputs': settings['secret_inputs'], 'require_nonvacuous': True,
                'layout': {'policy': 'preserve-byte-line-partition', 'regions': selected}}
    project.save(directory / 'approval.json', approval)
    project.save(directory / 'input-contract.json', settings)
    return directory / 'approval.json'


def prepare(workflow):
    """Mandatory exhaustive reference/ABI/layout gate BEFORE candidate execution."""
    validate_config(workflow.doc)
    require(workflow.report['checks']['layout']['status'] == 'PASS', 'Final linked layout validation failed')
    source = workflow.path(workflow.doc['protection']['approval_profile'])
    directory = workflow.root / 'validation/protection'
    settings = _read(source)
    if settings.get('schema') == 'bcl-protection-contract-1':
        profile = derive_contract(workflow, source, directory)
    else:
        profile = snapshot_contract(source, directory,
                                    {v: workflow.root / 'build' / v for v in ('original', 'transformed')}, workflow.regions)
    report = directory / 'approval-report.json'
    workflow.java('approve-transform', profile, '--report', report, allowed=(0, 3, 7))
    result = _read_report(report)
    require(result.get('bounded_transformation_approved') is True,
            'Candidate rejected before execution by exhaustive preservation/ABI/reference approval: ' + result.get('status', 'missing'))
    require(result.get('original_sha256') == workflow.report['artifacts']['original']['sha256'] and
            result.get('candidate_sha256') == workflow.report['artifacts']['transformed']['sha256'], 'Approval binary binding differs')
    discovery = {'schema': 'bcl-protection-reference-inventory-1', 'variants': {},
                 'scope': 'Every reference reached in the declared exhaustive finite entry/input domain; sensitivity is explicitly configured'}
    for field, variant in (('original', 'original'), ('rebuilt', 'transformed')):
        analysis = result['correspondence'][field + '_analysis']
        references = {}
        for execution in analysis['executions']:
            for access in execution['references']:
                key = (access['ip'], access['address'], access['width'], access['write'])
                references[key] = {k: access[k] for k in ('ip', 'address', 'width', 'write', 'overlapping_regions')}
        inventory = project.elf_inventory(workflow.root / 'build' / variant)
        discovery['variants'][variant] = {'binary_sha256': analysis['binary_sha256'],
                'objects': inventory['objects'], 'references': list(references.values()),
                'selected_regions': workflow.regions[variant], 'evaluated_executions': analysis['evaluated_executions']}
    project.save(directory / 'detected-references.json', discovery)
    workflow.protection_profile = profile
    if settings.get('schema')=='bcl-protection-contract-1' and 'native_cases' in settings:
        import protection_correspondence
        baseline=workflow.root/'validation/protection-baseline'
        derive_contract(workflow,source,baseline,target_variant='baseline')
        workflow.java('correspondence',baseline/'correspondence.json','--report',baseline/'correspondence-report.json',allowed=(0,3,7))
        comparison=_read_report(baseline/'correspondence-report.json')
        require(comparison.get('correspondence_established') is True,'Ordinary rebuild reference/ABI correspondence was not established')
        protection_correspondence.bind(workflow,settings,result['correspondence'],comparison)
    workflow.report['reference_coverage'] = 'EXHAUSTIVE_WITHIN_DECLARED_FINITE_CONTRACT'
    workflow.report['checks']['references'] = {'status': 'PASS', 'required': True,
            'detail': 'Exhaustive original/protected finite entry, functional/ABI and observation contract; outside-contract execution not proved',
            'evidence': ['validation/protection/approval-report.json']}


def main(args=None):
    import workflow as w
    parser = argparse.ArgumentParser(description='Lift, automatically protect and publish only an exhaustively approved final executable.')
    parser.add_argument('input', type=Path)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--approval', type=Path, help='Explicit finite approval contract; otherwise use [protection].approval_profile')
    opts = parser.parse_args(args)

    class ProtectedWorkflow(w.Workflow):
        def load_config(self):
            doc = w.config(self.config_path)
            if opts.approval:
                doc['protection'] = {'approval_profile': str(opts.approval.resolve())}
            require('protection' in doc, 'Supply --approval or a [protection] approval_profile')
            return validate_config(doc)

    report = ProtectedWorkflow(opts.input, opts.config).run()
    return 0 if report.get('protection', {}).get('published') is True else 7
