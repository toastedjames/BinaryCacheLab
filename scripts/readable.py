"""Readable summaries. Saved JSON is the authoritative detailed evidence."""
import json
import textwrap

LABELS = {
    'BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED': 'Startup/shutdown helpers return boundary addresses; all callers are not proved safe.',
    'COMPLETE_REFERENCE_AND_ALIAS_COVERAGE': 'All references and aliases to the region',
    'CONTROL_FLOW_AND_ABI_CORRESPONDENCE': 'Control flow and calling-convention correspondence',
    'RUNTIME_LOADER_AND_EXTERNAL_CODE_BEHAVIOR': 'Loader, callbacks, and external-code behavior',
    'GENERAL_FUNCTIONAL_EQUIVALENCE': 'Functional equivalence for all inputs',
    'SATISFIED_FOR_TESTED_PAIR': 'Observation equality preserved for the tested secrets',
    'CANDIDATE_PRESERVATION_VIOLATION': 'Observation difference introduced by the rebuild',
    'ORIGINAL_OBSERVATIONS_DIFFER': 'Original already distinguishes the secrets',
    'FUNCTIONAL_OUTPUT_MISMATCH': 'Output correspondence failed',
    'INCONCLUSIVE_UNSTABLE_REPETITIONS': 'Inconclusive: repetitions are unstable',
}

def label(value):
    return LABELS.get(str(value), str(value).replace('_', ' ').lower())

def yes(value):
    return 'yes' if value is True else 'no' if value is False else 'not recorded'

def render(data):
    if not isinstance(data, dict):
        return json.dumps(data, indent=2)
    schema = data.get('schema', '')
    out = []
    def title(text):
        out.extend(['', text, '=' * min(len(text), 78)])
    def field(name, value):
        out.append(f'  {name + ":":<25} {value}')
    def bullet(text):
        out.append(textwrap.fill(str(text), width=92, initial_indent='  - ', subsequent_indent='    '))
    if schema == 'bcl-project-result-1':
        title('Selected-program result')
        field('Status', label(data.get('status')))
        field('Observation', label(data.get('verdict', 'NO_OBSERVATION_VERDICT')))
        field('Python/Java agreement', yes(data.get('python_java_agreement')))
        field('Callback mapping checked', yes(data.get('callback_mapping_checked')))
        for role, status in data.get('reference_status', {}).items():
            field(role + ' references', label(status))
        field('General rewriting', 'NOT APPROVED')
        if data.get('error'):
            bullet(data['error'])
    elif schema == 'bcl-project-assessment-1':
        title('Selected-program safety assessment')
        field('Decision', label(data.get('decision')))
        field('Declared layout checked', yes(data.get('declared_layout_checked')))
        field('Callback mapping checked', yes(data.get('callback_mapping_checked')))
        for role, libraries in data.get('external_libraries', {}).items():
            field(role + ' libraries', ', '.join(libraries) or 'none recorded')
        for obligation in data.get('unestablished_obligations', []):
            bullet(label(obligation))
        field('General rewriting', 'NOT APPROVED')
    elif schema == 'bcl-project-qualification-1':
        title('Selected-program qualification')
        field('Status', label(data.get('status')))
        field('Fresh FoxDec lifting', yes(data.get('fresh_lifting')))
        for case in data.get('cases', []):
            field(case['name'], ('PASS' if case.get('expectations_met') else 'FAIL') + ': ' + label(case.get('actual')))
        if data.get('error'):
            bullet(data['error'])
    elif schema == 'java-eligibility-1':
        title('Transformation safety')
        field('Decision', 'Approved under the stated model' if data.get('safe_to_transform') is True else 'NOT APPROVED')
        field('Coverage', label(data.get('reference_coverage', 'not recorded')))
        field('Automatic rewriting', yes(data.get('automatic_rewrite_allowed')))
        title('Why')
        for hazard in data.get('hazards', []):
            bullet(label(hazard))
        if not data.get('hazards'):
            bullet('No specific hazard was enumerated; coverage obligations still remain.')
        title('Still needs evidence')
        for item in data.get('unestablished_obligations', []):
            bullet(label(item))
        refs = data.get('instruction_reference_coverage', {})
        reads = refs.get('verified_direct_reads', {}).get('reads', [])
        if reads:
            title('Declared reads verified in the original ELF')
            for row in reads:
                field(f'IP {row["ip"]:#x}', f'{row["width_bytes"]} bytes at {row["target"]:#x}')
        counts = refs.get('unresolved_counts', {})
        if counts:
            title('Unresolved instruction categories (counts, not confirmed bugs)')
            for name, count in counts.items():
                bullet(f'{label(name)}: {count}')
        callbacks = data.get('callback_metadata_comparisons', {})
        if callbacks:
            title('Callback metadata')
            for name, record in callbacks.items():
                field(name, 'source counts match; semantics unproved' if not record.get('differences') else 'differences require review')
        title('Interpretation')
        bullet('A finite observation test can pass while whole-program transformation safety remains unproved.')
    elif schema == 'whole-comparison-1':
        title('Four-run comparison')
        field('Result', label(data.get('verdict', 'not recorded')))
        field('Outputs correspond', yes(data.get('functional_checks')))
        field('Repetitions stable', yes(data.get('repeat_stability')))
        field('Observer', 'ordered 64-byte virtual data lines')
        comparisons = data.get('comparisons', [])
        if comparisons:
            title('Equality between secrets in each binary')
            for row in comparisons:
                name = row.get('binary', row.get('variant', row.get('kind', '?')))
                repeat = row.get('repeat', row.get('repetition', '?'))
                field(f'{name}, repeat {repeat}', yes(row.get('equal', row.get('observations_equal'))))
                difference = row.get('first_difference')
                if difference:
                    bullet('First differing token: ' + str(difference.get('token_index', '?')))
                    for secret in ('secret_0', 'secret_1'):
                        witness = difference.get(secret)
                        if isinstance(witness, dict):
                            bullet(f'{secret.replace("_", " ")}: instruction {witness.get("ip", "end")}, '
                                   f'address {witness.get("address", "end")}, {witness.get("size", "?")} bytes')
                        else:
                            bullet(secret.replace('_', ' ') + ': end of observation')
        bullet('Finite test result; whole-program transformation safety is a separate assessment.')
    elif schema == 'java-group-plan-1':
        title('Layout protection plan')
        field('Policy', data.get('policy'))
        field('Group / line size', f'{data.get("region_bytes")} / {data.get("line_bytes")} bytes')
        field('Start offset in line', data.get('required_line_residue'))
        field('Control shift', f'{data.get("control_shift_bytes")} bytes')
        bullet(data.get('reason', ''))
        field('Reference coverage', label(data.get('reference_coverage', 'not recorded')))
        field('Automatic rewriting', yes(data.get('automatic_rewrite_allowed')))
    elif schema == 'java-experiment-verification-1':
        title('Recorded evidence verification')
        field('Status', label(data.get('status')))
        field('Files checked', data.get('files_checked'))
        title('Recorded variants')
        for row in data.get('variants', []):
            field(row.get('variant', '?'), label(row.get('verdict', '?')))
        bullet(data.get('assurance', ''))
    elif schema == 'java-experiment-references-1':
        title('Declared instruction correspondence')
        field('Status', label(data.get('status')))
        for name, row in data.get('variants', {}).items():
            title(name.capitalize())
            field('Unique access sites', yes(row.get('access_correspondence', {}).get('all_sites_unique')))
            local = row.get('local_lookup_contract', {}).get('comparison', {})
            field('Local preservation', yes(local.get('preservation_for_all_selector_pairs_under_contract')))
        bullet('Applies to declared reads and the local entry contract; complete references remain unproved.')
    elif schema == 'java-stage3-1':
        title('Research workflow')
        field('Status', label(data.get('status')))
        field('Mode', label(data.get('workflow_mode', 'not recorded')))
        if data.get('eligibility_decision'):
            field('Safety assessment', label(data['eligibility_decision']))
        title('Stages')
        for row in data.get('stages', []):
            field(row.get('name', '').replace('-', ' '), label(row.get('status')))
        if data.get('variants'):
            title('Linked variants')
            for name, row in data['variants'].items():
                field(name.capitalize(), label(row.get('verdict', 'NO_OBSERVATION_VERDICT')))
        if data.get('failure'):
            title('Failure')
            bullet(data['failure'])
        bullet(data.get('assurance', 'Finite evidence; general transformation safety remains unproved.'))
    elif schema == 'bcl-easy-demo-1':
        title('BinaryCacheLab demo result')
        field('Run status', label(data.get('status')))
        if data.get('discovered'):
            field('Origin', 'existing validation found automatically')
        for name in ('build', 'validation', 'log_directory'):
            if data.get(name):
                field(name.replace('_', ' ').capitalize(), data[name])
        if data.get('verdict') and not data.get('variants'):
            field('Fresh baseline', label(data['verdict']))
        if data.get('evidence_verified'):
            field('Artifact/trace replay', 'verified, including callback mappings')
        if data.get('safety_decision'):
            field('General rewriting', 'NOT APPROVED' if data['safety_decision'] in
                ('REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS','INCONCLUSIVE_REFERENCE_COVERAGE')
                else label(data['safety_decision']))
        if data.get('error'):
            bullet(data['error'])
        if data.get('variants'):
            title('Fresh experiment results')
            for name, record in data['variants'].items():
                field(name.capitalize(), label(record.get('verdict')))
            if data.get('detector_control'):
                field('Detector control', label(data['detector_control'].get('verdict')))
        else:
            bullet('Historical shifted/protected controls are separate from the fresh baseline.')
    elif schema == 'bcl-multi-region-plan-1':
        title('Multi-region layout plan')
        field('Constraints', label(data.get('status')))
        field('Line size', str(data.get('line_bytes')) + ' bytes')
        for index, group in enumerate(data.get('groups', []), 1):
            title(f'Group {index}: {group.get("span_bytes")} bytes')
            field('Alignment / residue', f'{group.get("alignment")} / {group.get("residue")}')
            for region in group.get('members', []):
                field(region['name'], f'{region["original_address"]:#x} -> planned {region["planned_address"]:#x}; {region["size"]} bytes')
        bullet('Planned placements are candidates. Verify the final linked ELF; reference safety is separate.')
    elif schema == 'bcl-multi-region-link-check-1':
        title('Linked region verification')
        field('Status', label(data.get('status')))
        field('Line equality preserved', yes(data.get('declared_byte_line_equality_preserved')))
        for region in data.get('regions', []):
            field(region['name'], f'{region["original_address"]:#x} -> {region["rebuilt_address"]:#x}; {region["size"]} bytes')
        bullet(data.get('scope', 'Declared regions only.'))
    elif schema == 'bcl-bounded-transformation-report-1':
        title('Exact bounded transformation approval')
        field('Status', label(data.get('status')))
        field('Exact candidate approved', yes(data.get('bounded_transformation_approved')))
        field('Linked layout', label(data.get('linked_layout', {}).get('status', 'not checked')))
        observation = data.get('observation', {})
        field('Observation equality preserved', yes(observation.get('preservation_holds')))
        field('Originally equal secret pairs', observation.get('original_equal_secret_pairs', 0))
        if data.get('rejection'):
            bullet(data['rejection']['kind'] + ': ' + data['rejection']['detail'])
        for witness in observation.get('witnesses', [])[:6]:
            bullet('First differing token: ' + str(witness['first_different_token']))
            for side in ('first', 'second'):
                access = witness[side]
                bullet(side + ': end' if access == 'end' else f'{side}: IP {access["responsible_ip"]:#x}, address {access["address"]:#x}, line {access["line"]:#x}')
        if data.get('publication'):
            field('Published', data['publication']['output'])
        bullet(data.get('scope', ''))
    elif schema == 'bcl-bounded-correspondence-report-1':
        title('Bounded program correspondence')
        field('Status', label(data.get('status')))
        field('Correspondence established', yes(data.get('correspondence_established')))
        field('Input cases compared', data.get('cases_compared', 0))
        field('Differences', data.get('difference_count', 0))
        if data.get('rejection'):
            bullet(data['rejection']['kind'] + ': ' + data['rejection']['detail'])
        for witness in data.get('witnesses', [])[:6]:
            bullet(witness['component'] + ': ' + witness['kind'] + '; case ' + witness['case'])
        if data.get('witnesses'):
            bullet('Concrete values and complete original/rebuilt executions are retained in the JSON report.')
        for key in ('original_runtime', 'rebuilt_runtime'):
            if key in data:
                field(key.replace('_', ' ').title(), 'supported' if data[key]['supported'] else 'rejected: unsupported dependencies')
                for hazard in data[key].get('hazards', [])[:4]:
                    bullet(hazard['kind'])
        field('Automatic rewriting authorized', yes(data.get('automatic_rewrite_allowed')))
        bullet(data.get('scope', ''))
    elif schema == 'bcl-bounded-reference-report-1':
        title('Exhaustive bounded reference analysis')
        field('Status', label(data.get('status')))
        field('All declared executions completed', yes(data.get('exhaustive')))
        field('Executions evaluated / expected', str(data.get('evaluated_executions')) + ' / ' + str(data.get('expected_executions')))
        field('Instructions / data accesses', str(data.get('total_steps')) + ' / ' + str(data.get('reference_events')))
        for row in data.get('executions', [])[:8]:
            detail = row.get('failure', {})
            bullet('Case ' + str(row['index']) + ', entry ' + hex(row['entry']) + ': ' + row['status'] +
                   ('. ' + detail.get('kind', '') + ': ' + detail.get('detail', '') if detail else ''))
        if len(data.get('executions', [])) > 8:
            bullet('All case results and ordered accesses are retained in the JSON report.')
        if data.get('rejection'):
            bullet(str(data['rejection']['kind']) + ': ' + str(data['rejection']['detail']))
        field('Automatic rewriting authorized', yes(data.get('automatic_rewrite_allowed')))
        bullet(data.get('scope', ''))
    elif schema == 'bcl-reference-closure-1':
        title('Reference closure under the declared entry contract')
        field('Status', label(data.get('status')))
        field('Reachable instructions', data.get('reachable_instructions'))
        field('Abstract states', data.get('abstract_states'))
        if 'analyzed_entry_addresses' in data:
            field('Declared entries analyzed', ', '.join(hex(ip) for ip in data['analyzed_entry_addresses']))
            field('Unvisited supplied rows', len(data.get('unvisited_supplied_instruction_addresses', [])))
        field('Whole-program proof', yes(data.get('whole_program_entries_and_runtime_contract_proved')))
        unresolved = data.get('unresolved', [])
        field('Unresolved obligations', len(unresolved))
        for row in unresolved[:10]:
            bullet(f'IP {row.get("ip", 0):#x}: {label(row.get("kind"))}. {row.get("detail", "")}')
        if len(unresolved) > 10:
            bullet('Showing the first 10 obligations; use --json or the saved report for all records.')
        bullet('Entry and external contracts are assumptions; a local result does not authorize general rewriting.')
    elif schema == 'bcl-suite-description-1':
        title('Suite jobs (preview; nothing executed)')
        for index, job in enumerate(data.get('jobs', []), 1):
            field(f'{index}. {job.get("id", "job")}', f'expected exit {job.get("expected_exit")}, timeout {job.get("timeout_seconds")}s')
            bullet('Command: ' + ' '.join(map(str, job.get('argv', []))))
            if job.get('requires'):
                bullet('After: ' + ', '.join(job['requires']))
    else:
        title(label(schema or data.get('status', 'Report')).capitalize())
        for key, value in data.items():
            if key != 'schema' and (isinstance(value, (str, int, bool)) or value is None):
                field(key.replace('_', ' ').capitalize(), value)
        nested = [key for key, value in data.items() if isinstance(value, (list, dict))]
        if nested:
            bullet('Detailed records: ' + ', '.join(nested) + '. Use --json or the saved report to inspect them.')
    return '\n'.join(out) + '\n'
