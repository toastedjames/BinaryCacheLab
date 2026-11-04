"""Protection boundary tests. Synthetic native statuses are NOT native evidence."""
import copy
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import automatic
import project
import protection
import workflow
import workflow_events

ROOT = Path(__file__).resolve().parent.parent


def configuration():
    value = workflow.config(ROOT / 'examples/workflow/bcl.toml')
    value.pop('reference_analysis', None)
    value['execution']['repetitions'] = 2
    value['protection'] = {'approval_profile': 'contract.json'}
    return value


def native_report(doc):
    row = {'assessed': True, 'stable': True, 'equal_across_secrets': True,
           'evidence': [{'equal': True}, {'equal': True}]}
    checks = {name: workflow.check('PASS', 'unit-test evidence double') for name in
              ('functional', 'references', 'layout', 'event_correspondence', 'repeat_stability', 'observations')}
    checks.update({'stage_' + str(i): workflow.check('PASS', 'unit-test stage double') for i in range(1, 8)})
    return {'configuration': doc, 'checks': checks,
            'event_statistics': {v: {'runs': 4, 'incomplete_traces': 0} for v in workflow.VARIANTS},
            'security_assessment': {'repeat_stability_tested': True, 'secret_pairs': [
                {'cases': ['secret0', 'secret1'], 'by_variant': {v: copy.deepcopy(row) for v in workflow.VARIANTS}}]}}


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.doc = configuration()
    def tearDown(self):
        self.temp.cleanup()
    def test_mandatory_source_final_constraints_are_added_once(self):
        protection.validate_config(self.doc)
        first = copy.deepcopy(self.doc)
        protection.validate_config(self.doc)
        self.assertEqual(first, self.doc)
        self.assertEqual(3, sum(x['id'].startswith('PROTECTION-') for x in self.doc['layout_constraints']))
    def test_capture_only_and_disabled_checks_are_rejected(self):
        for name in self.doc['checks']:
            doc = copy.deepcopy(self.doc); doc['checks'][name] = False
            with self.assertRaises(ValueError): protection.validate_config(doc)
        self.doc['mode'] = 'program'
        with self.assertRaisesRegex(ValueError, 'capture-only'): protection.validate_config(self.doc)
    def test_one_run_does_not_authorize_protection(self):
        self.doc['execution']['repetitions'] = 1
        with self.assertRaisesRegex(ValueError, 'repeated'): protection.validate_config(self.doc)
    def test_no_sampled_only_or_unknown_protection_option(self):
        self.doc['protection']['sampled_only'] = True
        with self.assertRaisesRegex(ValueError, 'no sampled-only'): protection.validate_config(self.doc)
    def test_cannot_override_mandatory_layout_rule(self):
        self.doc['layout_constraints'].append({'id': 'PROTECTION-LINES', 'kind': 'line_partition', 'source': 'baseline', 'target': 'transformed'})
        with self.assertRaisesRegex(ValueError, 'override'): protection.validate_config(self.doc)
    def test_every_case_must_be_in_secret_test(self):
        self.doc['security']['cases'] = ['secret0']
        with self.assertRaisesRegex(ValueError, 'every'): protection.validate_config(self.doc)
    def test_native_gate_rejects_functional_failure_despite_compromise(self):
        report = native_report(self.doc)
        report['checks']['functional']['status'] = 'FAIL'
        report['security_assessment']['compromise_demonstrated'] = True
        self.assertEqual('FAIL', workflow.verdict(report['checks'], report['security_assessment']))
        with self.assertRaisesRegex(ValueError, 'functional'): protection.native_gate(report)
    def test_existing_distinction_is_not_certified_resistant(self):
        report = native_report(self.doc)
        row = report['security_assessment']['secret_pairs'][0]['by_variant']['original']
        row['equal_across_secrets'] = False; row['evidence'] = [{'equal': False}, {'equal': False}]
        with self.assertRaisesRegex(ValueError, 'already distinguishes'): protection.native_gate(report)
    def test_new_distinction_blocks_publication(self):
        report = native_report(self.doc)
        row = report['security_assessment']['secret_pairs'][0]['by_variant']['transformed']
        row['equal_across_secrets'] = False; row['evidence'] = [{'equal': False}, {'equal': False}]
        with self.assertRaisesRegex(ValueError, 'splits'): protection.native_gate(report)
    def test_incomplete_and_missing_runs_are_rejected(self):
        for key, value in (('runs', 3), ('incomplete_traces', 1)):
            report = native_report(self.doc); report['event_statistics']['transformed'][key] = value
            with self.assertRaises(ValueError): protection.native_gate(report)
    def test_unstable_missing_or_contradictory_pair_evidence_is_rejected(self):
        for edit in ('stable', 'evidence', 'summary'):
            report = native_report(self.doc)
            row = report['security_assessment']['secret_pairs'][0]['by_variant']['transformed']
            if edit == 'stable': row['stable'] = False
            elif edit == 'evidence': row['evidence'] = [{'equal': True}]
            else: row['evidence'][0]['equal'] = False
            with self.assertRaises(ValueError): protection.native_gate(report)
    def test_missing_pair_is_rejected(self):
        report = native_report(self.doc); report['security_assessment']['secret_pairs'] = []
        with self.assertRaises(ValueError): protection.native_gate(report)
    def test_checker_jar_cannot_change_between_native_run_and_approval(self):
        candidate=workflow.Workflow(self.root/'input',self.root/'config')
        candidate.doc=self.doc;candidate.root=self.root
        (self.root/'toolkit.jar').write_bytes(b'changed checker')
        candidate.report['reproducibility']['toolkit_jar_sha256']='0'*64
        with self.assertRaisesRegex(workflow.Stop,'checker JAR changed'):
            candidate.java('approve-transform',self.root/'approval.json')
    def test_all_prerequisites_are_needed_before_compromised_verdict(self):
        self.assertEqual('INCONCLUSIVE', workflow.verdict({'functional': workflow.check('NOT_RUN', 'not tested')}, {'compromise_demonstrated': True}))
        self.assertEqual('COMPROMISED', workflow.verdict({'functional': workflow.check('PASS', 'tested'), 'security': workflow.check('FAIL', 'difference')}, {'compromise_demonstrated': True}))
    def test_protection_never_automatically_falls_back_to_program_mode(self):
        import program_workflow
        source = self.root / 'ordinary.asm'; source.write_text('global _start\n_start:\nret\n')
        config = self.root / 'settings.toml'; config.write_text('[protection]\napproval_profile="contract.json"\nmode="program"\n')
        with patch.object(workflow, 'config', return_value=self.doc):
            result = program_workflow.workflow_for(source, config)
        self.assertIs(type(result), workflow.Workflow)
    def transfers(self, entry, events):
        return {'executions': [{'entry': entry, 'inputs': [{'register': 'rdi', 'value': 0}],
                                'correspondence': {'transfers': events}}]}
    def test_control_mapping_handles_repeated_loop_transfers(self):
        a = self.transfers(100, [{'from': 110, 'to': 105, 'kind': 'branch'}] * 3 + [{'from': 115, 'to': 999, 'kind': 'entry-return'}])
        b = self.transfers(200, [{'from': 214, 'to': 207, 'kind': 'branch'}] * 3 + [{'from': 220, 'to': 999, 'kind': 'entry-return'}])
        mapping = protection.propose_control_map(a, b, [(100, 200)])
        self.assertEqual({100: 200, 110: 214, 105: 207, 115: 220}, {x['original']: x['rebuilt'] for x in mapping})
    def test_control_mapping_rejects_inconsistent_sites(self):
        a = self.transfers(100, [{'from': 110, 'to': 105, 'kind': 'branch'}] * 2)
        b = self.transfers(200, [{'from': 214, 'to': 207, 'kind': 'branch'}, {'from': 216, 'to': 207, 'kind': 'branch'}])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): protection.propose_control_map(a, b, [(100, 200)])
    def test_control_mapping_does_not_guess_changed_structure(self):
        with self.assertRaisesRegex(ValueError, 'structure'):
            protection.propose_control_map(self.transfers(100, []), self.transfers(200, [{'from': 210, 'to': 999, 'kind': 'entry-return'}]), [(100, 200)])
    def test_adjacent_regions_receive_zero_byte_unique_end_alias(self):
        assembly = self.root / 'source.asm'
        assembly.write_text('section .data\na:\ndb 7,0,0,0\nb:\ndb 7,0,0,0\nend:\n')
        profile = {'assembly': str(assembly), 'regions': [{'name': 'a', 'end_label': 'b'}, {'name': 'b', 'end_label': 'end'}]}
        result = protection.planner_input(profile, self.root)
        self.assertEqual('BCL_PROTECTION_END_0', result['regions'][0]['end_label'])
        self.assertIn('BCL_PROTECTION_END_0:\nb:', Path(result['assembly']).read_text())
        self.assertEqual('b', profile['regions'][0]['end_label'])
        self.assertEqual(2, Path(result['assembly']).read_text().count('db 7,0,0,0'))
    def test_supplied_protection_config_validates(self):
        doc = workflow.config(ROOT / 'examples/protection/bcl.toml')
        self.assertEqual(2, len(doc['regions']))
        self.assertEqual(3, len(doc['layout_constraints']))
    def test_unrelated_required_failure_also_blocks_publication(self):
        report = native_report(self.doc)
        report['checks']['region_mapping'] = workflow.check('FAIL', 'overlapping regions')
        with self.assertRaisesRegex(ValueError, 'region_mapping'): protection.native_gate(report)


class RealBoundedProtectionTests(unittest.TestCase):
    """Real Java approval/publication on encoded ELFs; native statuses are doubles."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name); (self.root / 'build').mkdir(); (self.root / 'validation').mkdir()
        self.doc = configuration()
        fixture = self.root / 'fixture'
        policy = runpy.run_path(str(Path(__file__).with_name('make-automatic-example.py')))['make'](fixture)
        original = project.read(fixture / 'original/lookup.json')
        raw = (fixture / 'original/lookup.elf').read_bytes()
        analysis = {'instruction_coverage': [{'ip': 0x400206, 'bytes': raw[0x206:0x210].hex()}]}
        rewritten, delta, _ = automatic.candidate(raw, analysis, automatic.validate(policy), 0x401040)
        (self.root / 'build/original').write_bytes(raw); (self.root / 'build/transformed').write_bytes(rewritten)
        # Independent analyzer provides the complete original control inventory.
        original['binary'] = str(self.root / 'build/original')
        project.save(fixture / 'source.json', original)
        self.invoke('bounded-references', fixture / 'source.json', '--report', fixture / 'analysis.json')
        full = project.read(fixture / 'analysis.json')
        rebuilt, pair, approval = automatic.contracts(original, full, automatic.validate(policy), delta, policy)
        original['binary'] = 'ignored-original.elf'
        rebuilt['binary'] = 'ignored-candidate.elf'
        project.save(fixture / 'original.json', original); project.save(fixture / 'rebuilt.json', rebuilt)
        pair.update(original='original.json', rebuilt='rebuilt.json')
        project.save(fixture / 'correspondence.json', pair); project.save(fixture / 'approval.json', approval)
        self.doc['protection']['approval_profile'] = str(fixture / 'approval.json')
        self.regions = {'original': [{'name': 'table', 'address': 0x401000, 'size': 8}],
                        'transformed': [{'name': 'table', 'address': 0x401040, 'size': 8}]}
        self.doc['regions'] = [{'name': 'table', 'size': 8}]
        self.report = native_report(self.doc)
        self.report['artifacts'] = {v: {'sha256': workflow_events.sha(self.root / 'build' / v)} for v in self.regions}
        self.w = SimpleNamespace(root=self.root, doc=self.doc, report=self.report, regions=self.regions,
                                 path=lambda value: Path(value), java=self.invoke)
    def tearDown(self): self.temp.cleanup()
    def invoke(self, *args, allowed=(0,)):
        process = subprocess.run([os.environ.get('JAVA', 'java'), '-jar', str(ROOT / 'binarycachelab.jar'), *map(str, args)], capture_output=True, text=True, encoding='utf-8', timeout=60)
        if process.returncode not in allowed: raise RuntimeError(process.stdout + process.stderr)
        return process.stdout, process.returncode
    def test_real_approval_then_publication_of_exact_bytes(self):
        protection.prepare(self.w)
        protection.enforce(self.w)
        self.assertTrue(self.report['protection']['published'], self.report['protection'])
        self.assertEqual((self.root / 'build/transformed').read_bytes(), (self.root / 'protected/program').read_bytes())
        self.assertEqual('PASS', self.report['checks']['protection']['status'])
    def test_hash_change_after_native_status_blocks_publication(self):
        protection.prepare(self.w)
        with (self.root / 'build/transformed').open('ab') as stream: stream.write(b'changed')
        protection.enforce(self.w)
        self.assertFalse(self.report['protection']['published']); self.assertFalse((self.root / 'protected/program').exists())
    def test_changed_snapshot_is_rejected_by_real_reanalysis(self):
        protection.prepare(self.w)
        path = self.root / 'validation/protection/rebuilt.elf'
        raw = bytearray(path.read_bytes()); raw[0x1040] = 99; path.write_bytes(raw)
        protection.enforce(self.w)
        self.assertFalse(self.report['protection']['published']); self.assertFalse((self.root / 'protected/program').exists())
    def test_bad_final_map_is_rejected_before_execution(self):
        self.regions['transformed'][0]['address'] += 4
        with self.assertRaisesRegex(ValueError, 'addresses'): protection.prepare(self.w)
        self.assertFalse((self.root / 'protected/program').exists())
    def test_no_preexecution_approval_means_no_publication(self):
        protection.enforce(self.w)
        self.assertFalse(self.report['protection']['published']); self.assertFalse((self.root / 'protected/program').exists())
    def test_publication_does_not_overwrite_an_existing_path(self):
        protection.prepare(self.w)
        (self.root / 'protected').mkdir(); path = self.root / 'protected/program'; path.write_bytes(b'keep')
        protection.enforce(self.w)
        self.assertFalse(self.report['protection']['published']); self.assertEqual(b'keep', path.read_bytes())
    def symbolic_contract(self, split=False):
        original = project.read(self.root / 'fixture/original.json')
        value = {key: original[key] for key in ('machine', 'inputs', 'bounds')}
        if split:
            self.regions = {'original': [{'name': 'left', 'address': 0x401000, 'size': 4}, {'name': 'right', 'address': 0x401004, 'size': 4}],
                            'transformed': [{'name': 'left', 'address': 0x401040, 'size': 4}, {'name': 'right', 'address': 0x401044, 'size': 4}]}
            self.doc['regions'] = [{'name': 'left'}, {'name': 'right'}]
            self.w.regions = self.regions
        value.update(schema='bcl-protection-contract-1', entries=[{'original': 'lookup', 'transformed': 'lookup'}],
                     regions=[{'name': r['name'], 'alignment': 4} for r in self.regions['original']], secret_inputs=[0],
                     register_outputs=[{'register': 'rax', 'encoding': 'scalar'}])
        path = self.root / 'fixture/symbolic.json'; project.save(path, value)
        self.doc['protection']['approval_profile'] = str(path)
        # A symbol-provider double only: actual machine analysis/approval runs in Java.
        self.w.runner = SimpleNamespace(command=lambda *a: ('0000000000400200 T lookup\n', 0))
        return path
    def test_automatic_symbol_binding_and_control_map_real_approval(self):
        self.symbolic_contract()
        protection.prepare(self.w)
        protection.enforce(self.w)
        self.assertTrue(self.report['protection']['published'], self.report['protection'])
        pair = project.read(self.root / 'validation/protection/correspondence.json')
        self.assertIn({'original': 0x400213, 'rebuilt': 0x400213}, pair['control_map'])
    def test_multiple_adjacent_regions_real_approval(self):
        self.symbolic_contract(split=True)
        protection.prepare(self.w); protection.enforce(self.w)
        self.assertTrue(self.report['protection']['published'], self.report['protection'])
        result = project.read(self.root / 'validation/protection/approval-report.json')
        self.assertEqual(2, len(result['linked_layout']['regions']))
    def test_real_baseline_reference_proof_and_explicit_native_binding(self):
        contract=self.symbolic_contract()
        settings=project.read(contract)
        settings['native_cases']=[{'id':'secret0','entry':0,'values':[0]},{'id':'secret1','entry':0,'values':[1]}]
        project.save(contract,settings)
        shutil.copyfile(self.root/'build/original',self.root/'build/baseline')
        self.regions['baseline']=copy.deepcopy(self.regions['original'])
        self.report['artifacts']['baseline']={'sha256':workflow_events.sha(self.root/'build/baseline')}
        protection.prepare(self.w)
        self.assertEqual(1,len(self.w.certified_reference_sequences['baseline']['secret0']))
        baseline=project.read(self.root/'validation/protection-baseline/correspondence-report.json')
        self.assertTrue(baseline['correspondence_established'])
    def test_controlled_split_rejected_by_real_observation_checker(self):
        self.symbolic_contract(split=True)
        path = self.root / 'build/transformed'; raw = bytearray(path.read_bytes())
        data = bytes(raw[0x1040:0x1048]); raw[0x1040:0x1048] = bytes(8); raw[0x103c:0x1044] = data
        struct.pack_into('<Q', raw, 0x208, 0x40103c)
        struct.pack_into('<QQ', raw, 0xcd0, 0x40103c, 0x103c)
        path.write_bytes(raw)
        self.report['artifacts']['transformed']['sha256'] = workflow_events.sha(path)
        self.regions['transformed'][0]['address'] = 0x40103c; self.regions['transformed'][1]['address'] = 0x401040
        with self.assertRaisesRegex(ValueError, 'PRESERVATION_COUNTEREXAMPLE'): protection.prepare(self.w)
        approval = project.read(self.root / 'validation/protection/approval-report.json')
        self.assertFalse(approval['observation']['preservation_holds'])
        self.assertGreater(approval['observation']['split_witness_count'], 0)
        self.assertFalse((self.root / 'protected/program').exists())
    def test_finalization_failure_revokes_published_output(self):
        protection.prepare(self.w); protection.enforce(self.w)
        self.assertTrue((self.root / 'protected/program').exists())
        protection.revoke(self.w, 'sealing failed')
        self.assertFalse((self.root / 'protected/program').exists())
        self.assertFalse(self.report['protection']['published'])
        self.assertFalse(project.read(self.root / 'validation/protection-decision.json')['published'])
    def test_interrupted_publication_removes_partial_executable(self):
        protection.prepare(self.w)
        def interrupted(*args, **kwargs):
            if args[0] == 'publish-transform':
                (self.root / 'protected/program').write_bytes(b'partial')
                raise KeyboardInterrupt()
            return self.invoke(*args, **kwargs)
        self.w.java = interrupted
        with self.assertRaises(KeyboardInterrupt): protection.enforce(self.w)
        self.assertFalse((self.root / 'protected/program').exists())
        self.assertFalse(self.report['protection']['published'])

    def test_real_machine_constructs_in_automatic_protection(self):
        pointer = b'\x48\xb9' + struct.pack('<Q', 0x401000)
        # Encoded fixture bodies run in the real exhaustive integer machine.
        # They are not claimed to be native PIN/FoxDec integration tests.
        bodies = {
            'loop': b'\x41\xb8\x02\x00\x00\x00' + pointer + b'\x31\xc0\x8b\x14\xb9\x01\xd0\x41\xff\xc8\x75\xf6\xc3',
            'branch': b'\x85\xff\x74\x0e' + pointer + b'\x8b\x41\x04\xc3' + pointer + b'\x8b\x01\xc3',
            'call': b'\x48\x83\xec\x08\xe8\x05\x00\x00\x00\x48\x83\xc4\x08\xc3' + pointer + b'\x8b\x04\xb9\xc3',
            'recursion': bytes.fromhex('41b8020000004883ec08e8050000004883c408c34585c0741141ffc84883ec08e8efffffff4883c408c3') + pointer + b'\x8b\x04\xb9\xc3',
            'write': pointer + b'\x8b\x04\xb9\x89\x04\xb9\xc3',
            'byte': pointer + b'\x0f\xb6\x04\xb9\xc3',
            'word': pointer + b'\x0f\xb7\x04\xb9\xc3',
            'qword': pointer + b'\x48\x8b\x01\xc3',
            'rex': b'\x49\xb9' + struct.pack('<Q', 0x401000) + b'\x41\x8b\x04\xb9\xc3'}
        template = project.read(self.root / 'fixture/original.json')
        for name, code in bodies.items():
            with self.subTest(construct=name):
                folder = self.root / name; (folder / 'build').mkdir(parents=True); (folder / 'validation').mkdir()
                original = bytearray((self.root / 'build/original').read_bytes())
                original[0x200:0x280] = b'\x90' * 0x80
                original[0x200:0x200 + len(code)] = code
                (folder / 'build/original').write_bytes(original)
                profile = copy.deepcopy(template); profile['binary'] = str(folder / 'build/original')
                project.save(folder / 'analysis-profile.json', profile)
                self.invoke('bounded-control', folder / 'analysis-profile.json', '--report', folder / 'source-analysis.json')
                analysis = project.read(folder / 'source-analysis.json')
                rewritten, _, _ = automatic.candidate(bytes(original), analysis, [{'name': 'table', 'address': 0x401000, 'size': 8, 'alignment': 4}], 0x401040)
                (folder / 'build/transformed').write_bytes(rewritten)
                settings = {key: template[key] for key in ('machine', 'inputs', 'bounds')}
                settings.update(schema='bcl-protection-contract-1', entries=[{'original': 'lookup', 'transformed': 'lookup'}],
                                regions=[{'name': 'table', 'alignment': 4}], secret_inputs=[0],
                                register_outputs=[{'register': 'rax', 'encoding': 'scalar'}])
                project.save(folder / 'contract.json', settings)
                doc = copy.deepcopy(self.doc); doc['protection']['approval_profile'] = str(folder / 'contract.json')
                report = native_report(doc)
                report['artifacts'] = {v: {'sha256': workflow_events.sha(folder / 'build' / v)} for v in self.regions}
                instance = SimpleNamespace(root=folder, doc=doc, report=report, regions=copy.deepcopy(self.regions),
                           path=lambda value: Path(value), java=self.invoke,
                           runner=SimpleNamespace(command=lambda *a: ('0000000000400200 T lookup\n', 0)))
                protection.prepare(instance); protection.enforce(instance)
                self.assertTrue(report['protection']['published'], report['protection'])


if __name__ == '__main__': unittest.main()
