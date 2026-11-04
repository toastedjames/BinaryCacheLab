"""Portable project tests; no native target execution required."""
import json
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import project
import console


class ProjectTests(unittest.TestCase):
    def test_restore_crt_alias_from_verified_section_bytes(self):
        blob=bytearray(512);blob[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<Q',blob,40,64);struct.pack_into('<HHH',blob,58,64,3,2)
        names=b'\0.data\0.shstrtab\0';blob[300:300+len(names)]=names;blob[400:404]=bytes([0,255,7,0])
        struct.pack_into('<IIQQQQIIQQ',blob,128,1,1,3,0x4080,400,4,0,0,1,0)
        struct.pack_into('<IIQQQQIIQQ',blob,192,7,3,0,0,300,len(names),0,0,1,0)
        original=self.root/'alias.elf';original.write_bytes(blob)
        asm=self.root/'alias.asm';text='mov eax,[__TMC_END__]\nsection .data align=64 ; @4080\nbase:\ndb 00h\ndb 0ffh\ndb 07h\ndb 00h\n'
        asm.write_text(text)
        self.assertTrue(project.restore_tmc_alias(asm,'4082 D __TMC_END__\n',original))
        self.assertIn('db 0ffh\n__TMC_END__:\ndb 07h',asm.read_text())
        asm.write_text(text+'L_.data_END:\n')
        self.assertTrue(project.restore_tmc_alias(asm,'4084 D __TMC_END__\n',original))
        self.assertIn('__TMC_END__:\nL_.data_END:',asm.read_text())
        struct.pack_into('<IIQQQQIIQQ',blob,128,1,8,3,0x4080,400,4,0,0,1,0)
        blob[300:306]=b'\0.bss\0';original.write_bytes(blob)
        asm.write_text('mov eax,__TMC_END__\nsection .bss align=1 ; @4080\n__bss_start:\nresb 4\nL_.bss_END:\nsection .bss\n')
        self.assertTrue(project.restore_tmc_alias(asm,'4084 B __TMC_END__\n',original))
        self.assertIn('resb 4\n__TMC_END__:\nL_.bss_END:',asm.read_text())
        struct.pack_into('<IIQQQQIIQQ',blob,128,1,1,3,0x4080,400,4,0,0,1,0)
        blob[300:306]=b'\0.data';original.write_bytes(blob)
        for wrong in (text.replace('0ffh','0feh'),text.replace('db 07h','db `x`')):
            asm.write_text(wrong)
            with self.assertRaises(ValueError):project.restore_tmc_alias(asm,'4082 D __TMC_END__\n',original)
            self.assertEqual(asm.read_text(),wrong)

    def test_restore_crt_alias_requires_matching_original_address(self):
        asm = self.root / 'alias.asm'
        original = 'mov eax,[__TMC_END__]\nL_.data_0x4080:\ndd 7\n'
        asm.write_text(original)
        self.assertTrue(project.restore_tmc_alias(asm, '0000000000004080 D __TMC_END__\n'))
        self.assertIn('__TMC_END__ equ L_.data_0x4080', asm.read_text())
        self.assertFalse(project.restore_tmc_alias(asm, ''))
        for symbols in ('', '0000000000004090 D __TMC_END__\n', '4080 D __TMC_END__\n4090 D __TMC_END__\n'):
            asm.write_text(original)
            with self.assertRaises(ValueError): project.restore_tmc_alias(asm, symbols)
            self.assertEqual(asm.read_text(), original)

    def test_correspondence_snapshots_profiles_and_blocks_failed_results(self):
        contract = self.root / 'bounded-correspondence-side.json'
        project.save(contract, {'schema': 'bcl-bounded-references-1', 'binary': 'untrusted-source-path'})
        pair = self.root / 'pair.json'
        project.save(pair, {'schema': 'bcl-bounded-correspondence-1', 'original': contract.name, 'rebuilt': contract.name})
        project.save(self.path, dict(self.doc, correspondence=str(pair)))
        for status in ('CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS', 'CORRESPONDENCE_COUNTEREXAMPLE', 'REJECTED_CORRESPONDENCE_MODEL'):
            success = status == 'CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS'
            with self.subTest(status=status), patch.object(project.easy, 'Runner') as runner:
                def command(name, argv, **kwargs):
                    self.assertEqual('program-correspondence', name)
                    self.assertEqual((0, 3, 7), kwargs['allowed'])
                    snapshot = Path(argv[argv.index('correspondence') + 1])
                    data = project.read(snapshot)
                    for label in ('original', 'rebuilt'):
                        self.assertEqual('correspondence-' + label + '.json', data[label])
                        self.assertEqual(label, project.read(snapshot.parent / data[label])['binary'])
                    project.save(Path(argv[argv.index('--report') + 1]), {'status': status, 'correspondence_established': success})
                    return '', 0 if success else 3 if status.endswith('COUNTEREXAMPLE') else 7
                runner.return_value.command.side_effect = command
                if success:
                    evidence = project.run_project(self.path, True)
                    result = project.read(evidence / 'summary.json')
                    self.assertEqual(status, result['correspondence_status'])
                    self.assertFalse(result['automatic_rewrite_allowed'])
                else:
                    with self.assertRaisesRegex(ValueError, 'Program correspondence failed'):
                        project.run_project(self.path, True)

    def test_approval_gate_snapshots_policy_and_refuses_negative_results(self):
        side = self.root / 'side.json'
        project.save(side, {'schema': 'bcl-bounded-references-1'})
        pair = self.root / 'pair.json'
        project.save(pair, {'schema': 'bcl-bounded-correspondence-1', 'original': side.name, 'rebuilt': side.name})
        policy = self.root / 'approval.json'
        project.save(policy, {'schema': 'bcl-bounded-transformation-1', 'correspondence': pair.name})
        project.save(self.path, dict(self.doc, approval=str(policy)))
        for status in ('APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS', 'PRESERVATION_COUNTEREXAMPLE', 'TRANSFORMATION_REJECTED'):
            success = status.startswith('APPROVED_')
            with self.subTest(status=status), patch.object(project.easy, 'Runner') as runner:
                def command(name, argv, **kwargs):
                    if name == 'program-correspondence':
                        report = {'status': 'CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS', 'correspondence_established': True}
                    else:
                        self.assertEqual('transformation-approval', name)
                        snapshot = Path(argv[argv.index('approve-transform') + 1])
                        self.assertEqual('correspondence.json', project.read(snapshot)['correspondence'])
                        report = {'status': status, 'bounded_transformation_approved': success}
                    project.save(Path(argv[argv.index('--report') + 1]), report)
                    return '', 0
                runner.return_value.command.side_effect = command
                if success:
                    evidence = project.run_project(self.path, True)
                    result = project.read(evidence / 'summary.json')
                    self.assertTrue(result['bounded_transformation_approved'])
                    self.assertEqual(status, result['safety_decision'])
                    self.assertFalse(result['automatic_rewrite_allowed'])
                else:
                    with self.assertRaisesRegex(ValueError, 'Transformation rejected'):
                        project.run_project(self.path, True)

    def test_bounded_contract_dispatch_preserves_rejection_and_relative_binary(self):
        contract = self.root / 'bounded.json'
        project.save(contract, {'schema': 'bcl-bounded-references-1'})
        project.save(self.path, dict(self.doc, contracts={'original': str(contract)}))
        def run(name, argv, **kwargs):
            self.assertIn('bounded-references', argv)
            self.assertNotIn('objdump', argv)
            self.assertEqual((0, 7), kwargs['allowed'])
            profile_path = Path(argv[argv.index('bounded-references') + 1])
            self.assertEqual('original', project.read(profile_path)['binary'])
            self.assertNotIn('disassembly', project.read(profile_path))
            project.save(Path(argv[argv.index('--report') + 1]), {'status': 'REJECTED_MODEL_OR_BOUNDS'})
            return '', 7
        with patch.object(project.easy, 'Runner') as runner:
            runner.return_value.command.side_effect = run
            evidence = project.run_project(self.path, True)
        result = project.read(evidence / 'summary.json')
        self.assertEqual('REJECTED_MODEL_OR_BOUNDS', result['reference_status']['original'])
        self.assertFalse(result['automatic_rewrite_allowed'])
        self.assertEqual('NO_OBSERVATION_VERDICT', result['verdict'])

    def test_command_failure_is_readable_without_a_traceback(self):
        output = io.StringIO()
        with patch.object(console, 'main', side_effect=RuntimeError('callback-plan failed; see log')), contextlib.redirect_stderr(output):
            self.assertEqual(2, console.entrypoint())
        self.assertIn('callback-plan failed', output.getvalue())
        self.assertNotIn('Traceback', output.getvalue())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.original = project.ROOT / 'fixtures/group_lookup/original'
        self.doc = {'schema': 'bcl-project-1', 'original': str(self.original), 'rebuilt': str(self.original),
                    'output': str(self.root / 'experiments')}
        self.path = self.root / 'project.json'
        project.save(self.path, self.doc)

    def tearDown(self):
        self.temp.cleanup()

    def test_discovers_real_bundled_elf_without_its_hash_being_required(self):
        inventory = project.elf_inventory(self.original)
        self.assertTrue(inventory['entry'] > 0)
        self.assertTrue(inventory['functions'])
        self.assertFalse(inventory['discovery_complete'])

    def test_rejects_nonelf(self):
        self.path.write_bytes(b'not an elf')
        with self.assertRaises(ValueError):
            project.elf_inventory(self.path)

    def test_rejects_truncated_section_table(self):
        blob = bytearray(self.original.read_bytes())
        struct.pack_into('<Q', blob, 40, len(blob) - 1)
        self.path.write_bytes(blob)
        with self.assertRaises(ValueError):
            project.elf_inventory(self.path)

    def test_rejects_wrong_architecture(self):
        blob = bytearray(self.original.read_bytes())
        struct.pack_into('<H', blob, 18, 183)
        self.path.write_bytes(blob)
        with self.assertRaises(ValueError):
            project.elf_inventory(self.path)

    def test_profile_defaults(self):
        _, doc = project.profile(self.path)
        self.assertEqual(3, doc['repetitions'])
        self.assertEqual(['0', '1'], doc['secrets'])

    def test_symbol_contract_resolves_addresses_without_asserting_immutability_or_stack_disjointness(self):
        inventory = project.elf_inventory(self.original)
        contract = project.symbol_contract(inventory, {'entries': ['secret_lookup'], 'regions': ['group']})
        self.assertEqual([0x1149], contract['entries'])
        self.assertEqual(0x4040, contract['regions'][0]['address'])
        self.assertFalse(contract['regions'][0]['immutable'])
        self.assertFalse(contract['stack_disjoint_from_regions'])

    def test_symbol_contract_rejects_missing_objects(self):
        with self.assertRaisesRegex(ValueError, 'Missing or ambiguous'):
            project.symbol_contract(project.elf_inventory(self.original), {'entries': ['secret_lookup'], 'regions': ['missing']})

    def test_project_tui_can_quit_without_execution(self):
        with patch('builtins.input', return_value='q'), patch.object(project, 'run_project') as run:
            self.assertEqual(0, project.project_tui(self.path))
            run.assert_not_called()

    def test_qualification_checks_all_four_cases_and_replays_each(self):
        def run(profile):
            doc = project.read(profile)
            evidence = Path(doc['output']) / 'project-test'
            evidence.mkdir(parents=True)
            expected = 'SATISFIED_FOR_TESTED_PAIR' if Path(profile).stem in ('equal_line', 'multiple_regions') else 'ORIGINAL_OBSERVATIONS_DIFFER'
            project.save(evidence / 'summary.json', {'status': 'COMPARISON_COMPLETE', 'verdict': expected})
            return evidence
        with patch.object(project, 'run_project', side_effect=run), patch.object(project, 'replay_project') as replay:
            root = project.qualify(self.root / 'qualification')
            self.assertEqual(4, replay.call_count)
        self.assertEqual('PROJECT_QUALIFICATION_EXPECTATIONS_MET', project.read(root / 'qualification.json')['status'])
        self.assertEqual(4, len(project.read(root / 'qualification.json')['cases']))
        self.assertGreater(project.verify_manifest(root), 8)

    def test_qualification_does_not_accept_wrong_verdicts(self):
        evidence = self.root / 'bad-evidence'
        evidence.mkdir()
        project.save(evidence / 'summary.json', {'status': 'COMPARISON_COMPLETE', 'verdict': 'ORIGINAL_OBSERVATIONS_DIFFER'})
        with patch.object(project, 'run_project', return_value=evidence), patch.object(project, 'replay_project'):
            with self.assertRaisesRegex(ValueError, 'expectation failed'):
                project.qualify(self.root / 'qualification')
        root, = (self.root / 'qualification').glob('project-qualification-*')
        self.assertEqual('FAILED', project.read(root / 'qualification.json')['status'])

    def test_static_replay_refuses_forged_observation_conclusion(self):
        with patch.object(project.sys, 'platform', 'linux'), patch.object(project.easy, 'Runner'):
            evidence = project.run_project(self.path, True)
            result = project.read(evidence / 'summary.json')
            result['verdict'] = 'SATISFIED_FOR_TESTED_PAIR'
            project.save(evidence / 'summary.json', result)
            project.seal(evidence)
            with self.assertRaisesRegex(ValueError, 'Static checks cannot'):
                project.replay_project(evidence)

    def test_rejects_misspelled_fields_and_bad_limits(self):
        for update in ({'repetition': 3}, {'repetitions': True}, {'repetitions': 1},
                       {'timeout': 0}, {'secrets': ['x', 'x']}, {'contracts': {'typo': 'x'}}):
            project.save(self.path, dict(self.doc, **update))
            with self.assertRaises(ValueError):
                project.profile(self.path)

    def test_nested_manifests_are_bound(self):
        (self.root / 'nested').mkdir()
        (self.root / 'nested/SHA256SUMS').write_text('nested hash list')
        project.seal(self.root)
        self.assertEqual(2, project.verify_manifest(self.root))
        (self.root / 'nested/SHA256SUMS').write_text('tampered')
        with self.assertRaises(ValueError):
            project.verify_manifest(self.root)

    def test_unmanifested_file_rejected(self):
        project.seal(self.root)
        (self.root / 'extra').write_text('extra')
        with self.assertRaises(ValueError):
            project.verify_manifest(self.root)

    def test_manifest_traversal_rejected(self):
        (self.root / 'SHA256SUMS').write_text('0' * 64 + '  ../escape\n')
        with self.assertRaises(ValueError):
            project.verify_manifest(self.root)

    def test_manifest_duplicate_rejected(self):
        project.seal(self.root)
        manifest = self.root / 'SHA256SUMS'
        manifest.write_text(manifest.read_text() * 2)
        with self.assertRaises(ValueError):
            project.verify_manifest(self.root)

    def test_init_creates_a_project_and_never_overwrites(self):
        dest = self.root / 'new.json'
        args = ['init', '--original', str(self.original), '--rebuilt', str(self.original), '--output', str(dest)]
        self.assertEqual(0, project.main(args))
        self.assertEqual('bcl-project-1', project.read(dest)['schema'])
        with self.assertRaises(ValueError):
            project.main(args)

    def test_static_pipeline_keeps_safety_inconclusive_and_seals(self):
        with patch.object(project.sys, 'platform', 'linux'), patch.object(project.easy, 'Runner') as runner:
            evidence = project.run_project(self.path, True)
            runner.return_value.command.assert_not_called()
        result = project.read(evidence / 'summary.json')
        self.assertEqual('STATIC_CHECKS_COMPLETED', result['status'])
        self.assertFalse(result['automatic_rewrite_allowed'])
        self.assertEqual('NO_OBSERVATION_VERDICT', result['verdict'])
        self.assertGreater(project.verify_manifest(evidence), 5)

    def test_failed_build_is_retained_as_failed_not_qualified(self):
        project.save(self.path, dict(self.doc, build_jobs=[{'argv': ['false']}]))
        with patch.object(project.sys, 'platform', 'linux'), patch.object(project.easy, 'Runner') as runner:
            runner.return_value.command.side_effect = RuntimeError('build failed')
            with self.assertRaises(RuntimeError):
                project.run_project(self.path)
        evidence, = (self.root / 'experiments').glob('project-*')
        self.assertEqual('FAILED', project.read(evidence / 'summary.json')['status'])
        self.assertGreater(project.verify_manifest(evidence), 3)

    def test_init_can_request_fresh_lifting_without_a_rebuilt_binary(self):
        dest = self.root / 'lift.json'
        project.main(['init', '--original', str(self.original), '--lift', '--output', str(dest)])
        self.assertEqual({}, project.read(dest)['lift'])

    def test_fresh_lift_uses_callback_roots_pinned_image_and_cleanup(self):
        root = self.root / 'lift'
        root.mkdir()
        shutil.copy2(self.original, root / 'original')
        with patch.object(project.easy, 'Runner') as factory:
            runner = factory.return_value
            runner.docker = ['docker']
            runner.foxdec.return_value = 'foxdec'
            def command(name, argv, **kwargs):
                if name == 'callback-plan':
                    project.save(root / 'callback-plan.json', {'required_roots': [{'original_entry': 4096}],
                                'linker_arguments': ['-Wl,-init,_init']})
                if name == 'image-identity':
                    return 'sha256:' + 'a' * 64 + '\n', 0
                if name == 'foxdec-lift':
                    artifacts = root / 'lift-artifacts'
                    (artifacts / 'nasm').mkdir()
                    for name in ('nasm/program.asm', 'nasm/__gmon_start__.c', 'nasm/program.asm.json', 'program.metrics.txt'):
                        (artifacts / name).write_text('test output')
                return '', 0
            runner.command.side_effect = command
            assembly, link = project.lift_original(root, {'extra_link_args': ['-lm']}, runner, ['java', '-jar', 'toolkit.jar'], self.root)
            self.assertEqual('0x1000\n', (root / 'lift-input/program.entry').read_text())
            self.assertTrue(assembly.is_file())
            self.assertEqual(root / 'lifted-host.asm', assembly)
            self.assertEqual('test output', (root / 'lift-artifacts/nasm/program.asm').read_text())
            self.assertEqual('test output', assembly.read_text())
            self.assertIn('-Wl,-init,_init', link)
            self.assertIn('-lm', link)
            runner.capture.assert_called_once()
            calls = runner.command.call_args_list
            lift = next(c for c in calls if c.args[0] == 'foxdec-lift')
            self.assertIn('sha256:' + 'a' * 64, lift.args[1])

    def test_fresh_lift_failure_stops_and_cleans_container(self):
        root = self.root / 'lift'
        root.mkdir()
        with patch.object(project.easy, 'Runner') as factory:
            runner = factory.return_value
            runner.docker = ['docker']
            runner.foxdec.return_value = 'foxdec'
            def command(name, argv, **kwargs):
                if name == 'callback-plan':
                    project.save(root / 'callback-plan.json', {'required_roots': [], 'linker_arguments': []})
                    (root / 'original').write_text('mock')
                    return '', 0
                if name == 'image-identity':
                    return 'sha256:' + 'b' * 64, 0
                raise RuntimeError('unsupported opcode')
            runner.command.side_effect = command
            with self.assertRaisesRegex(RuntimeError, 'unsupported opcode'):
                project.lift_original(root, {}, runner, ['java'], self.root)
            runner.capture.assert_called_once()

    def test_static_replay_rejects_an_inventory_forgery_even_with_new_hashes(self):
        with patch.object(project.sys, 'platform', 'linux'), patch.object(project.easy, 'Runner'):
            evidence = project.run_project(self.path, True)
            inventory = project.read(evidence / 'original-inventory.json')
            inventory['entry'] += 1
            project.save(evidence / 'original-inventory.json', inventory)
            project.seal(evidence)
            with self.assertRaisesRegex(ValueError, 'inventory disagreement'):
                project.replay_project(evidence)

    def test_general_pipeline_forwards_public_inputs_and_seals_source_snapshots(self):
        source = self.root / 'source.c'
        source.write_text('int main(void) { return 0; }')
        stdin = self.root / 'public.txt'
        stdin.write_text('fixed stdin')
        project.save(self.path, dict(self.doc, inputs={'source.c': str(source)}, public_before=['--secret'],
                                    public_after=['fixed'], stdin_file=str(stdin)))
        captured = []
        def fake_command(name, argv, **kwargs):
            argv = list(map(str, argv))
            if name == 'collect':
                captured.extend(argv)
                batch = Path(argv[argv.index('--output-parent') + 1]) / 'whole-collection-test'
                (batch / 'binaries').mkdir(parents=True)
                for role in ('original', 'rebuilt'):
                    shutil.copy2(self.original, batch / 'binaries' / role)
            if name in ('python-comparison', 'java-comparison'):
                project.save(argv[argv.index('--report') + 1], {
                    'schema': 'whole-comparison-1', 'exit_code': 0, 'verdict': 'SATISFIED_FOR_TESTED_PAIR',
                    'functional_checks': True, 'repeat_stability': True, 'comparisons': [], 'runs': [],
                    'manifest_sha256': 'test', 'observer': {'line_size_bytes': 64, 'addresses': 'raw-virtual',
                    'repetitions': 'retained', 'order': 'event order; ascending touched lines within event', 'excluded': []}})
            return '', 0
        with patch.object(project.sys, 'platform', 'linux'), patch.object(project.easy, 'Runner') as runner:
            runner.return_value.command.side_effect = fake_command
            evidence = project.run_project(self.path)
        self.assertIn('--public-before=--secret', captured)
        self.assertIn('--public-after=fixed', captured)
        self.assertIn('--stdin-file', captured)
        self.assertEqual(source.read_bytes(), (evidence / 'inputs/source.c').read_bytes())
        self.assertEqual('SATISFIED_FOR_TESTED_PAIR', project.read(evidence / 'summary.json')['verdict'])
        self.assertGreater(project.verify_manifest(evidence), 8)

    def test_collector_passes_identical_public_argv_and_stdin_to_all_four_runs(self):
        backend = project.ROOT / 'backend'
        with patch.object(sys, 'path', [str(backend), *sys.path]):
            spec = importlib.util.spec_from_file_location('test_bcl_collector', backend / 'collect_whole.py')
            collector = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(collector)
        stdin = self.root / 'stdin'
        stdin.write_text('fixed')
        calls = []
        def execute(argv, directory, env, prefix, timeout, stdin_path=None):
            if prefix.name != 'aslr-probe':
                calls.append((argv, stdin_path))
                prefix.with_suffix('.stdout').write_bytes(b'7\n')
                prefix.with_suffix('.stderr').write_bytes(b'')
        real_is_file = Path.is_file
        args = ['collect', '--original', str(self.original), '--rebuilt', str(self.original),
                '--pin', str(self.original), '--tool', str(self.original), '--tool-source', str(self.original),
                '--output-parent', str(self.root), '--repetitions', '2', '--public-before=--secret',
                '--public-after=fixed', '--stdin-file', str(stdin)]
        with patch.object(sys, 'argv', args), patch.object(collector.platform, 'system', return_value='Linux'), \
             patch.object(collector.platform, 'machine', return_value='x86_64'), \
             patch.object(collector.shutil, 'which', return_value='/usr/bin/setarch'), \
             patch.object(Path, 'is_file', lambda p: p.as_posix() == '/usr/bin/timeout' or real_is_file(p)), \
             patch.object(collector, 'execute', side_effect=execute), patch.object(collector, 'Collection'), \
             patch.object(collector, 'load'), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, collector.main())
        self.assertEqual(16, len(calls))
        for argv, stdin_path in calls:
            self.assertEqual('--secret', argv[-3])
            self.assertIn(argv[-2], ('0', '1'))
            self.assertEqual('fixed', argv[-1])
            self.assertEqual(b'fixed', Path(stdin_path).read_bytes())
        batch, = self.root.glob('whole-collection-*')
        config = project.read(batch / 'experiment.json')
        self.assertEqual(2, config['secret_argv_index'])
        self.assertEqual(['--secret', 'fixed'], config['public_inputs']['other_arguments'])


if __name__ == '__main__':
    unittest.main()
