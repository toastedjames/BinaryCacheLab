"""Run with python3 -B scripts/test_easy.py. No apt, Docker, PIN, or native experiments."""
import contextlib
import io
import json
import os
import subprocess
import shutil
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import easy
import readable


class EasyTests(unittest.TestCase):
    def test_linux_jobs_keep_session_and_have_separate_process_group(self):
        with patch.object(easy.sys, 'platform', 'linux'), \
             patch.object(easy.sys, 'version_info', (3, 12)):
            self.assertEqual({'process_group': 0}, easy.command_process_options())

    def test_python310_jobs_keep_session_and_have_separate_process_group(self):
        with patch.object(easy.sys, 'platform', 'linux'), \
             patch.object(easy.sys, 'version_info', (3, 10)), \
             patch.object(easy.os, 'setpgrp', create=True) as setpgrp:
            self.assertEqual({'preexec_fn': setpgrp}, easy.command_process_options())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='bcl easy tests ', dir=Path(__file__).resolve().parent)
        self.root = Path(self.directory.name)
        self.patches = [patch.object(easy, 'ROOT', self.root), patch.object(easy, 'STATE', self.root / '.bcl')]
        for item in self.patches:
            item.start()
        (self.root / 'bcl.toml').write_text('[project]\noutput = "experiments"\n[tools]\npin = "/missing"\ntracer = "tracer.so"\ndocker_sudo = false\n[lift]\nenabled = false\nimage = "foxdec"\n')

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.directory.cleanup()

    def test_config_preserves_unrelated_settings_and_backs_up(self):
        original = (self.root / 'bcl.toml').read_text()
        easy.configure({'tools.pin': '/a path/pin', 'lift.enabled': True})
        self.assertEqual('/a path/pin', easy.config_values()['tools.pin'])
        self.assertTrue(easy.config_values()['lift.enabled'])
        self.assertEqual('experiments', easy.config_values()['project.output'])
        backups = list((self.root / '.bcl/config-backups').glob('*.toml'))
        self.assertEqual(original, backups[0].read_text())

    def test_command_passes_session_preserving_options_to_child(self):
        runner = easy.Runner()
        with patch.object(easy, 'command_process_options', return_value={'process_group': 0}), \
             patch.object(easy.subprocess, 'Popen') as popen:
            popen.return_value.poll.return_value = 0
            popen.return_value.returncode = 0
            runner.command('test-child', ['java', '-version'])
            self.assertEqual(0, popen.call_args.kwargs['process_group'])
            self.assertNotIn('start_new_session', popen.call_args.kwargs)

    def test_existing_pin_is_discovered_without_downloading(self):
        pin = self.root / 'installed pin'
        pin.write_text('test fixture')
        pin.chmod(0o755)
        runner = easy.Runner()
        with patch.object(runner, 'capture', return_value=(0, 'Pin 4.4 build 99977')):
            self.assertEqual(pin.resolve(), runner.find_pin({'tools.pin': str(pin)}))

    def test_existing_foxdec_is_reused(self):
        runner = easy.Runner()
        runner.docker = ['docker']
        with patch.object(runner, 'capture', return_value=(0, 'foxdec:latest')), \
             patch.object(runner, 'image_works', return_value=True), \
             patch.object(easy, 'download') as download:
            self.assertEqual('foxdec', runner.foxdec({'lift.image': 'foxdec'}))
            download.assert_not_called()

    def test_missing_foxdec_uses_pinned_release_and_checks_result(self):
        runner = easy.Runner()
        runner.docker = ['docker']
        def fake_download(url, target, expected):
            self.assertEqual(easy.FOX_URL, url)
            self.assertEqual(easy.FOX_SHA, expected)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(target, 'w') as archive:
                archive.writestr('FoxDec/Dockerfile', 'FROM haskell:9\nRUN true\n')
        with patch.object(runner, 'capture', return_value=(0, '')), \
             patch.object(runner, 'image_works', side_effect=[False, False, True]), \
             patch.object(easy, 'download', side_effect=fake_download), \
             patch.object(runner, 'command', return_value=('', 0)) as command:
            self.assertEqual('bcl-foxdec:v0.7', runner.foxdec({}))
            self.assertEqual('install-foxdec', command.call_args.args[0])
            self.assertTrue((self.root / '.bcl/foxdec-source/FoxDec/Dockerfile.bcl').read_text().startswith('FROM haskell:9.6.7\n'))

    def test_unsafe_zip_is_rejected(self):
        archive = self.root / 'bad.zip'
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('../outside.txt', 'bad')
        with zipfile.ZipFile(archive) as stream:
            with self.assertRaises(ValueError):
                easy.safe_zip(stream, self.root / 'extract')

    def test_unsafe_tar_is_rejected(self):
        archive = self.root / 'bad.tar'
        with tarfile.open(archive, 'w') as stream:
            member = tarfile.TarInfo('escape')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc'
            stream.addfile(member)
        with tarfile.open(archive) as stream:
            with self.assertRaises(ValueError):
                easy.safe_tar(stream, self.root / 'extract')

    def test_hazard_is_readable_and_not_approved(self):
        report = {'schema': 'java-eligibility-1', 'decision': 'REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS',
                  'safe_to_transform': False, 'automatic_rewrite_allowed': False,
                  'hazards': ['BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED'],
                  'unestablished_obligations': ['GENERAL_FUNCTIONAL_EQUIVALENCE']}
        text = readable.render(report)
        self.assertIn('NOT APPROVED', text)
        self.assertIn('Startup/shutdown', text)
        self.assertNotIn('"schema"', text)
        self.assertNotIn('BOUNDARY_HELPER', text)

    def test_divergence_witness_is_preserved_in_readable_form(self):
        report = {'schema': 'whole-comparison-1', 'verdict': 'CANDIDATE_PRESERVATION_VIOLATION',
                  'functional_checks': True, 'repeat_stability': True,
                  'comparisons': [{'binary': 'rebuilt', 'repeat': 0, 'equal': False,
                    'first_difference': {'token_index': 53878,
                        'secret_0': {'ip': '0x114e', 'address': '0x407c', 'size': 4}, 'secret_1': None}}]}
        text = readable.render(report)
        self.assertIn('53878', text)
        self.assertIn('0x114e', text)
        self.assertIn('end of observation', text)

    def test_failed_demo_is_recorded_and_not_called_complete(self):
        runner = easy.Runner()
        with patch.object(runner, 'setup', side_effect=RuntimeError('dependency unavailable')):
            with self.assertRaises(RuntimeError):
                runner.demo()
        record = easy.read(self.root / '.bcl/latest-demo.json')
        self.assertEqual('FAILED', record['status'])
        self.assertIn('dependency unavailable', record['error'])

    def test_cache_guard_precedes_checker_import(self):
        app = Path(__file__).resolve().parent.parent
        source = (app / 'backend/collect_whole.py').read_text()
        self.assertLess(source.index('sys.dont_write_bytecode = True'), source.index('from whole_trace_check import'))
        driver = (app / 'scripts/validate-baseline.py').read_text()
        self.assertIn("os.environ['PYTHONDONTWRITEBYTECODE'] = '1'", driver)

    def test_collector_import_does_not_create_cache(self):
        app = Path(__file__).resolve().parent.parent
        isolated = self.root / 'sealed backend'
        isolated.mkdir()
        for name in ('collect_whole.py', 'whole_trace_check.py'):
            shutil.copyfile(app / 'backend' / name, isolated / name)
        environment = dict(os.environ)
        environment.pop('PYTHONDONTWRITEBYTECODE', None)
        code = 'import runpy,sys; sys.path.insert(0,sys.argv[1]); runpy.run_path(sys.argv[2])'
        result = subprocess.run([sys.executable, '-c', code, str(isolated), str(isolated / 'collect_whole.py')],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse((isolated / '__pycache__').exists())

    def test_demo_keeps_finite_result_separate_from_safety(self):
        runner = easy.Runner()
        build = self.root / 'build'
        variants = {name: {'verdict': 'CANDIDATE_PRESERVATION_VIOLATION' if name == 'shifted' else 'SATISFIED_FOR_TESTED_PAIR'} for name in ('baseline','shifted','protected')}
        easy.save(build / 'summary.json', {'status': 'DEMO_EXPECTATIONS_MET', 'workflow_mode': 'CONTROLLED_FIXTURE_EXPERIMENT', 'variants': variants})
        easy.save(runner.logs / 'assessment.json', {'decision': 'REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS'})
        easy.save(runner.logs / 'verification.json', {'status': 'RECORDED_EXPECTATIONS_CONFIRMED', 'callback_entry_mapping_replayed': True})
        def command(name, argv, **kwargs):
            if name == 'fresh-three-layout-experiment':
                return 'Experiment: ' + str(build) + '\n', 0
            return '', 0
        with patch.object(runner, 'setup'), patch.object(runner, 'command', side_effect=command), \
             patch.object(runner, 'detector_control', return_value={'verdict':'ORIGINAL_OBSERVATIONS_DIFFER'}), patch.object(easy, 'show_latest'):
            self.assertEqual(0, runner.demo())
        report = easy.read(self.root / '.bcl/latest-demo.json')
        self.assertEqual('COMPLETED', report['status'])
        self.assertEqual('REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS', report['safety_decision'])
        self.assertEqual('SATISFIED_FOR_TESTED_PAIR', report['verdict'])
        self.assertEqual('CANDIDATE_PRESERVATION_VIOLATION', report['variants']['shifted']['verdict'])
        self.assertNotIn('historical_verified', report)

    def test_detector_control_checks_real_comparison_contract(self):
        runner = easy.Runner()
        app = Path(__file__).resolve().parent.parent
        (self.root / 'examples/benchmarks').mkdir(parents=True)
        (self.root / 'scripts').mkdir()
        for name in ('secret_line.c', 'fixture.h'):
            shutil.copyfile(app / 'examples/benchmarks' / name, self.root / 'examples/benchmarks' / name)
        shutil.copyfile(app / 'scripts/validate-baseline.py', self.root / 'scripts/validate-baseline.py')
        config = self.root / 'bcl.toml'
        config.write_text(config.read_text() + '\n[experiment]\nrepetitions = 3\ntimeout = 120\neager_binding = true\n')
        report = {'schema':'whole-comparison-1','exit_code':5,'verdict':'ORIGINAL_OBSERVATIONS_DIFFER',
            'functional_checks':True,'repeat_stability':True,'comparisons':[],'runs':[], 'manifest_sha256':'x',
            'observer':{'line_size_bytes':64,'addresses':'raw-virtual','repetitions':'retained',
                        'order':'event order; ascending touched lines within each event','excluded':[]}}
        def command(name, argv, **kwargs):
            if name == 'build-secret-dependent-control':
                Path(argv[-1]).write_bytes(b'unit-test binary; not a native scientific result')
            elif name == 'collect-secret-dependent-control':
                original = argv[argv.index('--original')+1]
                rebuilt = argv[argv.index('--rebuilt')+1]
                self.assertEqual(original, rebuilt)
                (Path(argv[argv.index('--output-parent')+1]) / 'whole-collection-unit').mkdir()
            elif name.startswith('check-secret-dependent'):
                easy.save(argv[-1], report)
                return '', 5
            return '', 0
        with patch.object(runner, 'command', side_effect=command):
            result = runner.detector_control('java', self.root / 'build')
        self.assertEqual('ORIGINAL_OBSERVATIONS_DIFFER', result['verdict'])
        self.assertTrue(result['python_java_agreement'])

    def test_existing_manual_validation_is_discovered_without_execution(self):
        validation = self.root / 'experiments/baseline-validation-existing'
        easy.save(validation / 'summary.json', {'status': 'COMPARISON_COMPLETE',
            'build_evidence': str(self.root / 'build'), 'observation_verdict': 'SATISFIED_FOR_TESTED_PAIR'})
        easy.save(validation / 'assessment.json', {'schema': 'java-eligibility-1',
            'decision': 'REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS', 'safe_to_transform': False})
        with contextlib.redirect_stdout(io.StringIO()) as output:
            easy.show_latest()
        self.assertIn('existing validation found automatically', output.getvalue())
        self.assertIn('NOT APPROVED', output.getvalue())
        self.assertTrue((self.root / '.bcl/latest-report.txt').is_file())


if __name__ == '__main__':
    unittest.main()
