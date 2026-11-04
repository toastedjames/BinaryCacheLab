"""Configuration adapter tests, plus POSIX subprocess cleanup where available."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import dashboard_backend as backend


class DashboardBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.config = self.root / 'bcl.toml'
        self.config.write_text((backend.workflow.ROOT / 'examples/workflow/bcl.toml').read_text())
        (self.root / 'sample1.asm').write_text('test configuration selection only')

    def tearDown(self): self.temp.cleanup()

    def test_description_uses_actual_configuration(self):
        doc = backend.describe(self.config)
        self.assertEqual(64, doc['line_bytes'])
        self.assertEqual(str(self.root / 'sample1.asm'), doc['input'])
        self.assertEqual(list(backend.workflow.STAGES), list(doc['stages']))
        self.assertEqual('UNVERIFIED', doc['coverage'])
        self.assertEqual(str(self.root / 'runs'), doc['output'])

    def test_default_assessments_are_required_and_enabled(self):
        doc=backend.workflow.config(self.config)
        self.assertTrue(doc['checks']['references'])
        self.assertTrue(doc['security']['enabled'])
        self.assertEqual('declared_lookup_kernel',doc['reference_analysis']['adapter'])

    def test_incomplete_entry_contract_is_rejected(self):
        self.config.write_text(self.config.read_text().replace('immutable_region = true','immutable_region = false'))
        with self.assertRaisesRegex(RuntimeError,'entry contract'):backend.describe(self.config)

    def test_ambiguous_input_not_guessed(self):
        (self.root / 'other.asm').write_text('other')
        self.assertEqual('', backend.describe(self.config)['input'])

    def test_valid_edit_keeps_backup_and_unrelated_settings(self):
        old = self.config.read_text()
        result = backend.edit(self.config, 'execution.repetitions=3')
        self.assertEqual('PASS', result['status'])
        self.assertEqual(old, Path(result['backup']).read_text())
        self.assertEqual(old.replace('repetitions = 1', 'repetitions = 3'), self.config.read_text())

    def test_invalid_edit_leaves_bytes_and_no_backup(self):
        old = self.config.read_bytes()
        with self.assertRaises((ValueError, RuntimeError)): backend.edit(self.config, 'comparison.line_bytes=3')
        self.assertEqual(old, self.config.read_bytes())
        self.assertFalse(list(self.root.glob('*.backup-*')))
        self.assertFalse(list(self.root.glob('.bcl-config-*')))

    def test_wrong_type_rejected(self):
        with self.assertRaises(ValueError): backend.edit(self.config, 'execution.repetitions="3"')

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError): backend.edit(self.config, 'execution.unknown=3')

    def test_array_editor_not_silently_rewritten(self):
        with self.assertRaises(ValueError): backend.edit(self.config, 'regions=[]')

    def test_run_dispatches_same_workflow_and_returns_its_exit(self):
        with patch.object(sys, 'argv', ['dashboard_backend.py', 'run', str(self.config), str(self.root/'sample1.asm')]), patch.object(backend.signal, 'signal'), patch.object(backend.workflow, 'main', return_value=7) as call:
            self.assertEqual(7, backend.main())
        call.assert_called_once_with([str(self.root/'sample1.asm'), '--config', str(self.config)])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Native POSIX process-group cleanup requires Linux')
    def test_sigterm_uses_existing_runner_cleanup(self):
        marker = self.root / 'cancelled'; pidfile = self.root / 'child.pid'
        code = '''
import pathlib, sys
import dashboard_backend as backend
def run(args):
    root=pathlib.Path(sys.argv[2]).parent
    runner=backend.workflow.Runner(root,{})
    try:
        runner.command('long-stage',[sys.executable,'-c',"import os,time,pathlib; pathlib.Path("+repr(str(root/'child.pid'))+").write_text(str(os.getpid())); time.sleep(60)"],seconds=120)
    except KeyboardInterrupt:
        (root/'cancelled').write_text('cleanup completed')
        return 7
backend.workflow.main=run
raise SystemExit(backend.main())
'''
        env = dict(os.environ, PYTHONPATH=str(Path(backend.__file__).parent), PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.Popen([sys.executable, '-B', '-c', code, 'run', str(self.config), 'sample.asm'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        import time
        try:
            end = time.monotonic()+10
            while not pidfile.exists() and process.poll() is None and time.monotonic()<end: time.sleep(.05)
            self.assertTrue(pidfile.exists(), 'Test child did not start')
            child = int(pidfile.read_text())
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=15)
            self.assertEqual(7, process.returncode, error.decode())
            self.assertTrue(marker.exists())
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)
        finally:
            if process.poll() is None: process.kill(); process.communicate()


if __name__ == '__main__': unittest.main()


