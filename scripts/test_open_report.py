from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock
import open_report


class OpenReportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.path=Path(self.temp.name)/'trace_diff.txt';self.path.write_text('Exact generated report')
    def tearDown(self):self.temp.cleanup()
    def test_wsl_opens_generated_file_in_notepad_without_a_shell(self):
        found={'notepad.exe':'/mnt/c/Windows/notepad.exe','wslpath':'/usr/bin/wslpath'}
        with patch.object(open_report.shutil,'which',side_effect=found.get),patch.object(open_report.subprocess,'run',return_value=Mock(stdout='C:\\report.txt\n')),patch.object(open_report.subprocess,'Popen') as launch:
            result=open_report.open_report(self.path)
        self.assertEqual('OPEN_REQUESTED',result['status'])
        self.assertEqual(['/mnt/c/Windows/notepad.exe','C:\\report.txt'],launch.call_args.args[0])
        self.assertNotIn('shell',launch.call_args.kwargs)
        self.assertEqual('Exact generated report',self.path.read_text())
    def test_wslview_is_available_fallback(self):
        with patch.object(open_report.shutil,'which',side_effect=lambda n:'/usr/bin/wslview' if n=='wslview' else None),patch.object(open_report.subprocess,'Popen') as launch:
            self.assertEqual('OPEN_REQUESTED',open_report.open_report(self.path)['status'])
        self.assertEqual('/usr/bin/wslview',launch.call_args.args[0][0])
    def test_missing_desktop_viewer_requests_internal_display(self):
        with patch.object(open_report.shutil,'which',return_value=None),patch.object(open_report.subprocess,'Popen') as launch:
            self.assertEqual('UNAVAILABLE',open_report.open_report(self.path)['status'])
        launch.assert_not_called()
    def test_non_text_file_is_rejected(self):
        path=self.path.with_suffix('.json');path.write_text('{}')
        with self.assertRaises(ValueError):open_report.open_report(path)


if __name__=='__main__':unittest.main()
