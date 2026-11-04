from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock
import console


class TuiAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.config=Path(self.temp.name)/'bcl.toml'
        self.config.write_text('[tools]\ndocker_sudo=true\n[lift]\nadapter="foxdec"\n')
        self.args=['tui','--config',str(self.config)]
    def tearDown(self):self.temp.cleanup()
    def test_cached_credentials_never_prompt(self):
        with patch.object(console.sys,'platform','linux'),patch.object(console.subprocess,'run',return_value=Mock(returncode=0)) as run,patch.object(console.subprocess,'call',return_value=0),patch.object(console.sys.stdin,'isatty',return_value=False):
            self.assertEqual(0,console.tui_call(['java'],{},self.args))
        self.assertTrue(all(call.args[0]==['sudo','-n','-v'] for call in run.call_args_list))
    def test_uncached_noninteractive_launch_does_not_wait_for_password(self):
        with patch.object(console.sys,'platform','linux'),patch.object(console.subprocess,'run',return_value=Mock(returncode=1)) as run,patch.object(console.subprocess,'call',return_value=0),patch.object(console.sys.stdin,'isatty',return_value=False):
            self.assertEqual(0,console.tui_call(['java'],{},self.args))
        run.assert_called_once()
        self.assertEqual(['sudo','-n','-v'],run.call_args.args[0])
    def test_interactive_auth_happens_before_java_input_reader(self):
        order=[]
        def run(argv,**kwargs):order.append(argv);return Mock(returncode=0 if argv==['sudo','-v'] else 1)
        def start(*args,**kwargs):order.append(['java']);return 0
        with patch.object(console.sys,'platform','linux'),patch.object(console.subprocess,'run',side_effect=run),patch.object(console.subprocess,'call',side_effect=start),patch.object(console.sys.stdin,'isatty',return_value=True):
            console.tui_call(['java'],{},self.args)
        self.assertEqual([['sudo','-n','-v'],['sudo','-v'],['java']],order)
    def test_plain_tui_selects_the_integrated_workflow(self):
        with patch.object(console.sys,'argv',['console.py','tui']),patch.object(console,'tui_call',return_value=0) as launch:
            self.assertEqual(0,console.main())
        args=launch.call_args.args[2]
        self.assertIn('--input',args)
        self.assertTrue(args[args.index('--config')+1].endswith(str(Path('examples/workflow/bcl.toml'))))

    def test_direct_asm_workflow_uses_foreground_authentication(self):
        import workflow
        argv=['console.py','program.asm','--config',str(self.config)]
        def launch(command,env,args,action=None):
            self.assertEqual([],command);self.assertEqual(argv[1:],args);self.assertIsNotNone(action)
            return action()
        with patch.object(console.sys,'argv',argv),patch.object(console,'tui_call',side_effect=launch),patch.object(workflow,'main',return_value=7) as run:
            self.assertEqual(7,console.main())
            run.assert_called_once_with(argv[1:])
    def test_action_authenticates_before_running_workflow(self):
        order=[]
        def run(argv,**kwargs):order.append(argv);return Mock(returncode=0 if argv==['sudo','-v'] else 1)
        def action():order.append(['workflow']);return 0
        with patch.object(console.sys,'platform','linux'),patch.object(console.subprocess,'run',side_effect=run),patch.object(console.sys.stdin,'isatty',return_value=True):
            self.assertEqual(0,console.tui_call([],{},self.args,action=action))
        self.assertEqual([['sudo','-n','-v'],['sudo','-v'],['workflow']],order)

    def test_invalid_configuration_still_launches_diagnostic_ui(self):
        self.config.write_text('invalid config')
        with patch.object(console.subprocess,'run') as run,patch.object(console.subprocess,'call',return_value=0):
            self.assertEqual(0,console.tui_call(['java'],{},self.args))
        run.assert_not_called()


if __name__=='__main__':unittest.main()
