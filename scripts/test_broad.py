"""Broader qualification wiring and measurable fixture dimensions; mocked native paths are not native qualification."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import automatic
import broad_fixtures
import project
import qualify_broad

class BroadQualificationTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def test_larger_linear_program_and_explicit_domain(self):
        dimensions=broad_fixtures.make(self.root/'linear','linear')
        profile=project.read(self.root/'linear/original.json')
        self.assertGreater(dimensions['code_bytes'],3000)
        self.assertEqual(32,dimensions['inputs'])
        self.assertEqual(135168,profile['bounds']['max_memory_bytes'])
        self.assertEqual(16,len(profile['inputs'][0]['values']))
    def test_multiple_regions_keep_line_relationships(self):
        broad_fixtures.make(self.root/'multi','multi')
        policy=project.read(self.root/'multi/rewrite.json')
        self.assertEqual(8,len(policy['regions']))
        self.assertTrue(all(r['address']%64==0 and r['size']==64 for r in policy['regions']))
    def test_sectionless_is_explicit_and_not_mislabeled_stripped(self):
        broad_fixtures.make(self.root/'noheaders','loop',False)
        raw=(self.root/'noheaders/original.elf').read_bytes()
        self.assertEqual(0,struct.unpack_from('<Q',raw,40)[0])
        self.assertEqual(0,struct.unpack_from('<H',raw,60)[0])
        self.assertIn('not a tool-stripped artifact',Path(qualify_broad.__file__).read_text())
    def test_unknown_fixture_rejected(self):
        with self.assertRaises(ValueError):broad_fixtures.make(self.root/'invalid','invented')
    def test_missing_native_tools_is_a_blocker(self):
        with patch.object(qualify_broad.sys,'platform','linux'),patch.object(qualify_broad.shutil,'which',return_value=None):
            report=qualify_broad.native(self.root/'native')
        self.assertEqual('BLOCKED_NATIVE_ENVIRONMENT',report['status'])
        self.assertEqual({'gcc','clang','nm','strip'},set(report['missing_tools']))
    def native_mocks(self,failure=False):
        def command(name,argv,**kwargs):
            if '-o' in argv:Path(argv[argv.index('-o')+1]).write_bytes(b'encoded ELF placeholder for command-wiring test')
            if '-symbols' in name:return '400200 100 T kernel\n410000 40 D table\n412000 8000 D spare\n',0
            return 'tool version recorded',0
        def result(profile,evidence):
            if failure:raise ValueError('unsupported instruction in this test')
            return {'bounded_transformation_approved':Path(evidence).name!='unstripped-rejection'}
        return command,result
    def test_all_compiler_settings_and_strip_commands_are_wired(self):
        command,result=self.native_mocks()
        with patch.object(qualify_broad.sys,'platform','linux'),patch.object(qualify_broad.shutil,'which',side_effect=lambda name:name),patch.object(qualify_broad.easy,'Runner') as runner,patch.object(automatic,'run',side_effect=result),patch.object(automatic,'verify'):
            runner.return_value.command.side_effect=command
            report=qualify_broad.native(self.root/'native')
            calls=runner.return_value.command.call_args_list
        self.assertEqual('NATIVE_COMPILER_EXPECTATIONS_MET',report['status'])
        self.assertEqual(10,len(report['cases']))
        self.assertEqual({'-O0','-O1','-O2','-O3','-Os'},{r['optimization'] for r in report['cases']})
        self.assertEqual(10,sum('--strip-all' in call.args[1] for call in calls))
        self.assertTrue(all(r['reference_replay'] and r['unstripped_symbol_table_rejection'] for r in report['cases']))
    def test_native_failures_do_not_skip_the_rest_of_the_matrix(self):
        command,result=self.native_mocks(True)
        with patch.object(qualify_broad.sys,'platform','linux'),patch.object(qualify_broad.shutil,'which',side_effect=lambda name:name),patch.object(qualify_broad.easy,'Runner') as runner,patch.object(automatic,'run',side_effect=result):
            runner.return_value.command.side_effect=command
            report=qualify_broad.native(self.root/'native')
        self.assertEqual('NATIVE_COMPILER_EXPECTATIONS_FAILED',report['status'])
        self.assertEqual(10,len(report['cases']))
        self.assertTrue(all(r['status']=='FAILED' for r in report['cases']))
    def test_native_failure_is_not_a_portable_only_success(self):
        with patch.object(qualify_broad,'portable',return_value={'status':'passed'}),patch.object(qualify_broad,'isolated_install',return_value={'status':'passed'}),patch.object(qualify_broad,'native',return_value={'status':'NATIVE_COMPILER_EXPECTATIONS_FAILED'}):
            result=qualify_broad.qualify(self.root/'failed',True)
        self.assertEqual('BROADER_QUALIFICATION_FAILED',result['status'])
    def test_required_native_gate_cannot_succeed_when_blocked(self):
        output=self.root/'blocked'
        with patch.object(qualify_broad,'portable',return_value={'status':'passed'}),patch.object(qualify_broad,'isolated_install',return_value={'status':'passed'}),patch.object(qualify_broad,'native',return_value={'status':'BLOCKED_NATIVE_ENVIRONMENT'}):
            self.assertEqual(7,qualify_broad.main(['--native','--output',str(output)],True))
        self.assertEqual('PORTABLE_QUALIFIED_NATIVE_UNVERIFIED',project.read(output/'summary.json')['status'])
    def test_clean_install_checks_network_isolation_and_status(self):
        root=Path(__file__).resolve().parent.parent
        script=(root/'scripts/qualify-clean-linux.sh').read_text()
        self.assertIn('--no-cache',script)
        self.assertIn('--network none',script)
        self.assertIn('CLEAN-INSTALL-PASSED.json',script)
        self.assertIn('BROADER_QUALIFICATION_EXPECTATIONS_MET',(root/'qualification/run-clean.sh').read_text())

if __name__=='__main__':unittest.main()
