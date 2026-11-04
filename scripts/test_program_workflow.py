"""Program-mode tests. Subprocess doubles do not attest native execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import workflow as w
import workflow_events as trace
import program_workflow as p
import project
import syscall_lift
import verify_workflow_report

ROOT=Path(__file__).resolve().parent.parent

class ProgramTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.tmp.name)
        self.doc=w.config(ROOT/'examples/workflow/bcl.toml')
        self.asm=self.root/'hello.asm';shutil.copyfile(ROOT/'examples/programs/hello_start.asm',self.asm)
    def tearDown(self):self.tmp.cleanup()
    def test_entry_detection_and_standalone_link(self):
        desc=p.asm_description(self.asm);self.assertEqual('_start',desc['entry']);self.assertTrue(desc['static_start'])
        doc=p.program_config(self.doc,desc,True)
        self.assertEqual('ld',doc['build']['original'][1][0]);self.assertEqual([],doc['execution']['cases'][0]['argv'])
        self.assertEqual('all',doc['comparison']['scope']);self.assertFalse(doc['security']['enabled']);self.assertNotIn('reference_analysis',doc)
        self.assertEqual(1,doc['execution']['repetitions'])
    def test_main_selects_gcc(self):
        desc=p.asm_description(ROOT/'examples/programs/hello_main.asm');doc=p.program_config(self.doc,desc,True)
        self.assertEqual('main',desc['entry']);self.assertEqual(['gcc','-no-pie'],doc['build']['original'][1][:2])
    def test_start_with_external_calls_uses_no_crt(self):
        self.asm.write_text('global _start\nextern puts\n_start:\nret\n')
        desc=p.asm_description(self.asm);doc=p.program_config(self.doc,desc,True)
        self.assertFalse(desc['static_start']);self.assertIn('-nostartfiles',doc['build']['original'][1])
    def test_entry_missing_ambiguous_duplicate_rejected(self):
        for code in ('db "main:"\n; _start:\n','main:\n_start:\n','main:\nmain:\n'):
            self.asm.write_text(code)
            with self.assertRaises(w.Stop):p.asm_description(self.asm)
    def test_fixture_retains_original_workflow(self):
        instance=p.workflow_for(ROOT/'examples/workflow/sample1.asm',ROOT/'examples/workflow/bcl.toml')
        self.assertIs(type(instance),w.Workflow)
    def test_hello_auto_selects_program(self):
        instance=p.workflow_for(self.asm,ROOT/'examples/workflow/bcl.toml')
        self.assertIsInstance(instance,p.ProgramWorkflow);self.assertTrue(instance.automatic)
        doc=instance.load_config();self.assertEqual('NOT_CONFIGURED',instance.report['security_assessment']['status'])
        self.assertEqual('program',doc['mode']);self.assertEqual('none',doc['transform']['adapter'])
    def test_dashboard_preflight_uses_actual_input_profile(self):
        import dashboard_backend
        result=dashboard_backend.describe(ROOT/'examples/workflow/bcl.toml',self.asm)
        self.assertEqual('raw_virtual / all',result['observer'])
        self.assertEqual('program',result['configuration']['mode'])
        self.assertFalse(result['configuration']['security']['enabled'])
    def test_custom_declared_contract_is_not_auto_replaced(self):
        import json
        cfg=self.root/'custom.toml';cfg.write_bytes((ROOT/'examples/workflow/bcl.toml').read_bytes())
        self.assertIs(type(p.workflow_for(self.asm,cfg)),w.Workflow)
    def test_explicit_program_config_validates(self):
        doc=w.config(ROOT/'examples/programs/bcl.toml')
        self.assertEqual('program',doc['mode']);self.assertFalse(doc['security']['enabled'])
        self.assertIsInstance(p.workflow_for(self.asm,ROOT/'examples/programs/bcl.toml'),p.ProgramWorkflow)
    def test_explicit_contract_never_silently_disabled(self):
        doc=copy.deepcopy(self.doc);doc['mode']='program'
        with self.assertRaises(w.Stop):p.program_config(doc,p.asm_description(self.asm),False)
    def test_explicit_secret_cases_preserved(self):
        desc=p.asm_description(self.asm);doc=p.program_config(self.doc,desc,True)
        doc['security']={'enabled':True,'criterion':'stable_disjoint_virtual_line_sequences','variant':'baseline','cases':['s0','s1'],'secret_argv_index':0}
        doc['execution']['cases']=[{'id':'s0','argv':['0']},{'id':'s1','argv':['1']}]
        result=p.program_config(doc,desc,False)
        self.assertEqual(doc['security'],result['security']);self.assertEqual(doc['execution']['cases'],result['execution']['cases'])
        doc['security']['variant']='transformed'
        with self.assertRaises(w.Stop):p.program_config(doc,desc,False)
    def test_invalid_program_adapter_rejected(self):
        self.doc['build']['adapter']='guess'
        with self.assertRaises(w.Stop):p.program_config(self.doc,p.asm_description(self.asm),True)
    def test_main_pointer_rebinding_is_narrow(self):
        asm=self.root/'lifted.asm';asm.write_text('_start:\n  MOV RDI, 0x401130\n  CALL __libc_start_main wrt ..plt\n  HLT\nmain:\n  MOV RAX,0x401130\n  RET\n')
        self.assertTrue(p.rebind_main_startup(asm,'401130 T main\n'))
        self.assertIn('LEA RDI, [rel main]',asm.read_text());self.assertIn('MOV RAX,0x401130',asm.read_text())
        self.assertFalse(p.rebind_main_startup(asm,'401130 T main\n'))
    def test_unknown_startup_not_guessed(self):
        asm=self.root/'lifted.asm'
        for body in ('MOV RDI,0x1234\nCALL __libc_start_main\nHLT','MOV RDI,0x401130\nCALL different\nHLT','MOV RDI,0x401130\nCALL __libc_start_main'):
            original='_start:\n'+body+'\n';asm.write_text(original)
            with self.assertRaises(w.Stop):p.rebind_main_startup(asm,'401130 T main\n')
            self.assertEqual(original,asm.read_text())
    def empty_raw(self):
        raw=self.root/'raw';raw.mkdir();meta=dict(trace.REQUIRED);meta.update(events='0',image_events='1',mapping_snapshots='1',empty_trace_allowed='true')
        (raw/'trace.properties').write_text(''.join(k+'='+v+'\n' for k,v in meta.items()))
        (raw/'trace.csv').write_text(','.join(trace.HEADER)+'\n')
        (raw/'images.csv').write_text('image_sequence,action,next_memory_sequence,image_id,is_main,low,high_inclusive,load_offset,name_hex\n0,LOAD,0,1,1,0x400000,0x403000,0x0,'+str(self.asm).encode().hex()+'\n')
        return raw
    def test_zero_trace_requires_explicit_controller_and_collector_support(self):
        raw=self.empty_raw();dest=self.root/'traces/original.jsonl'
        with self.assertRaises(ValueError):trace.convert(raw,dest,'original','default',0,64,[],['READ'],expected_binary=self.asm)
        result=trace.convert(raw,dest,'original','default',0,64,[],['READ'],expected_binary=self.asm,allow_empty=True)
        self.assertEqual(0,result['events']);self.assertEqual([],list(trace.events(result)))
    def test_empty_trace_still_rejects_bad_metadata_or_image(self):
        raw=self.empty_raw();dest=self.root/'traces/original.jsonl';props=raw/'trace.properties';original=props.read_text()
        for changed in (original.replace('empty_trace_allowed=true','empty_trace_allowed=false'),original.replace('status=complete','status=incomplete'),original.replace('events=0\n','events=1\n'),original.replace('application_threads=1','application_threads=2')):
            props.write_text(changed)
            with self.assertRaises(ValueError):trace.convert(raw,dest,'original','default',0,64,[],['READ'],allow_empty=True)
        props.write_text(original)
        with self.assertRaises(ValueError):trace.convert(raw,dest,'original','default',0,64,[],['READ'],expected_binary=self.root/'wrong',allow_empty=True)

class ProgramPipelineTests(unittest.TestCase):
    setUp=ProgramTests.setUp
    tearDown=ProgramTests.tearDown
    def test_capture_pipeline_zero_events_and_no_false_security_claim(self):
        doc=p.program_config(self.doc,p.asm_description(self.asm),True);doc['output']=str(self.root/'runs')
        pin=self.root/'pin';pin.write_text('test-only pin');doc['tools']['pin']=str(pin)
        cfg=self.root/'bcl.toml';cfg.write_text('# Test double configuration\n')
        instance=p.ProgramWorkflow(self.asm,cfg,doc,False);instance.description=p.asm_description(self.asm)
        class FakeRunner(w.Runner):
            def command(runner,name,argv,**kwargs):
                argv=list(map(str,argv));runner.commands.append({'name':name,'argv':argv,'exit_code':0})
                if name.startswith('original-build-') and name.endswith('-1') or name=='baseline-link':
                    target=Path(argv[-1]);shutil.copyfile(ROOT/'fixtures/group_lookup/original',target)
                if name.startswith('symbols-entry-'):return '401000 T _start\n',0
                if name.endswith(('-native','-pin')) and 'output' in kwargs:
                    Path(kwargs['output']).write_bytes(b'Hello, World\n');Path(kwargs['error']).write_bytes(b'')
                    if name.endswith('-pin'):
                        raw=Path(argv[argv.index('-o')+1]).parent;binary=Path(argv[argv.index('--')+1]);meta=dict(trace.REQUIRED);meta.update(events='0',image_events='1',mapping_snapshots='1',empty_trace_allowed='true')
                        (raw/'trace.properties').write_text(''.join(k+'='+v+'\n' for k,v in meta.items()));(raw/'trace.csv').write_text(','.join(trace.HEADER)+'\n')
                        (raw/'images.csv').write_text('image_sequence,action,next_memory_sequence,image_id,is_main,low,high_inclusive,load_offset,name_hex\n0,LOAD,0,1,1,0x400000,0x500000,0x0,'+str(binary).encode().hex()+'\n')
                        (raw/'maps.log').write_text('test-only maps\n')
                return '',0
        def lift(root,*args,**kwargs):
            project.save(root/'callback-plan.json',{'array_slots':[]})
            (root/'syscall-extension').mkdir();project.save(root/'syscall-extension/contract.json',{'schema':'bcl-static-syscalls-1','sites':[]})
            asm=root/'test-lifted.asm';asm.write_text('global _start\nsection .text\n_start:\nret\n');return asm,['gcc','{object}','-o','{output}']
        with patch.object(instance,'load_config',return_value=doc),patch.object(instance,'preflight'),patch.object(instance,'java'),patch.object(w,'Runner',FakeRunner),patch.object(w.platform,'system',return_value='Linux'),patch.object(w.platform,'machine',return_value='x86_64'),patch.object(project,'lift_original',side_effect=lift),patch.object(syscall_lift,'contract',return_value={'schema':'bcl-static-syscalls-1','sites':[]}),contextlib.redirect_stdout(io.StringIO()):
            # load_config was patched, so set its normal explicit security status.
            instance.report['security_assessment']={'status':'NOT_CONFIGURED','compromise_demonstrated':False}
            result=instance.run()
        self.assertEqual('PASS',result['overall_verdict'],json.dumps(result));self.assertEqual('NOT_CONFIGURED',result['security_assessment']['status'])
        self.assertEqual({'original','baseline'},set(result['artifacts']));self.assertEqual(0,result['event_statistics']['original']['events'])
        self.assertEqual('NOT_REQUESTED',result['checks']['stage_6']['status']);self.assertFalse(result['checks']['stage_6']['required'])
        self.assertEqual('NOT_APPLICABLE',result['checks']['observation_population']['status'])
        text=(instance.root/'comparisons/trace_diff.txt').read_text();self.assertIn('Hello, World',text);self.assertIn('No user-space data accesses',text)
        self.assertEqual('REPORT_CONSISTENCY_VERIFIED',verify_workflow_report.verify(instance.root)['status'])

if __name__=='__main__':unittest.main()
