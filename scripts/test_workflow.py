"""Workflow event, comparison, verdict and report tests. Synthetic records here are tests, never native qualification."""
from pathlib import Path
import contextlib
import copy
import csv
import io
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
import workflow
import workflow_events as events
import workflow_compare as compare

ROOT=Path(__file__).resolve().parent.parent

def event(seq,address=4096,offset=0,operation='READ',width=4,variant='baseline',region='group'):
    return {'schema_version':'bcl-memory-event-1','variant':variant,'event_id':variant+'/'+str(seq),'sequence':seq,'thread':0,'instruction_address':0x400000+seq*4,
            'instruction_module':{'is_main':True,'link_address':0x400000+seq*4},'effective_address':address,'width':width,'operation':operation,'cache_line_size':64,
            'virtual_cache_lines':events.lines(address,width,64),'cross_line':len(events.lines(address,width,64))>1,
            'region':None if region is None else {'name':region,'offset':offset,'runtime_start':address-offset,'size':128},'input_case':'s0','repetition':0,'trace_completeness':'complete',
            'trace_ref':{'path':'traces/'+variant+'.jsonl','line':seq+1}}

class WorkflowTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def runfile(self,name,rows):
        path=self.root/(name+'.jsonl');path.write_text(''.join(json.dumps(r)+'\n' for r in rows));return {'path':str(path),'start':0,'end':path.stat().st_size}
    def comparison(self,a,b,policy='region_relative',identity='region_relative'):
        left=self.runfile('a',a);right=self.runfile('b',b)
        writer=compare.Writer(self.root/'comparisons',policy,2,1)
        pair={'name':'baseline__transformed','case':'s0','repeat':0,'left':'baseline','right':'transformed'}
        result=writer.compare(pair,left,right,{'scope':'declared_regions','lookahead':16,'line_identity':identity},{'baseline':'a','transformed':'b'})
        writer.close();return result,writer
    def test_boundary_access_reports_both_line_bases(self):self.assertEqual([64,128],events.lines(127,2,64))
    def test_aligned_access_has_one_line(self):self.assertEqual([128],events.lines(128,64,64))
    def test_invalid_width_and_overflow_rejected(self):
        for address,width in [(0,0),(-1,1),(2**64-1,2)]:
            with self.assertRaises(ValueError):events.lines(address,width,64)
    def test_region_relative_allows_address_and_line_movement(self):
        result,writer=self.comparison([event(0)],[event(7,address=8192,variant='transformed')])
        self.assertEqual('PASS',result['status']);self.assertEqual(0,writer.violations_count)
        self.assertEqual(1,writer.counts['ADDRESS_CHANGED']);self.assertEqual(1,writer.counts['CACHE_LINE_CHANGED'])
    def test_strict_address_change_fails_without_compromise_claim(self):
        result,writer=self.comparison([event(0)],[event(9,address=8192,variant='transformed')],'strict_address')
        self.assertEqual('FAIL',result['status']);self.assertGreater(writer.violations_count,0)
        checks={'obs':workflow.check('FAIL','test')};self.assertEqual('FAIL',workflow.verdict(checks,{'compromise_demonstrated':False}))
    def test_type_and_width_changes_have_separate_findings(self):
        result,writer=self.comparison([event(0)],[event(1,operation='WRITE',width=8)],'strict_address')
        self.assertEqual('FAIL',result['status']);self.assertEqual(1,writer.counts['ACCESS_TYPE_CHANGED']);self.assertEqual(1,writer.counts['ACCESS_WIDTH_CHANGED'])
    def test_cross_line_change(self):
        result,writer=self.comparison([event(0,address=4159,width=1)],[event(1,address=4159,width=2)],'strict_address')
        self.assertEqual(1,writer.counts['CROSS_LINE_CHANGE'])
    def test_reordered_unique_region_offsets(self):
        a=[event(0,offset=0),event(1,address=4100,offset=4)];b=[event(9,address=4100,offset=4),event(10,offset=0)]
        result,writer=self.comparison(a,b)
        self.assertEqual('FAIL',result['status']);self.assertEqual(1,writer.counts['ORDER_CHANGED'])
    def test_new_and_missing_events(self):
        a=[event(0)];b=[event(7),event(8,address=4100,offset=4)]
        result,writer=self.comparison(a,b);self.assertEqual(1,writer.counts['NEW_ACCESS']);self.assertEqual('FAIL',result['status'])
    def test_ambiguous_repeated_accesses_are_not_sequence_matches(self):
        result,writer=self.comparison([event(0),event(1)],[event(8),event(9)])
        self.assertEqual('INCONCLUSIVE',result['status']);self.assertGreater(writer.counts['INCONCLUSIVE'],0)
    def test_unknown_regions_are_unmatched_not_invented(self):
        a=event(0,region=None);b=event(8,region=None)
        output=list(compare.matched_events(iter([a]),iter([b]),16,{'a':'x','b':'y'}))
        self.assertEqual('INCONCLUSIVE',output[0][2])
    def test_cache_sequence_uses_selected_identity(self):
        result,writer=self.comparison([event(0)],[event(4,address=8192)],'cache_line_sequence','region_relative')
        self.assertEqual('PASS',result['status']);self.assertTrue(result['line_comparison']['equal'])
    def test_raw_cache_sequence_detects_real_line_difference(self):
        result,writer=self.comparison([event(0)],[event(4,address=8192)],'cache_line_sequence','raw_virtual')
        self.assertEqual('FAIL',result['status']);self.assertEqual('TRACE-LINE-001',writer.samples[0]['rule_id'])
    def test_layout_only_keeps_trace_changes_as_diagnostics(self):
        result,writer=self.comparison([event(0)],[event(4,address=8192)],'layout_only')
        self.assertEqual('PASS',result['status']);self.assertEqual(0,writer.violations_count)
    def test_csv_jsonl_and_violation_array_are_consistent(self):
        result,writer=self.comparison([event(0)],[event(4,address=8192)],'strict_address')
        with (self.root/'comparisons/trace_diff.csv').open() as f:rows=list(csv.DictReader(f))
        findings=[json.loads(line) for line in (self.root/'comparisons/trace_diff.jsonl').read_text().splitlines()]
        violations=json.loads((self.root/'comparisons/violations.json').read_text())
        self.assertEqual(len(rows),len(findings));self.assertEqual(writer.violations_count,len(violations));self.assertEqual(1,len(writer.samples))
        self.assertEqual(findings[0]['classification'],rows[0]['classification'])
    def test_security_compromise_requires_explicit_positive_criterion(self):
        checks={'check':workflow.check('PASS','test')}
        self.assertEqual('PASS',workflow.verdict(checks,{'compromise_demonstrated':False}))
        self.assertEqual('COMPROMISED',workflow.verdict(checks,{'compromise_demonstrated':True}))
        self.assertEqual('INCONCLUSIVE',workflow.verdict({'r':workflow.check('NOT_ASSESSED','missing')},{'compromise_demonstrated':False}))
    def test_optional_missing_check_does_not_certify_it(self):
        self.assertEqual('PASS',workflow.verdict({'optional':workflow.check('NOT_ASSESSED','not provided',False)},{'compromise_demonstrated':False}))
    def test_config_requires_version_and_policy(self):
        path=self.root/'bad.toml';path.write_text('schema_version="1.0"\n')
        with self.assertRaises(workflow.Stop):workflow.config(path)
    def test_configuration_rejects_instruction_fetch_backend_claim(self):
        text=(ROOT/'examples/workflow/bcl.toml').read_text().replace('instruction_fetch = false','instruction_fetch = true')
        path=self.root/'unsupported.toml';path.write_text(text)
        with self.assertRaisesRegex(workflow.Stop,'Instruction-fetch'):workflow.config(path)
    def test_invalid_config_still_reports_unique_inconclusive_runs(self):
        config=self.root/'bad.toml';config.write_text('schema_version="1.0"\n')
        with patch.object(Path,'cwd',return_value=self.root),contextlib.redirect_stdout(io.StringIO()):
            a=workflow.Workflow(self.root/'missing.asm',config);report=a.run();b=workflow.Workflow(self.root/'missing.asm',config);other=b.run()
        self.assertNotEqual(report['run_id'],other['run_id']);self.assertEqual('INCONCLUSIVE',report['overall_verdict'])
        self.assertTrue((a.root/'summary.txt').exists());self.assertTrue((a.root/'report.json').exists());self.assertTrue((a.root/'manifest.json').exists())
        self.assertFalse((a.root/'traces/original.jsonl').exists());self.assertGreater(workflow.project.verify_manifest(a.root),0)
    def raw(self,count=1,status='complete'):
        raw=self.root/'raw/v/case/0';raw.mkdir(parents=True)
        meta=dict(events.REQUIRED);meta.update(status=status,events=str(count),mapping_snapshots='1',image_events='1')
        (raw/'trace.properties').write_text(''.join(k+'='+v+'\n' for k,v in meta.items()))
        (raw/'trace.csv').write_text(','.join(events.HEADER)+'\n0,0,0x401000,0x40303f,2,READ,PIN\n')
        (raw/'images.csv').write_text('image_sequence,action,next_memory_sequence,image_id,is_main,low,high_inclusive,load_offset,name_hex\n0,LOAD,0,1,1,0x400000,0x500000,0x0,2f746172676574\n')
        return raw
    def test_streaming_raw_conversion_module_region_and_crossing(self):
        raw=self.raw();output=self.root/'traces/original.jsonl'
        run=events.convert(raw,output,'original','s0',0,64,[{'name':'group','address':0x403000,'size':128}],['READ','WRITE'])
        record=next(events.events(run));self.assertTrue(record['cross_line']);self.assertEqual(2,len(record['virtual_cache_lines']))
        self.assertEqual(63,record['region']['offset']);self.assertEqual(0x401000,record['instruction_module']['link_address']);self.assertEqual(1,run['events'])
        self.assertEqual('traces/original.jsonl',record['trace_ref']['path'])
    def test_incomplete_raw_trace_never_gets_complete_jsonl(self):
        raw=self.raw(status='incomplete');output=self.root/'traces/original.jsonl'
        with self.assertRaises(ValueError):events.convert(raw,output,'original','s0',0,64,[],['READ'])
        self.assertFalse(output.exists())
    def test_event_count_mismatch_is_not_success(self):
        raw=self.raw(count=2);output=self.root/'traces/original.jsonl'
        with self.assertRaisesRegex(ValueError,'count'):events.convert(raw,output,'original','s0',0,64,[],['READ'])
        self.assertFalse(output.exists())


class TestOnlyNativeRunner(workflow.Runner):
    """A subprocess double: these tests explicitly do not attest native execution."""
    def command(self,name,argv,allowed=(0,),seconds=600,cwd=None,env=None,output=None,error=None,stdin=None):
        argv=list(map(str,argv));self.commands.append({'name':name,'argv':argv,'exit_code':0})
        if name.startswith('version-'):return 'test-only tool version',0
        if name.startswith('symbols-'):return '0000000000004078 D group\n0000000000004078 D L_.data_0x4078\n0000000000001149 T main\n',0
        if name.startswith('original-build-') or name.startswith('baseline-build-') or name.startswith('transformed-build-'):
            target=Path(argv[-1]);shutil.copy2(ROOT/'fixtures/group_lookup/original',target)
        if name in ('lift-0','transform-0'):Path(argv[-1]).write_text('section .data\ngroup: db 7,0,0,0,7,0,0,0\n')
        if name.endswith(('-native','-pin')):
            Path(output).write_bytes(b'7\n');Path(error).write_bytes(b'')
            if name.endswith('-pin'):
                raw=Path(argv[argv.index('-o')+1]).parent
                binary=Path(argv[argv.index('--')+1]);secret=int(argv[-1]);bias=0x555555554000
                if self.doc.get('_test_shift') and binary.name=='transformed':bias+=0x10000
                meta=dict(events.REQUIRED);meta.update(events='2' if self.doc.get('_test_bad_trace') else '1',mapping_snapshots='1',image_events='1')
                (raw/'trace.properties').write_text(''.join(k+'='+v+'\n' for k,v in meta.items()))
                (raw/'trace.csv').write_text(','.join(events.HEADER)+'\n0,0,'+hex(bias+0x1149)+','+hex(bias+0x4078+4*secret)+',4,READ,PIN\n')
                if self.doc.get('_test_bad_trace'):Path(error).write_bytes(b'PIN instrumentation failed\n')
                (raw/'maps.log').write_text('test-only snapshot\n')
                (raw/'images.csv').write_text('image_sequence,action,next_memory_sequence,image_id,is_main,low,high_inclusive,load_offset,name_hex\n0,LOAD,0,1,1,'+hex(bias)+','+hex(bias+0x10000)+','+hex(bias)+','+str(binary).encode().hex()+'\n')
        return '',0

class WorkflowPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.temp.name)
        shutil.copy2(ROOT/'examples/workflow/sample1.asm',self.root/'sample1.asm')
        self.doc=workflow.config(ROOT/'examples/workflow/bcl.toml');self.doc['output']=str(self.root/'runs')
        self.doc.pop('reference_analysis',None);self.doc['checks']['references']=False;self.doc['security']={'enabled':False}
        self.doc['lift']={'adapter':'commands','commands':[['test-only-lift','{original}','{lifted}']]}
        self.doc['transform']={'adapter':'commands','commands':[['test-only-transform','{lifted}','{transformed_asm}']]}
        self.doc['build']={'original':[['test-only-build','{input}','{original}']],'baseline':[['test-only-build','{lifted}','{baseline}']],'transformed':[['test-only-build','{transformed_asm}','{transformed}']]}
        pin=self.root/'pin';pin.write_text('test-only tool placeholder')
        self.doc['tools']['pin']=str(pin)
        for key,name in [('tracer','WholeProgramMemoryTracer.so'),('tracer_source','WholeProgramMemoryTracer.cpp')]:self.doc['tools'][key]=str(ROOT/'fixtures/pin'/name)
        self.path=self.root/'bcl.toml';self.path.write_text('# Effective configuration is injected by this explicit subprocess-double test\n')
    def tearDown(self):self.temp.cleanup()
    def run_workflow(self):
        instance=workflow.Workflow(self.root/'sample1.asm',self.path)
        def java(*args,allowed=(0,)):
            if args[0]!='audit-region':raise AssertionError('Unexpected Java command in subprocess-double test')
            binary=Path(args[1]);target=Path(args[args.index('--report')+1])
            workflow.write(target,{'schema':'java-elf-region-audit-1','binary_sha256':events.sha(binary),'region_sha256':'test-literal-commitment','relocations':[],'reference_coverage':'INCOMPLETE'})
            return '',0
        with patch.object(workflow,'config',return_value=self.doc),patch.object(workflow.platform,'system',return_value='Linux'),patch.object(workflow.platform,'machine',return_value='x86_64'),patch.object(workflow,'Runner',TestOnlyNativeRunner),patch.object(instance,'java',side_effect=java),contextlib.redirect_stdout(io.StringIO()):result=instance.run()
        return instance,result
    def test_complete_mocked_pipeline_writes_consistent_evidence_formats(self):
        instance,result=self.run_workflow()
        self.assertEqual('PASS',result['overall_verdict']);self.assertEqual('NOT_ASSESSED',result['security_assessment']['status'])
        self.assertEqual('NOT_ASSESSED',result['checks']['references']['status'])
        self.assertEqual(6,len(instance.runs));self.assertEqual(6,len(result['comparison']['pairs']))
        for variant in workflow.VARIANTS:
            self.assertEqual(2,result['event_statistics'][variant]['events'])
            with (instance.root/'traces'/(variant+'.jsonl')).open() as stream:self.assertEqual(2,sum(1 for _ in stream))
        saved=json.loads((instance.root/'report.json').read_text());self.assertEqual(result,saved)
        import verify_workflow_report
        self.assertEqual('REPORT_CONSISTENCY_VERIFIED',verify_workflow_report.verify(instance.root)['status'])
        text=(instance.root/'comparisons/trace_diff.txt').read_text()
        self.assertIn('C1 |',text);self.assertIn('Memory:',text)
        self.assertNotIn('Repetition:',text);self.assertNotIn('COMPARISON 20',text)
        self.assertIn('Policy violations: 0',text)
        self.assertNotIn('Correspondence:',text);self.assertNotIn('Explanation:',text)
        self.assertNotIn('Reported observation is permitted by the selected policy.',text)
        import export_differences
        exported=export_differences.export(instance.root)
        self.assertIn('Run verdict: PASS',exported.read_text())
        self.assertGreater(workflow.project.verify_manifest(instance.root),30)
        self.assertIn('OVERALL VERDICT: PASS',(instance.root/'summary.txt').read_text())
        manifest=json.loads((instance.root/'manifest.json').read_text());self.assertIn('summary.txt',manifest['files']);self.assertIn('comparisons/preserved_constraints.csv',manifest['files'])
        self.assertGreater(workflow.project.verify_manifest(instance.root),30)
        instrumented=[row['argv'] for row in instance.runner.commands if row['name'].endswith('-pin') and '--' in row['argv']]
        self.assertEqual(6,len(instrumented))
        self.assertTrue(all(Path(row[row.index('--')+1]).name in workflow.VARIANTS for row in instrumented))
    def test_required_missing_reference_evidence_is_inconclusive(self):
        self.doc['checks']['references']=True
        instance,result=self.run_workflow()
        self.assertEqual('INCONCLUSIVE',result['overall_verdict']);self.assertEqual('NOT_ASSESSED',result['checks']['references']['status'])
        self.assertEqual('INCONCLUSIVE',result['checks']['stage_6']['status'])
        self.assertFalse((instance.root/'validation/reference_checks.json').exists())
        self.assertEqual('NOT_RUN',result['checks']['stage_7']['status'])
        self.assertFalse(any(key[0]=='transformed' for key in instance.runs))
    def test_mocked_strict_violation_has_no_compromise_label(self):
        self.doc['policy']='strict_address';self.doc['_test_shift']=True
        instance,result=self.run_workflow()
        self.assertEqual('FAIL',result['overall_verdict']);self.assertGreater(result['comparison']['policy_violations'],0)
        self.assertFalse(result['security_assessment']['compromise_demonstrated'])
        self.assertEqual('FAIL',result['checks']['stage_8']['status'])
    def test_invalid_instrumentation_trace_cannot_pass(self):
        self.doc['_test_bad_trace']=True
        instance,result=self.run_workflow()
        self.assertEqual('INCONCLUSIVE',result['overall_verdict']);self.assertEqual('NOT_RUN',result['checks']['stage_4']['status'])
        self.assertEqual(1,result['event_statistics']['original']['incomplete_traces'])
        self.assertEqual('NOT_RUN',result['checks']['functional']['status'])
    def test_rebuilt_missing_main_is_rejected_before_execution(self):
        instance=workflow.Workflow(self.root/'sample1.asm',self.path);instance.root=self.root
        from unittest.mock import Mock
        instance.runner=Mock()
        instance.runner.command.side_effect=[('0000000000001149 T main\n',0),('0000000000001000 T _start\n',0)]
        with self.assertRaisesRegex(workflow.Stop,'omits original main'):instance.check_main_definition('baseline')

    def test_missing_region_mapping_is_not_an_incomplete_trace(self):
        instance=workflow.Workflow(self.root/'sample1.asm',self.path)
        def missing():raise workflow.Stop('UNSUPPORTED','Missing/ambiguous symbol')
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(workflow.Stop):instance.stage(5,missing)
        self.assertEqual('UNSUPPORTED',instance.report['checks']['stage_5']['status'])
        self.assertEqual({},instance.report['event_statistics'])

    def test_layout_failure_changes_stage_and_overall_verdict(self):
        self.doc['layout_constraints']=[{'id':'BAD-ALIGN','kind':'alignment','region':'group','bytes':64}]
        instance,result=self.run_workflow()
        self.assertEqual('FAIL',result['checks']['layout']['status']);self.assertEqual('FAIL',result['checks']['stage_6']['status']);self.assertEqual('FAIL',result['overall_verdict'])
    def test_no_layout_evidence_is_not_vacuously_passing(self):
        self.doc['layout_constraints']=[]
        instance,result=self.run_workflow();self.assertEqual('INCONCLUSIVE',result['overall_verdict'])

class WorkflowSecurityTests(unittest.TestCase):
    setUp=WorkflowTests.setUp
    tearDown=WorkflowTests.tearDown
    runfile=WorkflowTests.runfile
    def security_instance(self):
        instance=workflow.Workflow(self.root/'unused',self.root/'unused.toml')
        instance.doc={'policy':'security_evaluation','execution':{'cases':[{'id':'s0','argv':['0','fixed']},{'id':'s1','argv':['1','fixed']}],'repetitions':2},'comparison':{'scope':'declared_regions','line_identity':'raw_virtual'},
                      'security':{'enabled':True,'criterion':'stable_disjoint_virtual_line_sequences','variant':'transformed','cases':['s0','s1'],'secret_argv_index':0}}
        for rep in (0,1):
            for secret in (0,1):
                run=self.runfile(str(rep)+'-'+str(secret),[event(0,address=4096+64*secret,offset=4*secret)])
                for variant in workflow.VARIANTS:instance.runs[variant,'s'+str(secret),rep]=run
        return instance
    def test_explicit_stable_disjoint_criterion_can_demonstrate_compromise(self):
        instance=self.security_instance();instance.security(True)
        self.assertTrue(instance.report['security_assessment']['compromise_demonstrated'])
        self.assertEqual('COMPROMISED',workflow.verdict(instance.report['checks'],instance.report['security_assessment']))
    def test_unstable_observations_cannot_demonstrate_compromise(self):
        instance=self.security_instance();instance.security(False)
        self.assertFalse(instance.report['security_assessment']['compromise_demonstrated']);self.assertEqual('INCONCLUSIVE',instance.report['security_assessment']['status'])
    def test_line_instability_is_checked_even_if_policy_signature_was_stable(self):
        instance=self.security_instance()
        instance.runs['transformed','s0',1]=self.runfile('unstable',[event(0,address=12288)])
        instance.security(True)
        self.assertEqual('INCONCLUSIVE',instance.report['security_assessment']['status'])
        self.assertFalse(instance.report['security_assessment']['compromise_demonstrated'])

    def test_changed_public_arguments_reject_security_claim(self):
        instance=self.security_instance();instance.doc['execution']['cases'][1]['argv'][1]='changed-public'
        with self.assertRaisesRegex(workflow.Stop,'only at'):instance.security(True)

if __name__=='__main__':unittest.main()
