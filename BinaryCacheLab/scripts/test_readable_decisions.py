"""Readable decisions and finite secret pairs. Synthetic traces are not native evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import workflow
import workflow_compare as compare
from workflow_text import DifferenceTextWriter,render_report
from test_workflow import event
import test_workflow as _support


class ReadableDecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def rows(self,repeat=0,case='s0'):
        writer=compare.Writer(self.root/('source'+str(repeat)+case),'region_relative')
        pair={'name':'original__transformed','case':case,'repeat':repeat,'left':'original','right':'transformed'}
        a=event(0,variant='original');b=event(1,address=8192,variant='transformed')
        for finding in compare.classify(a,b,None):writer.emit(pair,a,b,finding,False,'test','declared-region')
        writer.close()
        return [json.loads(line) for line in (writer.root/'trace_diff.jsonl').read_text().splitlines()]
    def test_one_access_has_all_findings(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'region_relative')
        rows=self.rows()
        for row in rows:writer.emit(row)
        writer.close('PASS')
        text=out.read_text();self.assertIn('FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED',text)
        self.assertEqual(1,text.count('C1 |'));self.assertNotIn('C2 |',text)
        self.assertNotIn('Repetition:',text);self.assertNotIn('COMPARISON',text)
    def test_repeat_display_rows_collapse_without_erasing_changed_states(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'region_relative')
        for repeat in (0,1):
            for row in self.rows(repeat):writer.emit(row)
        writer.close('PASS');text=out.read_text()
        self.assertIn('Unique access comparisons: 1',text)
        self.assertEqual(1,text.count('FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED'))
    def test_different_observations_are_not_hidden(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'region_relative');rows=self.rows()
        for row in rows:writer.emit(row)
        changed=copy.deepcopy(rows[0]);changed['transformed_address']=12288;changed['transformed_lines']=[12288];writer.emit(changed)
        writer.close('PASS');self.assertIn('Unique access comparisons: 2',out.read_text())
    def test_program_specific_image_and_memory_addresses_are_recorded(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'layout_only')
        writer.placement('original',{'name':'/actual/alpha','low':0x333335554000,'bias':0x333335554000})
        writer.placement('baseline',{'name':'/actual/beta','low':0x400000,'bias':0})
        observed=event(0,address=0x333335558078,variant='original');observed['instruction_address']=0x333335555183
        writer.event(observed);writer.close('PASS');text=out.read_text()
        self.assertIn('/actual/alpha',text);self.assertIn('Recorded image start: 0x333335554000',text)
        self.assertIn('Memory 0x333335558078',text);self.assertIn('IP 0x333335555183',text)
        self.assertIn('Recorded image start: 0x400000 | Load bias: 0x0',text)
        self.assertNotIn('0x555555554000',text)

    def test_no_fixed_twenty_access_limit(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'layout_only')
        for seq in range(75):writer.event(event(seq))
        writer.close('PASS');text=out.read_text()
        self.assertEqual(75,text.count(' | IP '));self.assertIn(hex(0x400000+74*4),text)
        self.assertFalse(list(self.root.glob('.readable-*.sqlite')))
    def test_secret_keys_and_decisions_are_together(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'region_relative')
        config={'execution':{'cases':[{'id':'s0','argv':['0']},{'id':'s1','argv':['1']}]},'security':{'secret_argv_index':0,'variant':'transformed'}}
        rows={v:{'assessed':True,'stable':None,'equal_across_secrets':v!='transformed'} for v in ('original','baseline','transformed')}
        report={'configuration':config,'security_assessment':{'secret_pairs':[{'cases':['s0','s1'],'by_variant':rows}]}}
        writer.close('COMPROMISED',report=report);text=out.read_text()
        self.assertIn("G1: s0 [key='0'] versus s1 [key='1']",text)
        self.assertIn('Original: SAME',text);self.assertIn('Transformed: DIFFERENT',text);self.assertIn('NEW SECRET DISTINCTION',text)
    def test_existing_leak_not_attributed_to_transform(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'region_relative')
        row={'assessed':True,'equal_across_secrets':False}
        writer.close('COMPROMISED',report={'security_assessment':{'cases':['s0','s1'],'by_variant':{'original':row,'transformed':row}}})
        self.assertIn('ALREADY PRESENT IN ORIGINAL',out.read_text())
    def test_no_configured_secrets_does_not_infer_security(self):
        out=self.root/'report.txt';writer=DifferenceTextWriter(out,'layout_only');writer.close('PASS',report={'security_assessment':{'status':'NOT_CONFIGURED'}})
        self.assertIn('Security: NOT_CONFIGURED',out.read_text());self.assertNotIn('NO SECRET DISTINCTION OBSERVED',out.read_text())


class FinitePairTests(unittest.TestCase):
    setUp=ReadableDecisionTests.setUp
    tearDown=ReadableDecisionTests.tearDown
    security_instance=_support.WorkflowSecurityTests.security_instance
    runfile=_support.WorkflowSecurityTests.runfile
    def test_single_run_does_not_claim_repeat_stability(self):
        instance=self.security_instance();instance.doc['execution']['repetitions']=1
        instance.doc['security']['criterion']='configured_virtual_line_sequences';instance.security(True)
        result=instance.report['security_assessment']
        self.assertTrue(result['compromise_demonstrated']);self.assertFalse(result['repeat_stability_tested'])
        self.assertIsNone(result['by_variant']['original']['stable']);self.assertTrue(result['by_variant']['original']['assessed'])
    def test_old_stable_criterion_needs_repeats(self):
        instance=self.security_instance();instance.doc['execution']['repetitions']=1;instance.security(True)
        self.assertEqual('INCONCLUSIVE',instance.report['security_assessment']['status']);self.assertFalse(instance.report['security_assessment']['compromise_demonstrated'])
    def test_three_secrets_compare_all_pairs(self):
        instance=self.security_instance();instance.doc['execution']['cases'].append({'id':'s2','argv':['2','fixed']});instance.doc['security']['cases'].append('s2')
        for rep in (0,1):
            for variant in workflow.VARIANTS:instance.runs[variant,'s2',rep]=self.runfile(variant+str(rep),[event(0,address=4224)])
        instance.security(True);pairs=instance.report['security_assessment']['secret_pairs']
        self.assertEqual([['s0','s1'],['s0','s2'],['s1','s2']],[p['cases'] for p in pairs])
    def test_default_runs_each_input_once(self):
        config=workflow.config(Path(workflow.__file__).parent.parent/'examples/workflow/bcl.toml')
        self.assertEqual(1,config['execution']['repetitions']);self.assertEqual('configured_virtual_line_sequences',config['security']['criterion'])

if __name__=='__main__':unittest.main()
