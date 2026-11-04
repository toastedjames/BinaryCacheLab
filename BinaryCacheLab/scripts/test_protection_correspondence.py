"""Certified occurrences must reject any native/model discrepancy."""
import copy
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
import protection_correspondence as proof
import workflow_compare
from test_workflow import event

class CertifiedOccurrenceTests(unittest.TestCase):
    def setUp(self):
        self.a=[event(i,variant='original') for i in range(3)]
        self.b=[event(i,variant='transformed',address=8192) for i in range(3)]
        for row in self.a+self.b:row['instruction_module']['link_address']=0x401000
        self.certificate={'left':[proof.event_signature(row) for row in self.a], 'right':[proof.event_signature(row) for row in self.b]}
    def match(self,a=None,b=None):
        return list(workflow_compare.matched_events(iter(self.a if a is None else a),iter(self.b if b is None else b),16,
                    {'_certified_sequence':self.certificate}))
    def test_repeated_identical_sites_match_only_with_complete_certificate(self):
        rows=self.match();self.assertEqual(3,len(rows));self.assertTrue(all(row[2] is None for row in rows))
        old=list(workflow_compare.matched_events(iter(self.a),iter(self.b),16,{'original':'a','transformed':'b'}))
        self.assertTrue(any(row[2]=='INCONCLUSIVE' for row in old))
    def test_changed_instruction_cannot_use_ordinal_as_evidence(self):
        changed=copy.deepcopy(self.b);changed[1]['instruction_module']['link_address']+=1
        self.assertEqual('INCONCLUSIVE',self.match(b=changed)[1][2])
    def test_changed_offset_width_or_operation_is_rejected(self):
        for field in ('offset','width','operation'):
            changed=copy.deepcopy(self.b)
            if field=='offset':changed[0]['region']['offset']=4
            elif field=='width':changed[0]['width']=8
            else:changed[0]['operation']='WRITE'
            self.assertEqual('INCONCLUSIVE',self.match(b=changed)[0][2])
    def test_missing_extra_or_empty_capture_is_rejected(self):
        for changed in (self.b[:-1],self.b+[copy.deepcopy(self.b[0])],[]):
            self.assertTrue(any(row[2]=='INCONCLUSIVE' for row in self.match(b=changed)))
    def test_library_instruction_is_not_a_proven_main_site(self):
        changed=copy.deepcopy(self.b);changed[0]['instruction_module']['is_main']=False
        self.assertEqual('INCONCLUSIVE',self.match(b=changed)[0][2])
    def test_cross_region_model_access_is_rejected(self):
        execution={'references':[{'ip':1,'address':4094,'width':4,'write':False}]}
        with self.assertRaisesRegex(ValueError,'crosses'):proof.selected(execution,[{'name':'table','address':4096,'size':8}])
    def test_certified_binding_requires_every_case_and_actual_binary_hash(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root=Path(temp);(root/'validation/protection').mkdir(parents=True)
            signature={'ip':0x401000,'address':4096,'width':4,'write':False}
            analysis={'exhaustive':True,'binary_sha256':'a','contract':{'entries':[0x401000]},
                      'executions':[{'entry':0x401000,'inputs':[{'value':0}],'references':[signature]}]}
            w=SimpleNamespace(root=root,doc={'comparison':{'scope':'declared_regions'},'execution':{'cases':[{'id':'zero'}],'operations':['READ','WRITE']}},
                              report={'artifacts':{v:{'sha256':'a'} for v in ('original','baseline','transformed')}},
                              regions={v:[{'name':'table','address':4096,'size':8}] for v in ('original','baseline','transformed')})
            settings={'entries':[{}],'inputs':[{}],'native_cases':[{'id':'zero','entry':0,'values':[0]}]}
            pair={'original_analysis':analysis,'rebuilt_analysis':analysis}
            proof.bind(w,settings,pair,pair)
            self.assertIn('zero',w.certified_reference_sequences['original'])
            w.report['artifacts']['baseline']['sha256']='changed'
            with self.assertRaisesRegex(ValueError,'actual-binary'):proof.bind(w,settings,pair,pair)

if __name__=='__main__':unittest.main()
