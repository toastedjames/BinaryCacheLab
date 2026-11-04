"""Automatic rewriting safety boundaries and generated artifact contracts."""
import copy
from pathlib import Path
import runpy
import struct
import tempfile
import unittest
import automatic
import project

class AutomaticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root=Path(self.temp.name)
        self.policy=runpy.run_path(str(Path(__file__).with_name('make-automatic-example.py')))['make'](self.root)
        self.raw=(self.root/'original/lookup.elf').read_bytes()
        self.original=project.read(self.root/'original/lookup.json')
        self.regions=automatic.validate(self.policy)
        self.analysis={'instruction_coverage':[{'ip':0x400206,'bytes':self.raw[0x206:0x210].hex()}]}
    def tearDown(self):self.temp.cleanup()
    def rewrite(self,address=0x401040):return automatic.candidate(self.raw,self.analysis,self.regions,address)
    def test_actual_instruction_and_literal_relocation(self):
        rewritten,delta,patches=self.rewrite()
        self.assertEqual(64,delta)
        self.assertEqual(bytes(8),rewritten[0x1000:0x1008])
        self.assertEqual(self.raw[0x1000:0x1008],rewritten[0x1040:0x1048])
        self.assertEqual(0x401040,struct.unpack_from('<Q',rewritten,0x208)[0])
        self.assertEqual(0x400206,patches[0]['ip'])
        self.assertNotEqual(self.raw,rewritten)
    def test_clang_32bit_immediate_rebinding(self):
        raw=bytearray(self.raw)
        raw[0x206:0x210]=b'\xb8'+struct.pack('<I',0x401000)+b'\x90'*5
        self.raw=bytes(raw)
        self.analysis={'instruction_coverage':[{'ip':0x400206,'bytes':raw[0x206:0x20b].hex()}]}
        rewritten,delta,patches=self.rewrite()
        self.assertEqual(0x401040,struct.unpack_from('<I',rewritten,0x207)[0])
        self.assertEqual(4,patches[0]['width'])
        self.assertEqual(raw[0x20b:0x210],rewritten[0x20b:0x210])
    def test_32bit_pointer_rebinding_never_truncates(self):
        raw=bytearray(self.raw)+bytearray(4096)
        struct.pack_into('<H',raw,56,3)
        struct.pack_into('<IIQQQQQQ',raw,176,1,6,0x2000,0x100000000,0,0x1000,0x1000,0x1000)
        raw[0x206:0x210]=b'\xb8'+struct.pack('<I',0x401000)+b'\x90'*5
        self.raw=bytes(raw)
        self.analysis={'instruction_coverage':[{'ip':0x400206,'bytes':raw[0x206:0x20b].hex()}]}
        with self.assertRaisesRegex(ValueError,'immediate width'):self.rewrite(0x100000000)
    def test_rex_32bit_immediate_rebinding(self):
        raw=bytearray(self.raw)
        raw[0x206:0x210]=b'\x41\xb8'+struct.pack('<I',0x401000)+b'\x90'*4
        self.raw=bytes(raw)
        self.analysis={'instruction_coverage':[{'ip':0x400206,'bytes':raw[0x206:0x20c].hex()}]}
        rewritten,_,patches=self.rewrite()
        self.assertEqual(0x401040,struct.unpack_from('<I',rewritten,0x208)[0])
        self.assertEqual(4,patches[0]['width'])
    def test_alternate_entry_inside_32bit_immediate_is_rejected(self):
        raw=bytearray(self.raw);raw[0x206:0x210]=b'\xb8'+struct.pack('<I',0x401000)+b'\x90'*5
        self.raw=bytes(raw)
        self.analysis={'instruction_coverage':[{'ip':0x400206,'bytes':raw[0x206:0x20b].hex()},{'ip':0x400208,'bytes':'90'}]}
        with self.assertRaisesRegex(ValueError,'alternate'):self.rewrite()
    def test_section_metadata_matches_final_bytes(self):
        raw,_,_=self.rewrite()
        self.assertEqual((0x401040,0x1040),struct.unpack_from('<QQ',raw,0xcd0))
    def test_bad_line_placement_rejected(self):
        with self.assertRaisesRegex(ValueError,'residue'):self.rewrite(0x401004)
    def test_identity_is_not_a_rewrite(self):
        with self.assertRaisesRegex(ValueError,'must move'):self.rewrite(0x401000)
    def test_nonzero_destination_rejected(self):
        raw=bytearray(self.raw);raw[0x1040]=3;self.raw=bytes(raw)
        with self.assertRaisesRegex(ValueError,'zero'):self.rewrite()
    def test_outside_load_destination_rejected(self):
        with self.assertRaisesRegex(ValueError,'mapping'):self.rewrite(0x402000)
    def test_executable_data_destination_rejected(self):
        with self.assertRaisesRegex(ValueError,'nonexecutable'):self.rewrite(0x400240)
    def test_no_supported_executed_address_load_rejected(self):
        self.analysis['instruction_coverage']=[]
        with self.assertRaisesRegex(ValueError,'MOVABS'):self.rewrite()
    def test_overlapping_alternate_decode_rejected(self):
        self.analysis['instruction_coverage'].append({'ip':0x400208,'bytes':'90'})
        with self.assertRaisesRegex(ValueError,'alternate'):self.rewrite()
    def test_partial_data_section_rejected(self):
        self.regions[0]['size']=4
        with self.assertRaisesRegex(ValueError,'section'):self.rewrite()
    def test_symbol_inventory_rejected(self):
        raw=bytearray(self.raw);struct.pack_into('<I',raw,0xc44,2);self.raw=bytes(raw)
        with self.assertRaisesRegex(ValueError,'symbol'):self.rewrite()
    def test_unsupported_runtime_rejected(self):
        raw=bytearray(self.raw);struct.pack_into('<I',raw,120,2);self.raw=bytes(raw)
        with self.assertRaisesRegex(ValueError,'loader'):self.rewrite()
    def test_overlapping_regions_rejected(self):
        self.policy['regions'].append({'name':'overlap','address':0x401004,'size':4,'alignment':4})
        with self.assertRaisesRegex(ValueError,'Overlapping'):automatic.validate(self.policy)
    def test_attempt_limit_and_unknown_fields_rejected(self):
        self.policy['destinations']=list(range(33))
        with self.assertRaises(ValueError):automatic.validate(self.policy)
        self.policy['unexpected']=True
        with self.assertRaises(ValueError):automatic.validate(self.policy)
    def test_contracts_automatically_bind_generated_binary(self):
        rebuilt,pair,approval=automatic.contracts(self.original,self.analysis,self.regions,64,self.policy)
        self.assertEqual('candidate.elf',rebuilt['binary'])
        self.assertEqual(0x401040,rebuilt['regions'][0]['address'])
        self.assertNotIn('alignment',rebuilt['regions'][0])
        self.assertEqual(0x401040,pair['memory_maps'][0]['rebuilt'])
        self.assertEqual('../original.json',pair['original'])
        self.assertEqual('correspondence.json',approval['correspondence'])
        self.assertEqual([0],approval['secret_inputs'])
    def test_initial_pointer_and_memory_input_contracts_rejected(self):
        self.original['machine']['initial_registers']={'rcx':0x401000}
        with self.assertRaisesRegex(ValueError,'zero initial'):automatic.contracts(self.original,self.analysis,self.regions,64,self.policy)
        self.original['machine']['initial_registers']={}
        self.original['inputs']=[{'address':0x401000,'width':4,'values':[1,2]}]
        with self.assertRaisesRegex(ValueError,'scalar register'):automatic.contracts(self.original,self.analysis,self.regions,64,self.policy)
    def test_original_and_output_not_overwritten(self):
        before=(self.root/'original/lookup.elf').read_bytes()
        with self.assertRaisesRegex(ValueError,'new nonsymlink'):automatic.run(self.root/'rewrite.json',self.root)
        self.assertEqual(before,(self.root/'original/lookup.elf').read_bytes())
    def test_reference_rebinding_rejects_stale_reference(self):
        access={'ip':10,'width':4,'write':False,'address':0x401000}
        pair={'cases':[{'original_case':0,'rebuilt_case':0}],
              'original_analysis':{'executions':[{'references':[access]}]},
              'rebuilt_analysis':{'executions':[{'references':[dict(access)]}]}}
        with self.assertRaisesRegex(ValueError,'rebound'):automatic.verify_rebinding({'correspondence':pair},self.regions,64)
        pair['rebuilt_analysis']['executions'][0]['references'][0]['address']+=64
        automatic.verify_rebinding({'correspondence':pair},self.regions,64)
    def test_crossing_outside_region_is_rejected(self):
        a={'ip':10,'width':8,'write':False,'address':0x401004}
        b=dict(a,address=0x401044)
        pair={'cases':[{'original_case':0,'rebuilt_case':0}], 'original_analysis':{'executions':[{'references':[a]}]},'rebuilt_analysis':{'executions':[{'references':[b]}]}}
        with self.assertRaisesRegex(ValueError,'outside-object'):automatic.verify_rebinding({'correspondence':pair},self.regions,64)

if __name__=='__main__':unittest.main()
