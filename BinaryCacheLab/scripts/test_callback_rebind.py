import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import callback_rebind as c


class CallbackRebindTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.tmp.name)
        self.blob=bytearray(512);self.blob[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',self.blob,16,2)
        struct.pack_into('<Q',self.blob,40,64);struct.pack_into('<HHH',self.blob,58,64,3,2)
        names=b'\0.init_array\0.shstrtab\0';self.blob[300:300+len(names)]=names
        struct.pack_into('<IIQQQQIIQQ',self.blob,128,1,14,3,0x403df8,400,8,0,0,8,8)
        struct.pack_into('<IIQQQQIIQQ',self.blob,192,13,3,0,0,300,len(names),0,0,1,0)
        struct.pack_into('<Q',self.blob,400,0x401120)
        self.original=self.root/'original';self.original.write_bytes(self.blob)
        self.assembly=self.root/'lifted.asm'
        self.text='frame_dummy:\nret\nsection .init_array align=8 ; @403df8\narray_begin:\ndb 020h\ndb 011h\ndb `@`, 0\ndb 00h\ndb 00h\ndb 00h\ndb 00h\narray_end:\n\nsection .data align=8 ; @404000\ndq 7\n'
        self.assembly.write_text(self.text)
        self.plan={'original_binary_sha256':hashlib.sha256(self.blob).hexdigest(),'required_roots':[{'original_entry':0x401120,'symbol':'frame_dummy'}],
            'array_slots':[{'source':'DT_INIT_ARRAY','index':0,'slot':0x403df8,'original_target':0x401120,'symbol':'frame_dummy'}]}
    def tearDown(self):self.tmp.cleanup()
    def run_repair(self):return c.restore(self.assembly,self.original,self.plan)
    def reject(self,pattern):
        before=self.assembly.read_bytes()
        with self.assertRaisesRegex(RuntimeError,pattern):self.run_repair()
        self.assertEqual(before,self.assembly.read_bytes(),'Failed repair changed assembly')
    def test_literal_pointer_rebound_and_labels_preserved(self):
        rows=self.run_repair();text=self.assembly.read_text()
        self.assertEqual('frame_dummy',rows[0]['symbol']);self.assertIn('array_begin:\ndq frame_dummy',text)
        self.assertIn('array_end:',text);self.assertIn('section .data align=8 ; @404000\ndq 7',text)
    def test_symbolic_pointer_is_validated_and_retained(self):
        self.assembly.write_text(self.text.replace('db 020h\ndb 011h\ndb `@`, 0\ndb 00h\ndb 00h\ndb 00h\ndb 00h','dq frame_dummy'))
        self.run_repair();self.assertIn('dq frame_dummy',self.assembly.read_text())
    def test_source_hash_changed(self):
        self.plan['original_binary_sha256']='wrong';self.reject('source hash')
    def test_wrong_emitted_byte(self):
        self.assembly.write_text(self.text.replace('db 020h','db 021h'));self.reject('emitted callback bytes')
    def test_missing_emitted_section(self):
        self.assembly.write_text('frame_dummy:\nret\n');self.reject('missing emitted callback section')
    def test_missing_code_definition(self):
        self.assembly.write_text(self.text.replace('frame_dummy:\n','global frame_dummy\n'));self.reject('definition')
    def test_wrong_original_slot(self):
        self.plan['array_slots'][0]['slot']+=8;self.reject('slot/symbol')
    def test_wrong_target(self):
        self.plan['array_slots'][0]['original_target']+=1;self.reject('slot/symbol')
    def test_malformed_directive(self):
        self.assembly.write_text(self.text.replace('db 020h','times 1 db 020h'));self.reject('unsupported callback section directive')
    def test_mid_pointer_label(self):
        self.assembly.write_text(self.text.replace('db 011h','inside:\ndb 011h'));self.reject('label inside')
    def test_inventory_does_not_cover_whole_array(self):
        struct.pack_into('<Q',self.blob,128+32,16);self.original.write_bytes(self.blob)
        self.plan['original_binary_sha256']=hashlib.sha256(self.blob).hexdigest();self.reject('cover section exactly')
    def test_duplicate_section_rejected(self):
        self.assembly.write_text(self.text+self.text[self.text.index('section .init_array'):]);self.reject('duplicate callback section')
    def test_dynamic_not_rewritten(self):
        struct.pack_into('<H',self.blob,16,3);self.original.write_bytes(self.blob)
        self.assertEqual([],self.run_repair());self.assertEqual(self.text,self.assembly.read_text())
    def test_no_array_slots_no_rewrite(self):
        self.plan['array_slots']=[];self.assertEqual([],self.run_repair());self.assertEqual(self.text,self.assembly.read_text())
    def test_literals_reject_ambiguous_or_overflow(self):
        for body in ('256','unknown','-1','`bad\\n`'):
            with self.assertRaises(RuntimeError):
                values=c.operands(body)
                for value in values:c.literal(value,1,{})

if __name__=='__main__':unittest.main()
