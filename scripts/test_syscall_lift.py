import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
import syscall_lift as s


class SyscallLiftTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root=Path(self.tmp.name)
        self.blob=bytearray(0x2000)
        self.blob[:7]=b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQ',self.blob,16,2,62,1,0x401000,64,0)
        struct.pack_into('<HHH',self.blob,52,64,56,2)
        struct.pack_into('<IIQQQQQQ',self.blob,64,1,5,0x1000,0x401000,0,64,64,0x1000)
        struct.pack_into('<IIQQQQQQ',self.blob,120,1,6,0x1800,0x402000,0,13,13,0x1000)
        self.code=bytes.fromhex('b801000000bf0100000048be0020400000000000ba0d0000000f05b83c00000031ff0f05')
        self.blob[0x1000:0x1000+len(self.code)]=self.code
        self.blob[0x1800:0x180d]=b'Hello, World\n'
        self.path=self.root/'original'
    def tearDown(self):self.tmp.cleanup()
    def analyze(self):
        self.path.write_bytes(self.blob)
        return s.contract(self.path)
    def test_exact_byte_contract(self):
        doc=self.analyze()
        self.assertEqual(['write','exit'],[row['kind'] for row in doc['sites']])
        self.assertEqual(0x401019,doc['sites'][0]['ip'])
        self.assertEqual(hashlib.sha256(b'Hello, World\n').hexdigest(),doc['sites'][0]['buffer_sha256'])
        self.assertEqual(self.code.hex(),''.join(row['bytes'] for row in doc['instructions']))
    def test_unknown_number_rejected(self):
        self.blob[0x1001]=2
        with self.assertRaisesRegex(RuntimeError,'syscall numbers'):self.analyze()
    def test_read_syscall_rejected(self):
        self.blob[0x1001]=0
        with self.assertRaisesRegex(RuntimeError,'syscall numbers'):self.analyze()
    def test_unknown_return_not_reused_as_number(self):
        self.blob[0x101b:0x1020]=bytes.fromhex('9090909090')
        with self.assertRaisesRegex(RuntimeError,'syscall numbers'):self.analyze()
    def test_nonzero_exit_rejected(self):
        self.blob[0x1020:0x1024]=bytes.fromhex('b7010f05')
        with self.assertRaises(RuntimeError):self.analyze()
    def test_unmapped_buffer_rejected(self):
        self.blob[0x100c:0x1014]=(0x999000).to_bytes(8,'little')
        with self.assertRaisesRegex(RuntimeError,'file backed'):self.analyze()
    def test_bad_fd_rejected(self):
        self.blob[0x1006]=3
        with self.assertRaisesRegex(RuntimeError,'stdout/stderr'):self.analyze()
    def test_instruction_and_buffer_bounds(self):
        self.blob[0x1015:0x1019]=(1048577).to_bytes(4,'little')
        with self.assertRaisesRegex(RuntimeError,'bounded length'):self.analyze()
    def test_branch_rejected(self):
        self.blob[0x1000:0x1002]=b'\xeb\x00'
        with self.assertRaisesRegex(RuntimeError,'opcode'):self.analyze()
    def test_dynamic_rejected(self):
        struct.pack_into('<I',self.blob,120,2)
        with self.assertRaisesRegex(RuntimeError,'dynamic loading'):self.analyze()
    def test_overlapping_code_mapping_rejected(self):
        struct.pack_into('<IIQQQQQQ',self.blob,120,1,5,0x1000,0x401000,0,64,64,0x1000)
        with self.assertRaisesRegex(RuntimeError,'uniquely'):self.analyze()
    def test_source_patch_and_license(self):
        self.analyze();patch=self.root/'patch';doc=s.prepare(self.path,patch)
        self.assertEqual(4,len(doc['source_files']));self.assertTrue((patch/'LICENSE').is_file())
        with zipfile.ZipFile(Path(s.__file__).with_name('foxdec-syscall-base.zip')) as base:
            for row in doc['source_files']:
                self.assertEqual(hashlib.sha256(base.read(row['path'])).hexdigest(),row['base_sha256'])
                self.assertEqual(hashlib.sha256((patch/row['path']).read_bytes()).hexdigest(),row['patched_sha256'])
        control=(patch/'src/WithAbstractPredicates/ControlFlow.hs').read_text()
        self.assertIn(str([doc['sites'][-1]['ip']])+' = Terminal',control)
        self.assertIn('Undeclared syscall site',control)
        semantics=(patch/'src/WithAbstractSymbolicValues/SymbolicExecution.hs').read_text()
        self.assertIn('[RAX,RCX,R11]',semantics)
        self.assertIn('sha256sum -c',s.container_setup())

if __name__=='__main__':unittest.main()
