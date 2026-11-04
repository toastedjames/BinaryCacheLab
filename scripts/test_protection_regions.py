"""Exact emitted-data/ELF boundary binding; aliases are never guessed."""
from pathlib import Path
import runpy
import tempfile
import unittest
import protection_regions as regions


class ProtectionRegionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        runpy.run_path(str(Path(__file__).with_name('make-bounded-example.py')))['make'](self.root / 'fixture')
        self.binary = self.root / 'fixture/lookup.elf'
        self.assembly = self.root / 'lifted.asm'
        self.text = 'section .data align=64 ; @401000\nlegacy_start:\ndb 7,0,0,0\nlegacy_end:\ndb 7,0,0,0\nsection .bss\ntmp:\nresb 8\n'
        self.assembly.write_text(self.text)
        self.declarations = [{'address': 0x401000, 'size': 4, 'start_label': 'left', 'end_label': 'middle'},
                             {'address': 0x401004, 'size': 4, 'start_label': 'middle', 'end_label': 'end'}]
    def tearDown(self): self.temp.cleanup()
    def test_alternate_alias_and_missing_end_are_materialized(self):
        result = regions.restore(self.assembly, self.binary, self.declarations)
        self.assertEqual({'left': 0x401000, 'middle': 0x401004, 'end': 0x401008}, result['aliases'])
        text = self.assembly.read_text()
        self.assertIn('middle:', text); self.assertIn('legacy_end:', text); self.assertIn('end:', text)
        self.assertEqual(8, text.count('db 0x'))
    def test_boundary_inside_word_literal_is_split_without_changing_bytes(self):
        self.assembly.write_text('section .data align=64 ; @401000\ndq 0x0000000700000007\n')
        result = regions.restore(self.assembly, self.binary, self.declarations)
        self.assertTrue(result['section_bytes_preserved'])
        self.assertEqual(8, self.assembly.read_text().count('db 0x'))
    def test_original_section_byte_mismatch_refuses_binding(self):
        self.assembly.write_text(self.text.replace('db 7,0,0,0', 'db 9,0,0,0', 1))
        before = self.assembly.read_bytes()
        with self.assertRaisesRegex(ValueError, 'differs'): regions.restore(self.assembly, self.binary, self.declarations)
        self.assertEqual(before, self.assembly.read_bytes())
    def test_existing_alias_at_wrong_offset_is_not_reused(self):
        self.assembly.write_text(self.text.replace('legacy_start:', 'middle:'))
        with self.assertRaisesRegex(ValueError, 'wrong'): regions.restore(self.assembly, self.binary, self.declarations)
    def test_unknown_data_expression_is_rejected(self):
        self.assembly.write_text(self.text.replace('db 7,0,0,0', 'dq unknown_pointer', 1))
        with self.assertRaisesRegex(ValueError, 'Nonliteral'): regions.restore(self.assembly, self.binary, self.declarations)
    def test_original_section_address_annotation_is_checked(self):
        self.assembly.write_text(self.text.replace('@401000', '@501000'))
        with self.assertRaisesRegex(ValueError, 'original address'): regions.restore(self.assembly, self.binary, self.declarations)
    def test_duplicate_label_elsewhere_is_rejected(self):
        self.assembly.write_text('section .text\nleft:\nret\n' + self.text)
        with self.assertRaisesRegex(ValueError, 'out-of-section'): regions.restore(self.assembly, self.binary, self.declarations)


if __name__ == '__main__': unittest.main()
