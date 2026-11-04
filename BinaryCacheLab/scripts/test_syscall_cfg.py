"""Encoded ELF control-flow fixtures; these tests do not claim native execution."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import syscall_cfg as cfg
import syscall_lift


class Fixture:
    def __init__(self):self.rows=[];self.labels={};self.ip=0x401000
    def mark(self,name):self.labels[name]=self.ip
    def emit(self,raw,text):
        raw=bytes.fromhex(raw);self.rows.append([self.ip,raw,text]);self.ip+=len(raw)
    def branch(self,opcode,text,target):
        raw=bytes.fromhex(opcode)+bytes(4);self.rows.append([self.ip,raw,text+' @'+target]);self.ip+=len(raw)
    def save(self,path):
        code=bytearray();lines=[]
        for ip,raw,text in self.rows:
            if ' @' in text:
                mnemonic,name=text.split(' @');target=self.labels[name]
                raw=raw[:-4]+struct.pack('<i',target-ip-len(raw));text=mnemonic+' '+format(target,'x')+' <'+name+'>'
            code.extend(raw);lines.append(format(ip,'x')+': '+raw.hex(' ')+'   '+text)
        blob=bytearray(0x3000);blob[:7]=b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQ',blob,16,2,62,1,0x401000,64,0);struct.pack_into('<HHH',blob,52,64,56,2)
        struct.pack_into('<IIQQQQQQ',blob,64,1,5,0x1000,0x401000,0,len(code),len(code),0x1000)
        struct.pack_into('<IIQQQQQQ',blob,120,1,6,0x2000,0x402000,0,32,32,0x1000)
        blob[0x1000:0x1000+len(code)]=code;path.write_bytes(blob)
        return '\n'.join(lines)


class SyscallCfgTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).parent);self.root=Path(self.tmp.name);self.path=self.root/'program'
    def tearDown(self):self.tmp.cleanup()
    def loop_program(self):
        f=Fixture();f.emit('b902000000','mov ecx,0x2');f.branch('e8','call','helper')
        f.emit('b83c000000','mov eax,0x3c');f.emit('31ff','xor edi,edi');f.emit('0f05','syscall')
        f.mark('helper');f.mark('loop');f.emit('4885c9','test rcx,rcx');f.branch('0f84','je','write')
        f.emit('48f7f1','div rcx');f.emit('48ffc9','dec rcx');f.branch('e9','jmp','loop')
        f.mark('write');f.emit('4889ca','mov rdx,rcx');f.emit('488d342513204000','lea rsi,ds:0x402013');f.emit('c6060a','mov BYTE PTR [rsi],0xa')
        f.emit('bf01000000','mov edi,0x1');f.emit('b801000000','mov eax,0x1');f.emit('0f05','syscall');f.emit('c3','ret');return f
    def test_calls_loops_divide_and_dynamic_buffer(self):
        text=self.loop_program().save(self.path);doc=cfg.contract(self.path,text)
        self.assertEqual('bcl-static-syscalls-2',doc['schema'])
        self.assertEqual(['exit','write'],[row['kind'] for row in doc['sites']])
        self.assertEqual([60,1],[row['number'] for row in doc['sites']])
        self.assertTrue(any(i['mnemonic']=='call' for i in doc['instructions']))
        self.assertTrue(any(i['mnemonic']=='div' for i in doc['instructions']))
        self.assertTrue(all(row['arguments']=='runtime register values' for row in doc['sites']))
    def test_prepare_uses_cfg_for_nonstraight_program(self):
        text=self.loop_program().save(self.path);doc=syscall_lift.prepare(self.path,self.root/'patch',disassembly=text)
        self.assertEqual('bcl-static-syscalls-2',doc['schema']);self.assertEqual(4,len(doc['source_files']))
        source=(self.root/'patch/src/WithAbstractPredicates/ControlFlow.hs').read_text()
        self.assertIn(str([doc['sites'][0]['ip']])+' = Terminal',source)
    def test_different_syscall_numbers_at_join_rejected(self):
        f=Fixture();f.branch('0f84','je','exit_number');f.emit('b801000000','mov eax,1');f.branch('e9','jmp','site')
        f.mark('exit_number');f.emit('b83c000000','mov eax,60');f.mark('site');f.emit('0f05','syscall')
        with self.assertRaisesRegex(RuntimeError,'(?:unknown or ambiguous|unmodeled) syscall'):cfg.contract(self.path,f.save(self.path))
    def test_unknown_implicit_register_effect_is_not_ignored(self):
        f=Fixture();f.emit('b801000000','mov eax,1');f.emit('0fa2','cpuid');f.emit('0f05','syscall')
        with self.assertRaisesRegex(RuntimeError,'(?:unknown or ambiguous|unmodeled) syscall'):cfg.contract(self.path,f.save(self.path))
    def test_callee_constant_return_is_propagated(self):
        f=Fixture();f.branch('e8','call','helper');f.emit('0f05','syscall');f.mark('helper');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        self.assertEqual(60,cfg.contract(self.path,f.save(self.path))['sites'][0]['number'])
    def test_partial_register_write_does_not_zero_high_bits(self):
        f=Fixture();f.emit('b800010000','mov eax,0x100');f.emit('b001','mov al,1');f.emit('0f05','syscall')
        with self.assertRaisesRegex(RuntimeError,'257'):cfg.contract(self.path,f.save(self.path))
    def test_exit_group_supported(self):
        f=Fixture();f.emit('b8e7000000','mov eax,0xe7');f.emit('0f05','syscall')
        self.assertEqual(231,cfg.contract(self.path,f.save(self.path))['sites'][0]['number'])
    def test_memory_writing_read_syscall_remains_rejected(self):
        f=Fixture();f.emit('31c0','xor eax,eax');f.emit('0f05','syscall')
        with self.assertRaisesRegex(RuntimeError,'(?:unknown or ambiguous|unmodeled) syscall'):cfg.contract(self.path,f.save(self.path))
    def test_instruction_bytes_checked_against_elf(self):
        text=self.loop_program().save(self.path);blob=bytearray(self.path.read_bytes());blob[0x1000]^=1;self.path.write_bytes(blob)
        with self.assertRaisesRegex(RuntimeError,'bytes differ'):cfg.contract(self.path,text)
    def test_indirect_control_flow_not_guessed(self):
        f=Fixture();f.emit('ffe0','jmp rax')
        with self.assertRaisesRegex(RuntimeError,'indirect'):cfg.contract(self.path,f.save(self.path))
    def test_writable_code_rejected(self):
        text=self.loop_program().save(self.path);blob=bytearray(self.path.read_bytes());struct.pack_into('<I',blob,68,7);self.path.write_bytes(blob)
        with self.assertRaisesRegex(RuntimeError,'writable executable'):cfg.contract(self.path,text)
    def test_unresolved_instruction_boundary_rejected(self):
        f=Fixture();f.branch('e9','jmp','missing');f.labels['missing']=0x409999
        with self.assertRaisesRegex(RuntimeError,'boundary'):cfg.contract(self.path,f.save(self.path))
    def test_nested_function_return_summaries(self):
        f=Fixture();f.branch('e8','call','outer');f.emit('0f05','syscall')
        f.mark('outer');f.branch('e8','call','inner');f.emit('c3','ret')
        f.mark('inner');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        doc=cfg.contract(self.path,f.save(self.path));self.assertEqual(3,len(doc['function_entries']))
        self.assertEqual(60,doc['sites'][0]['number'])
    def test_recursive_function_reaches_fixed_point(self):
        f=Fixture();f.branch('e8','call','recursive');f.emit('0f05','syscall')
        f.mark('recursive');f.emit('85ff','test edi,edi');f.branch('0f84','je','base')
        f.branch('e8','call','recursive');f.emit('c3','ret')
        f.mark('base');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        doc=cfg.contract(self.path,f.save(self.path));self.assertEqual(60,doc['sites'][0]['number']);self.assertLess(doc['dataflow_steps'],100)
    def test_register_indirect_call_is_resolved(self):
        f=Fixture();f.emit('48b8'+('00'*8),'movabs rax,0');f.emit('ffd0','call rax');f.emit('0f05','syscall')
        f.mark('helper');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        target=f.labels['helper'];f.rows[0][1]=b'\x48\xb8'+struct.pack('<Q',target);f.rows[0][2]='movabs rax,'+hex(target)
        doc=cfg.contract(self.path,f.save(self.path));self.assertIn(target,doc['function_entries'])
    def pointer_program(self,indexed=False,writable=False):
        f=Fixture()
        if indexed:f.emit('83e701','and edi,1')
        f.emit('ff14fd00204000' if indexed else 'ff142500204000','call QWORD PTR [rdi*8+0x402000]' if indexed else 'call QWORD PTR ds:0x402000')
        f.emit('0f05','syscall');f.mark('one');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        f.mark('two');f.emit('b83c000000','mov eax,60');f.emit('c3','ret')
        text=f.save(self.path);blob=bytearray(self.path.read_bytes());struct.pack_into('<I',blob,124,6 if writable else 4)
        struct.pack_into('<QQ',blob,0x2000,f.labels['one'],f.labels['two']);self.path.write_bytes(blob)
        return f,text
    def test_readonly_function_pointer(self):
        f,text=self.pointer_program();doc=cfg.contract(self.path,text)
        self.assertIn(f.labels['one'],doc['function_entries']);self.assertEqual(60,doc['sites'][0]['number'])
    def test_masked_function_pointer_table_covers_all_targets(self):
        f,text=self.pointer_program(indexed=True);doc=cfg.contract(self.path,text)
        self.assertTrue({f.labels['one'],f.labels['two']}<=set(doc['function_entries']))
        self.assertEqual(60,doc['sites'][0]['number'])
    def test_writable_pointer_is_not_treated_as_immutable(self):
        f,text=self.pointer_program(writable=True)
        with self.assertRaisesRegex(RuntimeError,'indirect'):cfg.contract(self.path,text)
    def test_unknown_callee_effects_remain_unknown(self):
        f=Fixture();f.branch('e8','call','helper');f.emit('0f05','syscall')
        f.mark('helper');f.emit('b83c000000','mov eax,60');f.emit('0fa2','cpuid');f.emit('c3','ret')
        with self.assertRaisesRegex(RuntimeError,'unknown'):cfg.contract(self.path,f.save(self.path))
    def test_relative_table_signed_extension(self):
        state={2:frozenset([0x402000])}
        result=cfg.transfer('movsxd','rax,DWORD PTR [rdx]',state,read=lambda a,w:0xfffffff0)
        result=cfg.transfer('add','rax,rdx',result)
        self.assertEqual(frozenset([0x401ff0]),result[0])
    def test_varied_branch_conditions_are_program_independent(self):
        for opcode,mnemonic in [('0f84','je'),('0f85','jne'),('0f8f','jg'),('0f8c','jl'),('0f87','ja'),('0f82','jb')]:
            with self.subTest(mnemonic=mnemonic):
                f=Fixture();f.branch(opcode,mnemonic,'second');f.emit('b83c000000','mov eax,60');f.branch('e9','jmp','exit')
                f.mark('second');f.emit('b83c000000','mov eax,60');f.mark('exit');f.emit('0f05','syscall')
                self.assertEqual(60,cfg.contract(self.path,f.save(self.path))['sites'][0]['number'])
    def with_bss_sections(self):
        text=self.loop_program().save(self.path);blob=bytearray(self.path.read_bytes())
        names=b'\0.bss\0.shstrtab\0';blob[0x2700:0x2700+len(names)]=names
        struct.pack_into('<Q',blob,40,0x2800);struct.pack_into('<HHH',blob,58,64,3,2)
        struct.pack_into('<IIQQQQIIQQ',blob,0x2840,1,8,3,0x402000,0,20,0,0,1,0)
        struct.pack_into('<IIQQQQIIQQ',blob,0x2880,6,3,0,0,0x2700,len(names),0,0,1,0)
        struct.pack_into('<Q',blob,152,0)
        self.path.write_bytes(blob);return text
    def test_bss_bounds_seed_real_writable_region(self):
        text=self.with_bss_sections();doc=syscall_lift.prepare(self.path,self.root/'patch',disassembly=text)
        self.assertEqual([{'name':'.bss','address':0x402000,'size':20,'zero_initialized':True}],doc['global_memory_regions'])
        self.assertEqual(5,len(doc['source_files']))
        source=(self.root/'patch/src/WithAbstractPredicates/ContextSensitiveAnalysis.hs').read_text()
        self.assertIn('IM.fromList [(4202496,False),(4202516,False)]',source)
        self.assertNotIn('  let empty_L0 = L0 IM.empty IM.empty IM.empty ""',source)
    def test_bss_range_outside_writable_load_rejected(self):
        self.with_bss_sections();blob=bytearray(self.path.read_bytes());struct.pack_into('<Q',blob,0x2840+32,100);self.path.write_bytes(blob)
        with self.assertRaisesRegex(RuntimeError,'writable load mapping'):syscall_lift.writable_regions(self.path)
    def test_readonly_section_does_not_get_writable_seed(self):
        self.with_bss_sections();blob=bytearray(self.path.read_bytes());struct.pack_into('<Q',blob,0x2840+8,2);self.path.write_bytes(blob)
        self.assertEqual([],syscall_lift.writable_regions(self.path))
    def test_unmapped_writable_section_rejected(self):
        self.with_bss_sections();blob=bytearray(self.path.read_bytes());struct.pack_into('<Q',blob,0x2840+16,0x909000);self.path.write_bytes(blob)
        with self.assertRaisesRegex(RuntimeError,'writable load mapping'):syscall_lift.writable_regions(self.path)
    def test_invalid_writable_section_names_rejected(self):
        self.with_bss_sections();blob=bytearray(self.path.read_bytes());struct.pack_into('<I',blob,0x2840,999);self.path.write_bytes(blob)
        with self.assertRaisesRegex(RuntimeError,'section name'):syscall_lift.writable_regions(self.path)

    def test_complete_recorded_disassembly_used_instead_of_preview(self):
        root=self.root
        class Runner:
            logs=root
            def command(self,name,argv):
                (self.logs/('001-'+name+'.log')).write_text('complete instruction inventory')
                return 'truncated preview',0
        self.assertEqual('complete instruction inventory',cfg.disassemble(self.path,Runner(),'inventory'))

    def test_syscall_rax_reloaded_after_unknown_instruction(self):
        f=Fixture();f.emit('0fa2','cpuid');f.emit('b83c000000','mov eax,60');f.emit('0f05','syscall')
        self.assertEqual(60,cfg.contract(self.path,f.save(self.path))['sites'][0]['number'])

if __name__=='__main__':unittest.main()
