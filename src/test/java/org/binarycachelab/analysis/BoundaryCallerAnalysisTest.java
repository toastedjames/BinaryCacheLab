package org.binarycachelab.analysis;

import java.nio.file.*;
import java.util.*;

public final class BoundaryCallerAnalysisTest {
    private static int checks;
    private record Fixture(byte[] raw,String text){}
    public static void main(String[] args)throws Exception{
        Path file=Files.createTempFile("bcl-callers-",".elf");Fixture f=fixture(0);Files.write(file,f.raw);
        Map<String,Object> result=BoundaryCallerAnalysis.analyze(file,f.text,0x400e00,8);Map<?,?> path=path(result),cont=continuation(path);
        check(Boolean.TRUE.equals(cont.get("checked")),"Exact byte store/pop/ret continuation not checked");
        check(Boolean.FALSE.equals(cont.get("live_boundary_registers_consumed")),"Continuation uses live registers");
        check(((Map<?,?>)cont.get("boundary_values_live_at_return")).keySet().equals(Set.of("rax","rdi")),"Register values incorrectly considered dead");
        Map<?,?> store=(Map<?,?>)((List<?>)cont.get("constant_byte_stores")).get(0);
        check(store.get("target").equals(0x400e08L)&&store.get("value").equals(1),"Actual outside-object store omitted");
        check(((List<?>)cont.get("stack_effects")).size()==2,"Implicit stack accesses omitted");
        check(((List<?>)path.get("matching_callback_roots")).size()==1,"Byte-checked init callback tail edge missing");
        check(((List<?>)path.get("enumerated_direct_incoming_edges")).size()==2,"Direct call/tail jump inventory wrong");
        check(Boolean.FALSE.equals(result.get("caller_contract_proved"))&&Boolean.FALSE.equals(result.get("automatic_rewrite_allowed")),"Local caller check authorized rewrite");
        for(int mode=1;mode<=4;mode++){f=fixture(mode);Files.write(file,f.raw);result=BoundaryCallerAnalysis.analyze(file,f.text,0x400e00,8);
            check(Boolean.FALSE.equals(continuation(path(result)).get("checked")),"Unsafe/unknown continuation mode "+mode+" accepted");}
        f=fixture(5);Files.write(file,f.raw);result=BoundaryCallerAnalysis.analyze(file,f.text,0x400e00,8);
        check(((List<?>)path(result).get("matching_callback_roots")).isEmpty(),"Unrelated callback entry assigned to helper");
        f=fixture(6);Files.write(file,f.raw);result=BoundaryCallerAnalysis.analyze(file,f.text,0x400e00,8);
        check(!((List<?>)path(result).get("enumerated_alternate_entries")).isEmpty(),"Alternate direct entry missing");
        f=fixture(0);Files.write(file,f.raw);String renamed=f.text.replace("caller","misleading_label");
        check(Boolean.TRUE.equals(continuation(path(BoundaryCallerAnalysis.analyze(file,renamed,0x400e00,8))).get("checked")),"Byte analysis depends on labels");
        f.raw[0xa05]=0x48;Files.write(file,f.raw);boolean rejected=false;
        try{BoundaryCallerAnalysis.analyze(file,f.text,0x400e00,8);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"Forged disassembly not rejected");
        System.out.println("All "+checks+" boundary caller checks passed.");
    }
    private static Map<?,?> path(Map<String,Object> result){return (Map<?,?>)((List<?>)result.get("paths")).get(0);}
    private static Map<?,?> continuation(Map<?,?> path){return (Map<?,?>)((Map<?,?>)((List<?>)path.get("enumerated_direct_incoming_edges")).get(0)).get("continuation");}
    private static Fixture fixture(int mode){
        byte[] raw=ElfCallbackInventoryTest.fixture();var b=ElfCallbackInventoryTest.buffer(raw);b.putLong(0x410,mode==5?0x400610:0x400c00).putLong(0x428,0x400a00);
        TreeMap<Integer,String> rows=new TreeMap<>();
        emit(raw,rows,0x700,rip("8b0500000000",2,0x400700,0x400e00),"mov eax,DWORD PTR [rip+0x6fa]");
        emit(raw,rows,0x800,rip("488d3d00000000",3,0x400800,0x400e08),"lea rdi,[rip+0x601]");
        emit(raw,rows,0x807,rip("488d0500000000",3,0x400807,0x400e08),"lea rax,[rip+0x5fa]");
        emit(raw,rows,0x80e,hex("4839f8"),"cmp rax,rdi");emit(raw,rows,0x811,hex("7401"),"je 400814");
        emit(raw,rows,0x813,hex("cc"),"int3");emit(raw,rows,0x814,hex("c3"),"ret");
        if(mode==6)emit(raw,rows,0x900,rip("e900000000",1,0x400900,0x400807),"jmp 400807");
        emit(raw,rows,0xa00,rip("e800000000",1,0x400a00,0x400800),"call caller");
        if(mode==1)emit(raw,rows,0xa05,hex("4889c7"),"mov rdi,rax");
        else if(mode==2)emit(raw,rows,0xa05,hex("ffd0"),"call rax");
        else emit(raw,rows,0xa05,rip("c6050000000001",2,0x400a05,mode==3?0x400e00:0x400e08),"mov BYTE PTR [rip+0x3fc],0x1");
        emit(raw,rows,0xa0c,hex("5d"),"pop rbp");if(mode!=4)emit(raw,rows,0xa0d,hex("c3"),"ret");
        emit(raw,rows,0xc00,hex("f30f1efa"),"endbr64");emit(raw,rows,0xc04,rip("e900000000",1,0x400c04,0x400800),"jmp caller");
        return new Fixture(raw,String.join("\n",rows.values())+"\n");
    }
    private static byte[] hex(String s){return HexFormat.of().parseHex(s);}
    private static byte[] rip(String hex,int displacement,long ip,long target){byte[] bytes=hex(hex);ElfCallbackInventoryTest.buffer(bytes).putInt(displacement,(int)(target-ip-bytes.length));return bytes;}
    private static void emit(byte[] raw,Map<Integer,String> rows,int offset,byte[] code,String text){System.arraycopy(code,0,raw,offset,code.length);
        rows.put(offset,Long.toHexString(0x400000L+offset)+": "+HexFormat.ofDelimiter(" ").formatHex(code)+"  "+text);}
    private static void check(boolean value,String label){if(!value)throw new AssertionError(label);checks++;}
}
