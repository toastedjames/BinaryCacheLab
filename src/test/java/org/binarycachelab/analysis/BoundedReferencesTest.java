package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;

/** Concrete encoded ELF tests: exhaustiveness, bounds, arithmetic branches, memory and runtime rejection. */
public final class BoundedReferencesTest {
    static final long CODE=0x400200,DATA=0x401000;
    static int checks,cases;
    static Path root;
    static final class Program {
        final byte[] raw=new byte[8192];final Map<String,Object> profile=new LinkedHashMap<>();long next=CODE;
        Program(){ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;b.putShort(16,(short)2).putShort(18,(short)62).putInt(20,1).putLong(24,CODE);
            b.putLong(32,64).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)2);
            b.putInt(64,1).putInt(68,5).putLong(72,0).putLong(80,0x400000).putLong(96,0x1000).putLong(104,0x1000);
            b.putInt(120,1).putInt(124,6).putLong(128,0x1000).putLong(136,DATA).putLong(152,0x1000).putLong(160,0x1000);
            b.putLong(0x1000,7).putLong(0x1008,9);
            profile.put("schema","bcl-bounded-references-1");profile.put("binary","input.elf");profile.put("entries",List.of(CODE));
            profile.put("regions",List.of(Map.of("name","table","address",DATA,"size",32)));
            profile.put("machine",new LinkedHashMap<>(Map.of("runtime","closed-static-x86-64","register_defaults","zero","initial_registers",Map.of(),"flags","zero","memory_initialization","elf-file-bss-zero-stack-zero","stack",Map.of("address",0x700000,"size",4096))));
            object(profile.get("machine")).put("instruction_set","bcl-x86-64-integer-1");
            profile.put("inputs",List.of());profile.put("bounds",new LinkedHashMap<>(Map.of("max_steps_per_execution",100,"max_total_steps",10000,"max_executions",256,"max_memory_bytes",12288,"max_reference_events",10000)));
        }
        Program code(String... chunks){for(String h:chunks){byte[] bytes=HexFormat.of().parseHex(h);System.arraycopy(bytes,0,raw,(int)(next-0x400000),bytes.length);next+=bytes.length;}return this;}
        Program at(long value){next=value;return this;}
        Program registers(Map<String,Object> values){object(profile.get("machine")).put("initial_registers",values);return this;}
        Program input(String register,long... values){profile.put("inputs",List.of(Map.of("register",register,"values",Arrays.stream(values).boxed().toList())));return this;}
        Program bound(String key,long value){object(profile.get("bounds")).put(key,value);return this;}
        Path save()throws Exception{Path directory=Files.createDirectory(root.resolve(String.format("case-%04d",++cases)));Files.write(directory.resolve("input.elf"),raw);Files.writeString(directory.resolve("profile.json"),Json.write(profile));return directory.resolve("profile.json");}
        Map<String,Object> run()throws Exception{Path path=save();Map<String,Object> report=BoundedReferences.analyze(path);Files.writeString(path.resolveSibling("report.json"),Json.write(report));return report;}
    }
    @SuppressWarnings("unchecked") static Map<String,Object> object(Object value){return (Map<String,Object>)value;}
    static void check(boolean result,String message){checks++;if(!result)throw new AssertionError(message);}
    static List<?> executions(Map<String,Object> report){return (List<?>)report.get("executions");}
    static long rax(Map<String,Object> report,int index){return ((Number)object(object(executions(report).get(index)).get("final_registers")).get("rax")).longValue();}
    static Map<String,Object> complete(Program p)throws Exception{Map<String,Object> r=p.run();check(Boolean.TRUE.equals(r.get("exhaustive")),"Not exhaustive: "+Json.write(r));check(Boolean.FALSE.equals(r.get("automatic_rewrite_allowed")),"Analysis authorized rewriting");return r;}
    static void reject(Program p,String kind)throws Exception{Map<String,Object> r=p.run();check(Boolean.FALSE.equals(r.get("exhaustive")),"Invalid execution accepted");
        boolean found=r.containsKey("rejection")&&kind.equals(object(r.get("rejection")).get("kind"));
        for(Object e:executions(r)){Map<String,Object> row=object(e);if(row.containsKey("failure"))found|=kind.equals(object(row.get("failure")).get("kind"));}check(found,"Missing "+kind+": "+r);}
    static String imm(long value,int bytes){ByteBuffer b=ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value);return HexFormat.of().formatHex(Arrays.copyOf(b.array(),bytes));}
    static boolean expectedCondition(int cc,boolean c,boolean p,boolean z,boolean s,boolean o){return switch(cc){case 0->o;case 1->!o;case 2->c;case 3->!c;case 4->z;case 5->!z;case 6->c||z;case 7->!c&&!z;case 8->s;case 9->!s;case 10->p;case 11->!p;case 12->s!=o;case 13->s==o;case 14->z||s!=o;case 15->!z&&s==o;default->throw new AssertionError();};}
    static void branches(String prefix,boolean carry,boolean parity,boolean zero,boolean sign,boolean overflow)throws Exception{
        for(int cc=0;cc<16;cc++){Program p=new Program().code(prefix,String.format("%02x07",0x70+cc),"b800000000","eb05","b801000000","c3");
            Map<String,Object> report=complete(p);check(rax(report,0)==(expectedCondition(cc,carry,parity,zero,sign,overflow)?1:0),"Wrong branch condition "+cc+" for "+prefix);}
    }
    static void compilerIncrementRegression()throws Exception {
        for(int width:new int[]{4,8})for(boolean decrement:new boolean[]{false,true})for(boolean carry:new boolean[]{false,true}){
            long sign=width==4?0x80000000L:Long.MIN_VALUE,mask=width==4?0xffffffffL:-1;
            for(long initial:new long[]{0,1,sign-1,sign,mask}){
                String setCarry=carry?"31c083f801":"31c0";
                String move=(width==8?"48b8":"b8")+imm(initial,width);
                String operation=(width==8?"48":"")+(decrement?"ffc8":"ffc0");
                var report=complete(new Program().code(setCarry,move,operation,"c3"));
                long expected=(initial+(decrement?-1:1))&mask;
                check(rax(report,0)==expected,"INC/DEC result/zero extension");
                var flags=object(object(executions(report).get(0)).get("final_flags"));
                check(Boolean.valueOf(carry).equals(flags.get("cf")),"INC/DEC changed carry");
                check(Boolean.valueOf((initial&mask)==(decrement?sign:(sign-1)&mask)).equals(flags.get("of")),"INC/DEC signed overflow");
                check(Boolean.valueOf(expected==0).equals(flags.get("zf")),"INC/DEC zero flag");
                check(Boolean.valueOf((expected&sign)!=0).equals(flags.get("sf")),"INC/DEC sign flag");
                check(Boolean.valueOf((Integer.bitCount((int)expected&255)&1)==0).equals(flags.get("pf")),"INC/DEC parity flag");
            }
        }
        var report=complete(new Program().code("b807000000894424fcff4424fc8b4424fcc3"));
        check(rax(report,0)==8,"Clang memory INC result");
        check(((List<?>)object(executions(report).get(0)).get("references")).size()==5,"Memory INC must record its read and write");
        report=complete(new Program().code("48b8ffffffffffffffff48894424f048ff4424f0488b4424f0c3"));
        check(rax(report,0)==0,"64-bit memory INC wrap");
        report=complete(new Program().code("31c083f801b807000000ffc07206b800000000c3b801000000c3"));
        check(rax(report,0)==1,"Branch after INC lost preserved carry");
    }
    public static void main(String[] args)throws Exception{
        root=args.length==0?Files.createTempDirectory("bcl-bounded-tests-"):Files.createDirectory(Path.of(args[0]));
        compilerIncrementRegression();
        Map<String,Object> r=complete(new Program().code("b807000000","c3"));check(rax(r,0)==7,"Return value");
        r=complete(new Program().code("488b07","c3").input("rdi",DATA,DATA+8));check(executions(r).size()==2&&rax(r,0)==7&&rax(r,1)==9,"Input enumeration omitted an alias");
        Program p=new Program().code("488b07","4801f0","c3");p.profile.put("inputs",List.of(Map.of("register","rdi","values",List.of(DATA,DATA+8)),Map.of("register","rsi","values",List.of(1,2,3))));
        r=complete(p);check(executions(r).size()==6,"Cartesian input product");check(rax(r,5)==12,"Last combination skipped");
        p=new Program().code("48b8"+imm(DATA,8),"8b00","c3");p.profile.put("inputs",List.of(Map.of("address",DATA,"width",4,"values",List.of(23,42))));r=complete(p);check(rax(r,0)==23&&rax(r,1)==42,"Memory input values");
        r=complete(new Program().code("48b88877665544332211","50","c6442401aa","58","c3"));check(rax(r,0)==0x112233445566aa88L,"Byte overlap/spill reconstruction");
        r=complete(new Program().code("55","4889e5","b807000000","c9","c3"));check(rax(r,0)==7,"LEAVE frame restoration");
        r=complete(new Program().code("b8ffffffff","4863c0","c3"));check(rax(r,0)==-1,"MOVSXD sign extension");
        r=complete(new Program().code("49b8"+imm(CODE+32,8),"41ffd0","c3").at(CODE+32).code("b807000000","c3"));check(rax(r,0)==7,"Indirect call/return");
        p=new Program().code("48b8"+imm(DATA,8),"ff24c8").at(CODE+32).code("b807000000","c3").at(CODE+48).code("b809000000","c3").input("rcx",0,1);
        ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x1000,CODE+32).putLong(0x1008,CODE+48);r=complete(p);check(rax(r,0)==7&&rax(r,1)==9,"Jump table targets");
        p=new Program().code("b890c30000","c3");p.profile.put("entries",List.of(CODE,CODE+1));r=complete(p);check(executions(r).size()==2&&rax(r,1)==0,"Alternate entry inside another decoding");
        p=new Program().code("488d4740","48890425"+imm(DATA+32,4),"8b00","c3").registers(Map.of("rdi",DATA));r=complete(p);
        check(!((List<?>)object(executions(r).get(0)).get("escapes")).isEmpty(),"Derived pointer escape missing");
        p=new Program().code("48b8"+imm(DATA+0x100,8),"488b00","c3");ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(152,0x100);r=complete(p);check(rax(r,0)==0,"BSS initialization");
        // Independently specified flag truth tables for all sixteen condition codes.
        branches("b8ffffffff83c001",true,true,true,false,false); // unsigned 32-bit overflow
        branches("b8ffffff7f83c001",false,true,false,true,true); // signed 32-bit overflow
        branches("31c083e801",true,true,false,true,false);      // 0 - 1
        branches("b80000008083e801",false,true,false,false,true);
        branches("48b8ffffffffffffffff4883c001",true,true,true,false,false);
        branches("48b8ffffffffffffff7f4883c001",false,true,false,true,true);
        branches("b801000000d1e8",true,true,true,false,false); // SHR 1
        branches("b800000080d1f8",false,true,false,true,false); // SAR 1
        branches("b80700000083f807",false,true,true,false,false); // CMP, no destination write
        branches("b80300000083e001",false,false,false,false,false); // AND
        branches("b80000000083c801",false,false,false,false,false); // OR
        branches("b80100000085c0",false,false,false,false,false); // TEST
        branches("31c0",false,true,true,false,false); // XOR
        r=complete(new Program().code("b80700000083f807c3"));check(rax(r,0)==7,"CMP must preserve destination");
        r=complete(new Program().code("b80700000085c0c3"));check(rax(r,0)==7,"TEST must preserve destination");
        r=complete(new Program().code("8b05"+imm(DATA-CODE-6,4),"c3"));check(rax(r,0)==7,"RIP-relative load");
        r=complete(new Program().code("0f1f00f30f1efa6aff58c3"));check(rax(r,0)==-1,"NOP, ENDBR64 and sign-extended PUSH immediate");
        r=complete(new Program().code("440fb6074489c0c3").registers(Map.of("rdi",DATA)));check(rax(r,0)==7,"Extended-register MOVZX");
        r=complete(new Program().code("0fb707c3").registers(Map.of("rdi",DATA)));check(rax(r,0)==7,"Word memory MOVZX");
        r=complete(new Program().code("31c00fb7c7c3").registers(Map.of("rdi",0xffff000080ffL)));check(rax(r,0)==0x80ff,"Word register MOVZX must zero-extend low 16 bits");
        check(Boolean.TRUE.equals(object(object(executions(r).get(0)).get("final_flags")).get("zf")),"MOVZX changed zero flag");
        r=complete(new Program().code("410fb7c0c3").registers(Map.of("r8",0xffff00001234L)));check(rax(r,0)==0x1234,"REX.B word source");
        r=complete(new Program().code("480fb7c7c3").registers(Map.of("rdi",0xffff000080ffL)));check(rax(r,0)==0x80ff,"REX.W MOVZX64 must zero-extend");
        r=complete(new Program().code("4c0fb6074c89c0c3").registers(Map.of("rdi",DATA)));check(rax(r,0)==7,"REX.W/R MOVZX64 memory");
        r=complete(new Program().code("8d07c3").registers(Map.of("rdi",0x100000001L)));check(rax(r,0)==1,"32-bit LEA truncation");
        r=complete(new Program().code("8d07c3").registers(Map.of("rdi",0x100000000L+DATA)));
        check(!((List<?>)object(executions(r).get(0)).get("escapes")).isEmpty(),"Truncation-produced region pointer lost");
        r=complete(new Program().code("89f885c0740583e801ebf7c3").input("rdi",0,1,2));check(executions(r).size()==3&&rax(r,2)==0,"Bounded loop input paths");
        r=complete(new Program().code("48b801000000ffffffff","c1e000","c3"));check(rax(r,0)==1,"32-bit zero-count shift must zero-extend destination");
        reject(new Program().code("b801000000c1e0027000c3"),"UNDEFINED_FLAG_DEPENDENCY");
        reject(new Program().code("ebfe").bound("max_steps_per_execution",3),"INSTRUCTION_BOUND_EXCEEDED");
        reject(new Program().code("31c0c3").input("rdi",0,1).bound("max_total_steps",3),"TOTAL_STEP_BOUND_EXCEEDED");
        reject(new Program().code("c3").input("rdi",0,1).bound("max_executions",1),"EXECUTION_BOUND_EXCEEDED");
        reject(new Program().code("5058c3").bound("max_reference_events",1),"REFERENCE_EVENT_BOUND_EXCEEDED");
        reject(new Program().code("c3").bound("max_memory_bytes",4096),"MEMORY_BOUND_EXCEEDED");
        reject(new Program().code("488b07c3").input("rdi",DATA,-1),"MEMORY_OUT_OF_BOUNDS");
        reject(new Program().code("488b07c3").input("rdi",DATA,0x900000),"MEMORY_OUT_OF_BOUNDS");
        reject(new Program().code("48b8"+imm(CODE,8),"c60090c3"),"MEMORY_PERMISSION");
        p=new Program().code("48b8"+imm(CODE,8),"c60090c3");ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putInt(68,7);reject(p,"SELF_MODIFICATION_UNSUPPORTED");
        reject(new Program().code("0f05"),"UNSUPPORTED_INSTRUCTION");
        reject(new Program().code("0f0b"),"UNSUPPORTED_INSTRUCTION");
        reject(new Program().code("48b8"+imm(0x7ffffffffff0L,8),"50c3"),"RETURN_STACK_CONTRACT");
        reject(new Program().code("48c7042400000000c3"),"MEMORY_OUT_OF_BOUNDS");
        p=new Program().code("c3");ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putShort(16,(short)3);reject(p,"UNSUPPORTED_RUNTIME");
        p=new Program().code("c3");ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putInt(120,2);reject(p,"UNSUPPORTED_RUNTIME");
        p=new Program().code("c3");object(p.profile.get("machine")).put("stack",Map.of("address",DATA,"size",4096));reject(p,"OVERLAPPING_MAPPINGS");
        p=new Program().code("c3");p.profile.put("inputs",List.of(Map.of("address",0x700ff8,"width",8,"values",List.of(0))));reject(p,"CALLER_CONTINUATION_INPUT");
        p=new Program().code("c3");p.profile.put("inputs",List.of(Map.of("register","rdi","values",List.of(0,0))));
        try{p.run();throw new AssertionError("Duplicate input accepted");}catch(IllegalArgumentException expected){checks++;}
        p=new Program().code("b807000000c3");Path profile=p.save();Map<String,Object> first=BoundedReferences.analyze(profile),second=BoundedReferences.analyze(profile);
        check(Json.write(first).equals(Json.write(second)),"Replay must be deterministic");
        Files.writeString(root.resolve("summary.json"),Json.write(Map.of("schema","bcl-bounded-qualification-1","status","BOUNDED_QUALIFICATION_EXPECTATIONS_MET","checks",checks,"cases",cases,"scope","Encoded ELF exhaustive machine-model tests; no general rewrite authorization")));
        System.out.println("All "+checks+" bounded reference checks passed ("+cases+" encoded ELF cases).");
    }
}
