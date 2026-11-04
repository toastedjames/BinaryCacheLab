package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;

/** Encoded-instruction tests against file-bound ELF bytes, including rejection paths. */
public final class ReferenceClosureTest {
    private static final long CODE=0x400200, DATA=0x400800;
    private static int checks;
    private static int cases;
    private static Path directory;
    private static final class Program {
        final byte[] raw=new byte[4096];
        final NavigableMap<Long,byte[]> rows=new TreeMap<>();
        final Map<String,Object> profile=new LinkedHashMap<>();
        long next=CODE;
        Program(){
            ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;
            b.putShort(16,(short)2).putShort(18,(short)62).putInt(20,1).putLong(24,CODE);
            b.putLong(32,64).putLong(40,0xc00).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)1);
            b.putShort(58,(short)64).putShort(60,(short)3).putShort(62,(short)1);
            b.putInt(64,1).putInt(68,7).putLong(72,0).putLong(80,0x400000).putLong(96,4096).putLong(104,4096);
            byte[] names="\0.shstrtab\0.text\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);System.arraycopy(names,0,raw,0xb00,names.length);
            b.putInt(0xc40,1).putInt(0xc44,3).putLong(0xc58,0xb00).putLong(0xc60,names.length);
            b.putInt(0xc80,11).putInt(0xc84,1).putLong(0xc88,6).putLong(0xc90,CODE).putLong(0xc98,0x200).putLong(0xca0,0x100);
            b.putLong(0x800,7).putLong(0x808,7);
            profile.put("schema","bcl-closure-1");profile.put("entries",List.of(CODE));
            profile.put("regions",List.of(Map.of("name","data","address",DATA,"size",32,"immutable",true)));
            profile.put("initial_registers",Map.of("rsp","stack"));
            profile.put("observed_return_registers",List.of("rax"));profile.put("stack_disjoint_from_regions",true);
        }
        Program code(String... hex){for(String h:hex){byte[] bytes=HexFormat.of().parseHex(h);rows.put(next,bytes);System.arraycopy(bytes,0,raw,(int)(next-0x400000),bytes.length);next+=bytes.length;}return this;}
        Program at(long ip){next=ip;return this;}
        Program inputs(Map<String,Object> values){Map<String,Object> regs=new LinkedHashMap<>(values);regs.put("rsp","stack");profile.put("initial_registers",regs);return this;}
        Map<String,Object> run()throws Exception{
            Path folder=Files.createDirectory(directory.resolve(String.format("case-%03d",++cases)));
            Path bin=folder.resolve("input.elf"),asm=folder.resolve("input.asm"),json=folder.resolve("profile.json");
            Files.write(bin,raw);StringBuilder text=new StringBuilder();
            rows.forEach((ip,bytes)->{text.append(Long.toHexString(ip)).append(": ");for(byte v:bytes)text.append(String.format("%02x ",v&255));text.append("encoded\n");});
            Files.writeString(asm,text);profile.put("binary","input.elf");profile.put("disassembly","input.asm");Files.writeString(json,Json.write(profile));
            Map<String,Object> result=ReferenceClosure.analyze(json);Files.writeString(folder.resolve("report.json"),Json.write(result));return result;
        }
    }
    static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    static boolean issue(Map<String,Object> r,String kind){return ((List<?>)r.get("unresolved")).stream().anyMatch(x->kind.equals(((Map<?,?>)x).get("kind")));}
    static void closed(Program p,String message)throws Exception{Map<String,Object> r=p.run();check("CLOSED_UNDER_DECLARED_ENTRY_CONTRACT".equals(r.get("status")),message+": "+r.get("unresolved"));check(Boolean.FALSE.equals(r.get("automatic_rewrite_allowed")),"Local closure authorized general rewriting");}
    static void unresolved(Program p,String kind)throws Exception{Map<String,Object> r=p.run();check(issue(r,kind),kind+": "+r);check("UNRESOLVED_REFERENCE_CLOSURE".equals(r.get("status")),"Unresolved analysis closed");}
    public static void main(String[] args)throws Exception{
        directory=args.length==0?Files.createTempDirectory("bcl-reference-closure-"):Files.createDirectory(Path.of(args[0]));
        closed(new Program().code("b807000000","c3"),"Ordinary return");
        closed(new Program().code("55","4889e5","b807000000","c9","c3"),"Frame pointer / LEAVE");
        closed(new Program().code("b8ffffffff","4863c0","c3"),"MOVSXD negative constant");
        closed(new Program().code("49b82002400000000000","41ffe0").at(CODE+32).code("b807000000","c3"),"Extended register indirect jump");
        closed(new Program().code("49b82002400000000000","41ffd0","c3").at(CODE+32).code("b807000000","c3"),"Extended register indirect call and return");
        unresolved(new Program().code("ffe0"),"INDIRECT_CONTROL_FLOW_UNRESOLVED");
        unresolved(new Program().code("48c7042400000000","b807000000","c3"),"ENTRY_RETURN_STACK_UNRESOLVED");
        unresolved(new Program().code("4883c408","b807000000","c3"),"ENTRY_RETURN_STACK_UNRESOLVED");
        unresolved(new Program().code("0f0b"),"UNSUPPORTED_INSTRUCTION_OR_BOUNDARY");
        unresolved(new Program().code("8b07","c3"),"MEMORY_ALIAS_UNRESOLVED");
        Program p=new Program().inputs(Map.of("rdi",List.of(DATA,DATA+8))).code("8b07","c3");
        closed(p,"Finite points-to input set");check(((List<?>)p.run().get("accesses")).size()==2,"Both aliases must be recorded");
        p=new Program().inputs(Map.of("rdi",List.of(DATA,0x900000L))).code("8b07","c3");
        unresolved(p,"STATIC_MAPPING_OR_PERMISSION_UNRESOLVED");
        // LEA can move a pointer outside its original numeric range; provenance must survive.
        unresolved(new Program().inputs(Map.of("rdi",DATA)).code("488d8740000000","c3"),"REGION_POINTER_LIVE_AT_ENTRY_RETURN");
        unresolved(new Program().inputs(Map.of("rdi",DATA)).code("488d8740000000","8b00","c3"),"REGION_DERIVED_OUTSIDE_ACCESS");
        unresolved(new Program().inputs(Map.of("rdi",DATA)).code("488d8740000000","4889042520094000","31c0","c3"),"STORED_REGION_POINTER_LIFETIME_UNRESOLVED");
        unresolved(new Program().code("48893c2520094000","31c0","c3"),"STORED_VALUE_PROVENANCE_UNRESOLVED");
        unresolved(new Program().inputs(Map.of("rdi",DATA)).code("c70700000000","31c0","c3"),"IMMUTABLE_REGION_WRITE");
        unresolved(new Program().inputs(Map.of("rdi",DATA+30)).code("8b07","c3"),"REGION_BOUNDARY_CROSSING_ACCESS");
        unresolved(new Program().inputs(Map.of("rax",CODE+1)).code("ffe0"),"CONTROL_FLOW_BOUNDARY_OR_EXTERNAL_CODE_UNRESOLVED");
        // Unknown condition explores both aliases and converges at the shared read.
        p=new Program().code("85ff","740c","48b80008400000000000","eb0a","48b80808400000000000","8b00","c3");
        closed(p,"Control-flow join retains both aliases");check(((List<?>)p.run().get("accesses")).size()==2,"Joined alias omitted");
        p=new Program().code("ebfe");closed(p,"Stable self-loop reaches a fixpoint without inventing a return");
        closed(new Program().code("48b80700000000000000","50","8b0424","4883c408","c3"),"Contained 32-bit read of 64-bit stack spill");
        unresolved(new Program().inputs(Map.of("rdi",DATA)).code("57","8b0424","4883c408","c3"),"REGION_POINTER_LIVE_AT_ENTRY_RETURN");
        unresolved(new Program().code("b807000000","50","c644240100","488b0424","4883c408","c3"),"OBSERVED_RETURN_VALUE_PROVENANCE_UNRESOLVED");
        p=new Program().code("31c0","c3").at(CODE+32).code("8b07","c3");p.profile.put("entries",List.of(CODE,CODE+32));
        unresolved(p,"MEMORY_ALIAS_UNRESOLVED");check(((List<?>)p.run().get("analyzed_entry_addresses")).size()==2,"Alternate entry omitted");
        // Immutable jump table, two possible indices, both callees checked.
        p=new Program().inputs(Map.of("rcx",List.of(0,1))).code("48b80008400000000000","ff24c8").at(CODE+32).code("b807000000","c3").at(CODE+48).code("b809000000","c3");
        ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x800,CODE+32).putLong(0x808,CODE+48);
        closed(p,"Immutable indexed jump table");check(((List<?>)p.run().get("accesses")).size()==2,"Jump table aliases missing");
        p=new Program().code("31c0","c3");p.profile.put("stack_disjoint_from_regions",false);unresolved(p,"STACK_REGION_ALIAS_UNRESOLVED");
        p=new Program().code("31c0","c3");p.profile.put("state_budget",1);unresolved(p,"FIXPOINT_BUDGET_EXHAUSTED");
        p=new Program().inputs(Map.of("rdi",List.of(0,1,2,3,4,5,6,7,8))).code("31c0","c3");
        try{p.run();throw new AssertionError("Oversized input set accepted");}catch(IllegalArgumentException expected){checks++;}
        p=new Program().code("31c0","c3");p.raw[0x200]=(byte)0x90;
        try{p.run();throw new AssertionError("Unbound instruction accepted");}catch(IllegalArgumentException expected){checks++;}
        System.out.println("All "+checks+" reference closure checks passed.");
        Files.writeString(directory.resolve("summary.json"),Json.write(Map.of("schema","bcl-reference-qualification-1","status","REFERENCE_QUALIFICATION_EXPECTATIONS_MET","checks",checks,"cases",cases,"scope","Encoded ELF fixtures and declared entry contracts; no native execution or whole-program proof","automatic_rewrite_allowed",false)));
    }
}
