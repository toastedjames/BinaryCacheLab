package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;

/** Positive and negative relational tests over independently encoded ELF pairs. */
public final class BoundedCorrespondenceTest {
    private static final long CODE=BoundedReferencesTest.CODE,DATA=BoundedReferencesTest.DATA;
    private static int checks,pairs;
    static Path root;
    private static BoundedReferencesTest.Program program(String... code){return new BoundedReferencesTest.Program().code(code);}
    private static String imm(long n,int width){return BoundedReferencesTest.imm(n,width);}
    private static Map<String,Object> object(Object o){return BoundedReferencesTest.object(o);}
    private static Map<String,Object> point(long a,long b){return Map.of("original",a,"rebuilt",b);}
    static final class Pair {
        final BoundedReferencesTest.Program a,b;final Map<String,Object> profile=new LinkedHashMap<>();
        Pair(BoundedReferencesTest.Program a,BoundedReferencesTest.Program b){this.a=a;this.b=b;
            profile.put("schema","bcl-bounded-correspondence-1");profile.put("abi","sysv-amd64-integer");profile.put("entries",List.of(point(CODE,CODE)));
            profile.put("control_map",List.of(point(a.next-1,b.next-1)));profile.put("memory_maps",List.of(memory(DATA,DATA,32)));
            profile.put("register_outputs",List.of(Map.of("register","rax","encoding","scalar")));
            List<Map<String,Object>> inputs=new ArrayList<>();for(int i=0;i<Math.min(((List<?>)a.profile.get("inputs")).size(),((List<?>)b.profile.get("inputs")).size());i++)inputs.add(Map.of("original",i,"rebuilt",i,"encoding","scalar"));profile.put("input_map",inputs);
        }
        Path save()throws Exception {profile.put("original",a.save().toString());profile.put("rebuilt",b.save().toString());Path path=root.resolve("pair-"+(++pairs)+".json");Files.writeString(path,Json.write(profile));return path;}
        Map<String,Object> run()throws Exception {Path path=save();var report=BoundedCorrespondence.analyze(path);Files.writeString(path.resolveSibling(path.getFileName()+".report.json"),Json.write(report));return report;}
    }
    private static Map<String,Object> memory(long a,long b,long size){return Map.of("name","global","original",a,"rebuilt",b,"size",size);}
    private static void check(boolean okay,String detail){checks++;if(!okay)throw new AssertionError(detail);}
    private static Map<String,Object> established(Pair pair)throws Exception {var r=pair.run();check(Boolean.TRUE.equals(r.get("correspondence_established")),Json.write(r));check("CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS".equals(r.get("status")),"Wrong successful status");check(Boolean.FALSE.equals(r.get("automatic_rewrite_allowed")),"Correspondence authorized rewriting");return r;}
    private static void rejected(Pair pair,String kind)throws Exception {var r=pair.run();check("REJECTED_CORRESPONDENCE_MODEL".equals(r.get("status")),Json.write(r));check(kind.equals(object(r.get("rejection")).get("kind")),Json.write(r));check(Boolean.FALSE.equals(r.get("correspondence_established")),"Rejected model approved");}
    private static Map<String,Object> counterexample(Pair pair,String component)throws Exception {var r=pair.run();check("CORRESPONDENCE_COUNTEREXAMPLE".equals(r.get("status")),Json.write(r));
        check(((List<?>)r.get("witnesses")).stream().anyMatch(w->component.equals(object(w).get("component"))),"Missing "+component+" witness");check(Boolean.FALSE.equals(r.get("correspondence_established")),"Counterexample approved");return r;}
    private static void relocatedData(BoundedReferencesTest.Program p,long start){ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putLong((int)(start-0x400000),7).putLong((int)(start-0x400000)+8,9);}
    private static Pair scalarPair(){return new Pair(program("b807000000c3"),program("b807000000c3"));}
    private static void callbacks(BoundedReferencesTest.Program p,int type){ByteBuffer b=ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN);b.putLong(40,0xc00).putShort(58,(short)64).putShort(60,(short)2);
        b.putInt(0xc44,type).putLong(0xc58,0x1000).putLong(0xc60,8);}
    public static void main(String[] args)throws Exception {
        root=args.length==0?Files.createTempDirectory("bcl-correspondence-"):Files.createDirectory(Path.of(args[0]));BoundedReferencesTest.root=root;
        established(scalarPair());
        established(new Pair(program("b807000000c3"),program("90b807000000c3")));
        Pair p=new Pair(program("89f8c3").input("rdi",0,1),program("89f8c3").input("rdi",1,0));var r=established(p);
        check(((Number)r.get("cases_compared")).intValue()==2,"Input enumeration skipped cases");
        check(((List<?>)r.get("cases")).stream().anyMatch(row->!object(row).get("original_case").equals(object(row).get("rebuilt_case"))),"Input reorder was paired by ordinal");
        counterexample(new Pair(program("b807000000c3"),program("b809000000c3")),"functional");
        r=counterexample(new Pair(program("89f8c3").input("rdi",0,1,2),program("89f883e001c3").input("rdi",0,1,2)),"functional");
        check(((Number)r.get("cases_compared")).intValue()==3,"Later-case difference was skipped");
        check(Boolean.TRUE.equals(object(((List<?>)r.get("cases")).get(0)).get("functional"))&&Boolean.FALSE.equals(object(((List<?>)r.get("cases")).get(2)).get("functional")),"Difference attributed to wrong logical case");
        var multiA=program("b807000000c3").at(CODE+32).code("b809000000c3");var multiB=program("b807000000c3").at(CODE+32).code("b809000000c3");
        multiA.profile.put("entries",List.of(CODE,CODE+32));multiB.profile.put("entries",List.of(CODE+32,CODE));p=new Pair(multiA,multiB);
        p.profile.put("entries",List.of(point(CODE,CODE),point(CODE+32,CODE+32)));p.profile.put("control_map",List.of(point(CODE+5,CODE+5),point(CODE+37,CODE+37)));r=established(p);check(((Number)r.get("cases_compared")).intValue()==2,"Entry reorder was not paired exhaustively");
        String store="c70425"+imm(DATA+16,4);
        established(new Pair(program(store+imm(13,4),"31c0c3"),program(store+imm(13,4),"31c0c3")));
        counterexample(new Pair(program(store+imm(13,4),"31c0c3"),program(store+imm(14,4),"31c0c3")),"functional");
        p=new Pair(program(store+imm(13,4),"31c0c3"),program(store+imm(13,4),"31c0c3"));p.profile.put("memory_maps",List.of());rejected(p,"UNMAPPED_PERSISTENT_WRITE");
        counterexample(new Pair(program("b807000000c3"),program("bb01000000b807000000c3")),"abi");
        for(String move:new String[]{"bd01000000","41bc01000000","41bd01000000","41be01000000","41bf01000000"})counterexample(new Pair(program("b807000000c3"),program(move,"b807000000c3")),"abi");
        counterexample(new Pair(program("b807000000c3").input("rbx",0,9),program("31dbb807000000c3").input("rbx",0,9)),"abi");
        established(new Pair(program("b807000000c3"),program("b907000000bf08000000be09000000b807000000c3")));
        p=scalarPair();p.a.registers(Map.of("rbx",91,"rbp",92,"r12",93,"r13",94,"r14",95,"r15",96));p.b.registers(Map.of("rbx",91,"rbp",92,"r12",93,"r13",94,"r14",95,"r15",96));established(p);
        // The root restores RBX; the internal callee still violates its own call ABI.
        var a=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("b807000000c3");
        var b=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("bb01000000b807000000c3");
        p=new Pair(a,b);p.profile.put("control_map",List.of(point(CODE+1,CODE+1),point(CODE+6,CODE+6),point(CODE+7,CODE+7),point(CODE+32,CODE+32),point(CODE+37,CODE+42)));counterexample(p,"abi");
        a=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("b807000000c3");b=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("b807000000c3");
        p=new Pair(a,b);p.profile.put("control_map",List.of(point(CODE+1,CODE+1),point(CODE+6,CODE+6),point(CODE+7,CODE+7),point(CODE+32,CODE+32),point(CODE+37,CODE+37)));established(p);
        a=program("e8"+imm(27,4),"c3").at(CODE+32).code("b807000000c3");b=program("e8"+imm(27,4),"c3").at(CODE+32).code("b807000000c3");
        p=new Pair(a,b);p.profile.put("control_map",List.of(point(CODE+5,CODE+5),point(CODE+32,CODE+32),point(CODE+37,CODE+37)));counterexample(p,"abi");
        a=program("85ff7407b807000000eb05b807000000c3").input("rdi",0,1);b=program("85ff7507b807000000eb05b807000000c3").input("rdi",0,1);
        p=new Pair(a,b);p.profile.put("control_map",List.of(point(CODE+2,CODE+2),point(CODE+4,CODE+4),point(CODE+9,CODE+9),point(CODE+11,CODE+11),point(CODE+16,CODE+16)));counterexample(p,"control_flow");
        rejected(new Pair(program("85ff7407b807000000eb05b807000000c3").input("rdi",0,1),program("85ff7407b807000000eb05b807000000c3").input("rdi",0,1)),"UNMAPPED_CONTROL_SITE");
        p=scalarPair();p.profile.put("control_map",List.of(point(CODE+5,CODE+6),point(CODE+5,CODE+7)));rejected(p,"AMBIGUOUS_CODE_MAPPING");
        p=scalarPair();p.profile.put("control_map",List.of(point(CODE+5,CODE+5),point(DATA,DATA)));rejected(p,"NONEXECUTABLE_CODE_MAPPING");
        p=scalarPair();p.b.profile.put("entries",List.of(CODE,CODE+1));rejected(p,"ENTRY_DOMAIN_MISMATCH");
        rejected(new Pair(program("89f8c3").input("rdi",0,1),program("89f8c3").input("rdi",0,2)),"INPUT_VALUE_DOMAIN_MISMATCH");
        rejected(new Pair(program("89f8c3").input("rdi",0,1),program("89f8c3").input("rsi",0,1)),"INPUT_ABI_REGISTER_MISMATCH");
        p=scalarPair();p.b.registers(Map.of("rbx",1));rejected(p,"INITIAL_REGISTER_RELATION_MISMATCH");
        p=scalarPair();p.profile.put("input_map",List.of(Map.of("original",0,"rebuilt",0,"encoding","scalar")));
        try{p.run();throw new AssertionError("Out-of-range input mapping accepted");}catch(IllegalArgumentException expected){checks++;}
        p=scalarPair();ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x1000,111);rejected(p,"INITIAL_MEMORY_RELATION_MISMATCH");
        p=new Pair(program("48b8"+imm(DATA,8),"c3"),program("48b8"+imm(DATA+64,8),"c3"));relocatedData(p.b,DATA+64);p.profile.put("memory_maps",List.of(memory(DATA,DATA+64,32)));
        p.profile.put("register_outputs",List.of(Map.of("register","rax","encoding","address")));established(p);
        p=new Pair(program("48b8"+imm(DATA,8),"c3"),program("48b8"+imm(DATA+64,8),"c3"));relocatedData(p.b,DATA+64);p.profile.put("memory_maps",List.of(memory(DATA,DATA+64,32)));counterexample(p,"functional");
        p=new Pair(program("8b07c3").input("rdi",DATA,DATA+8),program("8b07c3").input("rdi",DATA+64,DATA+72));relocatedData(p.b,DATA+64);p.profile.put("memory_maps",List.of(memory(DATA,DATA+64,32)));p.profile.put("input_map",List.of(Map.of("original",0,"rebuilt",0,"encoding","address")));established(p);
        p=scalarPair();relocatedData(p.b,DATA+64);ByteBuffer.wrap(p.a.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x1010,DATA+8);ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x1050,DATA+72);
        var memory=new LinkedHashMap<>(memory(DATA,DATA+64,32));memory.put("pointer_fields",List.of(Map.of("offset",16,"width",8,"encoding","address")));p.profile.put("memory_maps",List.of(memory));established(p);
        p=new Pair(program("31c0c3"),program("31c0c3"));p.profile.put("register_outputs",List.of(Map.of("register","rax","encoding","nullable-address")));established(p);
        p=new Pair(program("31c0c3"),program("31c0c3"));p.profile.put("register_outputs",List.of(Map.of("register","rax","encoding","address")));rejected(p,"UNMAPPED_ADDRESS_CORRESPONDENCE");
        p=new Pair(program("48b8"+imm(DATA+16,8),"c3"),program("48b8"+imm(DATA+16,8),"c3"));var endpoint=new LinkedHashMap<>(memory(DATA,DATA,16));endpoint.put("allow_one_past",true);p.profile.put("memory_maps",List.of(endpoint));p.profile.put("register_outputs",List.of(Map.of("register","rax","encoding","address")));established(p);
        p=new Pair(program("48b8"+imm(DATA+8,8),"c3"),program("48b8"+imm(DATA+8,8),"c3"));endpoint=new LinkedHashMap<>(memory(DATA,DATA,8));endpoint.put("allow_one_past",true);var adjacent=Map.of("name","next","original",DATA+8,"rebuilt",DATA+8,"size",8);p.profile.put("memory_maps",List.of(endpoint,adjacent));p.profile.put("register_outputs",List.of(Map.of("register","rax","encoding","address")));rejected(p,"AMBIGUOUS_ADDRESS_CORRESPONDENCE");
        p=scalarPair();object(p.b.profile.get("machine")).put("stack",Map.of("address",0x710000,"size",4096));established(p);
        p=scalarPair();p.b.code("90"); // Stack domain mismatch rejected before exploration.
        object(p.b.profile.get("machine")).put("stack",Map.of("address",0x710000,"size",8192));rejected(p,"STACK_DOMAIN_MISMATCH");
        p=new Pair(program("ebfe"),program("ebfe"));rejected(p,"INCOMPLETE_BOUNDED_EXECUTION");
        p=new Pair(program("0f05"),program("0f05"));rejected(p,"INCOMPLETE_BOUNDED_EXECUTION");
        p=scalarPair();ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putShort(16,(short)3);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");
        p=scalarPair();ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putInt(120,2);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");
        for(int type:new int[]{6,14,15,16}){p=scalarPair();callbacks(p.b,type);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");}
        p=scalarPair();callbacks(p.b,4);ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0xc48,2);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");
        p=scalarPair();callbacks(p.b,2);ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0xc60,48).putLong(0xc78,24).put(0x101c,(byte)0x12);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");
        p=scalarPair();p.profile.put("abi","windows-x64");rejected(p,"UNSUPPORTED_ABI");
        for(String name:new String[]{".ctors",".dtors",".init",".fini"}){p=scalarPair();callbacks(p.b,1);ByteBuffer header=ByteBuffer.wrap(p.b.raw).order(ByteOrder.LITTLE_ENDIAN);
            byte[] names=("\0"+name+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII);System.arraycopy(names,0,p.b.raw,0xb00,names.length);
            header.putShort(60,(short)3).putShort(62,(short)2).putInt(0xc40,1).putInt(0xc84,3).putLong(0xc98,0xb00).putLong(0xca0,names.length);rejected(p,"UNSUPPORTED_RUNTIME_DEPENDENCIES");}
        a=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("b807000000c3");b=program("53e8"+imm(26,4),"5bc3").at(CODE+32).code("b807000000c3");
        p=new Pair(a,b);p.profile.put("control_map",List.of(point(CODE+1,CODE+1),point(CODE+7,CODE+7),point(CODE+37,CODE+37)));rejected(p,"UNMAPPED_CONTROL_TARGET");
        p=scalarPair();Path path=p.save();var one=BoundedCorrespondence.analyze(path);var two=BoundedCorrespondence.analyze(path);check(Json.write(one).equals(Json.write(two)),"Correspondence replay changed");
        Files.writeString(root.resolve("summary.json"),Json.write(Map.of("schema","bcl-correspondence-qualification-1","status","CORRESPONDENCE_QUALIFICATION_EXPECTATIONS_MET","checks",checks,"pairs",pairs,"scope","Bounded functional, ABI, control-flow and unsupported-runtime checks")));
        System.out.println("All "+checks+" bounded correspondence checks passed ("+pairs+" ELF pairs).");
    }
}
