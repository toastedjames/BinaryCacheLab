package org.binarycachelab.analysis;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Conservative reference obligations. No absence-of-alias or complete-decoding claim. */
public final class ReferenceCoverage {
    private ReferenceCoverage(){}
    private static final Pattern ROW=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
    private static final Pattern RIP=Pattern.compile("^rip(?:([+-])0x([0-9a-f]+))?$",Pattern.CASE_INSENSITIVE);
    private static final Pattern MEMORY=Pattern.compile("\\[([^]]+)\\]");
    private static final Pattern HEX=Pattern.compile("(?<![a-zA-Z0-9_])0x([0-9a-fA-F]+)(?![a-zA-Z0-9_])");
    public static Map<String,Object> analyze(Path binary,String text,long start,long size)throws IOException{
        Map<String,Object> report=inspect(text,start,size);
        Map<String,Object> metadata=ElfMetadata.read(binary).audit(start,size);
        Map<String,Object> result=new LinkedHashMap<>(report);result.put("elf_metadata",metadata);
        List<String> hazards=new ArrayList<>((List<String>)report.get("hazards"));hazards.addAll(ElfMetadata.detectedHazards(metadata));
        if(DirectReadInventory.supported(DirectReadInventory.inspect(text,start,size))){
            result.put("verified_direct_reads",LinkedReadVerification.verify(binary,text,start,size));
            if(hazards.contains("REGION_END_ADDRESS_IDENTITY_UNRESOLVED")){
                var helpers=BoundaryHelperAnalysis.analyze(binary,text,start,size);result.put("boundary_helper_analysis",helpers);
                result.put("boundary_caller_analysis",BoundaryCallerAnalysis.analyze(binary,text,start,size));
                Set<Long> covered=new HashSet<>();for(Object ip:(List<?>)helpers.get("covered_lea_ips"))covered.add(((Number)ip).longValue());
                boolean allCandidates=((List<?>)report.get("region_reference_candidates")).stream().filter(x->"REGION_END_ADDRESS_IDENTITY_CANDIDATE".equals(((Map<?,?>)x).get("classification")))
                    .allMatch(x->covered.contains(((Number)((Map<?,?>)x).get("ip")).longValue()));
                if(Boolean.TRUE.equals(helpers.get("all_candidate_paths_checked"))&&allCandidates){
                    hazards.removeIf("REGION_END_ADDRESS_IDENTITY_UNRESOLVED"::equals);hazards.add("BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED");
                    result.put("boundary_resolution_status","LOCAL_PATHS_CHECKED_CALLER_OBLIGATIONS_REMAIN");
                }
            }
        }else result.put("verified_direct_reads",Map.of("status","UNAVAILABLE_UNSUPPORTED_DIRECT_INVENTORY"));
        result.put("hazards",hazards.stream().distinct().toList());
        result.put("decision",hazards.isEmpty()?"INCONCLUSIVE_REFERENCE_COVERAGE":"REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS");
        return result;
    }
    public static Map<String,Object> inspect(String text,long start,long size){
        require(start>=0&&size>0&&start<=Long.MAX_VALUE-size,"Invalid coverage region");long end=start+size;
        require(text.length()<=32*1024*1024,"Disassembly exceeds coverage budget");
        List<Map<String,Object>> known=new ArrayList<>(),unresolved=new ArrayList<>();List<String> hazards=new ArrayList<>();
        long instructions=0;int candidates=0;
        for(String line:text.split("\\R")){
            Matcher row=ROW.matcher(line);
            if(!row.matches()){if(line.matches("\\s*[0-9a-fA-F]+:.*")){add(unresolved,0,"UNDECODED_INSTRUCTION_ROW",line);hazards.add("UNSUPPORTED_INSTRUCTION_DECODING");}continue;}
            require(++instructions<=1000000,"Instruction coverage budget exceeded");long ip=Long.parseLong(row.group(1),16);
            int length=row.group(2).trim().split("\\s+").length;require(length>0&&length<=15&&ip<=Long.MAX_VALUE-length,"Invalid instruction row length");
            String code=row.group(3).split("#",2)[0].trim().toLowerCase(Locale.ROOT);
            String[] split=code.split("\\s+",2);String mnemonic=split[0],operands=split.length==2?split[1]:"";
            if(code.contains("(bad)")||mnemonic.startsWith(".byte")){add(unresolved,ip,"UNDECODED_INSTRUCTION",code);hazards.add("UNSUPPORTED_INSTRUCTION_DECODING");continue;}
            boolean branch=mnemonic.startsWith("j")||mnemonic.startsWith("loop")||Set.of("call","callq").contains(mnemonic);
            if(branch){String target=operands.split("\\s",2)[0];
                if(!target.matches("[0-9a-f]+"))add(unresolved,ip,"INDIRECT_CONTROL_FLOW_TARGET",code);
                else{add(unresolved,ip,"DIRECT_CONTROL_FLOW_REACHABILITY_AND_EXTERNAL_BINDING",code);Long destination=low(target);
                    if(destination!=null&&destination>=start&&destination<end){addTarget(known,ip,"CONTROL_FLOW_INTO_DECLARED_DATA",code,destination,0);hazards.add("CONTROL_FLOW_INTO_DECLARED_DATA");}}}
            if(mnemonic.startsWith("ret")||Set.of("push","pushf","pushfq","pop","popf","popfq","enter","leave","call","callq").contains(mnemonic))
                add(unresolved,ip,"IMPLICIT_STACK_ADDRESS_AND_ALIAS",code);
            if(Set.of("syscall","sysenter","int","iret","iretq").contains(mnemonic))add(unresolved,ip,"KERNEL_OR_EXCEPTION_SIDE_EFFECTS",code);
            if(mnemonic.matches("(?:rep.*|movs[bwdq]?|stos[bwdq]?|lods[bwdq]?|scas[bwdq]?|cmps[bwdq]?|xlat.*)"))
                add(unresolved,ip,"IMPLICIT_OR_REPEATED_MEMORY_ACCESSES",code);
            Matcher memory=MEMORY.matcher(operands);boolean hasMemory=false;
            while(memory.find()){
                hasMemory=true;require(++candidates<=100000,"Memory candidate budget exceeded");String expression=memory.group(1).replace(" ","");
                boolean addressOnly=mnemonic.equals("lea"),segment=operands.substring(0,memory.start()).matches(".*\\b(?:fs|gs|cs|ds|ss|es):.*");
                if(segment){add(unresolved,ip,"SEGMENT_BASE_ADDRESS_UNRESOLVED",code);continue;}
                Long target=null;String kind="";Matcher rip=RIP.matcher(expression);
                try{if(rip.matches()){long displacement=0;
                    if(rip.group(2)!=null){displacement=Long.parseUnsignedLong(rip.group(2),16);
                        if("-".equals(rip.group(1)))displacement=Math.negateExact(displacement);
                        else if(displacement>=0x80000000L&&displacement<=0xffffffffL)displacement=(int)displacement;
                        require(displacement>=Integer.MIN_VALUE&&displacement<=Integer.MAX_VALUE,"RIP displacement exceeds disp32");}
                    target=Math.addExact(ip+length,displacement);kind="RIP_RELATIVE";
                }else if(expression.matches("0x[0-9a-f]+")){target=Long.parseLong(expression.substring(2),16);kind="ABSOLUTE";}}
                catch(ArithmeticException|IllegalArgumentException invalid){add(unresolved,ip,"UNSUPPORTED_STATIC_ADDRESS_EXPRESSION",code);hazards.add("UNSUPPORTED_STATIC_ADDRESS_EXPRESSION");continue;}
                int width=width(operands);
                if(target!=null){
                    if(addressOnly){if(target>=start&&target<=end){addTarget(known,ip,target==end?"REGION_END_ADDRESS_IDENTITY_CANDIDATE":"REGION_ADDRESS_TAKEN",code,target,0);hazards.add(target==end?"REGION_END_ADDRESS_IDENTITY_UNRESOLVED":"REGION_ADDRESS_TAKEN_REQUIRES_REVIEW");}
                        else add(unresolved,ip,"OTHER_ADDRESS_TAKEN_MAY_BE_ADJUSTED_OR_ESCAPE",code);}
                    else if(target>=0&&target<=Long.MAX_VALUE-Math.max(1,width)){
                        boolean overlap=target<end&&target+Math.max(1,width)>start;
                        if(overlap){String classification=kind.equals("RIP_RELATIVE")?"DIRECT_REGION_MEMORY_ACCESS":"ABSOLUTE_REGION_MEMORY_ACCESS";
                            addTarget(known,ip,classification,code,target,width);
                            if(kind.equals("ABSOLUTE"))hazards.add("ABSOLUTE_REGION_REFERENCE_NOT_REBOUND");
                            if(width==0)hazards.add("UNKNOWN_REGION_ACCESS_WIDTH");
                            if(target<start||target+Math.max(1,width)>end)hazards.add("ACCESS_CROSSES_REGION_BOUNDARY");}
                        else add(unresolved,ip,"OTHER_STATIC_MEMORY_MAY_CONTAIN_POINTERS_OR_INTERACT",code);
                    }else{add(unresolved,ip,"UNSUPPORTED_STATIC_ADDRESS_RANGE",code);hazards.add("UNSUPPORTED_STATIC_ADDRESS_RANGE");}
                }else{
                    add(unresolved,ip,addressOnly?"COMPUTED_ADDRESS_TAKING":"REGISTER_OR_INDEXED_MEMORY_ALIAS_UNRESOLVED",code);
                    Matcher base=HEX.matcher(expression);while(base.find()){Long value=low(base.group(1));if(value!=null&&value>=start&&value<=end){
                        addTarget(known,ip,"INDEXED_EXPRESSION_WITH_REGION_CONSTANT",code,value,width);hazards.add("INDEXED_REGION_ADDRESS_REQUIRES_REVIEW");}}
                }
            }
            String outside=operands.replaceAll("\\[[^]]+\\]","");
            if(!branch){Matcher immediate=HEX.matcher(outside);while(immediate.find()){Long value=low(immediate.group(1));if(value!=null&&value>=start&&value<=end){
                addTarget(known,ip,"REGION_ADDRESS_IMMEDIATE_CANDIDATE",code,value,0);hazards.add("REGION_ADDRESS_IMMEDIATE_REQUIRES_REVIEW");}}}
            if(!hasMemory&&operands.matches(".*\\b(?:fs|gs):.*"))add(unresolved,ip,"SEGMENT_RELATIVE_MEMORY_WITHOUT_BRACKETS",code);
        }
        var direct=DirectReadInventory.inspect(text,start,size);
        if(((List<?>)direct.get("reads")).isEmpty())hazards.add("NO_SUPPORTED_DECLARED_DIRECT_READS");
        if(!((List<?>)direct.get("unsupported_or_crossing")).isEmpty())hazards.add("UNSUPPORTED_OR_CROSSING_DIRECT_REGION_REFERENCE");
        Map<String,Long> counts=new TreeMap<>();for(var row:unresolved)counts.merge((String)row.get("classification"),1L,Long::sum);
        Map<String,Object> result=new LinkedHashMap<>();result.put("schema","java-reference-coverage-1");result.put("address",start);result.put("size",size);
        result.put("instruction_rows",instructions);result.put("region_reference_candidates",known);result.put("unresolved_sites",unresolved);result.put("unresolved_counts",counts);
        result.put("direct_inventory",direct);result.put("hazards",hazards.stream().distinct().toList());result.put("reference_coverage","INCOMPLETE");
        result.put("safe_to_transform",false);result.put("automatic_rewrite_allowed",false);
        result.put("decision",hazards.isEmpty()?"INCONCLUSIVE_REFERENCE_COVERAGE":"REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS");
        result.put("unestablished_obligations",List.of("COMPLETE_EXECUTABLE_BYTE_AND_INSTRUCTION_BOUNDARY_COVERAGE","REGISTER_AND_MEMORY_POINTER_DATAFLOW_FIXPOINT",
            "INDIRECT_CONTROL_FLOW_AND_EXTERNAL_CODE_CLOSURE","REGION_LIFETIME_AND_OUTSIDE_OBJECT_INTERACTIONS","RUNTIME_MAPPING_AND_LOADER_BINDINGS"));
        return result;
    }
    private static Long low(String hex){try{return Long.parseLong(hex,16);}catch(NumberFormatException ignored){return null;}}
    private static int width(String operands){Matcher m=Pattern.compile("\\b(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword) ptr\\b").matcher(operands);
        if(!m.find())return 0;return switch(m.group(1)){case "byte"->1;case "word"->2;case "dword"->4;case "qword"->8;case "tbyte"->10;case "xmmword"->16;case "ymmword"->32;default->64;};}
    private static void add(List<Map<String,Object>> rows,long ip,String kind,String code){require(rows.size()<100000,"Reference diagnostic budget exceeded");rows.add(Map.of("ip",ip,"classification",kind,"instruction",code));}
    private static void addTarget(List<Map<String,Object>> rows,long ip,String kind,String code,long target,int width){require(rows.size()<100000,"Region candidate budget exceeded");rows.add(Map.of("ip",ip,"classification",kind,"instruction",code,"target",target,"width_bytes",width));}
}
