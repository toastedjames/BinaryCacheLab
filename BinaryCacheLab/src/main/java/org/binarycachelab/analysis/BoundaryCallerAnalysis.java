package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Checked direct callers and deliberately narrow continuations; never caller closure. */
public final class BoundaryCallerAnalysis {
    private record Row(long ip,byte[] code) {long next(){return Math.addExact(ip,code.length);}String hex(){return HexFormat.of().formatHex(code);}}
    private record Edge(long source,long target,String kind){}
    private BoundaryCallerAnalysis(){}
    public static Map<String,Object> analyze(Path binary,String text,long start,long size)throws IOException{
        // This also binds every supplied row to the executable file before we use its bytes.
        Map<String,Object> helpers=BoundaryHelperAnalysis.analyze(binary,text,start,size);
        var callbacks=ElfCallbackInventory.analyze(binary);
        NavigableMap<Long,Row> rows=new TreeMap<>();Pattern pattern=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
        for(String line:text.split("\\R")){Matcher m=pattern.matcher(line);if(m.matches()){long ip=Long.parseLong(m.group(1),16);
            rows.put(ip,new Row(ip,HexFormat.of().parseHex(m.group(2).replaceAll("\\s",""))));}}
        List<Edge> edges=new ArrayList<>();for(Row row:rows.values()){Edge edge=edge(row);if(edge!=null)edges.add(edge);}
        List<Map<String,Object>> paths=new ArrayList<>();
        for(Object item:(List<?>)helpers.get("paths")){Map<?,?> helper=(Map<?,?>)item;long entry=((Number)helper.get("entry")).longValue();
            Map<String,Object> path=new LinkedHashMap<>();path.put("helper_entry",entry);path.put("helper_return_ip",helper.get("return_ip"));
            path.put("boundary_values_live_at_helper_return",helper.get("boundary_values_live_at_return"));
            List<Map<String,Object>> callers=new ArrayList<>(),interior=new ArrayList<>(),roots=new ArrayList<>();
            Set<Long> executed=new HashSet<>();for(Object ip:(List<?>)helper.get("executed_ips"))executed.add(((Number)ip).longValue());
            for(Edge edge:edges){
                if(edge.target==entry){Map<String,Object> caller=new LinkedHashMap<>();caller.put("ip",edge.source);caller.put("kind",edge.kind);
                    if(edge.kind.equals("CALL_REL32"))caller.put("continuation",continuation(rows,rows.get(edge.source).next(),start,size,helper));
                    else caller.put("return_values","Inherited return continuation unproved; tail transfer does not discard registers");callers.add(caller);
                }else if(!executed.contains(edge.source)&&executed.contains(edge.target))interior.add(Map.of("ip",edge.source,"target",edge.target,"kind",edge.kind));
            }
            for(Object cb:(List<?>)callbacks.get("callbacks")){Map<?,?> callback=(Map<?,?>)cb;
                if(!(callback.get("target") instanceof Number target)||!Boolean.TRUE.equals(callback.get("target_in_executable_file_mapping")))continue;
                long root=target.longValue(),pc=root;List<Long> prefix=new ArrayList<>();Row row=rows.get(pc);
                if(row!=null&&row.hex().equals("f30f1efa")){prefix.add(pc);pc=row.next();row=rows.get(pc);}
                if(pc==entry){roots.add(Map.of("source",callback.get("source"),"callback_entry",root,"prefix_ips",prefix,"relation","DIRECT_ENTRY_AFTER_OPTIONAL_ENDBR64"));continue;}
                Edge edge=row==null?null:edge(row);
                if(edge!=null&&edge.target==entry&&(edge.kind.equals("JMP_REL32")||edge.kind.equals("JMP_REL8"))){prefix.add(pc);
                    roots.add(Map.of("source",callback.get("source"),"callback_entry",root,"prefix_ips",prefix,"relation","TAIL_ENTRY_AFTER_OPTIONAL_ENDBR64"));}
            }
            path.put("enumerated_direct_incoming_edges",callers);path.put("enumerated_alternate_entries",interior);path.put("matching_callback_roots",roots);
            path.put("all_callers_and_entries_proved",false);paths.add(path);
        }
        return Map.ofEntries(Map.entry("schema","java-boundary-caller-analysis-1"),Map.entry("binary_sha256",helpers.get("binary_sha256")),
            Map.entry("paths",paths),Map.entry("callback_inventory",callbacks),Map.entry("supplied_instruction_rows",rows.size()),
            Map.entry("scope","Direct edges decoded from supplied bound rows; no exhaustive instruction boundary, indirect entry, fallthrough entry or external caller proof"),
            Map.entry("remaining_obligations",List.of("COMPLETE_CALLER_AND_ALTERNATE_ENTRY_CLOSURE","RUNTIME_CALLBACK_REGISTER_AND_MEMORY_CONTRACT","OUTSIDE_REGION_STORE_AND_STACK_ALIAS_CONTRACT")),
            Map.entry("caller_contract_proved",false),Map.entry("automatic_rewrite_allowed",false));
    }
    private static Edge edge(Row row){byte[] c=row.code;int op=c[0]&255;
        if(c.length==5&&(op==0xe8||op==0xe9))return new Edge(row.ip,Math.addExact(row.next(),disp(c,1)),op==0xe8?"CALL_REL32":"JMP_REL32");
        if(c.length==2&&(op==0xeb||(op>=0x70&&op<=0x7f)||(op>=0xe0&&op<=0xe3)))return new Edge(row.ip,Math.addExact(row.next(),(int)c[1]),op==0xeb?"JMP_REL8":"CONDITIONAL_REL8");
        if(c.length==6&&op==0x0f&&(c[1]&255)>=0x80&&(c[1]&255)<=0x8f)return new Edge(row.ip,Math.addExact(row.next(),disp(c,2)),"CONDITIONAL_REL32");
        return null;
    }
    private static int disp(byte[] c,int offset){return ByteBuffer.wrap(c,offset,4).order(ByteOrder.LITTLE_ENDIAN).getInt();}
    private static Map<String,Object> continuation(Map<Long,Row> rows,long entry,long start,long size,Map<?,?> helper){
        List<Long> executed=new ArrayList<>();List<Map<String,Object>> stores=new ArrayList<>();List<String> stack=new ArrayList<>();
        Map<String,Object> report=new LinkedHashMap<>();report.put("entry",entry);report.put("checked",false);
        // Only these exact instructions are accepted. In particular, no general MOV or CALL is skipped.
        long pc=entry;int pops=0;
        try{for(int step=0;step<16;step++){Row row=rows.get(pc);require(row!=null,"Missing continuation row");executed.add(pc);byte[] c=row.code;
            if(c.length==7&&(c[0]&255)==0xc6&&(c[1]&255)==5){long target=Math.addExact(row.next(),disp(c,2));
                require(target>=0&&!(target>=start&&target<start+size),"Continuation store overlaps selected group");
                stores.add(Map.of("ip",pc,"target",target,"width",1,"value",c[6]&255,"addressing","RIP_RELATIVE","outside_selected_region",true));
            }else if(row.hex().equals("5d")){require(++pops<=1,"Multiple stack pops unsupported");stack.add("POP_RBP_READS_STACK");
            }else if(row.hex().equals("c3")){stack.add("RET_READS_STACK");report.put("checked",true);report.put("return_ip",pc);
                report.put("live_boundary_registers_consumed",false);report.put("boundary_values_live_at_return",helper.get("boundary_values_live_at_return"));
                report.put("contract","Entry immediately after the checked helper returns; unchanged code; valid readable return stack, any saved rbp slot and writable RIP store targets; stack/code/group/store alias interactions excluded; no asynchronous events");break;
            }else throw new IllegalArgumentException("Unsupported continuation instruction at 0x"+Long.toHexString(pc)+": "+row.hex());
            pc=row.next();}
            if(!Boolean.TRUE.equals(report.get("checked")))report.put("reason","Continuation exceeds 16 instructions");
        }catch(IllegalArgumentException|ArithmeticException failure){report.put("reason",failure.getMessage());}
        report.put("executed_ips",executed);report.put("constant_byte_stores",stores);report.put("stack_effects",stack);
        report.put("caller_above_return_unproved",true);return report;
    }
}
