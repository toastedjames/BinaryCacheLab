package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Bounded, byte-driven interpretation of two constant-address startup idioms. */
public final class BoundaryHelperAnalysis {
    private BoundaryHelperAnalysis(){}
    private record Instruction(long ip,byte[] bytes){}
    public static Map<String,Object> analyze(Path binary,String text,long address,long size)throws IOException{
        require(text.length()<=32*1024*1024&&address>=0&&size>0&&address<=Long.MAX_VALUE-size,"Invalid helper analysis input");
        // Bind the rows to executable ELF bytes before interpreting any helper instruction.
        var binding=LinkedReadVerification.verify(binary,text,address,size);long boundary=address+size;
        Map<Long,Instruction> rows=new TreeMap<>();Pattern pattern=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
        for(String line:text.split("\\R")){Matcher m=pattern.matcher(line);if(m.matches()){long ip=Long.parseLong(m.group(1),16);
            rows.put(ip,new Instruction(ip,HexFormat.of().parseHex(m.group(2).replaceAll("\\s",""))));}}
        List<Map<String,Object>> paths=new ArrayList<>(),unsupported=new ArrayList<>();Set<Long> candidates=new TreeSet<>(),covered=new TreeSet<>();
        for(Instruction ins:rows.values())if(isLea(ins.bytes)&&leaTarget(ins)==boundary)candidates.add(ins.ip);
        for(Instruction ins:rows.values())if(isLea(ins.bytes)&&(ins.bytes[2]&255)==0x3d&&leaTarget(ins)==boundary){
            try{Map<String,Object> path=interpret(rows,ins.ip,boundary);paths.add(path);
                for(Object ip:(List<?>)path.get("boundary_lea_ips"))covered.add(((Number)ip).longValue());}
            catch(IllegalArgumentException|ArithmeticException failure){unsupported.add(Map.of("entry",ins.ip,"reason",failure.getMessage()));}}
        List<Long> missing=candidates.stream().filter(ip->!covered.contains(ip)).toList();
        return Map.ofEntries(Map.entry("schema","java-boundary-helper-analysis-1"),Map.entry("binary_sha256",binding.get("binary_sha256")),
            Map.entry("boundary",boundary),Map.entry("candidate_lea_ips",new ArrayList<>(candidates)),Map.entry("covered_lea_ips",new ArrayList<>(covered)),
            Map.entry("uncovered_lea_ips",missing),Map.entry("paths",paths),Map.entry("unsupported_entries",unsupported),
            Map.entry("all_candidate_paths_checked",!candidates.isEmpty()&&missing.isEmpty()),
            Map.entry("scope","Conditional paths from enumerated entries only; no whole-program entry, caller-register or loader proof"),
            Map.entry("reference_coverage","INCOMPLETE"),Map.entry("automatic_rewrite_allowed",false));
    }
    private static Map<String,Object> interpret(Map<Long,Instruction> rows,long entry,long boundary){
        Long rax=null,rdi=null,rsi=null;Boolean zero=null;long pc=entry;Set<Long> seen=new HashSet<>();
        List<Long> executed=new ArrayList<>(),leas=new ArrayList<>();List<Map<String,Object>> branches=new ArrayList<>();boolean comparison=false,arithmetic=false;
        for(int step=0;step<64;step++){
            require(seen.add(pc),"Repeated helper instruction/loop");Instruction ins=rows.get(pc);require(ins!=null,"Branch/fallthrough does not land on a bound instruction");
            executed.add(pc);byte[] code=ins.bytes;String hex=HexFormat.of().formatHex(code);long next=Math.addExact(pc,code.length);
            if(isLea(code)){long target=leaTarget(ins);int reg=code[2]&255;
                require(target==boundary,"Helper LEA targets differ from the selected boundary");
                if(reg==0x3d)rdi=target;else if(reg==5)rax=target;else rsi=target;leas.add(pc);
            }else if(hex.equals("4839f8")){require(rax!=null&&rdi!=null,"Unknown compare operands");zero=rax.longValue()==rdi.longValue();comparison=true;
            }else if(hex.equals("4829fe")){require(rsi!=null&&rdi!=null,"Unknown subtraction operands");rsi=rsi-rdi;zero=rsi==0;arithmetic=true;
            }else if(hex.equals("4889f0")){require(rsi!=null,"Unknown move operand");rax=rsi;
            }else if(hex.equals("48c1ee3f")){require(rsi!=null,"Unknown shift operand");rsi=rsi>>>63;zero=rsi==0;
            }else if(hex.equals("48c1f803")){require(rax!=null,"Unknown shift operand");rax=rax>>3;zero=rax==0;
            }else if(hex.equals("4801c6")){require(rax!=null&&rsi!=null,"Unknown addition operands");rsi=rsi+rax;zero=rsi==0;
            }else if(hex.equals("48d1fe")){require(rsi!=null,"Unknown shift operand");rsi=rsi>>1;zero=rsi==0;
            }else if(code.length==2&&(code[0]&255)==0x74){require(zero!=null,"Conditional branch depends on unknown flags");long target=Math.addExact(next,(int)code[1]);
                branches.add(Map.of("ip",pc,"zero_flag",zero,"taken",zero,"target",target));if(zero)next=target;
            }else if(code.length==6&&(code[0]&255)==0x0f&&(code[1]&255)==0x84){require(zero!=null,"Conditional branch depends on unknown flags");
                long target=Math.addExact(next,ByteBuffer.wrap(code,2,4).order(ByteOrder.LITTLE_ENDIAN).getInt());
                branches.add(Map.of("ip",pc,"zero_flag",zero,"taken",zero,"target",target));if(zero)next=target;
            }else if(hex.equals("c3")){
                require(leas.size()==2&&branches.size()==1&&(comparison^arithmetic),"Unsupported helper shape");
                Map<String,Long> returned=new TreeMap<>(),live=new TreeMap<>();
                if(rax!=null)returned.put("rax",rax);if(rdi!=null)returned.put("rdi",rdi);if(rsi!=null)returned.put("rsi",rsi);
                for(var value:returned.entrySet())if(value.getValue()==boundary)live.put(value.getKey(),boundary);
                return Map.ofEntries(Map.entry("entry",entry),Map.entry("return_ip",pc),Map.entry("executed_ips",executed),Map.entry("boundary_lea_ips",leas),
                    Map.entry("kind",comparison?"EQUAL_ADDRESS_COMPARE":"ZERO_TABLE_SIZE_ARITHMETIC"),Map.entry("branches",branches),Map.entry("known_registers_at_return",returned),
                    Map.entry("boundary_values_live_at_return",live),Map.entry("selected_region_dereferenced_on_checked_path",false),
                    Map.entry("external_call_or_jump_on_checked_path",false),Map.entry("memory_effects","Only normal ret reads the entry return-stack slot; no explicit memory accesses"),
                    Map.entry("contract","Execution enters at this first LEA; instruction bytes unchanged; uniform nonoverflowing load bias; ordinary x86-64; valid return stack separate from the group; no asynchronous events"),
                    Map.entry("unproved","Other entry paths, callers using live address registers, code/data closure, runtime loader/ABI effects"));
            }else throw new IllegalArgumentException("Unsupported reachable helper instruction at 0x"+Long.toHexString(pc)+": "+hex);
            pc=next;
        }
        throw new IllegalArgumentException("Helper path exceeds 64 instructions");
    }
    private static boolean isLea(byte[] code){return code.length==7&&(code[0]&255)==0x48&&(code[1]&255)==0x8d&&Set.of(5,0x35,0x3d).contains(code[2]&255);}
    private static long leaTarget(Instruction ins){return Math.addExact(Math.addExact(ins.ip,7),ByteBuffer.wrap(ins.bytes,3,4).order(ByteOrder.LITTLE_ENDIAN).getInt());}
}
