package org.binarycachelab.analysis;

import java.util.*;
import java.util.regex.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Restricted objdump RIP-relative inventory. Counts/targets are not control-flow equivalence. */
public final class DirectReadInventory {
    private DirectReadInventory(){}
    public static Map<String,Object> inspect(String disassembly,long start,long size){
        require(start>=0&&size>0&&start<=Long.MAX_VALUE-size,"Invalid direct-reference span");long end=start+size;
        List<Map<String,Object>> reads=new ArrayList<>(),flags=new ArrayList<>();List<String> undecoded=new ArrayList<>();long decoded=0;
        Pattern row=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
        Pattern memory=Pattern.compile("\\[rip(?:([+-])0x([0-9a-fA-F]+))?\\]",Pattern.CASE_INSENSITIVE);
        Pattern width=Pattern.compile("\\b(BYTE|WORD|DWORD|QWORD) PTR\\b",Pattern.CASE_INSENSITIVE);
        Pattern supported=Pattern.compile("(?:mov|movzx|movsx)\\s+[a-z][a-z0-9]*,\\s*(?:BYTE|WORD|DWORD|QWORD) PTR \\[rip(?:[+-]0x[0-9a-f]+)?\\]",Pattern.CASE_INSENSITIVE);
        for(String line:disassembly.split("\\R")){
            Matcher match=row.matcher(line);if(!match.matches()){if(line.matches("\\s*[0-9a-fA-F]+:.*"))undecoded.add(line);continue;}
            decoded++;long ip=Long.parseLong(match.group(1),16);int length=match.group(2).trim().split("\\s+").length;
            String code=match.group(3).split("#",2)[0].trim();if(code.contains("(bad)")||code.startsWith(".byte"))undecoded.add(line);
            Matcher rip=memory.matcher(code);if(!rip.find())continue;
            long displacement=0;
            try{if(rip.group(2)!=null){displacement=Long.parseUnsignedLong(rip.group(2),16);
                if("-".equals(rip.group(1)))displacement=Math.negateExact(displacement);
                else if(displacement>=0x80000000L&&displacement<=0xffffffffL)displacement=(int)displacement;
                require(displacement>=Integer.MIN_VALUE&&displacement<=Integer.MAX_VALUE,"Unsupported RIP displacement");}}
            catch(IllegalArgumentException|ArithmeticException invalid){undecoded.add(line);continue;}
            long target;try{target=Math.addExact(Math.addExact(ip,length),displacement);}catch(ArithmeticException error){undecoded.add(line);continue;}
            Matcher w=width.matcher(code);int bytes=0;if(w.find())bytes=switch(w.group(1).toUpperCase(Locale.ROOT)){case "BYTE"->1;case "WORD"->2;case "DWORD"->4;default->8;};
            if(target<0||target>Long.MAX_VALUE-Math.max(1,bytes)){undecoded.add(line);continue;}
            if(target>=end||target+Math.max(1,bytes)<=start)continue;
            Map<String,Object> entry=Map.of("ip",ip,"target",target,"offset",target-start,"width_bytes",bytes,"instruction",code);
            if(supported.matcher(code).matches()&&bytes>0&&target>=start&&target+bytes<=end)reads.add(entry);else flags.add(entry);
        }
        return Map.of("schema","java-direct-read-inventory-1","decoded_instruction_rows",decoded,"reads",reads,"unsupported_or_crossing",flags,
            "undecoded_rows",undecoded,"reference_coverage","INCOMPLETE","automatic_rewrite_allowed",false,
            "limitations",List.of("Only decoded RIP-relative operands are considered","Matching offset/width counts is not instruction/control-flow correspondence","Computed, absolute and overlapping/undecoded references remain unresolved"));
    }
    public static Map<String,Long> signature(Map<String,Object> report){Map<String,Long> counts=new TreeMap<>();
        for(Object value:(List<?>)report.get("reads")){Map<?,?> row=(Map<?,?>)value;String key=row.get("offset")+"/"+row.get("width_bytes");counts.merge(key,1L,Long::sum);}return counts;}
    public static boolean supported(Map<String,Object> report){return !((List<?>)report.get("reads")).isEmpty()&&((List<?>)report.get("unsupported_or_crossing")).isEmpty()&&((List<?>)report.get("undecoded_rows")).isEmpty();}
}
