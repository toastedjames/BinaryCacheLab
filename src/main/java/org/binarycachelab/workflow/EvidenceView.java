package org.binarycachelab.workflow;

import java.util.*;
import java.io.*;

/** Human presentation only. Every value and decision comes from saved evidence. */
final class EvidenceView {
    private EvidenceView(){}
    static String label(String text){return switch(text){case "references"->"Reference checks";case "functional"->"Functional checks";case "layout"->"Layout checks";case "observations"->"Observation comparison";case "event_correspondence"->"Event matching";case "repeat_stability"->"Repeat stability";default->text.replace('_',' ');};}
    static String name(Object value){String s=String.valueOf(value);return s.isEmpty()?s:Character.toUpperCase(s.charAt(0))+s.substring(1).replace('_',' ');}
    static String status(Object value){return String.valueOf(value).replace('_',' ');}
    static String hex(Object value){return value instanceof Number n?"0x"+Long.toHexString(n.longValue()):"-";}
    static String lines(Object value){if(!(value instanceof List<?> a)||a.isEmpty())return "-";return hex(a.get(0))+(a.size()>1?" (+"+(a.size()-1)+" more)":"");}
    static String region(Object value){if(!(value instanceof Map<?,?> r))return "Unmapped";return r.get("name")+" +"+hex(r.get("offset"));}
    static String access(Map<String,Object> row,String side){Object op=row.get(side+"_operation"),width=row.get(side+"_width");return op==null?"-":op+" / "+width+" B";}
    static String columns(String field,String a,String b){return String.format("%-16s %-27s %s",field,TerminalDashboard.clip(a,26),TerminalDashboard.clip(b,27));}
    static boolean sameAccess(Map<String,Object> a,Map<String,Object> b){
        if(!"TRACE-001".equals(a.get("rule_id"))||!Objects.equals(a.get("rule_id"),b.get("rule_id")))return false;
        if(a.get("baseline_trace_ref")==null&&a.get("transformed_trace_ref")==null)return false;
        for(String field:List.of("pair","input_case","repetition","baseline_variant","transformed_variant","baseline_trace_ref","transformed_trace_ref","baseline_ip","transformed_ip","baseline_address","transformed_address","baseline_lines","transformed_lines","baseline_operation","transformed_operation","baseline_width","transformed_width","baseline_region","transformed_region"))
            if(!Objects.equals(a.get(field),b.get(field)))return false;
        return true;
    }
    static List<Map<String,Object>> comparisons(BufferedReader reader,int limit)throws IOException {
        List<Map<String,Object>> out=new ArrayList<>();Map<String,Object> current=null;String line;
        while((line=reader.readLine())!=null){
            Map<String,Object> row=Json.evidenceObject(line);
            if(current!=null&&sameAccess(current,row)){
                @SuppressWarnings("unchecked") List<String> findings=(List<String>)current.get("classifications");
                String finding=String.valueOf(row.get("classification"));if(!findings.contains(finding))findings.add(finding);
                Object old=current.get("rule_violated"),next=row.get("rule_violated");
                Object combined;if(Boolean.TRUE.equals(old)||Boolean.TRUE.equals(next))combined=Boolean.TRUE;else if(old==null||next==null)combined=null;else combined=Boolean.FALSE;
                current.put("rule_violated",combined);
            }else{
                if(out.size()>=limit)break;
                current=new LinkedHashMap<>(row);current.put("classifications",new ArrayList<>(List.of(String.valueOf(row.get("classification")))));out.add(current);
            }
        }
        return out;
    }
    static List<String> card(Map<String,Object> row){
        String classification=String.valueOf(row.get("classification"));Object violation=row.get("rule_violated");
        List<String> findings=row.get("classifications") instanceof List<?> list?list.stream().map(String::valueOf).toList():List.of(classification);
        String policy=violation==null?"INCONCLUSIVE":Boolean.TRUE.equals(violation)?"VIOLATION":"PERMITTED";
        String reason=switch(classification){
            case "PRESERVED"->"Configured access properties agree.";
            case "ADDRESS_CHANGED"->"The memory address moved.";
            case "CACHE_LINE_CHANGED"->"The observed virtual cache line changed.";
            case "ACCESS_WIDTH_CHANGED"->"The access width changed.";
            case "ACCESS_TYPE_CHANGED"->"The read/write operation changed.";
            case "REGION_MAPPING_CHANGED"->"The logical region or byte offset changed.";
            case "CROSS_LINE_CHANGE"->"Whether the access crosses a cache line changed.";
            case "ORDER_CHANGED"->"Matched accesses occurred in a different order.";
            case "NEW_ACCESS"->"The right-hand trace has an additional access.";
            case "MISSING_ACCESS"->"An access is missing from the right-hand trace.";
            default->"The checker could not establish an unambiguous match.";};
        List<String> out=new ArrayList<>();
        out.add(name(row.get("baseline_variant"))+" -> "+name(row.get("transformed_variant"))+"  |  "+row.get("input_case")+"  |  repeat "+row.get("repetition"));
        out.addAll(TerminalDashboard.wrapped("FINDINGS: "+String.join("; ",findings.stream().map(EvidenceView::status).toList())));out.add("POLICY: "+policy+"    Rule: "+row.get("rule_id"));out.add("");
        out.add(columns("",name(row.get("baseline_variant")),name(row.get("transformed_variant"))));
        out.add(columns("Instruction IP",hex(row.get("baseline_ip")),hex(row.get("transformed_ip"))));
        out.add(columns("Memory address",hex(row.get("baseline_address")),hex(row.get("transformed_address"))));
        out.add(columns("Cache line",lines(row.get("baseline_lines")),lines(row.get("transformed_lines"))));
        out.add(columns("Access",access(row,"baseline"),access(row,"transformed")));
        out.add(columns("Region / offset",region(row.get("baseline_region")),region(row.get("transformed_region"))));
        out.add("");out.add(findings.size()>1?"All listed findings describe this same access pair.":reason);
        return out;
    }
    static String structured(Object value){StringBuilder out=new StringBuilder();format(value,out,0,"");return out.toString();}
    private static void format(Object value,StringBuilder out,int depth,String key){
        String indent="  ".repeat(Math.min(depth,12));
        if(value instanceof Map<?,?> map){if(!key.isEmpty()){out.append(indent).append(label(key)).append(":\n");depth++;}for(var item:map.entrySet())format(item.getValue(),out,depth,String.valueOf(item.getKey()));}
        else if(value instanceof List<?> list){out.append(indent).append(label(key)).append(" (").append(list.size()).append("):\n");int index=0;
            for(Object item:list){if(index==100){out.append(indent).append("  Further items retained in source file.\n");break;}out.append(indent).append("  Item ").append(++index).append(':').append('\n');format(item,out,depth+2,"");}}
        else out.append(indent).append(key.isEmpty()?"":label(key)+": ").append(value==null?"Not available":value).append('\n');
    }
}
