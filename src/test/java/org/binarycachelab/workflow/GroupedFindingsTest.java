package org.binarycachelab.workflow;
import java.util.*;
import java.io.*;
public final class GroupedFindingsTest {
    static int checks;
    static void check(boolean okay,String message){checks++;if(!okay)throw new AssertionError(message);}
    static List<Map<String,Object>> group(List<Map<String,Object>> rows,int limit)throws Exception {
        StringBuilder json=new StringBuilder();for(var row:rows)json.append(Json.write(row)).append('\n');
        return EvidenceView.comparisons(new BufferedReader(new StringReader(json.toString())),limit);
    }
    public static void main(String[] args)throws Exception {
        Map<String,Object> row=new LinkedHashMap<>();
        row.put("baseline_variant","baseline");row.put("transformed_variant","transformed");row.put("input_case","secret0");row.put("repetition",0L);
        row.put("classification","ADDRESS_CHANGED");row.put("rule_id","TRACE-001");row.put("rule_violated",false);
        for(String side:List.of("baseline","transformed")){
            row.put(side+"_ip",0x401000L);row.put(side+"_address",0x403000L);row.put(side+"_lines",List.of(0x403000L));
            row.put(side+"_operation","READ");row.put(side+"_width",4L);row.put(side+"_region",Map.of("name","group","offset",0L));
            row.put(side+"_trace_ref",Map.of("path","traces/"+side+".jsonl","line",10L));
        }
        var other=new LinkedHashMap<>(row);other.put("classification","CACHE_LINE_CHANGED");
        var result=group(List.of(row,other),100);
        check(result.size()==1,"Same access shown twice");
        String card=String.join("\n",EvidenceView.card(result.get(0)));
        check(card.contains("FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED"),"Finding omitted: "+card);
        check(row.get("classification").equals("ADDRESS_CHANGED")&&!row.containsKey("classifications"),"Evidence mutated");
        other.put("repetition",1L);check(group(List.of(row,other),100).size()==2,"Runs merged");other.put("repetition",0L);
        other.put("input_case","secret1");check(group(List.of(row,other),100).size()==2,"Secrets merged");other.put("input_case","secret0");
        other.put("transformed_trace_ref",Map.of("path","traces/transformed.jsonl","line",11L));check(!EvidenceView.sameAccess(row,other),"Loop events merged");
        other.put("transformed_trace_ref",row.get("transformed_trace_ref"));other.put("rule_violated",true);
        check(String.join("\n",EvidenceView.card(group(List.of(row,other),100).get(0))).contains("VIOLATION"),"Violation lost");
        other.put("rule_violated",null);check(String.join("\n",EvidenceView.card(group(List.of(row,other),100).get(0))).contains("INCONCLUSIVE"),"Unknown promoted");
        other.put("rule_id","TRACE-LINE-001");check(!EvidenceView.sameAccess(row,other),"Rules merged");other.put("rule_id","TRACE-001");
        check(((List<?>)group(List.of(row,other),1).get(0).get("classifications")).size()==2,"Limit hid second finding");
        var noRef=new LinkedHashMap<>(row);noRef.remove("baseline_trace_ref");noRef.remove("transformed_trace_ref");check(!EvidenceView.sameAccess(noRef,noRef),"Identity guessed without refs");
        List<Map<String,Object>> matrix=new ArrayList<>();
        for(int secret=0;secret<2;secret++)for(int repeat=0;repeat<2;repeat++)for(int pair=0;pair<3;pair++){
            var item=new LinkedHashMap<>(row);item.put("pair","pair"+pair);item.put("input_case","secret"+secret);item.put("repetition",repeat);item.put("classification",pair==0?"PRESERVED":"ADDRESS_CHANGED");
            matrix.add(item);if(pair>0){var changed=new LinkedHashMap<>(item);changed.put("classification","CACHE_LINE_CHANGED");matrix.add(changed);}
        }
        check(matrix.size()==20&&group(matrix,100).size()==12,"Expected 12 grouped cards for 20 findings");
        System.out.println("All "+checks+" grouped-finding checks passed.");
    }
}
