package org.binarycachelab.workflow;

import java.util.*;

public final class EvidenceViewTest {
    public static void main(String[] args){
        Map<String,Object> row=new LinkedHashMap<>();row.put("baseline_variant","baseline");row.put("transformed_variant","transformed");row.put("input_case","secret0");row.put("repetition",0L);
        row.put("classification","ADDRESS_CHANGED");row.put("rule_id","TRACE-001");row.put("rule_violated",false);row.put("correspondence","region_offset_context");
        for(String side:List.of("baseline","transformed")){row.put(side+"_ip",0x555555555147L);row.put(side+"_address",0x555555558078L);row.put(side+"_lines",List.of(0x555555558040L));row.put(side+"_operation","READ");row.put(side+"_width",4L);row.put(side+"_region",Map.of("name","group","offset",4L));}
        var card=EvidenceView.card(row);String text=String.join("\n",card);
        if(card.size()>15||card.stream().anyMatch(line->line.length()>76))throw new AssertionError("Card wraps or scrolls");
        for(String expected:List.of("0x555555558040","Baseline -> Transformed","PERMITTED","group +0x4","READ / 4 B"))if(!text.contains(expected))throw new AssertionError(expected);
        if(text.contains("938249")||text.contains("('group'")||text.contains("beyond this correspondence"))throw new AssertionError("Raw/repetitive serialization leaked into display");
        row.put("rule_violated",true);if(!String.join("\n",EvidenceView.card(row)).contains("VIOLATION"))throw new AssertionError("Violation hidden");
        row.put("rule_violated",null);if(!String.join("\n",EvidenceView.card(row)).contains("INCONCLUSIVE"))throw new AssertionError("Unknown match promoted");
        String structure=EvidenceView.structured(Map.of("security_assessment",Map.of("status","NOT_ASSESSED")));
        if(!structure.contains("security assessment:")||structure.contains("{"))throw new AssertionError("Raw JSON displayed");
        System.out.println("All 10 evidence presentation checks passed.");
    }
}
