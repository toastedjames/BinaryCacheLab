package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.analysis.*;

/** Separates structural policy applicability from unresolved transformation safety. */
public final class EligibilityAssessment {
    private EligibilityAssessment(){}
    public static Map<String,Object> withReferences(Map<String,Object> assessment,Map<String,Object> coverage){
        Map<String,Object> result=new LinkedHashMap<>(assessment);List<String> hazards=new ArrayList<>();
        for(Object row:(List<?>)assessment.get("hazards"))hazards.add(row.toString());
        for(Object row:(List<?>)coverage.get("hazards"))hazards.add(row.toString());
        result.put("instruction_reference_coverage",coverage);result.put("hazards",hazards.stream().distinct().toList());
        result.put("safe_to_transform",false);result.put("automatic_rewrite_allowed",false);result.put("reference_coverage","INCOMPLETE");
        result.put("research_fixture_checks_passed",hazards.isEmpty());
        result.put("decision",hazards.isEmpty()?"INCONCLUSIVE_REFERENCE_COVERAGE":"REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS");
        result.put("next_action",hazards.isEmpty()?"Resolve the enumerated reference obligations before general rewriting; only explicit controlled research may proceed":"Reject transformation: resolve the enumerated instruction/metadata hazards first");
        return result;
    }
    public static Map<String,Object> assess(Path binary,String assembly,GroupPlan plan)throws IOException{
        Map<String,Object> policy=plan.manifest(assembly);var dynamic=ElfRegionAudit.audit(binary,plan.address,plan.size());
        Map<String,Object> metadata=ElfMetadata.read(binary).audit(plan.address,plan.size());List<String> hazards=new ArrayList<>();
        if(!dynamic.regionSha256().equals(policy.get("region_sha256")))hazards.add("ORIGINAL_ASSEMBLY_REGION_BYTES_DISAGREE");
        if(dynamic.relocations().stream().anyMatch(r->r.writeOverlap()||r.interiorTarget()))hazards.add("DYNAMIC_RELOCATION_REGION_HAZARD");
        if(dynamic.relocations().stream().anyMatch(r->r.width()<0)||dynamic.blockers().stream().anyMatch(x->x.startsWith("DT_REL")))hazards.add("UNSUPPORTED_DYNAMIC_RELOCATION_COVERAGE");
        hazards.addAll(ElfMetadata.detectedHazards(metadata));
        List<String> missing=new ArrayList<>(List.of("COMPLETE_REFERENCE_AND_ALIAS_COVERAGE","CONTROL_FLOW_AND_ABI_CORRESPONDENCE",
            "RUNTIME_LOADER_AND_EXTERNAL_CODE_BEHAVIOR","GENERAL_FUNCTIONAL_EQUIVALENCE"));
        Map<String,Object> result=new LinkedHashMap<>();result.put("schema","java-eligibility-1");
        result.put("decision",hazards.isEmpty()?"INCONCLUSIVE_REFERENCE_COVERAGE":"REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS");
        result.put("safe_to_transform",false);result.put("automatic_rewrite_allowed",false);result.put("reference_coverage","INCOMPLETE");
        result.put("structural_policy_applicable",true);result.put("research_fixture_checks_passed",hazards.isEmpty());result.put("hazards",hazards);
        result.put("unestablished_obligations",missing);result.put("policy",policy);result.put("dynamic_relocations",Json.object(dynamic.json()));result.put("elf_metadata",metadata);
        result.put("conditional_layout_argument","If all selected accesses stay within the declared adjacent bytes and their references are correctly rebound, retaining region-relative byte offsets and start modulo 64 retains the group's virtual-line partition. These hypotheses are not complete semantic/reference proofs.");
        result.put("next_action",hazards.isEmpty()?"Only an explicitly opted-in controlled research experiment may proceed; no general safe rewrite authorization":"Reject the proposed transformation until the recorded hazards are resolved");return result;
    }
}
