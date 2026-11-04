package org.binarycachelab.workflow;

import java.util.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Explicit counterfactual experiments on the bundled fixture, never safe-rewrite approval. */
public final class FixtureExperiment {
    public static final String ORIGINAL_SHA256="8ead971f2e5dc227d07af0a2d09d0955c6187ab4f371deaab36c35f829cf6c19";
    public static final String REGION_SHA256="28625f27a2f3d7f965ec406e885f2f1050684660b9941c56e95d96c46bcb42f9";
    private static final Set<String> EXPERIMENTAL_OBLIGATIONS=Set.of("BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED");
    private FixtureExperiment(){}
    public static void requireKnownFixture(String originalHash,GroupPlan plan){
        require(ORIGINAL_SHA256.equals(originalHash),"Controlled experiment supports only the bundled original ELF; arbitrary inputs retain the normal safety gate");
        require(plan.address==0x4078&&plan.firstBytes==4&&plan.secondBytes==4&&plan.shift==4,
            "Controlled fixture experiment requires the recorded two-word policy");
        require(plan.first.equals("L_.data_0x4078")&&plan.second.equals("L_.data_0x407c")&&plan.end.equals("L_.data_END"),
            "Controlled fixture experiment requires the declared fixture labels");
    }
    public static void requireKnownObligations(Map<String,Object> coverage){
        require(coverage.get("hazards") instanceof List<?>,"Missing instruction hazard list");
        for(Object hazard:(List<?>)coverage.get("hazards"))
            require(EXPERIMENTAL_OBLIGATIONS.contains(hazard.toString()),"Additional hazard is outside the controlled fixture experiment: "+hazard);
    }
    public static Map<String,Object> record(){
        return Map.of("schema","bcl-controlled-fixture-1","original_sha256",ORIGINAL_SHA256,
            "accepted_unresolved_obligations",EXPERIMENTAL_OBLIGATIONS.stream().sorted().toList(),
            "scope","Explicit hypothesis test on one pinned fixture, including an intentionally violating layout; not general safe rewriting",
            "automatic_rewrite_allowed",false,"whole_program_safety_proved",false);
    }
}
