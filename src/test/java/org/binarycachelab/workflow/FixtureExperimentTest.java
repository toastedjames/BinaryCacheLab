package org.binarycachelab.workflow;

import java.nio.file.*;
import java.util.*;

/** No native runs: guards must never turn the controlled fixture into a general bypass. */
public final class FixtureExperimentTest {
    private static int checks;
    public static void main(String[] args)throws Exception{
        Path config=Path.of("fixture-test.toml");
        String sample=LabApp.sample();
        GroupPlan plan=new GroupPlan(LabConfig.parse(config,sample));
        FixtureExperiment.requireKnownFixture(FixtureExperiment.ORIGINAL_SHA256,plan);checks++;
        reject(()->FixtureExperiment.requireKnownFixture("0".repeat(64),plan));
        reject(()->FixtureExperiment.requireKnownFixture(FixtureExperiment.ORIGINAL_SHA256,new GroupPlan(LabConfig.parse(config,sample.replace("0x4078","0x4178")))));
        reject(()->FixtureExperiment.requireKnownFixture(FixtureExperiment.ORIGINAL_SHA256,new GroupPlan(LabConfig.parse(config,sample.replace("first_bytes = 4","first_bytes = 3")))));
        FixtureExperiment.requireKnownObligations(Map.of("hazards",List.of()));checks++;
        FixtureExperiment.requireKnownObligations(Map.of("hazards",List.of("BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED")));checks++;
        reject(()->FixtureExperiment.requireKnownObligations(Map.of("hazards",List.of("DYNAMIC_RELOCATION_REGION_HAZARD"))));
        reject(()->FixtureExperiment.requireKnownObligations(Map.of("hazards",List.of("BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED","UNSUPPORTED_INSTRUCTION"))));
        reject(()->FixtureExperiment.requireKnownObligations(Map.of()));
        check(Boolean.FALSE.equals(FixtureExperiment.record().get("automatic_rewrite_allowed")),"Controlled mode approved rewriting");
        check(Boolean.FALSE.equals(FixtureExperiment.record().get("whole_program_safety_proved")),"Controlled mode claimed safety");
        var assessment=EligibilityAssessment.withReferences(Map.of("hazards",List.of()),Map.of("hazards",List.of("BOUNDARY_HELPER_CALLER_CONTRACT_UNPROVED")));
        check("REJECTED_KNOWN_HAZARD_OR_UNSUPPORTED_ANALYSIS".equals(assessment.get("decision")),"Normal assessment was relaxed");
        check(Boolean.FALSE.equals(assessment.get("research_fixture_checks_passed")),"Normal run gate was relaxed");
        System.out.println("All "+checks+" controlled-fixture scope checks passed.");
    }
    private static void reject(Runnable work){try{work.run();}catch(IllegalArgumentException expected){checks++;return;}throw new AssertionError("Expected rejection");}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
}
