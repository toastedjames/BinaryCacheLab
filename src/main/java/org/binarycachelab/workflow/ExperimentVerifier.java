package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.analysis.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Offline verification binds final linked files to checksummed collection evidence and Java replay. */
public final class ExperimentVerifier {
    private ExperimentVerifier(){}
    public static Map<String,Object> assessReferences(Path root)throws IOException{
        EvidenceTree tree=new EvidenceTree(root);Map<String,Object> resolved=tree.object("resolved-config.json");
        StringBuilder toml=new StringBuilder();for(var entry:resolved.entrySet())toml.append(entry.getKey()).append(" = ").append(Json.write(entry.getValue())).append('\n');
        LabConfig config=LabConfig.parse(tree.root.resolve("bcl.toml"),toml.toString());GroupPlan p=new GroupPlan(config);
        String asm="inputs/program.asm";if(config.bool("lift.enabled")){String name=config.string("input.original").replace('\\','/');name=name.substring(name.lastIndexOf('/')+1);
            require(name.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*"),"Invalid lift input filename");asm="lift/artifacts/nasm/"+name+".asm";}
        var metadata=EligibilityAssessment.assess(tree.covered("inputs/original"),tree.text(asm),p);
        var coverage=ReferenceCoverage.analyze(tree.covered("inputs/original"),tree.text("logs/original-disassembly.log"),p.address,p.size());
        var result=EligibilityAssessment.withReferences(metadata,coverage);Map<String,Object> finalHelpers=new LinkedHashMap<>();
        var originalCallbacks=ElfCallbackInventory.analyze(tree.covered("inputs/original"));
        Map<String,Object> callbackComparisons=new LinkedHashMap<>();
        for(String variant:referenceVariants(tree)){
            Path binary=tree.covered(variant+"/program");long start=ElfMetadata.read(binary).selected(Set.of(p.first,p.second,p.end)).get(p.first);
            Map<String,Object> checked=new LinkedHashMap<>(BoundaryHelperAnalysis.analyze(binary,tree.text("logs/"+variant+"-disassembly.log"),start,p.size()));
            checked.put("caller_analysis",BoundaryCallerAnalysis.analyze(binary,tree.text("logs/"+variant+"-disassembly.log"),start,p.size()));
            finalHelpers.put(variant,checked);
            callbackComparisons.put(variant,ElfCallbackInventory.compareSources(originalCallbacks,ElfCallbackInventory.analyze(binary)));
        }
        result.put("final_boundary_helper_paths",finalHelpers);result.put("callback_metadata_comparisons",callbackComparisons);return result;
    }
    public static Map<String,Object> references(Path root)throws IOException{
        EvidenceTree tree=new EvidenceTree(root);Map<String,Object> resolved=tree.object("resolved-config.json");
        StringBuilder toml=new StringBuilder();for(var entry:resolved.entrySet())toml.append(entry.getKey()).append(" = ").append(Json.write(entry.getValue())).append('\n');
        GroupPlan p=new GroupPlan(LabConfig.parse(tree.root.resolve("bcl.toml"),toml.toString()));
        var original=LinkedReadVerification.verify(tree.covered("inputs/original"),tree.text("logs/original-disassembly.log"),p.address,p.size());
        Map<String,Object> variants=new LinkedHashMap<>();
        for(String variant:referenceVariants(tree)){
            Path binary=tree.covered(variant+"/program");long start=ElfMetadata.read(binary).selected(Set.of(p.first,p.second,p.end)).get(p.first);
            var checked=LinkedReadVerification.verify(binary,tree.text("logs/"+variant+"-disassembly.log"),start,p.size());
            Map<String,Object> evidence=new LinkedHashMap<>(Map.of("linked_reads",checked,"access_correspondence",LinkedReadVerification.correspond(original,checked)));
            try{var left=LinkedReadVerification.lookupKernel(tree.text("logs/original-disassembly.log"),original);
                var right=LinkedReadVerification.lookupKernel(tree.text("logs/"+variant+"-disassembly.log"),checked);
                boolean equalBytes=ElfRegionAudit.audit(tree.covered("inputs/original"),p.address,p.size()).regionSha256().equals(ElfRegionAudit.audit(binary,start,p.size()).regionSha256());
                evidence.put("local_lookup_contract",Map.of("original",left,"rebuilt",right,"comparison",LinkedReadVerification.compareKernels(left,right,equalBytes)));
            }catch(IllegalArgumentException unsupported){evidence.put("local_lookup_contract",Map.of("supported",false,"reason",unsupported.getMessage()));}
            variants.put(variant,evidence);
        }
        return Map.of("schema","java-experiment-references-1","status","DECLARED_READ_ENCODINGS_VERIFIED","original",original,"variants",variants,
            "evidence_manifest_sha256",Stage3Engine.digest(tree.path("SHA256SUMS")),"reference_coverage","INCOMPLETE","automatic_rewrite_allowed",false);
    }
    private static List<String> referenceVariants(EvidenceTree tree)throws IOException{
        return "BASELINE_REBUILD_ONLY".equals(tree.object("summary.json").get("workflow_mode"))?List.of("baseline"):List.of("baseline","shifted","protected");
    }
    public static Map<String,Object> verify(Path root)throws IOException{
        EvidenceTree tree=new EvidenceTree(root);Map<String,Object> summary=tree.object("summary.json"),resolved=tree.object("resolved-config.json");
        require("java-stage3-1".equals(summary.get("schema"))&&"DEMO_EXPECTATIONS_MET".equals(summary.get("status")),"Experiment workflow is incomplete or did not meet its controls");
        if(summary.containsKey("toolkit_version"))require(Files.isRegularFile(tree.root.resolve("completion.json")),"Evidence finalization interrupted; completion marker missing");
        StringBuilder toml=new StringBuilder();for(var entry:resolved.entrySet())toml.append(entry.getKey()).append(" = ").append(Json.write(entry.getValue())).append('\n');
        LabConfig config=LabConfig.parse(tree.root.resolve("bcl.toml"),toml.toString());GroupPlan p=new GroupPlan(config);
        boolean controlled="CONTROLLED_FIXTURE_EXPERIMENT".equals(summary.get("workflow_mode"));
        if(controlled){
            require(config.bool("lift.enabled"),"Controlled experiment must use a fresh lift");
            FixtureExperiment.requireKnownFixture(tree.hashes.get("inputs/original"),p);
            require(normal(FixtureExperiment.record()).equals(summary.get("controlled_fixture_experiment")),"Controlled fixture declaration differs from the supported experiment");
            require(Boolean.FALSE.equals(summary.get("automatic_rewrite_allowed")),"Controlled experiment cannot authorize general rewriting");
        }
        String asmName="inputs/program.asm";
        if(config.bool("lift.enabled")){String original=config.string("input.original").replace('\\','/');String name=original.substring(original.lastIndexOf('/')+1);
            require(name.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*"),"Invalid recorded lift filename");asmName="lift/artifacts/nasm/"+name+".asm";}
        String assembly=tree.text(asmName);Map<String,Object> used=object(summary,"assembly_used");
        require(tree.hashes.get(asmName).equals(used.get("sha256")),"Recorded assembly identity mismatch");
        Map<String,Object> plan=tree.object("plan.json");
        require(p.regionHash(assembly).equals(plan.get("region_sha256"))&&number(plan,"region_bytes")==p.size()
            &&number(plan,"required_line_residue")==p.address%64&&Objects.equals(plan.get("region_symbols"),List.of(p.first,p.second,p.end)),"Recorded transformation plan disagrees with input assembly/configuration");
        String originalHash=tree.hashes.get("inputs/original");
        require(ElfRegionAudit.audit(tree.covered("inputs/original"),p.address,p.size()).regionSha256().equals(p.regionHash(assembly)),"Original group bytes disagree");
        boolean encodingChecks=Boolean.TRUE.equals(summary.get("linked_read_encoding_verification"));
        Map<String,Object> originalEncodings=Map.of();
        if(encodingChecks){originalEncodings=LinkedReadVerification.verify(tree.covered("inputs/original"),tree.text("logs/original-disassembly.log"),p.address,p.size());
            require(normal(originalEncodings).equals(tree.object("original-linked-reads.json")),"Original linked-read encoding report disagrees with ELF");}
        boolean coverageChecks=Boolean.TRUE.equals(summary.get("instruction_reference_coverage_assessed"));
        if(controlled)require(encodingChecks&&coverageChecks,"Controlled experiment requires instruction checks");
        if(coverageChecks){var coverage=ReferenceCoverage.analyze(tree.covered("inputs/original"),tree.text("logs/original-disassembly.log"),p.address,p.size());
            require(normal(coverage).equals(tree.object("original-reference-coverage.json")),"Original reference coverage report disagrees with ELF/disassembly");
            if(controlled)FixtureExperiment.requireKnownObligations(coverage);
            else require(((List<?>)coverage.get("hazards")).isEmpty(),"Original reference hazards reject transformation");}
        if(controlled)require(normal(LinkedReadVerification.lookupKernel(tree.text("logs/original-disassembly.log"),originalEncodings)).equals(tree.object("original-local-kernel.json")),"Original local kernel evidence disagrees with decoded bytes");
        CallbackLiftPlan callbacks=controlled?new CallbackLiftPlan(tree.covered("inputs/original")):null;
        List<Map<String,Object>> verified=new ArrayList<>();Map<String,Object> variants=object(summary,"variants");
        for(String variant:List.of("baseline","shifted","protected")){
            Map<String,Object> declared=object(variants,variant);Path binary=tree.covered(variant+"/program");String binaryHash=tree.hashes.get(variant+"/program");
            require(binaryHash.equals(declared.get("binary_sha256")),"Final linked binary identity changed: "+variant);
            Map<String,Long> labels=ElfMetadata.read(binary).selected(Set.of(p.first,p.second,p.end));
            long a=labels.get(p.first),b=labels.get(p.second),end=labels.get(p.end);
            require(a==number(declared,"first_address")&&b==number(declared,"second_address")&&end==number(declared,"end_address"),"Recorded linked addresses disagree with actual ELF symbols");
            require(b-a==p.firstBytes&&end-b==p.secondBytes,"Linked region sizes/spacing changed");
            boolean same=a/64==(end-1)/64;require(variant.equals("shifted")?!same:(same&&a%64==p.address%64),"Final linked layout does not meet its declared control/policy");
            var region=ElfRegionAudit.audit(binary,a,p.size());require(region.regionSha256().equals(p.regionHash(assembly)),"Final linked bytes changed");
            require(ElfMetadata.detectedHazards(ElfMetadata.read(binary).audit(a,p.size())).isEmpty(),"Final linked section/pointer/reference hazard");
            require(region.relocations().stream().noneMatch(r->r.width()<0||r.writeOverlap()||r.interiorTarget())&&region.blockers().stream().noneMatch(x->x.startsWith("DT_REL")),"Final linked relocation hazard");
            if(encodingChecks){var checked=LinkedReadVerification.verify(binary,tree.text("logs/"+variant+"-disassembly.log"),a,p.size());
                require(normal(checked).equals(tree.object(variant+"-linked-reads.json")),"Final linked-read encoding report disagrees with ELF");
                require(normal(LinkedReadVerification.correspond(originalEncodings,checked)).equals(tree.object(variant+"-access-correspondence.json")),"Access-site correspondence disagrees with linked instructions");}
            if(coverageChecks){var coverage=ReferenceCoverage.analyze(binary,tree.text("logs/"+variant+"-disassembly.log"),a,p.size());
                require(normal(coverage).equals(tree.object(variant+"-reference-coverage.json")),"Final reference coverage disagrees with actual ELF/disassembly");
                if(controlled)FixtureExperiment.requireKnownObligations(coverage);
                else require(((List<?>)coverage.get("hazards")).isEmpty(),"Final reference hazards reject transformation");}
            if(controlled){
                require(FixtureExperiment.REGION_SHA256.equals(region.regionSha256()),"Controlled region bytes differ from the fixture");
                var encodings=LinkedReadVerification.verify(binary,tree.text("logs/"+variant+"-disassembly.log"),a,p.size());
                var left=LinkedReadVerification.lookupKernel(tree.text("logs/original-disassembly.log"),originalEncodings);
                var right=LinkedReadVerification.lookupKernel(tree.text("logs/"+variant+"-disassembly.log"),encodings);
                var local=LinkedReadVerification.compareKernels(left,right,true);
                require(normal(local).equals(tree.object(variant+"-local-kernel.json")),"Local kernel report differs from actual instruction bytes");
                require(Boolean.valueOf(!variant.equals("shifted")).equals(local.get("preservation_for_all_selector_pairs_under_contract")),"Unexpected local kernel control result");
                require(normal(callbacks.verifyLinked(binary)).equals(tree.object(variant+"-callback-link-check.json")),"Linked callback evidence differs from final ELF");
            }
            String prefix=variant+"/";Set<String> candidates=new HashSet<>();
            for(String name:tree.hashes.keySet())if(name.startsWith(prefix+"whole-collection-")){String folder=name.substring(prefix.length()).split("/",2)[0];candidates.add(folder);}
            require(candidates.size()==1,"Ambiguous/missing collection for "+variant);String batch=prefix+candidates.iterator().next();
            Map<String,Object> collection=tree.object(batch+"/collection.json");require("complete".equals(collection.get("status")),"Incomplete collection");
            Map<String,Object> settings=tree.object(batch+"/experiment.json"),sources=object(settings,"sources");
            require("whole-collection-1".equals(settings.get("schema"))&&number(settings,"repetitions")==config.number("experiment.repetitions"),"Collection schema/repetitions disagree");
            require(Objects.equals(settings.get("secrets"),List.of("0","1"))&&"single-argv-secret".equals(settings.get("input_transport")),"Collection input contract differs");
            require("empty".equals(object(settings,"public_inputs").get("stdin"))&&Objects.equals(object(settings,"public_inputs").get("other_arguments"),List.of()),"Public inputs differ");
            require("setarch x86_64 -R".equals(settings.get("aslr_request")),"ASLR execution declaration differs");
            Map<String,Object> environment=object(settings,"environment");Map<String,Object> expectedEnvironment=new HashMap<>(Map.of("PATH","/usr/bin:/bin","LC_ALL","C","TZ","UTC","HOME",settings.get("cwd")+"/home"));
            if(config.bool("experiment.eager_binding"))expectedEnvironment.put("LD_BIND_NOW","1");require(environment.equals(expectedEnvironment),"Recorded execution environment differs from supported contract");
            require(Objects.equals(settings.get("binding_request"),config.bool("experiment.eager_binding")?"eager":"loader-default"),"Loader binding declaration differs");
            require(originalHash.equals(object(sources,"original").get("sha256"))&&binaryHash.equals(object(sources,"rebuilt").get("sha256")),"Collected binary provenance differs from verified final files");
            require(originalHash.equals(tree.hashes.get(batch+"/binaries/original"))&&binaryHash.equals(tree.hashes.get(batch+"/binaries/rebuilt")),"Collected binary copies differ from final linked files");
            for(var tool:Map.of("tool","WholeProgramMemoryTracer.so","tool_source","WholeProgramMemoryTracer.cpp").entrySet()){
                String hash=tree.hashes.get(tool.getKey().equals("tool")?"inputs/tracer.so":"inputs/tracer.cpp");
                require(hash!=null&&hash.equals(object(sources,tool.getKey()).get("sha256"))&&hash.equals(tree.hashes.get(batch+"/tool/"+tool.getValue())),"Tracer identity mismatch");}
            WholeTraceAnalysis.Result replay=WholeTraceAnalysis.evaluate(tree.root.resolve(batch),(int)config.number("experiment.repetitions"));
            Map<String,Object> stored=tree.object(variant+"/comparison.json");
            for(String key:List.of("verdict","exit_code","functional_checks","repeat_stability","comparisons","runs","manifest_sha256"))
                require(Objects.equals(normal(stored.get(key)),normal(replay.report().get(key))),"Stored comparison disagrees with independent Java trace replay: "+variant+"/"+key);
            int expected=variant.equals("shifted")?3:0;require(replay.exit()==expected&&number(declared,"checker_exit")==expected&&Objects.equals(declared.get("verdict"),replay.report().get("verdict")),"Unexpected replayed scientific control");
            verified.add(Map.of("variant",variant,"binary_sha256",binaryHash,"linked_symbols_checked_directly",true,
                "trace_replayed_in_java",true,"verdict",replay.report().get("verdict"),"functional_checks",replay.report().get("functional_checks")));
        }
        require(summary.get("stages") instanceof List<?> && ((List<?>)summary.get("stages")).stream().allMatch(x->x instanceof Map<?,?> row&&"PASSED".equals(row.get("status"))),"Failed/incomplete recorded stage");
        Map<String,Object> result=new LinkedHashMap<>(Map.of("schema","java-experiment-verification-1","status","RECORDED_EXPECTATIONS_CONFIRMED","variants",verified,
            "evidence_manifest_sha256",Stage3Engine.digest(tree.path("SHA256SUMS")),"files_checked",tree.hashes.size(),
            "finalization_marker_present",Files.isRegularFile(tree.root.resolve("completion.json")),
            "reference_coverage","INCOMPLETE","automatic_rewrite_allowed",false,
            "assurance","Offline integrity, linked-artifact and finite-trace verification; not execution attestation or a universal safety/security proof"));
        result.put("linked_read_encoding_verification",encodingChecks);result.put("instruction_reference_coverage_assessed",coverageChecks);
        result.put("controlled_fixture_experiment",controlled);result.put("callback_entry_mapping_replayed",controlled);return result;
    }
    private static Object normal(Object value){return Json.read(Json.write(value));}
    @SuppressWarnings("unchecked") public static Map<String,Object> object(Map<String,Object> map,String key){Object value=map.get(key);require(value instanceof Map,"Missing JSON object: "+key);return (Map<String,Object>)value;}
    public static long number(Map<String,Object> map,String key){Object value=map.get(key);require(value instanceof Long,"Missing JSON integer: "+key);return (Long)value;}
}
