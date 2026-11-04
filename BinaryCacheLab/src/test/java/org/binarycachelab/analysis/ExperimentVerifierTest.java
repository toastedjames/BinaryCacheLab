package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.*;

/** Synthetic complete evidence packets exercise cross-artifact binding, not native correctness. */
public final class ExperimentVerifierTest {
    private static int checks;
    public static void main(String[] args)throws Exception{
        Path temp=Files.createTempDirectory("bcl-experiment-verifier-");
        Path good=fixture(temp,"good");check("RECORDED_EXPECTATIONS_CONFIRMED".equals(ExperimentVerifier.verify(good).get("status")),"Consistent evidence packet rejected");
        Path bad=fixture(temp,"address");Map<String,Object> summary=read(bad.resolve("summary.json"));
        ExperimentVerifier.object(ExperimentVerifier.object(summary,"variants"),"protected").put("first_address",0x40037cL);
        write(bad.resolve("summary.json"),summary);ToolkitEvidenceTest.seal(bad);reject(()->ExperimentVerifier.verify(temp.resolve("address")));
        bad=fixture(temp,"bytes");byte[] binary=Files.readAllBytes(bad.resolve("protected/program"));binary[0x378]=8;Files.write(bad.resolve("protected/program"),binary);
        summary=read(bad.resolve("summary.json"));ExperimentVerifier.object(ExperimentVerifier.object(summary,"variants"),"protected").put("binary_sha256",Stage3Engine.digest(bad.resolve("protected/program")));
        write(bad.resolve("summary.json"),summary);ToolkitEvidenceTest.seal(bad);reject(()->ExperimentVerifier.verify(temp.resolve("bytes")));
        bad=fixture(temp,"verdict");var report=read(bad.resolve("shifted/comparison.json"));report.put("verdict","SATISFIED_FOR_TESTED_PAIR");write(bad.resolve("shifted/comparison.json"),report);
        ToolkitEvidenceTest.seal(bad);reject(()->ExperimentVerifier.verify(temp.resolve("verdict")));
        bad=fixture(temp,"provenance");Path batch=bad.resolve("baseline/whole-collection-synthetic");var settings=read(batch.resolve("experiment.json"));
        ExperimentVerifier.object(ExperimentVerifier.object(settings,"sources"),"rebuilt").put("sha256","0".repeat(64));write(batch.resolve("experiment.json"),settings);
        ToolkitEvidenceTest.seal(batch);ToolkitEvidenceTest.seal(bad);reject(()->ExperimentVerifier.verify(temp.resolve("provenance")));
        bad=fixture(temp,"unsealed");summary=read(bad.resolve("summary.json"));summary.put("toolkit_version","0.4.0-research-preview");write(bad.resolve("summary.json"),summary);
        ToolkitEvidenceTest.seal(bad);reject(()->ExperimentVerifier.verify(temp.resolve("unsealed")));
        Path sealed=fixture(temp,"sealed");summary=read(sealed.resolve("summary.json"));summary.put("toolkit_version","0.4.0-research-preview");write(sealed.resolve("summary.json"),summary);
        ToolkitEvidenceTest.seal(sealed);write(sealed.resolve("completion.json"),Map.of("schema","bcl-evidence-seal-1","manifest_sha256",Stage3Engine.digest(sealed.resolve("SHA256SUMS"))));
        check("RECORDED_EXPECTATIONS_CONFIRMED".equals(ExperimentVerifier.verify(sealed).get("status")),"Finalized evidence marker rejected");
        write(sealed.resolve("completion.json"),Map.of("schema","bcl-evidence-seal-1","manifest_sha256","0".repeat(64)));reject(()->ExperimentVerifier.verify(sealed));
        Path forged=fixture(temp,"forged-controlled-mode");summary=read(forged.resolve("summary.json"));
        summary.put("workflow_mode","CONTROLLED_FIXTURE_EXPERIMENT");summary.put("controlled_fixture_experiment",FixtureExperiment.record());
        write(forged.resolve("summary.json"),summary);ToolkitEvidenceTest.seal(forged);reject(()->ExperimentVerifier.verify(forged));
        System.out.println("All "+checks+" experiment cross-artifact checks passed; synthetic evidence only.");
    }
    private static Path fixture(Path temp,String name)throws Exception{
        Path root=Files.createDirectory(temp.resolve(name));Files.createDirectory(root.resolve("inputs"));
        String assembly="section .data align=64\nfirst:\ndb 07h\ndb 00h\ndb 00h\ndb 00h\nsecond:\ndb 07h\ndb 00h\ndb 00h\ndb 00h\nend:\n";
        Files.writeString(root.resolve("inputs/program.asm"),assembly);Files.write(root.resolve("inputs/original"),ToolkitEvidenceTest.elf());
        Files.write(root.resolve("inputs/tracer.so"),new byte[]{1,2});Files.writeString(root.resolve("inputs/tracer.cpp"),"synthetic tracer identity");
        var base=LabConfig.parse(root.resolve("bcl.toml"),LabApp.sample());var values=new LinkedHashMap<>(base.values);
        values.put("region.first","first");values.put("region.second","second");values.put("region.end","end");values.put("region.address",0x400338L);
        values.put("experiment.repetitions",2L);values.put("experiment.eager_binding",false);
        StringBuilder toml=new StringBuilder();for(var e:values.entrySet())toml.append(e.getKey()).append(" = ").append(Json.write(e.getValue())).append('\n');
        LabConfig config=LabConfig.parse(root.resolve("bcl.toml"),toml.toString());GroupPlan plan=new GroupPlan(config);
        write(root.resolve("resolved-config.json"),values);write(root.resolve("plan.json"),plan.manifest(assembly));
        Map<String,Object> summary=new LinkedHashMap<>();summary.put("schema","java-stage3-1");summary.put("status","DEMO_EXPECTATIONS_MET");
        summary.put("assembly_used",Map.of("sha256",Stage3Engine.digest(root.resolve("inputs/program.asm"))));
        summary.put("stages",List.of(Map.of("name","synthetic-packet","status","PASSED")));Map<String,Object> variants=new LinkedHashMap<>();summary.put("variants",variants);
        String originalHash=Stage3Engine.digest(root.resolve("inputs/original"));
        for(String variant:List.of("baseline","shifted","protected")){
            Path folder=Files.createDirectory(root.resolve(variant));byte[] raw=ToolkitEvidenceTest.elf();ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            int first=variant.equals("shifted")?0x33c:variant.equals("protected")?0x378:0x338;
            Arrays.fill(raw,0x338,0x380,(byte)0);b.putInt(first,7).putInt(first+4,7);
            b.putLong(0x200+24+8,0x400000L+first).putLong(0x200+48+8,0x400004L+first).putLong(0x200+72+8,0x400008L+first);
            b.putLong(0x600+4*64+32,first+8-0x300);Files.write(folder.resolve("program"),raw);String hash=Stage3Engine.digest(folder.resolve("program"));
            Path batch=ToolkitEvidenceTest.batch(folder,"whole-collection-synthetic",false,variant.equals("shifted"));
            Files.createDirectory(batch.resolve("binaries"));Files.copy(root.resolve("inputs/original"),batch.resolve("binaries/original"));Files.copy(folder.resolve("program"),batch.resolve("binaries/rebuilt"));
            Files.createDirectory(batch.resolve("tool"));Files.copy(root.resolve("inputs/tracer.so"),batch.resolve("tool/WholeProgramMemoryTracer.so"));Files.copy(root.resolve("inputs/tracer.cpp"),batch.resolve("tool/WholeProgramMemoryTracer.cpp"));
            Map<String,Object> settings=new LinkedHashMap<>();settings.put("schema","whole-collection-1");settings.put("repetitions",2);settings.put("secrets",List.of("0","1"));settings.put("input_transport","single-argv-secret");
            settings.put("public_inputs",Map.of("stdin","empty","other_arguments",List.of()));settings.put("aslr_request","setarch x86_64 -R");settings.put("binding_request","loader-default");settings.put("cwd","/synthetic/"+variant);
            settings.put("environment",Map.of("PATH","/usr/bin:/bin","LC_ALL","C","TZ","UTC","HOME","/synthetic/"+variant+"/home"));
            settings.put("sources",Map.of("original",Map.of("sha256",originalHash),"rebuilt",Map.of("sha256",hash),
                "tool",Map.of("sha256",Stage3Engine.digest(root.resolve("inputs/tracer.so"))),"tool_source",Map.of("sha256",Stage3Engine.digest(root.resolve("inputs/tracer.cpp")))));
            write(batch.resolve("experiment.json"),settings);write(batch.resolve("collection.json"),Map.of("status","complete"));ToolkitEvidenceTest.seal(batch);
            var result=WholeTraceAnalysis.evaluate(batch,2);write(folder.resolve("comparison.json"),result.report());
            variants.put(variant,Map.of("first_address",0x400000L+first,"second_address",0x400004L+first,"end_address",0x400008L+first,
                "binary_sha256",hash,"checker_exit",result.exit(),"verdict",result.report().get("verdict")));
        }
        write(root.resolve("summary.json"),summary);ToolkitEvidenceTest.seal(root);return root;
    }
    private static Map<String,Object> read(Path file)throws Exception{return Json.object(Files.readString(file));}
    private static void write(Path file,Object value)throws Exception{Files.writeString(file,Json.write(value)+"\n");}
    @FunctionalInterface private interface Checked{void run()throws Exception;}
    private static void reject(Checked task){try{task.run();}catch(Exception expected){checks++;return;}throw new AssertionError("Expected evidence rejection");}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
}
