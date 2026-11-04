package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import org.binarycachelab.analysis.ElfRegionAudit;
import org.binarycachelab.analysis.ElfMetadata;
import org.binarycachelab.analysis.WholeTraceAnalysis;
import org.binarycachelab.analysis.DirectReadInventory;
import org.binarycachelab.analysis.LinkedReadVerification;
import org.binarycachelab.analysis.ReferenceCoverage;
import static org.binarycachelab.workflow.LabConfig.require;

/** Java planning/build/verification engine with explicit existing Python PIN adapters. */
public final class Stage3Engine {
    public final LabConfig config;
    public volatile String status="IDLE";
    public volatile Path experiment, activeLog;
    private volatile boolean cancelled;
    private volatile Process process;
    private final Consumer<String> events;
    private final List<Map<String,Object>> stages=new ArrayList<>();
    private final List<Map<String,Object>> commands=new ArrayList<>();
    private final Map<String,Object> summary=new LinkedHashMap<>();
    public Stage3Engine(LabConfig c,Consumer<String> events){config=c;this.events=events;}
    public void cancel(){cancelled=true;Process p=process;if(p!=null)stop(p);}
    private static void stop(Process p){var children=p.descendants().toList();
        for(int i=children.size()-1;i>=0;i--)children.get(i).destroyForcibly();p.destroyForcibly();}
    public List<String> diagnostics() {
        List<String> out=new ArrayList<>();
        out.add("Java "+System.getProperty("java.version")+"; "+System.getProperty("os.name")+" "+System.getProperty("os.arch"));
        for(String key:List.of("input.original","input.assembly","input.helper","tools.pin","tools.tracer","tools.tracer_source"))
            out.add((Files.isRegularFile(config.path(key))?"OK ":"MISSING ")+key+" = "+config.path(key));
        for(String name:List.of("collect_whole.py","whole_trace_check.py"))
            out.add((Files.isRegularFile(config.path("tools.backend").resolve(name))?"OK ":"MISSING ")+"backend/"+name);
        out.add("Research mode: "+config.bool("experiment.research_mode")+"; full reference coverage NOT established");
        out.add("Tool executability/version is checked on Linux at run time; no tools executed by this diagnostic.");return out;
    }
    public Map<String,Object> plan() throws IOException {
        GroupPlan p=new GroupPlan(config);String assembly=Files.readString(config.path("input.assembly"));return p.manifest(assembly);
    }
    public Map<String,Object> assess()throws IOException{return EligibilityAssessment.assess(config.path("input.original"),Files.readString(config.path("input.assembly")),new GroupPlan(config));}
    private List<String> docker(String...args){List<String> command=new ArrayList<>();if(config.bool("tools.docker_sudo"))command.addAll(List.of("sudo","-n","--"));
        command.add(config.string("tools.docker"));command.addAll(List.of(args));return command;}
    public int run() {return run(false,false);}
    public int rebuild() {return run(true,false);}
    public int demoFixture() {return run(false,true);}
    private int run(boolean baselineOnly,boolean controlledFixture) {
        try {
            require(System.getProperty("os.name").equals("Linux"),"Execution requires Linux x86-64; diagnostics/planning work elsewhere");
            require(Set.of("amd64","x86_64").contains(System.getProperty("os.arch")),"Require x86-64 host");
            require(config.bool("experiment.research_mode"),"General safe rewriting unavailable. This controlled fixture requires explicit research_mode=true.");
            for(String key:List.of("input.original","input.assembly","input.helper","tools.pin","tools.tracer","tools.tracer_source"))
                require(Files.isRegularFile(config.path(key)),"Missing "+key+": "+config.path(key));
            require(Files.isExecutable(config.path("input.original"))&&Files.isExecutable(config.path("tools.pin")),"Original/PIN must be executable");
            Map<String,Object> plan=plan();
            if(controlledFixture){
                require(config.bool("lift.enabled"),"Fresh controlled demonstration requires FoxDec lifting enabled");
                FixtureExperiment.requireKnownFixture(digest(config.path("input.original")),new GroupPlan(config));
            }
            Files.createDirectories(config.path("project.output"));
            experiment=Files.createTempDirectory(config.path("project.output"),"stage3-").toAbsolutePath();
            Files.createDirectories(experiment.resolve("logs"));Files.createDirectories(experiment.resolve("inputs/backend"));
            summary.put("schema","java-stage3-1");summary.put("started_utc",Instant.now().toString());
            summary.put("toolkit_version",org.binarycachelab.BinaryCacheLabCli.VERSION);
            summary.put("workflow_mode",baselineOnly?"BASELINE_REBUILD_ONLY":controlledFixture?"CONTROLLED_FIXTURE_EXPERIMENT":"LAYOUT_EXPERIMENT");
            if(controlledFixture)summary.put("controlled_fixture_experiment",FixtureExperiment.record());
            summary.put("reference_coverage","INCOMPLETE");summary.put("automatic_rewrite_allowed",false);
            summary.put("assurance","Controlled layout-policy demonstration; empirical preservation for tested inputs only");
            if(baselineOnly)summary.put("assurance","Baseline rebuild and callback metadata checks only; no program execution, observation verdict or semantic-equivalence proof");
            summary.put("lifting",config.bool("lift.enabled")?"foxdec-v0.7-container adapter requested":"Pre-lifted FoxDec NASM input supplied; fresh FoxDec invocation not performed");
            summary.put("stages",stages);summary.put("commands",commands);persist("RUNNING");
            events.accept("Experiment: "+experiment);
            stage("snapshot",()->{
                save("resolved-config.json",config.values);Files.copy(config.file,experiment.resolve("bcl.toml"));save("plan.json",plan);
                Map<String,Object> hashes=new LinkedHashMap<>();
                Map<String,String> inputs=Map.of("input.original","original","input.assembly","program.asm","input.helper","helper.c",
                    "tools.tracer","tracer.so","tools.tracer_source","tracer.cpp");
                for(var e:inputs.entrySet()){
                    Path dest=experiment.resolve("inputs/"+e.getValue());Files.copy(config.path(e.getKey()),dest,StandardCopyOption.COPY_ATTRIBUTES);
                    String hash=digest(dest);require(hash.equals(digest(config.path(e.getKey()))),"Input changed while copying");
                    hashes.put(e.getKey(),Map.of("source",config.path(e.getKey()).toString(),"sha256",hash));
                }
                for(String name:List.of("collect_whole.py","whole_trace_check.py")){
                    Path from=config.path("tools.backend").resolve(name),dest=experiment.resolve("inputs/backend/"+name);
                    Files.copy(from,dest);hashes.put(name,Map.of("source",from.toString(),"sha256",digest(dest)));
                }
                hashes.put("pin",Map.of("path",config.path("tools.pin").toString(),"sha256",digest(config.path("tools.pin"))));save("input-provenance.json",hashes);
            });
            GroupPlan initialPlan=new GroupPlan(config);
            summary.put("assembly_used",Map.of("path",experiment.resolve("inputs/program.asm").toString(),"sha256",digest(experiment.resolve("inputs/program.asm"))));
            stage("input-elf-validation",()->audit("input",experiment.resolve("inputs/original"),initialPlan.address,initialPlan));
            CallbackLiftPlan callbackPlan=new CallbackLiftPlan(experiment.resolve("inputs/original"));
            save("callback-lift-plan.json",callbackPlan.manifest());
            stage("metadata-eligibility",()->{
                var assessment=EligibilityAssessment.assess(experiment.resolve("inputs/original"),Files.readString(experiment.resolve("inputs/program.asm")),initialPlan);
                save("eligibility.json",assessment);summary.put("eligibility_decision",assessment.get("decision"));
                require(Boolean.TRUE.equals(assessment.get("research_fixture_checks_passed")),"Transformation rejected by eligibility assessment; see eligibility.json");
            });
            stage("tool-versions",()->{
                execute("gcc-version",List.of("gcc","--version"),30,Set.of(0));
                execute("nasm-version",List.of("nasm","-v"),30,Set.of(0));
                execute("nm-version",List.of("nm","--version"),30,Set.of(0));
                execute("objdump-version",List.of("objdump","--version"),30,Set.of(0));
                execute("python-version",List.of(config.string("tools.python"),"--version"),30,Set.of(0));
            });
            final Path[] assemblyPath={experiment.resolve("inputs/program.asm")};
            final Path[] helperPath={experiment.resolve("inputs/helper.c")};
            if(config.bool("lift.enabled"))stage("foxdec-lift",()->{
                String name=config.path("input.original").getFileName().toString();
                require(name.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*"),"FoxDec container adapter requires a plain input filename");
                require(!experiment.toString().contains(":"),"Container bind paths containing ':' unsupported");
                Path binaryDir=experiment.resolve("lift/binary"),artifacts=experiment.resolve("lift/artifacts");
                Files.createDirectories(binaryDir);Files.createDirectories(artifacts);
                Files.copy(experiment.resolve("inputs/original"),binaryDir.resolve(name),StandardCopyOption.COPY_ATTRIBUTES);
                Files.writeString(binaryDir.resolve(name+".entry"),callbackPlan.entries(),StandardOpenOption.CREATE_NEW);
                execute("foxdec-image",docker("image","inspect",config.string("lift.image"),"--format","{{.Id}}"),30,Set.of(0));
                String imageId=Files.readString(activeLog).trim();require(imageId.matches("sha256:[0-9a-f]{64}"),"Invalid FoxDec image identity");
                summary.put("foxdec_image_id",imageId);
                String script="set -euo pipefail; command -v ghc; ghc --numeric-version; cd /FoxDec/foxdec_v0.7; WORK=$(mktemp -d ./examples/bcl-XXXXXXXX); "+
                    "cp /binary/"+name+" \"$WORK/"+name+"\"; cp /binary/"+name+".entry \"$WORK/"+name+".entry\"; cabal run foxdec-exe -- -c ./config/config.dhall -d \"$WORK/\" -n "+name+
                    " -i BINARY --Gmetrics --Gcallgraph --Gfuncs --GNASM; cp -R --no-preserve=mode,ownership \"$WORK/.\" /artifacts/; chmod -R a+rX /artifacts/";
                String container="bcl-foxdec-"+UUID.randomUUID();summary.put("foxdec_container_name",container);
                try{execute("foxdec-lift",docker("run","--rm","--name",container,"--entrypoint","/bin/bash","-v",binaryDir+":/binary:ro","-v",artifacts+":/artifacts",
                    imageId,"-c",script),config.number("lift.timeout"),Set.of(0));}
                catch(Exception failure){cleanupContainer(container);throw failure;}
                Path fresh=artifacts.resolve("nasm/"+name+".asm"),mapping=artifacts.resolve("nasm/"+name+".asm.json");
                Path helper=artifacts.resolve("nasm/__gmon_start__.c"),metrics=artifacts.resolve(name+".metrics.txt");
                for(Path f:List.of(fresh,mapping,helper,metrics))require(Files.isRegularFile(f)&&Files.size(f)>0,"Incomplete FoxDec output: "+f);
                validateFoxDecMetrics(Files.readString(metrics));
                Object metadata=Json.read(Files.readString(mapping));
                require(metadata instanceof List<?> && !((List<?>)metadata).isEmpty(),"Missing FoxDec generated function metadata");
                for(Object item:(List<?>)metadata)require(item instanceof Map<?,?> function && function.get("name") instanceof String &&
                    function.get("blocks") instanceof List<?> blocks && !blocks.isEmpty() && function.get("control_flow") instanceof List<?>,"Malformed FoxDec NASM metadata");
                new GroupPlan(config).validateAssembly(Files.readString(fresh));
                assemblyPath[0]=fresh;helperPath[0]=helper;
                summary.put("lifting","Fresh FoxDec v0.7-compatible container invocation completed; partial-output checks passed; not complete binary coverage");
                summary.put("generated_nasm_metadata",Map.of("path",mapping.toString(),"sha256",digest(mapping),
                    "scope","Generated function/block metadata; not an original-to-rebuilt address correspondence proof"));
            });
            GroupPlan p=new GroupPlan(config);String asm=Files.readString(assemblyPath[0]);
            stage("lifted-callback-definitions",()->callbackPlan.validateAssembly(asm));
            summary.put("assembly_used",Map.of("path",assemblyPath[0].toString(),"sha256",digest(assemblyPath[0])));
            save("plan.json",p.manifest(asm));
            stage("original-region-audit",()-> audit("original",experiment.resolve("inputs/original"),p.address,p));
            var originalReads=new java.util.concurrent.atomic.AtomicReference<Map<String,Object>>(Map.of());
            var originalEncodings=new java.util.concurrent.atomic.AtomicReference<Map<String,Object>>(Map.of());
            stage("original-instruction-inventory",()->{
                execute("original-disassembly",List.of("objdump","-d","-w","-Mintel",experiment.resolve("inputs/original").toString()),30,Set.of(0));
                originalReads.set(DirectReadInventory.inspect(Files.readString(activeLog),p.address,p.size()));save("original-instruction-inventory.json",originalReads.get());
            });
            stage("instruction-reference-eligibility",()->{
                String disassembly=Files.readString(experiment.resolve("logs/original-disassembly.log"));
                var coverage=ReferenceCoverage.analyze(experiment.resolve("inputs/original"),disassembly,p.address,p.size());
                save("original-reference-coverage.json",coverage);
                var assessed=EligibilityAssessment.withReferences(Json.object(Files.readString(experiment.resolve("eligibility.json"))),coverage);
                save("eligibility.json",assessed);summary.put("eligibility_decision",assessed.get("decision"));summary.put("instruction_reference_coverage_assessed",true);
                if(controlledFixture)FixtureExperiment.requireKnownObligations(coverage);
                else if(!baselineOnly)require(Boolean.TRUE.equals(assessed.get("research_fixture_checks_passed")),"Instruction reference hazards reject transformation; see eligibility.json");
                originalEncodings.set(LinkedReadVerification.verify(experiment.resolve("inputs/original"),disassembly,p.address,p.size()));
                save("original-linked-reads.json",originalEncodings.get());summary.put("linked_read_encoding_verification",true);
                if(controlledFixture){
                    require(FixtureExperiment.REGION_SHA256.equals(p.regionHash(asm)),"Fixture region bytes changed");
                    save("original-local-kernel.json",LinkedReadVerification.lookupKernel(disassembly,originalEncodings.get()));
                }
            });
            stage("compile-helper",()->execute("compile-helper",List.of("gcc","-c",helperPath[0].toString(),"-o","helper.o"),timeout(),Set.of(0)));
            Map<String,Object> variants=new LinkedHashMap<>();summary.put("variants",variants);
            for(String variant:baselineOnly?List.of("baseline"):List.of("baseline","shifted","protected")) {
                stage(variant+"-build-and-verify",()->{
                    Path folder=experiment.resolve(variant);Files.createDirectory(folder);
                    String text=variant.equals("baseline")?asm:variant.equals("shifted")?p.shifted(asm):p.protectedAssembly(asm);
                    Files.writeString(folder.resolve("program.asm"),text,StandardOpenOption.CREATE_NEW);
                    execute(variant+"-assemble",List.of("nasm","-felf64","-g","-F","dwarf","-o",variant+"/program.o",variant+"/program.asm"),timeout(),Set.of(0));
                    List<String> link=new ArrayList<>(List.of("gcc","-g","-m64","-nostartfiles","-fgnu-tm","-o",variant+"/program",variant+"/program.o","helper.o"));
                    link.addAll(callbackPlan.linkerArguments());execute(variant+"-link",link,timeout(),Set.of(0));
                    Path binary=folder.resolve("program");require(Files.isExecutable(binary),"Linked binary lacks execute permission");
                    save(variant+"-callback-link-check.json",callbackPlan.verifyLinked(binary));summary.put("callback_link_mapping_checked",true);
                    execute(variant+"-nm",List.of("nm","-n",binary.toString()),30,Set.of(0));
                    Map<String,Long> symbols=symbols(Files.readString(activeLog),Set.of(p.first,p.second,p.end));
                    require(symbols.equals(ElfMetadata.read(binary).selected(Set.of(p.first,p.second,p.end))),"nm addresses disagree with actual ELF symbol tables");
                    long a=need(symbols,p.first),b=need(symbols,p.second),end=need(symbols,p.end);
                    require(b-a==p.firstBytes && end-b==p.secondBytes,"Linked span sizes/spacing changed");
                    boolean same=a/64==(end-1)/64;
                    require(variant.equals("shifted")?!same:same,"Linked cache-line partition violates plan");
                    if(!variant.equals("shifted"))require(a%64==p.address%64,"Linked line residue changed");
                    audit(variant,binary,a,p);
                    execute(variant+"-disassembly",List.of("objdump","-d","-w","-Mintel",binary.toString()),30,Set.of(0));
                    var reads=DirectReadInventory.inspect(Files.readString(activeLog),a,p.size());save(variant+"-instruction-inventory.json",reads);
                    require(DirectReadInventory.supported(reads)&&DirectReadInventory.signature(reads).equals(DirectReadInventory.signature(originalReads.get())),
                        "Final direct-read target/width inventory differs from original; inspect "+variant+"-instruction-inventory.json");
                    var encodings=LinkedReadVerification.verify(binary,Files.readString(activeLog),a,p.size());
                    save(variant+"-linked-reads.json",encodings);
                    save(variant+"-access-correspondence.json",LinkedReadVerification.correspond(originalEncodings.get(),encodings));
                    var coverage=ReferenceCoverage.analyze(binary,Files.readString(activeLog),a,p.size());save(variant+"-reference-coverage.json",coverage);
                    if(controlledFixture){
                        FixtureExperiment.requireKnownObligations(coverage);
                        var left=LinkedReadVerification.lookupKernel(Files.readString(experiment.resolve("logs/original-disassembly.log")),originalEncodings.get());
                        var right=LinkedReadVerification.lookupKernel(Files.readString(activeLog),encodings);
                        var local=LinkedReadVerification.compareKernels(left,right,true);
                        require(Boolean.valueOf(!variant.equals("shifted")).equals(local.get("preservation_for_all_selector_pairs_under_contract")),"Unexpected local kernel control result");
                        save(variant+"-local-kernel.json",local);
                    }else if(!baselineOnly)require(((List<?>)coverage.get("hazards")).isEmpty(),"Final instruction reference hazards; inspect "+variant+"-reference-coverage.json");
                    variants.put(variant,new LinkedHashMap<>(Map.of("binary_sha256",digest(binary),"first_address",a,"second_address",b,
                        "end_address",end,"same_line",same,"linked_layout_and_file_bytes_verified",true)));
                });
                if(baselineOnly)continue;
                stage(variant+"-collect-and-compare",()->{
                    Path folder=experiment.resolve(variant);List<String> collect=new ArrayList<>(List.of(config.string("tools.python"),
                        experiment.resolve("inputs/backend/collect_whole.py").toString(),"--original",experiment.resolve("inputs/original").toString(),
                        "--rebuilt",folder.resolve("program").toString(),"--pin",config.path("tools.pin").toString(),
                        "--tool",experiment.resolve("inputs/tracer.so").toString(),"--tool-source",experiment.resolve("inputs/tracer.cpp").toString(),
                        "--secret-0","0","--secret-1","1","--repetitions",Long.toString(config.number("experiment.repetitions")),
                        "--timeout",Long.toString(timeout()),"--output-parent",folder.toString()));
                    if(config.bool("experiment.eager_binding"))collect.add("--eager-binding");
                    execute(variant+"-collect",collect,timeout()*config.number("experiment.repetitions")*8+120,Set.of(0));
                    List<Path> batches;try(var dirs=Files.list(folder)){batches=dirs.filter(x->x.getFileName().toString().startsWith("whole-collection-")).toList();}
                    require(batches.size()==1,"Expected exactly one collection");Path report=folder.resolve("comparison.json");
                    int code=execute(variant+"-compare",List.of(config.string("tools.python"),experiment.resolve("inputs/backend/whole_trace_check.py").toString(),
                        batches.get(0).toString(),"--repetitions",Long.toString(config.number("experiment.repetitions")),"--line-size","64","--report",report.toString()),timeout(),Set.of(0,2,3,4,5));
                    Map<String,Object> result=Json.object(Files.readString(report));
                    WholeTraceAnalysis.Result independent=WholeTraceAnalysis.evaluate(batches.get(0),(int)config.number("experiment.repetitions"));
                    save(variant+"/java-comparison.json",independent.report());
                    for(String key:List.of("verdict","exit_code","functional_checks","repeat_stability","comparisons","runs","manifest_sha256"))
                        require(Objects.equals(Json.read(Json.write(result.get(key))),Json.read(Json.write(independent.report().get(key)))),"Python/Java observation comparison mismatch: "+key);
                    require("whole-comparison-1".equals(result.get("schema")),"Invalid/incomplete trace comparison for "+variant+"; inspect "+report);
                    require(result.get("exit_code") instanceof Long declared && declared==code,"Checker report/process exit disagreement");
                    require(Boolean.TRUE.equals(result.get("functional_checks")),"Functional comparison failed for "+variant);
                    require(Boolean.TRUE.equals(result.get("repeat_stability")),"Unstable observations for "+variant);
                    String expected=variant.equals("shifted")?"CANDIDATE_PRESERVATION_VIOLATION":"SATISFIED_FOR_TESTED_PAIR";
                    @SuppressWarnings("unchecked") Map<String,Object> v=(Map<String,Object>)variants.get(variant);
                    v.put("verdict",result.get("verdict"));v.put("checker_exit",code);v.put("report",report.toString());
                    require(expected.equals(result.get("verdict"))&&code==(variant.equals("shifted")?3:0),"Unexpected scientific result for "+variant+": "+result.get("verdict"));
                });
            }
            String completed=baselineOnly?"BASELINE_METADATA_CHECKED":"DEMO_EXPECTATIONS_MET";
            persist(completed);status="FINALIZING_EVIDENCE";finishReport();
            if(cancelled)throw new IOException("Cancelled during evidence finalization");status=completed;return 0;
        }catch(Exception e){status=cancelled?"CANCELLED":"FAILED";events.accept(status+": "+e.getMessage());
            if(experiment!=null)try{summary.put("failure",String.valueOf(e.getMessage()));persist(status);finishReport();}catch(Exception reportingFailure){events.accept("Evidence finalization failed: "+reportingFailure.getMessage());}
            return 2;
        }finally{process=null;}
    }
    private long timeout(){return config.number("experiment.timeout");}
    private void cleanupContainer(String name){
        // Killing a Docker client does not guarantee that its daemon-managed container stops.
        List<String> command=docker("rm","-f",name);
        try{
            save("logs/foxdec-cleanup.command.json",Map.of("argv",command));
            Process cleanup=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(experiment.resolve("logs/foxdec-cleanup.log").toFile()).start();
            if(!cleanup.waitFor(5,TimeUnit.SECONDS)){cleanup.destroyForcibly();summary.put("container_cleanup","Not confirmed; inspect named container and cleanup log");}
            else summary.put("container_cleanup",Map.of("exit",cleanup.exitValue(),"log","logs/foxdec-cleanup.log"));
        }catch(Exception error){summary.put("container_cleanup","Not confirmed: "+error.getMessage());}
    }
    public static void validateFoxDecMetrics(String text){
        for(String label:List.of("of which partially resolved","of which unresolved","of which ending in unresolved indirections","of which verification error")){
            var match=java.util.regex.Pattern.compile("(?m)^[ \\t]*\\("+java.util.regex.Pattern.quote(label)+"\\):[ \\t]*([0-9]+)[ \\t]*\\r?$").matcher(text);
            require(match.find(),"Missing FoxDec metric: "+label);require(match.group(1).equals("0"),"FoxDec requires manual review: "+label);
            require(!match.find(),"Ambiguous duplicate FoxDec metric: "+label);
        }
    }
    private void audit(String name,Path binary,long address,GroupPlan p)throws IOException{
        ElfRegionAudit.Result r=ElfRegionAudit.audit(binary,address,p.size());save(name+"-region-audit.json",Json.object(r.json()));
        var metadata=ElfMetadata.read(binary).audit(address,p.size());save(name+"-elf-metadata.json",metadata);
        require(ElfMetadata.detectedHazards(metadata).isEmpty(),"ELF section/reference/pointer hazard: "+ElfMetadata.detectedHazards(metadata));
        @SuppressWarnings("unchecked") Map<String,Object> used=(Map<String,Object>)summary.get("assembly_used");
        require(r.regionSha256().equals(p.regionHash(Files.readString(Path.of(used.get("path").toString())))),"Linked region bytes differ from declared input");
        require(r.relocations().stream().noneMatch(x->x.writeOverlap()||x.interiorTarget()||x.width()<0),"Relocation hazard or unknown relocation extent; fixture rejected");
        require(r.blockers().stream().noneMatch(x->x.startsWith("DT_REL")),"REL/RELR relocation encoding unsupported; fixture rejected");
        // Unresolved bindings elsewhere remain visible blockers: research mode is not a safety certificate.
    }
    public static Map<String,Long> symbols(String text,Set<String> selected){Map<String,Long> out=new HashMap<>();
        for(String line:text.split("\\R")){String[] f=line.trim().split("\\s+");if(f.length==3&&selected.contains(f[2])&&f[0].matches("[0-9a-fA-F]+")){
            long v=Long.parseLong(f[0],16);require(out.putIfAbsent(f[2],v)==null,"Duplicate linked symbol: "+f[2]);}}
        require(out.keySet().containsAll(selected),"Missing selected linked symbols: "+selected.stream().filter(s->!out.containsKey(s)).toList());
        return out;
    }
    private static long need(Map<String,Long> symbols,String name){require(symbols.containsKey(name),"Missing linked symbol: "+name);return symbols.get(name);}
    @FunctionalInterface private interface Work{void run()throws Exception;}
    private void stage(String name,Work work)throws Exception{
        if(cancelled)throw new IOException("Cancelled");status=name;events.accept("STAGE "+name);
        Map<String,Object> row=new LinkedHashMap<>(Map.of("name",name,"status","RUNNING","started_utc",Instant.now().toString()));stages.add(row);persist("RUNNING");
        try{work.run();if(cancelled)throw new IOException("Cancelled");row.put("status","PASSED");}
        catch(Exception e){row.put("status",cancelled?"CANCELLED":"FAILED");row.put("error",String.valueOf(e.getMessage()));throw e;}
        finally{row.put("finished_utc",Instant.now().toString());persist("RUNNING");}
    }
    int execute(String name,List<String> command,long seconds,Set<Integer> accepted)throws Exception{
        if(cancelled)throw new IOException("Cancelled");Path log=experiment.resolve("logs/"+name+".log");activeLog=log;
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("argv",command);row.put("timeout_seconds",seconds);commands.add(row);
        Files.writeString(experiment.resolve("logs/"+name+".command.json"),Json.write(row)+"\n",StandardOpenOption.CREATE_NEW);
        ProcessBuilder builder=new ProcessBuilder(command).directory(experiment.toFile()).redirectErrorStream(true).redirectOutput(log.toFile());
        builder.environment().put("PYTHONDONTWRITEBYTECODE","1");process=builder.start();
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
        try{
            while(!process.waitFor(200,TimeUnit.MILLISECONDS)){
                if(cancelled||System.nanoTime()>deadline){stop(process);throw new IOException(cancelled?"Cancelled":"Timed out: "+name);}
            }
            int code=process.exitValue();row.put("exit",code);row.put("log",log.toString());
            Files.writeString(experiment.resolve("logs/"+name+".exit"),code+"\n",StandardOpenOption.CREATE_NEW);
            require(accepted.contains(code),name+" exited "+code+"; see "+log);return code;
        }finally{if(process!=null&&process.isAlive())stop(process);process=null;}
    }
    private void save(String name,Object value)throws IOException{
        Path target=experiment.resolve(name),temporary=Files.createTempFile(target.getParent(),".bcl-",".tmp");
        try{Files.writeString(temporary,Json.write(value)+"\n");
            try{Files.move(temporary,target,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
            catch(AtomicMoveNotSupportedException unsupported){Files.move(temporary,target,StandardCopyOption.REPLACE_EXISTING);}
        }finally{Files.deleteIfExists(temporary);}
    }
    private void persist(String state)throws IOException{summary.put("status",state);summary.put("updated_utc",Instant.now().toString());save("summary.json",summary);status=state.equals("RUNNING")?status:state;}
    private void finishReport()throws IOException{
        String finalStatus=String.valueOf(summary.get("status"));
        boolean baselineOnly="BASELINE_REBUILD_ONLY".equals(summary.get("workflow_mode"));
        Files.writeString(experiment.resolve("report.txt"),"BinaryCacheLab "+(baselineOnly?"baseline rebuild":"controlled demonstration")+"\nStatus: "+finalStatus+
            "\nReference coverage: INCOMPLETE; automatic safe rewriting NOT authorized.\n"+
            "Java planner/transform/build/link verification; Python PIN collection and observation comparison.\n"+
            "Lifting: "+summary.get("lifting")+"\nObserver: ordered 64-byte raw virtual data lines, across secrets within each build.\n"+
            (baselineOnly?"No program execution or functional/observation evidence collected.\n":"Functional evidence: corresponding stdout/stderr/successful exit; not general semantic equivalence.\n")+LabApp.summaryText(summary)+"\n");
        List<Path> files;try(var walk=Files.walk(experiment)){files=walk.filter(Files::isRegularFile)
            .filter(f->!f.equals(experiment.resolve("SHA256SUMS"))&&!f.equals(experiment.resolve("completion.json"))).sorted().toList();}
        StringBuilder hashes=new StringBuilder();for(Path f:files)hashes.append(digest(f)).append("  ./").append(experiment.relativize(f).toString().replace('\\','/')).append('\n');
        Files.writeString(experiment.resolve("SHA256SUMS"),hashes);
        save("completion.json",Map.of("schema","bcl-evidence-seal-1","status",finalStatus,"manifest_sha256",digest(experiment.resolve("SHA256SUMS")),"files",files.size()));
    }
    public static String digest(Path file)throws IOException{try{var hash=java.security.MessageDigest.getInstance("SHA-256");
        try(var in=Files.newInputStream(file)){byte[] buffer=new byte[65536];int n;while((n=in.read(buffer))!=-1)hash.update(buffer,0,n);}return HexFormat.of().formatHex(hash.digest());
        }catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
