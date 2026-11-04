package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.analysis.ReferenceClosure;
import static org.binarycachelab.workflow.LabConfig.require;

/** Commands for the implemented analysis/planning/qualification pipeline. */
public final class ToolkitCommands {
    public static final Set<String> COMMANDS=Set.of("workflow-references","approve-transform","approval-replay","publish-transform","correspondence","correspondence-replay","bounded-references","bounded-control","bounded-replay","closure","plan-regions","apply-regions","verify-regions","suite","validate-baseline","callback-plan","callback-check");
    private ToolkitCommands(){}
    public static Path appDirectory(){try{Path path=Path.of(ToolkitCommands.class.getProtectionDomain().getCodeSource().getLocation().toURI());return Files.isDirectory(path)?path:path.getParent();}
        catch(Exception e){throw new IllegalStateException("Cannot locate application",e);}}
    public static int run(String[] args)throws Exception{
        require(args.length>=2,"Usage: "+args[0]+" PROFILE_OR_EVIDENCE [options]");String command=args[0];Path input=Path.of(args[1]);
        Map<String,String> options=new HashMap<>();Set<String> flags=new HashSet<>();
        for(int i=2;i<args.length;i++){String name=args[i];if(Set.of("--list","--check-only").contains(name)){require(flags.add(name),"Duplicate flag");}
            else{require(Set.of("--expected","--report","--output","--original","--rebuilt","--python","--assembly").contains(name)&&i+1<args.length,"Unknown/incomplete option: "+name);require(options.putIfAbsent(name,args[++i])==null,"Duplicate option");}}
        Set<String> allowed=switch(command){case "approval-replay","correspondence-replay","bounded-replay"->Set.of("--expected","--report");case "workflow-references","approve-transform","correspondence","bounded-references","bounded-control","closure","plan-regions"->Set.of("--report");case "callback-plan"->Set.of("--report","--assembly");case "callback-check"->Set.of("--report","--rebuilt");case "publish-transform","apply-regions"->Set.of("--output","--report");case "verify-regions"->Set.of("--original","--rebuilt","--report");case "validate-baseline"->Set.of("--python");default->Set.of();};
        require(allowed.containsAll(options.keySet()),"Option does not apply to "+command);
        require(flags.isEmpty()||(command.equals("suite")&&flags.equals(Set.of("--list")))||(command.equals("validate-baseline")&&flags.equals(Set.of("--check-only"))),"Flag does not apply to "+command);
        Map<String,Object> report;int code=0;
        switch(command){
            case "approve-transform","approval-replay","publish-transform" -> {
                if(command.equals("publish-transform")){
                    require(options.containsKey("--output"),"publish-transform requires --output NEW_ELF");
                    if(options.containsKey("--report"))require(!Files.exists(Path.of(options.get("--report"))),"Report already exists");
                    report=org.binarycachelab.analysis.BoundedTransformation.publish(input,Path.of(options.get("--output")));
                }else report=org.binarycachelab.analysis.BoundedTransformation.analyze(input);
                if(command.equals("approval-replay")){
                    require(options.containsKey("--expected"),"approval-replay requires --expected REPORT_JSON");
                    require(Json.object(Json.write(report)).equals(Json.object(Files.readString(Path.of(options.get("--expected"))))),"Approval differs from exhaustive replay");
                }
                code=Boolean.TRUE.equals(report.get("bounded_transformation_approved"))?0:"PRESERVATION_COUNTEREXAMPLE".equals(report.get("status"))?3:7;
            }
            case "correspondence","correspondence-replay" -> {
                report=org.binarycachelab.analysis.BoundedCorrespondence.analyze(input);
                if(command.equals("correspondence-replay")){
                    require(options.containsKey("--expected"),"correspondence-replay requires --expected REPORT_JSON");
                    require(Json.object(Json.write(report)).equals(Json.object(Files.readString(Path.of(options.get("--expected"))))),"Correspondence evidence differs from exhaustive replay");
                }
                code=Boolean.TRUE.equals(report.get("correspondence_established"))?0:"CORRESPONDENCE_COUNTEREXAMPLE".equals(report.get("status"))?3:7;
            }
            case "bounded-references","bounded-replay" -> {
                report=org.binarycachelab.analysis.BoundedReferences.analyze(input);
                if(command.equals("bounded-replay")){
                    require(options.containsKey("--expected"),"bounded-replay requires --expected REPORT_JSON");
                    require(Json.object(Json.write(report)).equals(Json.object(Files.readString(Path.of(options.get("--expected"))))),"Bounded evidence differs from exhaustive replay");
                }
                code=Boolean.TRUE.equals(report.get("exhaustive"))?0:7;
            }
            case "bounded-control" -> {report=org.binarycachelab.analysis.BoundedReferences.analyzeWithControl(input);code=Boolean.TRUE.equals(report.get("exhaustive"))?0:7;}
            case "workflow-references" -> {report=org.binarycachelab.analysis.WorkflowReferences.analyze(input);code=Boolean.TRUE.equals(report.get("verified"))?0:7;}
            case "callback-plan" -> {CallbackLiftPlan plan=new CallbackLiftPlan(input);if(options.containsKey("--assembly"))plan.validateAssembly(Files.readString(Path.of(options.get("--assembly"))));report=plan.manifest();}
            case "callback-check" -> {require(options.containsKey("--rebuilt"),"callback-check requires --rebuilt");report=new CallbackLiftPlan(input).verifyLinked(Path.of(options.get("--rebuilt")));}
            case "closure" -> {report=ReferenceClosure.analyze(input);code="CLOSED_UNDER_DECLARED_ENTRY_CONTRACT".equals(report.get("status"))?0:6;}
            case "plan-regions" -> report=new MultiRegionPlan(input).report();
            case "apply-regions" -> {require(options.containsKey("--output"),"apply-regions requires --output NEW_ASM");MultiRegionPlan plan=new MultiRegionPlan(input);Path source=plan.path("assembly"),target=Path.of(options.get("--output"));
                String text=plan.apply(Files.readString(source));require(!Files.exists(target),"Candidate output already exists");Map<String,Object> candidate=new LinkedHashMap<>(plan.report());
                candidate.put("source_sha256",Stage3Engine.digest(source));candidate.put("candidate_sha256",GroupPlan.hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));candidate.put("candidate_assembly",target.toAbsolutePath().toString());
                if(options.containsKey("--report"))require(!Files.exists(Path.of(options.get("--report"))),"Report already exists");Files.writeString(target,text,StandardOpenOption.CREATE_NEW);report=candidate;}
            case "verify-regions" -> {require(options.containsKey("--original")&&options.containsKey("--rebuilt"),"verify-regions requires --original and --rebuilt");report=new MultiRegionPlan(input).verify(Path.of(options.get("--original")),Path.of(options.get("--rebuilt")));}
            case "suite" -> {ToolkitSuite suite=new ToolkitSuite(input,appDirectory());if(flags.contains("--list"))report=suite.describe();else return suite.run();}
            case "validate-baseline" -> {require(System.getProperty("os.name").equals("Linux")||flags.contains("--check-only"),"Native validation requires Linux");Path script=appDirectory().resolve("scripts/validate-baseline.py");require(Files.isRegularFile(script),"Install the full toolkit package: missing "+script);
                List<String> argv=new ArrayList<>(List.of(options.getOrDefault("--python","python3"),script.toString(),"--app",appDirectory().toString(),"--evidence",input.toAbsolutePath().toString()));if(flags.contains("--check-only"))argv.add("--check-only");
                return new ToolkitSuite.NativeJob().execute(argv,null,null,null,86400);}
            default -> throw new IllegalArgumentException("Unknown toolkit command");
        }
        if(options.containsKey("--report"))writeNew(Path.of(options.get("--report")),Json.write(report)+"\n");System.out.println(Json.write(report));return code;
    }
    private static void writeNew(Path target,String text)throws IOException{Path absolute=target.toAbsolutePath().normalize();for(Path p=absolute;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p),"Report path contains a symlink");Files.writeString(absolute,text,StandardOpenOption.CREATE_NEW);}
}
