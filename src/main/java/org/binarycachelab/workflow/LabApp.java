package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** CLI and keyboard-driven terminal dashboard share Stage3Engine. */
public final class LabApp {
    private LabApp(){}
    public static int run(String[] args)throws Exception{
        String command=args[0];Path file=Path.of("bcl.toml");boolean check=false,seenConfig=false;Path selectedInput=null;
        for(int i=1;i<args.length;i++){
            if(args[i].equals("--config")&&!seenConfig&&i+1<args.length){file=Path.of(args[++i]);seenConfig=true;}
            else if(args[i].equals("--input")&&command.equals("tui")&&selectedInput==null&&i+1<args.length)selectedInput=Path.of(args[++i]);
            else if(args[i].equals("--check")&&command.endsWith(".asm")&&!check)check=true;
            else throw new IllegalArgumentException("Usage: "+command+" [--config bcl.toml]"+(command.endsWith(".asm")?" [--check]":""));
        }
        if(command.equals("--init")){Files.writeString(file,sample(),StandardOpenOption.CREATE_NEW);System.out.println("Created "+file+"; review paths and research scope before running.");return 0;}
        if(command.equals("tui"))return TerminalDashboard.run(file,selectedInput);
        LabConfig c=LabConfig.load(file);
        if(command.endsWith(".asm")){c=c.withAssembly(Path.of(command));command=check?"plan":"run";}
        Stage3Engine engine=new Stage3Engine(c,System.out::println);
        switch(command){
            case "--doctor" -> engine.diagnostics().forEach(System.out::println);
            case "plan" -> System.out.println(Json.write(engine.plan()));
            case "assess" -> {var result=engine.assess();System.out.println(Json.write(result));return Boolean.TRUE.equals(result.get("research_fixture_checks_passed"))?6:7;}
            case "run","rebuild","demo-fixture" -> {Thread hook=new Thread(engine::cancel);Runtime.getRuntime().addShutdownHook(hook);
                try{int result=command.equals("rebuild")?engine.rebuild():command.equals("demo-fixture")?engine.demoFixture():engine.run();
                    if(command.equals("rebuild")&&engine.experiment!=null)System.out.println(summaryText(Json.object(Files.readString(engine.experiment.resolve("summary.json")))));
                    return result;}finally{Runtime.getRuntime().removeShutdownHook(hook);}}
            case "history","--last" -> {var paths=history(c);if(command.equals("--last")&&!paths.isEmpty())System.out.println(Files.readString(paths.get(0).resolve("summary.json")));
                else for(int i=0;i<paths.size();i++)System.out.println((i+1)+" "+paths.get(i));}
            default -> throw new IllegalArgumentException("Unknown workflow command");
        }return 0;
    }
    private static List<Path> history(LabConfig c)throws IOException{
        if(!Files.isDirectory(c.path("project.output")))return List.of();
        try(var dirs=Files.list(c.path("project.output"))){return dirs.filter(Files::isDirectory)
            .filter(p->p.getFileName().toString().startsWith("stage3-")&&Files.isRegularFile(p.resolve("summary.json")))
            .sorted(Comparator.comparingLong((Path p)->p.toFile().lastModified()).reversed()).toList();}
    }
    static boolean shouldRedraw(boolean dirty,boolean interactive,boolean changed,long elapsedMillis){
        return dirty || (interactive && changed && elapsedMillis>=900);
    }
    public static String planText(Map<String,Object> data){return "POLICY: "+data.get("policy")+"\nRegions: "+data.get("region_symbols")+
        "\nGroup bytes: "+data.get("region_bytes")+"; line bytes: "+data.get("line_bytes")+"; required residue: "+data.get("required_line_residue")+
        "\nDeliberate control shift: "+data.get("control_shift_bytes")+" bytes\n"+data.get("reason")+
        "\nReference coverage: INCOMPLETE; general rewrite authorization: false\nAssumptions: "+data.get("assumptions");}
    public static String referencesText(Map<String,Object> data){StringBuilder out=new StringBuilder("REFERENCES: "+data.get("status")+"\n");
        Map<String,Object> variants=ExperimentVerifier.object(data,"variants");
        for(String name:List.of("baseline","shifted","protected")){var item=ExperimentVerifier.object(variants,name);var match=ExperimentVerifier.object(item,"access_correspondence");
            out.append(name).append(": unique access sites=").append(match.get("all_sites_unique")).append('\n');
            for(Object site:(List<?>)match.get("sites")){Map<?,?> row=(Map<?,?>)site;out.append("  offset/width ").append(row.get("offset_width")).append(" original IPs ").append(row.get("original_ips")).append(" -> rebuilt IPs ").append(row.get("rebuilt_ips")).append('\n');}
            Map<String,Object> local=ExperimentVerifier.object(item,"local_lookup_contract");
            if(local.containsKey("comparison"))out.append("  Local kernel preservation for all selector pairs under contract: ").append(ExperimentVerifier.object(local,"comparison").get("preservation_for_all_selector_pairs_under_contract")).append('\n');
            else out.append("  Local kernel contract unsupported: ").append(local.get("reason")).append('\n');}
        return out.append("Contract: entry at test edi; fixed valid return stack; readable immutable group; ordinary x86-64 execution.\nWhole-program references/ABI/loader and entry reachability remain unproved.").toString();}
    public static String coverageText(Map<String,Object> data){var coverage=ExperimentVerifier.object(data,"instruction_reference_coverage");
        StringBuilder out=new StringBuilder("ELIGIBILITY: "+data.get("decision")+"\nHazards: "+data.get("hazards")+"\n");
        Object verified=coverage.get("verified_direct_reads");int readCount=verified instanceof Map<?,?> checked&&checked.get("reads") instanceof List<?> reads?reads.size():0;
        out.append("Byte-verified declared read sites: ").append(readCount).append('\n');
        if(coverage.get("boundary_helper_analysis") instanceof Map<?,?> helper){
            out.append("Boundary LEA sites checked under local entry contract: ").append(helper.get("covered_lea_ips")).append('\n');
            for(Object item:(List<?>)helper.get("paths")){Map<?,?> path=(Map<?,?>)item;
                out.append("  entry 0x").append(Long.toHexString(((Number)path.get("entry")).longValue())).append(" -> ret 0x").append(Long.toHexString(((Number)path.get("return_ip")).longValue()))
                    .append("; group dereference=false; external call=false; live boundary registers=").append(path.get("boundary_values_live_at_return")).append('\n');}
            out.append("Local helper checks do not establish complete caller coverage.\n");}
        if(coverage.get("boundary_caller_analysis") instanceof Map<?,?> callers){
            out.append("Caller continuations and startup callbacks:\n");
            for(Object item:(List<?>)callers.get("paths")){Map<?,?> path=(Map<?,?>)item;
                out.append("  helper 0x").append(Long.toHexString(((Number)path.get("helper_entry")).longValue())).append(':').append('\n');
                for(Object incoming:(List<?>)path.get("enumerated_direct_incoming_edges")){Map<?,?> edge=(Map<?,?>)incoming;
                    out.append("    ").append(edge.get("kind")).append(" at 0x").append(Long.toHexString(((Number)edge.get("ip")).longValue()));
                    if(edge.get("continuation") instanceof Map<?,?> continuation){out.append("; continuation checked=").append(continuation.get("checked"));
                        if(Boolean.TRUE.equals(continuation.get("checked")))out.append("; consumes live boundary registers=false; still live at return=").append(continuation.get("boundary_values_live_at_return"));
                        else out.append("; ").append(continuation.get("reason"));}
                    out.append('\n');}
                for(Object root:(List<?>)path.get("matching_callback_roots")){Map<?,?> callback=(Map<?,?>)root;
                    out.append("    ").append(callback.get("source")).append(" candidate 0x").append(Long.toHexString(((Number)callback.get("callback_entry")).longValue())).append(" -> helper; ").append(callback.get("relation")).append('\n');}
                out.append("    Enumerated alternate entries: ").append(path.get("enumerated_alternate_entries")).append('\n');}
            out.append("Runtime callback contract and complete caller/entry closure remain unproved.\n");}
        if(data.get("callback_metadata_comparisons") instanceof Map<?,?> comparisons){
            for(var entry:comparisons.entrySet()){Map<?,?> comparison=(Map<?,?>)entry.getValue();
                out.append("Callback metadata ").append(entry.getKey()).append(": ").append(comparison.get("status")).append('\n');
                for(Object item:(List<?>)comparison.get("differences")){Map<?,?> difference=(Map<?,?>)item;
                    out.append("  ").append(difference.get("source")).append(" original=").append(difference.get("original_count")).append(" rebuilt=").append(difference.get("rebuilt_count")).append('\n');}}}
        out.append("Unresolved sites by category:\n");for(var row:ExperimentVerifier.object(coverage,"unresolved_counts").entrySet())out.append("  ").append(row.getKey()).append(": ").append(row.getValue()).append('\n');
        out.append("Missing coverage obligations: ").append(coverage.get("unestablished_obligations")).append('\n');
        return out.append("General safe transformation: false; automatic rewrite authorization: false\n").append(data.get("next_action")).toString();}
    public static String summaryText(Map<String,Object> data){StringBuilder out=new StringBuilder("WORKFLOW: "+data.get("status")+"\n");
        if(data.containsKey("eligibility_decision"))out.append("Safety assessment: ").append(data.get("eligibility_decision")).append("; controlled research mode only\n");
        if(data.get("stages") instanceof List<?> stages)for(Object item:stages)if(item instanceof Map<?,?> row)out.append(row.get("name")).append(" : ").append(row.get("status")).append('\n');
        if(data.get("variants") instanceof Map<?,?> variants)for(var entry:variants.entrySet())if(entry.getValue() instanceof Map<?,?> v)
            out.append(entry.getKey()).append(" => ").append(v.containsKey("verdict")?v.get("verdict"):"NO_OBSERVATION_VERDICT").append("; linked checks=").append(v.get("linked_layout_and_file_bytes_verified")).append('\n');
        if(data.containsKey("failure"))out.append("Failure: ").append(data.get("failure")).append('\n');
        return out.append("Assurance: ").append(data.get("assurance")).toString();}
    public static String comparisonText(Map<String,Object> data){
        if(!"whole-comparison-1".equals(data.get("schema")))throw new IllegalArgumentException("Expected whole-comparison-1 result");
        StringBuilder out=new StringBuilder(data.get("verdict")+"; functional="+data.get("functional_checks")+"; stable="+data.get("repeat_stability")+"\n");
        if(data.get("comparisons") instanceof List<?> comparisons)for(Object item:comparisons)if(item instanceof Map<?,?> row){
            out.append(row.get("binary")).append(" repeat ").append(row.get("repeat")).append(": equal=").append(row.get("equal"));
            if(row.get("first_difference") instanceof Map<?,?> diff){out.append("; first token=").append(diff.get("token_index"));
                for(String s:List.of("secret_0","secret_1"))if(diff.get(s) instanceof Map<?,?> witness)
                    out.append("\n  ").append(s).append(" IP ").append(witness.get("ip")).append(" -> ").append(witness.get("address"));}
            out.append('\n');}
        return out.toString();}
    private static Path selected(Stage3Engine engine,LabConfig c)throws IOException{if(engine.experiment!=null)return engine.experiment;
        List<Path> h=history(c);if(h.isEmpty())throw new IllegalArgumentException("No experiment yet");return h.get(0);}
    private static String clean(String s){return s.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]","?");}
    private static String tail(Path file)throws IOException{if(!Files.exists(file))return "Waiting for log...";
        try(var channel=Files.newByteChannel(file)){long start=Math.max(0,channel.size()-6000);channel.position(start);
            var bytes=java.nio.ByteBuffer.allocate(6000);channel.read(bytes);bytes.flip();String s=java.nio.charset.StandardCharsets.UTF_8.decode(bytes).toString();
            String[] lines=s.split("\\R");return String.join("\n",Arrays.copyOfRange(lines,Math.max(0,lines.length-10),lines.length));}}
    public static String sample(){
        return """
schema = 1
[project]
output = "experiments"
[input]
original = "fixtures/group_lookup/original"
assembly = "fixtures/group_lookup/group_lookup.asm"
helper = "fixtures/group_lookup/__gmon_start__.c"
[lift]
enabled = false
image = "foxdec"
timeout = 1800
[observation]
model = "ordered-raw-virtual-lines"
line_bytes = 64
[tools]
python = "python3"
docker = "docker"
docker_sudo = false
backend = "backend"
pin = "/absolute/path/to/pin"
tracer = "fixtures/pin/WholeProgramMemoryTracer.so"
tracer_source = "fixtures/pin/WholeProgramMemoryTracer.cpp"
[region]
first = "L_.data_0x4078"
second = "L_.data_0x407c"
end = "L_.data_END"
address = 0x4078
first_bytes = 4
second_bytes = 4
shift = 4
[experiment]
repetitions = 3
timeout = 120
eager_binding = true
research_mode = true
""";}
}
