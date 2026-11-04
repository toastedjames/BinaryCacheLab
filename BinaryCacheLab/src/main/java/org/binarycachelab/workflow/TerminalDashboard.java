package org.binarycachelab.workflow;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/** Screen/navigation refactor of LabApp's command-plus-Enter TUI. No terminal dependency. */
public final class TerminalDashboard {
    enum Screen { MAIN, PROGRESS, RESULTS, CONFIG, ADVANCED, DETAIL }
    final Path file;
    Path input, output, selected, transcript;
    LabConfig legacy;
    Stage3Engine engine;
    Map<String,Object> settings=Map.of(), report=Map.of();
    final LinkedHashMap<String,String> stages=new LinkedHashMap<>();
    final List<String> stageNames=new ArrayList<>();
    volatile Thread worker;
    volatile Process process;
    volatile String state="IDLE", current="None", notice="";
    volatile long revision;
    boolean modern, quit, explicitInput;
    String configError="", observer="UNAVAILABLE", coverage="UNAVAILABLE";
    long lineBytes;
    Screen screen=Screen.MAIN, back=Screen.MAIN;
    String title="", document="";
    int page;
    List<List<String>> cards=List.of();
    final Path app;
    final String python;

    TerminalDashboard(Path file,Path input) {
        this.file=file.toAbsolutePath().normalize();explicitInput=input!=null;this.input=input==null?null:input.toAbsolutePath().normalize();
        app=System.getenv("BCL_ROOT")==null?ToolkitCommands.appDirectory():Path.of(System.getenv("BCL_ROOT"));
        python=System.getenv().getOrDefault("BCL_PYTHON","python3");reload();
    }
    public static int run(Path file,Path input)throws Exception {
        TerminalDashboard ui=new TerminalDashboard(file,input);
        BlockingQueue<String> commands=new LinkedBlockingQueue<>();
        Thread reader=new Thread(()->{try{BufferedReader in=new BufferedReader(new InputStreamReader(System.in));String s;
            while((s=in.readLine())!=null)commands.put(s);commands.put("<EOF>");}
            catch(Exception e){commands.offer("<EOF>");}},"bcl-terminal-input");reader.setDaemon(true);reader.start();
        Thread hook=new Thread(()->{ui.cancel();ui.awaitCleanup();},"bcl-terminal-cleanup");
        Runtime.getRuntime().addShutdownHook(hook);
        boolean ansi=System.console()!=null;long last=0,seen=-1;boolean dirty=true;
        try {while(!ui.quit) {
            if(ui.worker!=null&&!ui.worker.isAlive()&&ui.state.equals("RUNNING")){ui.state="INCONCLUSIVE";ui.notice="Worker ended without a result";ui.revision++;}
            if(dirty||((ansi||!ui.running())&&seen!=ui.revision&&System.currentTimeMillis()-last>=500)) {
                if(ansi)System.out.print("\033[H\033[2J");
                System.out.print(ui.render());System.out.flush();last=System.currentTimeMillis();seen=ui.revision;dirty=false;
            }
            String command=commands.poll(120,TimeUnit.MILLISECONDS);
            if(command!=null){ui.command(command);dirty=true;}
        }} finally {ui.cancel();ui.awaitCleanup();Runtime.getRuntime().removeShutdownHook(hook);}
        return 0;
    }
    boolean running(){Thread t=worker;return t!=null&&t.isAlive();}
    synchronized void reload() {
        legacy=null;settings=Map.of();output=null;lineBytes=0;stageNames.clear();configError="";observer="UNAVAILABLE";coverage="UNAVAILABLE";
        try {
            String text=Files.readString(file);modern=Pattern.compile("(?m)^\\s*schema_version\\s*=").matcher(text).find();
            if(modern) {
                settings=helper("describe",explicitInput&&input!=null?input.toString():null);
                if("UNAVAILABLE".equals(settings.get("status")))throw new IllegalArgumentException(str(settings,"detail"));
                output=Path.of(str(settings,"output"));observer=str(settings,"observer");lineBytes=((Number)settings.get("line_bytes")).longValue();
                coverage=str(settings,"coverage");
                if(!explicitInput)input=str(settings,"input").isBlank()?null:Path.of(str(settings,"input"));
                stageNames.clear();for(Object s:(List<?>)settings.get("stages"))stageNames.add(String.valueOf(s));
            } else {
                legacy=LabConfig.load(file);output=legacy.path("project.output");
                if(!explicitInput)input=legacy.path("input.assembly");
                observer=legacy.string("observation.model");lineBytes=legacy.number("observation.line_bytes");coverage="INCOMPLETE";
                engine=new Stage3Engine(legacy,this::event);
            }
        }catch(Exception e){configError=e.getMessage();coverage="UNAVAILABLE";}
        revision++;
    }
    Map<String,Object> helper(String action,String value)throws Exception {
        List<String> argv=new ArrayList<>(List.of(python,app.resolve("scripts/dashboard_backend.py").toString(),action,file.toString()));
        if(value!=null)argv.add(value);
        Path log=Files.createTempFile("bcl-dashboard-", ".json");
        try {
            Process p=new ProcessBuilder(argv).redirectErrorStream(true).redirectOutput(log.toFile()).start();
            if(!p.waitFor(20,TimeUnit.SECONDS)){p.destroyForcibly();throw new IOException("Configuration adapter timed out");}
            String text=read(log,1024*1024);
            try{return Json.evidenceObject(text);}catch(Exception e){throw new IOException("Configuration adapter unavailable: "+clip(text,240));}
        }finally{Files.deleteIfExists(log);}
    }
    synchronized void event(String text) {
        if(text.startsWith("Experiment: "))selected=Path.of(text.substring(12).trim());
        if(text.startsWith("STAGE ")) {finishCurrent("PASS");current=text.substring(6).trim();stages.put(current,"RUNNING");}
        if(text.startsWith("FAILED:")||text.startsWith("CANCELLED:"))finishCurrent(text.startsWith("FAILED")?"FAIL":"INCONCLUSIVE");
        revision++;
    }
    void finishCurrent(String status){if(stages.containsKey(current)&&"RUNNING".equals(stages.get(current)))stages.put(current,status);}
    synchronized void outputLine(String line) {
        if(line.startsWith("Run directory: "))selected=Path.of(line.substring(15).trim());
        Matcher start=Pattern.compile("^\\[(\\d+)/(\\d+)\\] (.+) \\.\\.\\.$").matcher(line);
        if(start.matches()){current=start.group(3);stages.put(current,"RUNNING");}
        else if(line.startsWith("       ")) {
            String status=line.trim().split("[: ]",2)[0];
            if(Set.of("PASS","FAIL","INCONCLUSIVE","UNSUPPORTED","SKIPPED").contains(status))stages.put(current,status);
        }
        revision++;
    }
    synchronized void start()throws Exception {start("run");}
    synchronized void start(String mode)throws Exception {
        if(running()){screen=Screen.PROGRESS;throw new IllegalArgumentException("An analysis is already running; use C on the progress screen to cancel");}
        reload();if(!configError.isEmpty())throw new IllegalArgumentException(configError);
        if(modern&&!mode.equals("run"))throw new IllegalArgumentException("UNAVAILABLE: legacy fixture actions do not apply to this configuration");
        if(input==null||!Files.isRegularFile(input))throw new IllegalArgumentException("Input unavailable. Open Configuration and use I path");
        if(!modern&&!input.equals(legacy.path("input.assembly"))){legacy=legacy.withAssembly(input);engine=new Stage3Engine(legacy,this::event);}
        stages.clear();if(modern)for(String name:stageNames)stages.put(name,"WAITING");
        report=Map.of();selected=null;transcript=null;current="Starting";state="RUNNING";screen=Screen.PROGRESS;notice="";
        worker=new Thread(()->{
            try {
                if(modern) {
                    Path logs=app.resolve(".bcl/tui");Files.createDirectories(logs);transcript=Files.createTempFile(logs,"session-",".log");
                    ProcessBuilder builder=new ProcessBuilder(python,app.resolve("scripts/dashboard_backend.py").toString(),"run",file.toString(),input.toString());
                    builder.redirectErrorStream(true);builder.environment().put("PYTHONDONTWRITEBYTECODE","1");builder.environment().put("PYTHONUNBUFFERED","1");
                    process=builder.start();
                    // The Python adapter catches SIGTERM and lets Runner clean process groups.
                    if(state.equals("CANCELLING"))process.destroy();
                    try(BufferedReader stream=process.inputReader();BufferedWriter log=Files.newBufferedWriter(transcript)) {
                        String line;while((line=stream.readLine())!=null){log.write(line);log.newLine();log.flush();outputLine(line);}
                    }
                    int code=process.waitFor();process=null;
                    if(selected!=null&&Files.isRegularFile(selected.resolve("report.json"))){loadReport(selected);openTextReport();}
                    else {state=state.equals("CANCELLING")?"CANCELLED":"INCONCLUSIVE";notice="No final report; process exit "+code+". Partial logs retained.";}
                } else {Stage3Engine chosen=engine;if(mode.equals("rebuild"))chosen.rebuild();else if(mode.equals("fixture"))chosen.demoFixture();else chosen.run();selected=chosen.experiment;
                    if(selected!=null)loadReport(selected);else {state=chosen.status;notice="No run report was produced";}}
            }catch(Exception e){state="INCONCLUSIVE";notice="Analysis unavailable: "+e.getMessage();}
            finally {synchronized(this){if(state.equals("CANCELLING"))state="CANCELLED";finishCurrent("INCONCLUSIVE");if(screen==Screen.PROGRESS)screen=Screen.RESULTS;revision++;}}
        },"bcl-workflow");worker.start();revision++;
    }
    synchronized void cancel(){if(!running()||state.equals("CANCELLING"))return;state="CANCELLING";notice="Cancellation requested; waiting for cleanup and retained evidence";
        if(modern){Process p=process;if(p!=null)p.destroy();}else if(engine!=null)engine.cancel();revision++;}
    void awaitCleanup(){Thread t=worker;if(t!=null&&t.isAlive())try{t.join();}catch(InterruptedException e){Thread.currentThread().interrupt();}}
    List<Path> history()throws IOException {
        if(output==null||!Files.isDirectory(output))return List.of();
        try(var paths=Files.list(output)){return paths.filter(Files::isDirectory).filter(p->Files.isRegularFile(p.resolve("report.json"))||Files.isRegularFile(p.resolve("summary.json")))
            .sorted(Comparator.comparingLong((Path p)->p.toFile().lastModified()).reversed()).toList();}
    }
    synchronized void loadReport(Path path)throws IOException {
        Path source=path.resolve("report.json");if(!Files.isRegularFile(source))source=path.resolve("summary.json");
        report=Json.evidenceObject(read(source,16*1024*1024));selected=path;
        state=String.valueOf(report.getOrDefault("overall_verdict",report.getOrDefault("status","UNAVAILABLE")));
        var actual=map(map(report,"configuration"),"comparison");if(!actual.isEmpty()){observer=actual.get("line_identity")+" / "+actual.get("scope");if(actual.get("line_bytes") instanceof Number n)lineBytes=n.longValue();}
        if(report.get("checks") instanceof Map<?,?> checks) {
            for(int i=1;i<=stageNames.size();i++)if(checks.get("stage_"+i) instanceof Map<?,?> check)stages.put(stageNames.get(i-1),String.valueOf(check.get("status")));
        }else if(report.get("stages") instanceof List<?> list)for(Object item:list)if(item instanceof Map<?,?> row)stages.put(String.valueOf(row.get("name")),normal(String.valueOf(row.get("status"))));
        if(report.containsKey("reference_coverage"))coverage=str(report,"reference_coverage");
        else if(map(report,"checks").get("references") instanceof Map<?,?> refs)coverage="PASS".equals(refs.get("status"))?"UNVERIFIED":String.valueOf(refs.get("status")).replace("NOT_ASSESSED","UNVERIFIED");
    }
    void selectReport()throws IOException {if(running()&&report.isEmpty())throw new IllegalArgumentException("Analysis running; the final report will be available after cleanup");if(report.isEmpty()){var entries=history();if(entries.isEmpty())throw new IllegalArgumentException("No previous report. Run analysis to create one.");loadReport(entries.get(0));}}
    void latest()throws IOException {selectReport();screen=Screen.RESULTS;}
    void show(String name,String text){if(screen!=Screen.DETAIL)back=screen;screen=Screen.DETAIL;title=name;document=text;cards=List.of();page=0;}
    void saved(String name,String relative)throws IOException {if(selected==null)selectReport();Path path=selected.resolve(relative);
        if(!Files.isRegularFile(path))throw new IllegalArgumentException("UNAVAILABLE: no "+relative+" evidence for this run");show(name,EvidenceView.structured(Json.readEvidence(read(path,2*1024*1024))));}
    void logs()throws IOException {
        Path path=modern?transcript:engine==null?null:engine.activeLog;
        if(path==null&&selected!=null){Path dir=selected.resolve("logs");if(Files.isDirectory(dir))try(var files=Files.list(dir)){path=files.filter(Files::isRegularFile).max(Comparator.comparingLong(p->p.toFile().lastModified())).orElse(null);}}
        show("Logs",path==null?"No process log available.":path+"\n[Last 8 KiB; full log retained]\n"+tail(path));
    }
    void plan()throws Exception {
        if(!configError.isEmpty())throw new IllegalArgumentException(configError);
        if(!modern){show("Layout plan",LabApp.planText(new Stage3Engine(legacy,s->{}).plan()));return;}
        Path profile=selected==null?null:selected.resolve("build/regions.json");
        if(profile!=null&&Files.isRegularFile(profile)){show("Layout plan",Json.write(new MultiRegionPlan(profile).report()));return;}
        show("Layout planning","UNAVAILABLE: a derived layout plan needs lifted assembly and resolved labels.\nOpening this screen does not build or transform an executable.\nConfigured constraints (not validated results):\n"+Json.write(map(settings,"configuration").get("layout_constraints")));
    }
    synchronized void command(String raw) {
        String trimmed=raw.trim(),key=raw.equals("\033")?"ESC":trimmed.toUpperCase(Locale.ROOT);notice="";
        try {
            if(key.equals("<EOF>")){cancel();quit=true;return;}
            if(key.equals("\033")||key.equals("ESC")||key.equals("B")) {screen=screen==Screen.DETAIL?back:Screen.MAIN;return;}
            if(key.startsWith("E ")) {if(screen!=Screen.CONFIG)throw new IllegalArgumentException("Open Configuration (C) before editing");
                if(running())throw new IllegalArgumentException("Finish or cancel the active analysis before editing");
                String assignment=trimmed.substring(2);int equals=assignment.indexOf('=');if(equals<1)throw new IllegalArgumentException("Use E section.key=literal");
                if(modern){var result=helper("edit",assignment);if(!"PASS".equals(result.get("status")))throw new IllegalArgumentException(str(result,"detail"));}
                else legacy.edit(assignment.substring(0,equals).trim(),assignment.substring(equals+1).trim());
                reload();notice="Configuration validated and saved; previous file backed up.";return;}
            if(key.startsWith("I ")&&screen==Screen.CONFIG){if(running())throw new IllegalArgumentException("Cannot change input during a run");Path chosen=Path.of(trimmed.substring(2).trim()).toAbsolutePath().normalize();
                if(!Files.isRegularFile(chosen))throw new IllegalArgumentException("Input file does not exist");input=chosen;explicitInput=true;notice="Selected input updated for this session";return;}
            if(key.startsWith("J ")&&screen==Screen.ADVANCED){Path p=Path.of(trimmed.substring(2).trim());show("JSON evidence",EvidenceView.structured(Json.readEvidence(read(p,2*1024*1024))));return;}
            if(screen==Screen.ADVANCED&&trimmed.length()>2&&Set.of("F ","N ","U ").contains(key.substring(0,2))){
                Path profile=Path.of(trimmed.substring(2).trim());Object data=switch(key.substring(0,1)){
                    case "F"->org.binarycachelab.analysis.ReferenceClosure.analyze(profile);
                    case "N"->new MultiRegionPlan(profile).report();default->new ToolkitSuite(profile,app).describe();};
                show("Advanced profile",EvidenceView.structured(data));return;}
            if(key.matches("V [0-9]+")&&screen==Screen.ADVANCED){if(running())throw new IllegalArgumentException("Wait for the active run before changing evidence selection");var entries=history();int n=Integer.parseInt(key.substring(2))-1;
                if(n<0||n>=entries.size())throw new IllegalArgumentException("History index out of range");loadReport(entries.get(n));screen=Screen.RESULTS;return;}
            switch(screen) {
                case MAIN -> {switch(key){case "R"->start();case "P"->plan();case "V"->latest();case "C"->screen=Screen.CONFIG;case "A"->screen=Screen.ADVANCED;
                    case "Q"->{if(running()){screen=Screen.PROGRESS;notice="Analysis is active. Cancel with C, wait for cleanup, then quit.";}else quit=true;}
                    default->invalid();}}
                case PROGRESS -> {switch(key){case "C"->cancel();case "L"->logs();case "M"->screen=Screen.MAIN;case "R"->throw new IllegalArgumentException("An analysis is already running");default->invalid();}}
                case RESULTS -> {switch(key){case "V"->show("Run report",selected!=null&&"bcl-readable-decisions-2".equals(map(report,"presentation").get("schema"))?preview(selected.resolve("comparisons/trace_diff.txt")):resultText(true));case "D"->differences();case "T"->{if(selected==null)selectReport();openTextReport();}case "M"->screen=Screen.MAIN;default->invalid();}}
                case CONFIG -> {switch(key){case "R"->{if(running())throw new IllegalArgumentException("Cannot reload during a run");reload();notice=configError.isEmpty()?"Configuration reloaded":configError;}
                    case "V"->show("Active configuration",read(file,1024*1024));case "M"->screen=Screen.MAIN;default->invalid();}}
                case ADVANCED -> advanced(key);
                case DETAIL -> {switch(key){case "N"->page=Math.min(page+1,cards.isEmpty()?Math.max(0,(wrapped(document).size()-1)/13):cards.size()-1);case "P"->page=Math.max(0,page-1);case "M"->screen=Screen.MAIN;
                    case "L"->logs();default->invalid();}}
            }
        }catch(Exception e){notice="ERROR: "+e.getMessage();}finally{revision++;}
    }
    void advanced(String key)throws Exception {
        switch(key){
            case "D"->{if(!configError.isEmpty())throw new IllegalArgumentException(configError);
                if(!modern)show("Diagnostics",String.join("\n",new Stage3Engine(legacy,s->{}).diagnostics()));
                else {StringBuilder out=new StringBuilder("Preflight paths; versions/executability are checked by analysis.\n");out.append("Input: ").append(input!=null&&Files.isRegularFile(input)?"OK":"MISSING").append('\n');
                    for(var item:map(settings,"paths").entrySet())out.append(Files.isRegularFile(Path.of(String.valueOf(item.getValue())))?"OK ":"MISSING ").append(item.getKey()).append(" = ").append(item.getValue()).append('\n');show("Diagnostics",out.toString());}}
            case "T"->differences();
            case "K"->start("rebuild");
            case "X"->start("fixture");
            case "I","G"->{if(running())throw new IllegalArgumentException("Wait for the analysis to finish before offline evidence inspection");if(selected==null)selectReport();
                if(!modern){show(key.equals("I")?"Instruction correspondence":"Reference coverage",key.equals("I")?LabApp.referencesText(ExperimentVerifier.references(selected)):LabApp.coverageText(ExperimentVerifier.assessReferences(selected)));}
                else saved(key.equals("I")?"Instruction correspondence":"Reference validation","validation/reference_checks.json");}
            case "O"->show("Observer",observer+" / "+lineBytes+" B\nConfiguration: "+file+"\nEdit supported observer settings from Configuration using E key=literal.\nConfigured scope: "+(modern?Json.write(map(map(settings,"configuration"),"comparison")):"Ordered user-space virtual data lines; instruction fetches, kernel, timing and physical cache behavior excluded."));
            case "M"->{if(selected==null)selectReport();saved("Run manifest",Files.isRegularFile(selected.resolve("manifest.json"))?"manifest.json":"input-provenance.json");}
            case "H"->{StringBuilder out=new StringBuilder("V N selects a run from Advanced Tools; L opens logs.\n");var entries=history();for(int i=0;i<entries.size();i++)out.append(i+1).append(" ").append(entries.get(i)).append('\n');show("Run history",entries.isEmpty()?"No previous runs.":out.toString());}
            case "L"->logs();
            case "S"->{if(!report.isEmpty()&&report.containsKey("security_assessment"))show("Safety / security assessment",EvidenceView.structured(report.get("security_assessment"))+"\nFinite evidence only; layout changes alone do not establish compromise.");
                else if(!modern&&legacy!=null)show("Safety assessment",Json.write(new Stage3Engine(legacy,s->{}).assess()));else show("Safety assessment","NOT ASSESSED: no security assessment evidence for this selection.");}
            case "J"->show("Inspect JSON evidence","Return with B, then enter J /path/to/evidence.json. Read-only; size limit 2 MiB.");
            default->invalid();
        }
    }
    void openTextReport()throws Exception {
        Path text=selected.resolve("comparisons/trace_diff.txt");if(!Files.isRegularFile(text))return;
        Map<String,Object> result;
        try{result=helper("open-report",text.toString());}catch(Exception error){result=Map.of("status","UNAVAILABLE");}
        if("OPEN_REQUESTED".equals(result.get("status")))notice="TXT opening requested: comparisons/trace_diff.txt";
        else {show("Structured text report",preview(text));back=Screen.RESULTS;notice="TXT saved; no desktop viewer available. Showing the file here.";}
    }
    void differences()throws IOException {
        if(selected==null)selectReport();Path diff=selected.resolve("comparisons/trace_diff.jsonl");
        if("bcl-readable-decisions-2".equals(map(report,"presentation").get("schema"))&&Files.isRegularFile(selected.resolve("comparisons/trace_diff.txt"))){
            show("Secret comparisons",preview(selected.resolve("comparisons/trace_diff.txt")));return;
        }
        if(Files.isRegularFile(diff)){
            List<List<String>> formatted=new ArrayList<>();int firstChange=-1;
            try(var stream=Files.newBufferedReader(diff)){for(Map<String,Object> row:EvidenceView.comparisons(stream,100)){
                var card=EvidenceView.card(row);
                for(int i=0;i<card.size();i++)if(card.get(i).startsWith("POLICY:")){card.set(i,card.get(i)+" ("+map(report,"comparison").getOrDefault("policy","configured")+")");break;}
                if(firstChange<0&&!"PRESERVED".equals(row.get("classification")))firstChange=formatted.size();
                formatted.add(card);
            }}
            if(formatted.isEmpty()){show("Trace differences","No comparison rows were recorded.");return;}
            show("Trace differences","");cards=formatted;page=Math.max(0,firstChange);return;
        }
        StringBuilder out=new StringBuilder();for(String name:List.of("baseline","shifted","protected")){Path p=selected.resolve(name+"/comparison.json");if(Files.isRegularFile(p))out.append(name).append(": ").append(LabApp.comparisonText(Json.evidenceObject(read(p,2*1024*1024)))).append('\n');}
        show("Trace comparisons",out.length()==0?"UNAVAILABLE: no comparison evidence for this run.":out.toString());
    }
    void invalid(){notice="Invalid command. Use the displayed shortcuts, followed by Enter.";}
    String resultText(boolean detail) {
        if(report.isEmpty())return "No report available.";
        if(!report.containsKey("overall_verdict"))return LabApp.summaryText(report)+"\nNo unified verdict/event counts in this legacy report. Advanced Tools retains its comparisons.";
        StringBuilder out=new StringBuilder(("program".equals(map(report,"configuration").get("mode"))?"BUILD / TRACE RESULT: ":"VERDICT: ")+report.get("overall_verdict")+"\n");
        for(String key:List.of("references","functional","layout","observations","event_correspondence","repeat_stability")) {
            var row=map(map(report,"checks"),key);out.append(String.format("%-24s %s",EvidenceView.label(key),EvidenceView.status(row.getOrDefault("status","NOT_ASSESSED"))));if(detail)out.append(" â€” ").append(row.getOrDefault("detail","No evidence"));out.append('\n');}
        if(report.containsKey("protection")) {
            var protection=map(report,"protection");out.append("Protected build: ").append(protection.get("status")).append('\n');
            if(detail&&Boolean.TRUE.equals(protection.get("published")))out.append("Executable: ").append(selected).append('/').append(protection.get("executable")).append('\n');
        }
        if(map(report,"configuration").containsKey("reference_analysis"))out.append("Reference scope: declared lookup kernel\n");
        String security=str(map(report,"security_assessment"),"status");out.append("Security test: ").append(security.equals("NOT_ESTABLISHED")?"TESTED - NO DIFFERENCE":security.replace('_',' ')).append('\n');
        for(var entry:map(report,"event_statistics").entrySet())if(entry.getValue() instanceof Map<?,?> row)out.append(entry.getKey()).append(" events: ").append(row.get("events")).append("; incomplete: ").append(row.get("incomplete_traces")).append('\n');
        var cmp=map(report,"comparison");out.append("Preserved observations: ").append(cmp.getOrDefault("preserved_observations","NOT RUN")).append('\n');
        if(map(report,"security_assessment").get("secret_pairs") instanceof List<?> pairs)out.append("Secret comparison groups: ").append(pairs.size()).append(" (D to compare inputs)\n");
        out.append("Policy violations: ").append(cmp.getOrDefault("policy_violations","NOT RUN")).append("; unmatched: ").append(cmp.getOrDefault("unmatched_events","NOT RUN")).append('\n');
        if(report.get("violations") instanceof List<?> list&&!list.isEmpty()&&list.get(0) instanceof Map<?,?> first)out.append("First violation: ").append(first.get("rule_id")).append("\nLines: ").append(first.get("baseline_lines")).append(" -> ").append(first.get("transformed_lines")).append('\n');
        if(detail){out.append("All recorded checks:\n");for(var entry:map(report,"checks").entrySet())if(entry.getValue() instanceof Map<?,?> row)out.append("  ").append(entry.getKey()).append(": ").append(row.get("status")).append(" - ").append(row.get("detail")).append('\n');}
        if(detail)out.append("Classification counts: ").append(cmp.getOrDefault("classification_counts",Map.of())).append("\nReport: ").append(selected).append("/report.json");
        return out.toString();
    }
    synchronized String render() {
        List<String> lines=new ArrayList<>();String name=switch(screen){case MAIN->"";case PROGRESS->" â€” Running Analysis";case RESULTS->" â€” Analysis Complete";case CONFIG->" â€” Configuration";case ADVANCED->" â€” Advanced Tools";case DETAIL->" â€” "+title;};
        lines.add("BinaryCacheLab"+name+"  v"+org.binarycachelab.BinaryCacheLabCli.VERSION);
        lines.add("");
        switch(screen) {
            case MAIN->{lines.add("STATUS: "+state);lines.add("Input:    "+shortPath(input));lines.add("Config:   "+shortPath(file));lines.add("Observer: "+observer+" / "+lineBytes+" B");lines.add("Coverage: "+coverage);lines.add("");
                lines.add("[R] Run analysis");lines.add("[P] Plan layout transformation");lines.add("[V] View last report");lines.add("[C] Configuration");lines.add("[A] Advanced tools");lines.add("[Q] Quit");}
            case PROGRESS->{int n=0,total=stages.size();for(var row:stages.entrySet()){if(++n>12){lines.add("Earlier stages retained in report");break;}lines.add("["+n+(modern?"/"+total:"")+"] "+clip(row.getKey(),47)+"  "+row.getValue());}
                lines.add("Current stage: "+current);lines.add("State: "+state);lines.add("Input: "+shortPath(input));lines.add("Run ID: "+(selected==null?"Starting":selected.getFileName()));lines.add("[C] Cancel   [L] View logs   [M] Main menu");}
            case RESULTS->{lines.addAll(Arrays.asList(resultText(false).split("\n")));if(lines.size()>19){lines= new ArrayList<>(lines.subList(0,19));lines.add("Full details: V");}lines.add("[V] Report   [D] Differences   [T] Text report   [M] Main menu");}
            case CONFIG->{lines.add("Config: "+shortPath(file));lines.add("Input: "+shortPath(input));lines.add("Status: "+(configError.isEmpty()?"VALID":configError));lines.add("Output: "+shortPath(output));
                Map<String,Object> paths=modern?map(settings,"paths"):legacy==null?Map.of():new TreeMap<>(legacy.values);
                for(var item:paths.entrySet())if(item.getKey().startsWith("input.")||item.getKey().startsWith("tools.")||modern)lines.add(clip(item.getKey()+": "+item.getValue(),76));
                lines.add("[E key=literal] Edit setting (validated; backup retained)");lines.add("[I path] Select input   [R] Reload   [V] Full config   [B] Back");}
            case ADVANCED->{lines.add("[D] Diagnostics / preflight");lines.add("[T] Trace comparisons");lines.add("[I] Instruction correspondence");lines.add("[G] Reference coverage and eligibility");lines.add("[O] Observer settings");lines.add("[M] Run manifest");lines.add("[H] Run history   [L] Logs");lines.add("[S] Safety assessment");lines.add("[J] Inspect saved JSON evidence");lines.add("[F path] Closure  [N path] Region plan  [U path] Suite jobs");lines.add("[K] Legacy baseline rebuild   [X] Legacy fixture experiment");lines.add("[B] Back to main menu");}
            case DETAIL->{if(title.equals("Logs")){lines.add("State: "+state+"; current stage: "+current);try{Path log=modern?transcript:engine==null?null:engine.activeLog;if(log!=null)document=log+"\n[Last 8 KiB; full log retained]\n"+tail(log);}catch(IOException e){notice=e.getMessage();}}if(!cards.isEmpty()){lines.addAll(cards.get(page));lines.add("Comparison "+(page+1)+" of "+cards.size()+" (findings grouped per access; full stream saved)");}
                else {var wrapped=wrapped(document);int start=Math.min(page*13,Math.max(0,wrapped.size()-1));lines.addAll(wrapped.subList(start,Math.min(wrapped.size(),start+13)));lines.add("Page "+(page+1)+"/"+Math.max(1,(wrapped.size()+12)/13));}
                lines.add("[N] Next   [P] Previous   [B / Esc] Back   [M] Main");}
        }
        if(!configError.isEmpty()&&screen==Screen.MAIN)lines.add("UNAVAILABLE: invalid/missing configuration; open C");
        if(!notice.isEmpty())lines.add(clip(notice,76));
        String border="+"+"-".repeat(78)+"+\n";StringBuilder out=new StringBuilder(border);
        for(String line:lines)out.append("| ").append(String.format("%-76s",clip(clean(line),76))).append(" |\n");
        return out.append(border).append("Enter command > ").toString();
    }
    static String normal(String s){return s.equals("PASSED")?"PASS":s.equals("FAILED")?"FAIL":s;}
    static String str(Map<String,Object> m,String key){return String.valueOf(m.getOrDefault(key,""));}
    @SuppressWarnings("unchecked") static Map<String,Object> map(Map<String,Object> m,String key){return m.get(key) instanceof Map<?,?> value?(Map<String,Object>)value:Map.of();}
    static String hex(Object n){return n instanceof Number num?"0x"+Long.toHexString(num.longValue()):String.valueOf(n);}
    static String shortPath(Path p){return p==null?"UNAVAILABLE":p.toString().length()<=64?p.toString():"..."+p.toString().substring(p.toString().length()-61);}
    static String clip(String s,int n){return s.length()>n?s.substring(0,Math.max(0,n-3))+"...":s;}
    static String clean(String s){return s.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]","?");}
    static List<String> wrapped(String text){List<String> out=new ArrayList<>();for(String line:clean(text).split("\\R",-1)){
        if(line.isEmpty()){out.add("");continue;}
        while(line.length()>76){int cut=line.lastIndexOf(' ',76);if(cut<1)cut=76;out.add(line.substring(0,cut));line=line.substring(cut).stripLeading();}
        if(!line.isEmpty())out.add(line);
    }return out;}
    static String preview(Path path)throws IOException {
        try(var reader=Files.newBufferedReader(path)){char[] buffer=new char[65536];int count=reader.read(buffer);return count<0?"":new String(buffer,0,count)+(reader.read()<0?"":"\n[Preview limit reached; complete TXT is retained at "+path+"]");}
    }
    static String read(Path p,long max)throws IOException {if(Files.size(p)>max)throw new IOException("Evidence exceeds viewer limit; inspect full file: "+p);return Files.readString(p);}
    static String tail(Path p)throws IOException {try(var f=new RandomAccessFile(p.toFile(),"r")){long start=Math.max(0,f.length()-8192);f.seek(start);byte[] data=new byte[(int)(f.length()-start)];f.readFully(data);return new String(data,StandardCharsets.UTF_8);}}
}
