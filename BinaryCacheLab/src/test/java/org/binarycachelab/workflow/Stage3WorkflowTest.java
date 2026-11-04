package org.binarycachelab.workflow;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public final class Stage3WorkflowTest {
    private static int checks;
    private static final String ASM="section .data align=64\nL_.data_0x4078:\ndb 07h\ndb 00h\ndb 00h\ndb 00h\nL_.data_0x407c:\ndb 07h\ndb 00h\ndb 00h\ndb 00h\nL_.data_END:\n";
    public static void main(String[] args)throws Exception{
        Path root=Files.createTempDirectory("bcl-stage3-test-");
        String sample=LabApp.sample();LabConfig c=LabConfig.parse(root.resolve("bcl.toml"),sample);GroupPlan p=new GroupPlan(c);
        check(p.size()==8,"Group size");check(p.regionHash(ASM).length()==64,"Region hash");
        check(p.shifted(ASM).contains("times 4 db 0"),"Shift absent");
        String protectedAsm=p.protectedAssembly(ASM);
        check(protectedAsm.indexOf("times 4 db 0")<protectedAsm.indexOf("align 64, db 0"),"Protection applied before control shift");
        check(protectedAsm.contains("times 56 db 0"),"Original residue not restored");
        check(Boolean.FALSE.equals(p.manifest(ASM).get("automatic_rewrite_allowed")),"Plan authorized rewriting");
        check(p.references("MOV EAX, dword [L_.data_0x4078]\n"+ASM).size()==1,"Named direct read missed");
        reject(()->p.shifted("LEA RAX, [L_.data_0x4078]\n"+ASM));
        reject(()->p.shifted("MOV EAX, qword [L_.data_0x4078]\n"+ASM));
        reject(()->p.shifted("MOV RAX, L_.data_END\n"+ASM));
        reject(()->p.shifted(ASM+"L_.data_0x4078:\n"));
        reject(()->p.shifted(ASM.replace("section .data align=64","section .text")));
        reject(()->p.shifted(ASM.replace("db 07h","dq pointer")));
        reject(()->p.shifted(ASM.replace("align=64","align=32")));
        reject(()->p.shifted("%define X 1\n"+ASM));
        reject(()->p.shifted(protectedAsm));
        reject(()->LabConfig.parse(c.file,sample.replace("shift = 4","shift = 1")));
        reject(()->LabConfig.parse(c.file,sample.replace("first_bytes = 4","first_bytes = 0")));
        reject(()->LabConfig.parse(c.file,sample.replace("schema = 1","schema = 2")));
        reject(()->LabConfig.parse(c.file,sample+"unknown = 1\n"));
        reject(()->LabConfig.parse(c.file,sample.replace("timeout = 120","timeout = -1")));
        reject(()->LabConfig.parse(c.file,sample.replace("repetitions = 3","repetitions = 1")));
        reject(()->LabConfig.parse(c.file,sample.replace("research_mode = true","research_mode = \"true\"")));
        reject(()->LabConfig.parse(c.file,sample.replace("schema = 1","schema = 1\nschema = 1")));
        reject(()->LabConfig.parse(c.file,sample+"\n[region]\n"));
        reject(()->LabConfig.parse(c.file,sample.replace("line_bytes = 64","line_bytes = 128")));
        check(LabConfig.parse(c.file,sample.replace("schema = 1","schema = 1 # version")).number("schema")==1,"Comment parsing");
        check(LabConfig.parse(c.file,sample.replace("python = \"python3\"","python = \"some # path\"")).string("tools.python").equals("some # path"),"Quoted hash stripped");
        check(c.path("tools.backend").equals(root.resolve("backend")),"Relative path resolution");
        Files.writeString(c.file,sample);c.edit("experiment.timeout","75");check(LabConfig.load(c.file).number("experiment.timeout")==75,"Config edit");
        try(var files=Files.list(root)){check(files.anyMatch(x->x.getFileName().toString().contains("backup-")),"Config backup absent");}
        String before=Files.readString(c.file);reject(()->c.edit("experiment.timeout","0"));check(before.equals(Files.readString(c.file)),"Invalid edit mutated config");
        Object data=Json.read("{\"x\":[true,false,null,-2,\"a\\n\\\"\\\\\"]}");
        check(Json.read(Json.write(data)).equals(data),"JSON round trip");
        reject(()->Json.read("{\"x\":null,\"x\":1}"));reject(()->Json.read("[1,]"));reject(()->Json.read("01"));
        reject(()->Json.read("{} trailing"));reject(()->Json.read("\"unterminated"));
        check(Stage3Engine.symbols("00004078 d label\n",Set.of("label")).get("label")==0x4078,"Symbol read");
        reject(()->Stage3Engine.symbols("4078 d label\n4080 d label\n",Set.of("label")));
        check(Stage3Engine.symbols("2000 r __GNU_EH_FRAME_HDR\n2100 r __GNU_EH_FRAME_HDR\n4078 d label\n",Set.of("label")).size()==1,
            "Unrelated duplicate linker symbol rejected");
        reject(()->Stage3Engine.symbols("4078 d label\n4078 d label\n",Set.of("label")));
        reject(()->Stage3Engine.symbols("2000 r __GNU_EH_FRAME_HDR\n",Set.of("label")));
        Stage3Engine e=engine(c,root.resolve("process-ok"));
        int exit=e.execute("args-with-spaces",child("echo","path with spaces;$(literal)"),10,Set.of(0));
        check(exit==0 && Files.readString(e.activeLog).contains("path with spaces;$(literal)"),"Argument boundaries changed");
        check(e.execute("scientific-code",child("exit","3"),10,Set.of(3))==3,"Scientific exit lost");
        reject(()->e.execute("bad-exit",child("exit","4"),10,Set.of(0)));
        Stage3Engine timed=engine(c,root.resolve("process-timeout"));long start=System.nanoTime();
        reject(()->timed.execute("timeout",child("sleep"),1,Set.of(0)));
        check(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime()-start)<10,"Timeout did not bound process");
        Stage3Engine cancel=engine(c,root.resolve("process-cancel"));
        var pool=Executors.newSingleThreadExecutor();var future=pool.submit(()->{try{cancel.execute("cancel",child("sleep"),30,Set.of(0));return false;}catch(Exception expected){return true;}});
        Thread.sleep(250);cancel.cancel();check(future.get(5,TimeUnit.SECONDS),"Cancellation did not stop process");pool.shutdownNow();
        Files.writeString(root.resolve("fixture.asm"),ASM);
        Map<String,Object> tuiConfig=new LinkedHashMap<>(c.values);tuiConfig.put("input.assembly",root.resolve("fixture.asm").toString());
        StringBuilder toml=new StringBuilder();for(var entry:tuiConfig.entrySet())toml.append(entry.getKey()).append(" = ").append(Json.write(entry.getValue())).append('\n');
        Files.writeString(c.file,toml);
        Process tui=new ProcessBuilder(child("tui",c.file.toString())).redirectErrorStream(true).start();
        try(var stdin=tui.getOutputStream()){stdin.write("a\nd\nb\nb\np\nb\nc\ne experiment.timeout=76\nb\nq\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        String screen=new String(tui.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        check(tui.waitFor(5,TimeUnit.SECONDS)&&tui.exitValue()==0,"TUI command script failed");
        check(screen.contains("POLICY: preserve-group-line-residue")&&screen.contains("Configuration validated and saved"),"TUI plan/edit screens missing");
        check(LabConfig.load(c.file).number("experiment.timeout")==76,"TUI edit not applied");
        Files.writeString(c.file,sample.replace("docker_sudo = false\n",""));LabConfig oldConfig=LabConfig.load(c.file);
        check(!oldConfig.bool("tools.docker_sudo"),"Old config default unexpectedly elevates Docker");oldConfig.edit("tools.docker_sudo","true");
        check(LabConfig.load(c.file).bool("tools.docker_sudo"),"Optional adapter setting was not inserted into old config");
        Files.writeString(c.file,sample.replace("docker_sudo = false\n","").replace("[tools]","[tools] # paths"));
        LabConfig.load(c.file).edit("tools.docker_sudo","true");check(LabConfig.load(c.file).bool("tools.docker_sudo"),"Commented TOML table edit failed");
        reject(()->LabApp.comparisonText(Map.of("schema","other")));
        String metrics="(of which partially resolved): 0\n(of which unresolved): 0\n(of which ending in unresolved indirections): 0\n(of which verification error): 0\n";
        Stage3Engine.validateFoxDecMetrics(metrics);checks++;
        reject(()->Stage3Engine.validateFoxDecMetrics(metrics.replace("(of which unresolved): 0","(of which unresolved): 1")));
        reject(()->Stage3Engine.validateFoxDecMetrics(metrics+"(of which unresolved): 0\n"));
        reject(()->Stage3Engine.validateFoxDecMetrics(""));
        check(!LabApp.shouldRedraw(false,true,false,10000),"Unchanged idle/failed screen repeats");
        check(!LabApp.shouldRedraw(false,true,true,200),"Automatic redraw is not throttled");
        check(LabApp.shouldRedraw(false,true,true,1000),"Changed workflow/log is not refreshed");
        check(LabApp.shouldRedraw(true,true,false,0),"Command does not refresh interactive screen");
        check(!LabApp.shouldRedraw(false,false,true,1000),"Plain output is flooded by automatic refresh");
        check(LabApp.shouldRedraw(true,false,false,0),"Plain command response is not rendered");
        System.out.println("All "+checks+" Stage3 workflow checks passed. No native research experiments executed.");
    }
    private static Stage3Engine engine(LabConfig c,Path root)throws Exception{Files.createDirectories(root.resolve("logs"));Stage3Engine e=new Stage3Engine(c,s->{});e.experiment=root;return e;}
    private static List<String> child(String...args){List<String> cmd=new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString());
        cmd.addAll(List.of("-cp",System.getProperty("java.class.path"),Child.class.getName()));cmd.addAll(List.of(args));return cmd;}
    public static final class Child {public static void main(String[]args)throws Exception{switch(args[0]){
        case "sleep" -> Thread.sleep(30000);case "echo" -> System.out.println(args[1]);case "exit" -> System.exit(Integer.parseInt(args[1]));
        case "tui" -> System.exit(LabApp.run(new String[]{"tui","--config",args[1]}));default -> throw new IllegalArgumentException();}}}
    @FunctionalInterface private interface Checked{void run()throws Exception;}
    private static void reject(Checked work){try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("Expected rejection");}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
}
