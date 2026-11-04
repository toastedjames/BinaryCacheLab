package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Explicit argv jobs, dependency tracking, output assertions and retained qualification evidence. */
public final class ToolkitSuite {
    private final Path file,app;private final Map<String,Object> suite;private final List<Map<String,Object>> jobs=new ArrayList<>();
    public ToolkitSuite(Path file,Path app)throws IOException{this.file=file.toAbsolutePath().normalize();this.app=app;
        suite=Json.object(Files.readString(file));require("bcl-suite-1".equals(suite.get("schema")),"Expected bcl-suite-1");
        require(suite.get("jobs") instanceof List<?> list&&!list.isEmpty()&&list.size()<=1000,"Require 1..1000 suite jobs");Set<String> ids=new HashSet<>();
        for(Object item:(List<?>)suite.get("jobs")){Map<String,Object> job=MultiRegionPlan.object(item);String id=id(job.get("id"));require(ids.add(id),"Duplicate job id");
            require(job.get("argv") instanceof List<?> args&&!args.isEmpty()&&args.stream().allMatch(x->x instanceof String&&!((String)x).isEmpty()),"Job argv must be nonempty strings");
            long timeout=MultiRegionPlan.number(job,"timeout_seconds");require(timeout>=1&&timeout<=86400,"Job timeout must be 1..86400 seconds");
            require(job.get("expected_exit") instanceof Number,"Job requires expected_exit");
            if(job.get("requires") instanceof List<?> deps)for(Object dep:deps)require(dep instanceof String&&ids.contains(dep)&&!id.equals(dep),"Dependencies must precede the job");jobs.add(job);}
    }
    public Map<String,Object> describe(){return Map.of("schema","bcl-suite-description-1","jobs",jobs,"native_execution",false,"suite_file",file.toString());}
    public int run()throws IOException{
        require(System.getProperty("os.name").equals("Linux"),"Native qualification suite requires Linux");
        Object out=suite.get("output_parent");require(out instanceof String,"Suite requires output_parent");Path parent=resolve(file.getParent(),(String)out);Files.createDirectories(parent);
        Path root=Files.createTempDirectory(parent,"toolkit-suite-");Map<String,Path> paths=new HashMap<>();Map<String,Boolean> passed=new HashMap<>();List<Map<String,Object>> results=new ArrayList<>();
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","bcl-suite-result-1");report.put("started_utc",Instant.now().toString());report.put("suite_sha256",Stage3Engine.digest(file));
        report.put("jobs",results);report.put("automatic_rewrite_allowed",false);report.put("scope","Only declared exit/output/artifact expectations for these jobs; no general security certification");
        Files.copy(file,root.resolve("suite.json"));System.out.println("Suite: "+root);
        try{for(Map<String,Object> job:jobs){String id=id(job.get("id"));Path dir=root.resolve(id);Files.createDirectory(dir);paths.put(id,dir);
                Map<String,Object> result=new LinkedHashMap<>();result.put("id",id);results.add(result);
                List<?> deps=job.get("requires") instanceof List<?> list?list:List.of();
                if(deps.stream().anyMatch(d->!Boolean.TRUE.equals(passed.get(d.toString())))){result.put("status","SKIPPED_DEPENDENCY");passed.put(id,false);continue;}
                List<String> argv=new ArrayList<>();for(Object arg:(List<?>)job.get("argv"))argv.add(expand(arg.toString(),root,dir,paths));result.put("argv",argv);
                Files.writeString(dir.resolve("command.json"),Json.write(Map.of("argv",argv,"cwd",dir.toString())),StandardOpenOption.CREATE_NEW);
                System.out.println("JOB "+id);NativeJob process=new NativeJob();int code;
                try{code=process.execute(argv,dir,dir.resolve("stdout.log"),dir.resolve("stderr.log"),MultiRegionPlan.number(job,"timeout_seconds"));result.put("exit_code",code);
                    require(code==((Number)job.get("expected_exit")).intValue(),"Exit expectation failed");
                    for(String stream:List.of("stdout","stderr"))if(job.get(stream) instanceof String expected)require(Files.readString(dir.resolve(stream+".log")).equals(expected),stream+" expectation failed");
                    if(job.get("equal_stdout_to") instanceof String peer){require(Boolean.TRUE.equals(passed.get(peer)),"Output peer has not passed");require(Files.mismatch(dir.resolve("stdout.log"),paths.get(peer).resolve("stdout.log"))==-1,"Output pair differs");}
                    if(job.get("assertions") instanceof List<?> assertions)for(Object item:assertions){var a=MultiRegionPlan.object(item);Path artifact=Path.of(expand(Objects.toString(a.get("file")),root,dir,paths)).toAbsolutePath().normalize();
                        require(artifact.startsWith(root),"Suite assertions must read artifacts inside this suite output");Object value=pointer(Json.read(Files.readString(artifact)),Objects.toString(a.get("pointer")));
                        require(Objects.equals(Json.write(value),Json.write(a.get("equals"))),"Artifact assertion failed: "+a.get("pointer"));}
                    result.put("status","EXPECTATIONS_MET");passed.put(id,true);
                }catch(Exception error){result.put("status","FAILED");result.put("error",error.getMessage()==null?error.toString():error.getMessage());passed.put(id,false);}
                Files.writeString(root.resolve("summary.json"),Json.write(report)+"\n");}
            boolean okay=passed.values().stream().allMatch(Boolean.TRUE::equals);report.put("status",okay?"SUITE_EXPECTATIONS_MET":"SUITE_HAS_FAILURES");report.put("completed_utc",Instant.now().toString());
            Files.writeString(root.resolve("summary.json"),Json.write(report)+"\n");seal(root);System.out.println(report.get("status")+": "+root);return okay?0:2;
        }catch(Exception error){report.put("status","INTERRUPTED_OR_FAILED");report.put("error",error.toString());Files.writeString(root.resolve("summary.json"),Json.write(report)+"\n");seal(root);throw error;}
    }
    private String expand(String value,Path root,Path job,Map<String,Path> paths){String out=value.replace("${app}",app.toString()).replace("${suite}",file.getParent().toString()).replace("${root}",root.toString()).replace("${job}",job.toString());
        for(var entry:paths.entrySet())out=out.replace("${job:"+entry.getKey()+"}",entry.getValue().toString());require(!out.contains("${"),"Unknown suite placeholder: "+out);return out;}
    private static String id(Object value){require(value instanceof String&&((String)value).matches("[A-Za-z0-9][A-Za-z0-9_-]{0,79}"),"Invalid suite job id");return (String)value;}
    private static Path resolve(Path base,String value){Path p=Path.of(value);return p.isAbsolute()?p:base.resolve(p).normalize();}
    private static Object pointer(Object value,String path){require(path.isEmpty()||path.startsWith("/"),"Assertion pointer must use JSON Pointer syntax");if(path.isEmpty())return value;
        for(String part:path.substring(1).split("/",-1)){String key=part.replace("~1","/").replace("~0","~");if(value instanceof Map<?,?> m){require(m.containsKey(key),"Missing assertion key "+key);value=m.get(key);}
            else if(value instanceof List<?> l){int n=Integer.parseInt(key);require(n>=0&&n<l.size(),"Assertion list index out of bounds");value=l.get(n);}else throw new IllegalArgumentException("Assertion traverses scalar");}return value;}
    private static void seal(Path root)throws IOException{List<Path> files;try(var walk=Files.walk(root)){files=walk.filter(Files::isRegularFile).filter(p->!p.getFileName().toString().equals("SHA256SUMS")).sorted().toList();}
        StringBuilder out=new StringBuilder();for(Path f:files)out.append(Stage3Engine.digest(f)).append("  ./").append(root.relativize(f).toString().replace('\\','/')).append('\n');Files.writeString(root.resolve("SHA256SUMS"),out);}
    public static final class NativeJob {
        private volatile Process process;
        public void cancel(){Process p=process;if(p!=null){List<ProcessHandle> children=p.descendants().toList();for(int i=children.size()-1;i>=0;i--)children.get(i).destroyForcibly();p.destroyForcibly();}}
        public int execute(List<String> argv,Path cwd,Path stdout,Path stderr,long timeout)throws IOException,InterruptedException{
            Thread hook=new Thread(this::cancel);Runtime.getRuntime().addShutdownHook(hook);
            try{ProcessBuilder builder=new ProcessBuilder(argv);if(cwd!=null)builder.directory(cwd.toFile());
                if(stdout==null)builder.inheritIO();else builder.redirectOutput(stdout.toFile()).redirectError(stderr.toFile());process=builder.start();
                if(!process.waitFor(timeout,TimeUnit.SECONDS)){cancel();process.waitFor();throw new IOException("Native job timed out after "+timeout+" seconds");}return process.exitValue();
            }catch(InterruptedException e){cancel();Thread.currentThread().interrupt();throw e;}finally{process=null;Runtime.getRuntime().removeShutdownHook(hook);}
        }
    }
}
