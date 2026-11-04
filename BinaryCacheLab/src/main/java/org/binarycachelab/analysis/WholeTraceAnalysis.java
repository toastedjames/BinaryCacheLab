package org.binarycachelab.analysis;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Streaming Java evaluation of the existing whole-2 observer; no native execution. */
public final class WholeTraceAnalysis {
    private static final String HEADER="sequence,thread_id,instruction_address,memory_address,access_size_bytes,access_type,source_backend";
    private static final Map<String,String> REQUIRED=Map.ofEntries(
        Map.entry("status","complete"),Map.entry("reason","normal-exit"),Map.entry("tracer_version","whole-2"),
        Map.entry("application_threads","1"),Map.entry("main_images","1"),Map.entry("application_exit","0"),Map.entry("backend","PIN"),
        Map.entry("address_space","raw-virtual"),Map.entry("observation_filter","none"),Map.entry("normalization","none"),
        Map.entry("scope","pin-instrumented-user-space"),Map.entry("event_semantics","before-instruction-pin-predication"),
        Map.entry("read_modify_write","separate-read-then-write"),Map.entry("kernel_memory_accesses","excluded"),Map.entry("instruction_fetches","excluded"));
    private record Event(long ip,long address,long size,String access,long thread,long index){}
    private record Run(Path trace,long expected,Path nativeOut,Path nativeErr,int nativeExit,Path pinOut,Path pinErr,int pinExit,long tokens){}
    public record Result(Map<String,Object> report,int exit){}
    public static Result evaluate(Path batch,int repetitions)throws IOException{
        require(repetitions>=2&&repetitions<=20,"Need 2..20 repetitions");EvidenceTree tree=new EvidenceTree(batch);
        require("complete".equals(tree.object("collection.json").get("status")),"Collection is incomplete");
        var settings=tree.object("experiment.json");require("whole-collection-1".equals(settings.get("schema"))&&settings.get("repetitions") instanceof Long n&&n==repetitions,
            "Requested repetitions do not match the completed collection contract");
        Map<String,Run> runs=new HashMap<>();List<Map<String,Object>> summaries=new ArrayList<>(),comparisons=new ArrayList<>();
        boolean functional=true,stable=true,premise=true,preserved=true;
        for(String role:List.of("original","rebuilt"))for(int repeat=0;repeat<repetitions;repeat++)for(int secret=0;secret<2;secret++){
            String name="repeat-"+repeat+"/"+role+"-"+secret;Run run=load(tree,name);runs.put(role+"/"+repeat+"/"+secret,run);
            functional&=run.nativeExit==0&&run.pinExit==0&&sameOutput(run,run,true);
            List<Object> outputs=new ArrayList<>();for(String mode:List.of("native","pin")){
                boolean nativeMode=mode.equals("native");Path out=nativeMode?run.nativeOut:run.pinOut,err=nativeMode?run.nativeErr:run.pinErr;
                outputs.add(Map.of("mode",mode,"stdout_sha256",Stage3Engine.digest(out),"stderr_sha256",Stage3Engine.digest(err),
                    "stdout_bytes",Files.size(out),"stderr_bytes",Files.size(err),"exit",nativeMode?run.nativeExit:run.pinExit));}
            summaries.add(Map.of("run",name,"events",run.expected,"line_tokens",run.tokens,"outputs",outputs));
            if(repeat>0){Run first=runs.get(role+"/0/"+secret);stable&=sameOutput(first,run,false)&&sameEvents(first,run);}
        }
        for(int repeat=0;repeat<repetitions;repeat++)for(int secret=0;secret<2;secret++)
            functional&=sameOutput(runs.get("original/"+repeat+"/"+secret),runs.get("rebuilt/"+repeat+"/"+secret),false);
        for(String role:List.of("original","rebuilt"))for(int repeat=0;repeat<repetitions;repeat++){
            Map<String,Object> comparison=compare(runs.get(role+"/"+repeat+"/0"),runs.get(role+"/"+repeat+"/1"));
            comparison.put("binary",role);comparison.put("repeat",repeat);comparisons.add(comparison);
            if(role.equals("original"))premise&=Boolean.TRUE.equals(comparison.get("equal"));else preserved&=Boolean.TRUE.equals(comparison.get("equal"));
        }
        String verdict;int code;
        if(!stable){verdict="INCONCLUSIVE_UNSTABLE_REPETITIONS";code=2;}
        else if(!functional){verdict="FUNCTIONAL_OUTPUT_MISMATCH";code=4;}
        else if(!premise){verdict="ORIGINAL_OBSERVATIONS_DIFFER";code=5;}
        else if(!preserved){verdict="CANDIDATE_PRESERVATION_VIOLATION";code=3;}
        else{verdict="SATISFIED_FOR_TESTED_PAIR";code=0;}
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","whole-comparison-1");report.put("implementation","java-whole-1");
        report.put("batch",tree.root.toString());report.put("variant","rebuilt");report.put("verdict",verdict);report.put("exit_code",code);
        report.put("functional_checks",functional);report.put("repeat_stability",stable);report.put("runs",summaries);report.put("comparisons",comparisons);
        report.put("manifest_sha256",Stage3Engine.digest(tree.path("SHA256SUMS")));
        report.put("observer",Map.of("line_size_bytes",64,"addresses","raw-virtual","order","event order; ascending touched lines within event",
            "repetitions","retained","excluded",List.of("access types","event boundaries","instruction addresses","instruction fetches","kernel accesses")));
        report.put("layout_handling","Compare secrets within each build, not raw addresses across builds.");
        report.put("scope","Finite recorded runs; no physical-cache, timing, formal or general semantic-equivalence guarantee.");
        return new Result(report,code);
    }
    private static Run load(EvidenceTree tree,String name)throws IOException{
        Map<String,String> metadata=new HashMap<>();
        for(String line:tree.text(name+"/trace.properties").split("\\R")){if(line.isEmpty())continue;int eq=line.indexOf('=');require(eq>0,"Malformed trace metadata");
            require(metadata.putIfAbsent(line.substring(0,eq),line.substring(eq+1))==null,"Duplicate trace metadata key");}
        for(var entry:REQUIRED.entrySet())require(entry.getValue().equals(metadata.get(entry.getKey())),name+": incomplete/unsupported metadata: "+entry.getKey());
        require(Long.parseLong(metadata.getOrDefault("mapping_snapshots","0"))>0,"No mapping snapshots");
        long count=Long.parseLong(metadata.getOrDefault("events","0"));require(count>0&&count<=10000000,"Unsupported trace event count");
        Path trace=tree.covered(name+"/trace.csv");long tokens=0;
        try(Cursor cursor=new Cursor(trace,count)){Event event;while((event=cursor.next())!=null)tokens+=lastLine(event)-firstLine(event)+1;}
        return new Run(trace,count,tree.covered(name+"/native.stdout"),tree.covered(name+"/native.stderr"),Integer.parseInt(tree.text(name+"/native.exit").trim()),
            tree.covered(name+"/pin.stdout"),tree.covered(name+"/pin.stderr"),Integer.parseInt(tree.text(name+"/pin.exit").trim()),tokens);
    }
    private static boolean sameOutput(Run a,Run b,boolean nativeVsPin)throws IOException{
        if(nativeVsPin)return a.nativeExit==b.pinExit&&Files.mismatch(a.nativeOut,b.pinOut)==-1&&Files.mismatch(a.nativeErr,b.pinErr)==-1;
        return a.nativeExit==b.nativeExit&&a.pinExit==b.pinExit&&Files.mismatch(a.nativeOut,b.nativeOut)==-1&&Files.mismatch(a.nativeErr,b.nativeErr)==-1
            &&Files.mismatch(a.pinOut,b.pinOut)==-1&&Files.mismatch(a.pinErr,b.pinErr)==-1;
    }
    private static boolean sameEvents(Run a,Run b)throws IOException{
        boolean same=true;try(Cursor left=new Cursor(a.trace,a.expected);Cursor right=new Cursor(b.trace,b.expected)){
            while(true){Event x=left.next(),y=right.next();if(x==null&&y==null)return same;same&=Objects.equals(x,y);}
        }
    }
    private static Map<String,Object> compare(Run a,Run b)throws IOException{
        Map<String,Object> result=new LinkedHashMap<>();boolean equal=true;long index=0;
        try(Tokens left=new Tokens(a);Tokens right=new Tokens(b)){
            while(true){Long x=left.next(),y=right.next();if(x==null&&y==null)break;
                if(!Objects.equals(x,y)&&equal){equal=false;result.put("first_difference",Map.of("token_index",index,"secret_0",left.witness(x),"secret_1",right.witness(y)));}index++;
            }
        }result.put("equal",equal);return result;
    }
    private static long firstLine(Event e){return Long.divideUnsigned(e.address,64);}
    private static long lastLine(Event e){return Long.divideUnsigned(e.address+e.size-1,64);}
    private static final class Cursor implements AutoCloseable{
        final BufferedReader input;final long expected;long index,thread=-1;boolean ended;
        Cursor(Path file,long expected)throws IOException{input=Files.newBufferedReader(file);this.expected=expected;
            try{require(HEADER.equals(input.readLine()),"Invalid trace CSV header");}catch(Exception e){input.close();throw e;}}
        Event next()throws IOException{
            if(ended)return null;String line=input.readLine();if(line==null){ended=true;require(index==expected&&index>0,"Empty/truncated/count-mismatched trace");return null;}
            String[] cells=line.split(",",-1);require(cells.length==7,"Invalid trace CSV row width");
            long sequence=Long.parseLong(cells[0]),id=Long.parseLong(cells[1]),ip=hex(cells[2]),address=hex(cells[3]),size=Long.parseLong(cells[4]);
            require(sequence==index&&id>=0&&size>0&&(cells[5].equals("READ")||cells[5].equals("WRITE"))&&cells[6].equals("PIN"),"Invalid memory event");
            require(Long.compareUnsigned(address+size-1,address)>=0,"Memory access wraps address space");
            require(thread<0||thread==id,"Multiple trace thread IDs");thread=id;Event event=new Event(ip,address,size,cells[5],id,index++);
            require(lastLine(event)-firstLine(event)<=65535,"Access exceeds projection limit");require(index<=expected,"Trace has extra events");return event;
        }
        public void close()throws IOException{input.close();}
    }
    private static long hex(String text){require(text.matches("(?:0[xX])?[0-9a-fA-F]{1,16}"),"Invalid trace address");return Long.parseUnsignedLong(text.replaceFirst("^0[xX]",""),16);}
    private static final class Tokens implements AutoCloseable{
        final Cursor cursor;Event event;long next,last,current;
        Tokens(Run run)throws IOException{cursor=new Cursor(run.trace,run.expected);}
        Long next()throws IOException{if(event==null||next>last){event=cursor.next();if(event==null)return null;next=firstLine(event);last=lastLine(event);}current=next++;return current;}
        Map<String,Object> witness(Long token){if(token==null)return Map.of("end_of_observation",true);
            return Map.of("line",token,"event",event.index,"csv_row",event.index+2,"ip","0x"+Long.toUnsignedString(event.ip,16),
                "address","0x"+Long.toUnsignedString(event.address,16),"size",event.size,"access_type",event.access,"thread",event.thread);}
        public void close()throws IOException{cursor.close();}
    }
}
