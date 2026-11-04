package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Exhaustive relational checking over two closed, finite machine models. */
public final class BoundedCorrespondence {
    private static final String[] REGS={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    private static final Set<String> SAVED=Set.of("rbx","rbp","r12","r13","r14","r15");
    private static final Set<String> ENCODINGS=Set.of("scalar","address","nullable-address");
    private static final long RETURN=0x7ffffffffff0L;
    private record Field(int offset,int width,String encoding){}
    private record MemoryMap(String name,long original,long rebuilt,int size,List<Field> pointers,boolean onePast){}
    private record InputMap(int original,int rebuilt,String encoding){}
    private static final class Problem extends RuntimeException {final String kind;Problem(String kind,String detail){super(detail);this.kind=kind;}}
    private static final class Hazards extends ArrayList<Map<String,Object>> {long count;@Override public boolean add(Map<String,Object> value){count++;return size()<128?super.add(value):true;}}
    private static void check(boolean value,String kind,String detail){if(!value)throw new Problem(kind,detail);}
    private static Map<String,Object> object(Object value){return MultiRegionPlan.object(value);}
    private static List<?> list(Object value){require(value instanceof List<?>,"Expected list");return (List<?>)value;}
    private static long number(Object value){require(value instanceof Long||value instanceof Integer,"Expected integer");return ((Number)value).longValue();}
    private static long n(Map<String,Object> map,String key){return number(map.get(key));}
    private static void keys(Map<String,Object> map,String... names){require(Set.of(names).containsAll(map.keySet()),"Unknown correspondence fields: "+map.keySet().stream().filter(k->!Set.of(names).contains(k)).toList());}
    private static String encoding(Object value){String s=Objects.toString(value);require(ENCODINGS.contains(s),"Encoding must be scalar, address or nullable-address");return s;}
    private static boolean overlap(long a,long size,long b,long length){return a<b+length&&b<a+size;}
    private static boolean extent(long a,long size){return a>=0&&size>0&&a<0x800000000000L&&size<=0x800000000000L-a;}
    private record Document(Map<String,Object> data,String hash){}
    private static Document read(Path path)throws IOException {byte[] bytes;try(var in=Files.newInputStream(path)){bytes=in.readNBytes(1024*1024+1);}require(bytes.length<=1024*1024,"Correspondence profile exceeds 1 MiB");return new Document(Json.object(new String(bytes,java.nio.charset.StandardCharsets.UTF_8)),GroupPlan.hash(bytes));}
    private static Path resolve(Path base,Object value){require(value instanceof String,"Expected path");return base.resolve((String)value).normalize();}
    private final Path file;private final Map<String,Object> profile;private final String profileHash;
    private Context original,rebuilt;
    private final List<MemoryMap> maps=new ArrayList<>();private final List<InputMap> inputs=new ArrayList<>();
    private final Map<Long,Long> forward=new TreeMap<>(),reverse=new TreeMap<>(),entryForward=new TreeMap<>();
    private final Map<String,String> initialEncodings=new TreeMap<>(),outputs=new TreeMap<>();
    private final List<Map<String,Object>> witnesses=new ArrayList<>(),cases=new ArrayList<>();
    private long differences;
    private final class Context {
        final Path path,binary;final Map<String,Object> contract;final boolean isOriginal;final String profileHash;
        final long stackStart,stackSize;Map<String,Object> report,runtime;
        Context(Path path,boolean isOriginal)throws IOException{this.path=path;this.isOriginal=isOriginal;Document doc=read(path);contract=doc.data;profileHash=doc.hash;
            require("bcl-bounded-references-1".equals(contract.get("schema")),"Correspondence requires bounded-reference profiles");binary=resolve(path.getParent(),contract.get("binary"));
            var machine=object(contract.get("machine"));var stack=object(machine.get("stack"));stackStart=n(stack,"address");stackSize=n(stack,"size");
            check(extent(stackStart,stackSize),"INVALID_STACK_RELATION","Invalid stack extent");}
        long address(MemoryMap map){return isOriginal?map.original:map.rebuilt;}
    }
    private BoundedCorrespondence(Path path)throws IOException {file=path.toAbsolutePath().normalize();Document doc=read(file);profile=doc.data;profileHash=doc.hash;}
    public static Map<String,Object> analyze(Path path)throws IOException{return new BoundedCorrespondence(path).run();}

    private void codePair(long a,long b){check(!forward.containsKey(a)||forward.get(a)==b,"AMBIGUOUS_CODE_MAPPING","Original address has multiple rebuilt mappings");
        check(!reverse.containsKey(b)||reverse.get(b)==a,"AMBIGUOUS_CODE_MAPPING","Rebuilt address has multiple original mappings");forward.put(a,b);reverse.put(b,a);}
    private void prepare()throws IOException {
        keys(profile,"schema","original","rebuilt","abi","entries","control_map","memory_maps","input_map","initial_register_encodings","register_outputs");
        require("bcl-bounded-correspondence-1".equals(profile.get("schema")),"Expected bcl-bounded-correspondence-1");
        check("sysv-amd64-integer".equals(profile.get("abi")),"UNSUPPORTED_ABI","Only the modeled System V AMD64 integer ABI is supported");
        original=new Context(resolve(file.getParent(),profile.get("original")),true);rebuilt=new Context(resolve(file.getParent(),profile.get("rebuilt")),false);
        check(original.stackSize==rebuilt.stackSize,"STACK_DOMAIN_MISMATCH","Stack extents must have equal sizes");
        require(list(profile.get("entries")).size()<=128&&list(profile.get("control_map")).size()<=100000,"Excessive code mapping size");
        for(Object row:list(profile.get("entries"))){var entry=object(row);keys(entry,"original","rebuilt");long a=n(entry,"original"),b=n(entry,"rebuilt");
            require(entryForward.putIfAbsent(a,b)==null,"Duplicate original entry mapping");codePair(a,b);}
        Set<Long> aEntries=new HashSet<>(),bEntries=new HashSet<>();for(Object a:list(original.contract.get("entries")))aEntries.add(number(a));for(Object b:list(rebuilt.contract.get("entries")))bEntries.add(number(b));
        check(!aEntries.isEmpty()&&entryForward.keySet().equals(aEntries)&&new HashSet<>(entryForward.values()).equals(bEntries),"ENTRY_DOMAIN_MISMATCH","Map every original and rebuilt declared entry bijectively");
        for(Object row:list(profile.get("control_map"))){var point=object(row);keys(point,"original","rebuilt");codePair(n(point,"original"),n(point,"rebuilt"));}
        require(list(profile.get("memory_maps")).size()<=63,"At most 63 persistent memory maps");
        for(Object row:list(profile.get("memory_maps"))){var map=object(row);keys(map,"name","original","rebuilt","size","pointer_fields","allow_one_past");
            require(map.get("name") instanceof String,"Memory map name required");String name=(String)map.get("name");long size=n(map,"size"),a=n(map,"original"),b=n(map,"rebuilt");
            require(size<=4*1024*1024&&extent(a,size)&&extent(b,size),"Invalid memory-map extent");
            require(!map.containsKey("allow_one_past")||map.get("allow_one_past") instanceof Boolean,"allow_one_past must be boolean");
            check(!overlap(a,size,original.stackStart,original.stackSize)&&!overlap(b,size,rebuilt.stackStart,rebuilt.stackSize),"STACK_OUTPUT_MAPPING","Persistent memory mappings cannot include stack scratch space");
            List<Field> fields=new ArrayList<>();for(Object item:list(map.getOrDefault("pointer_fields",List.of()))){var field=object(item);keys(field,"offset","width","encoding");long at=n(field,"offset"),width=n(field,"width");
                require((width==4||width==8)&&at>=0&&at<=size-width,"Invalid pointer field");String enc=encoding(field.get("encoding"));require(!enc.equals("scalar"),"Pointer fields require an address encoding");
                for(Field old:fields)require(!overlap(at,width,old.offset,old.width),"Overlapping pointer fields");fields.add(new Field((int)at,(int)width,enc));}
            fields.sort(Comparator.comparingInt(Field::offset));
            for(MemoryMap old:maps)require(!old.name.equals(name)&&!overlap(a,size,old.original,old.size)&&!overlap(b,size,old.rebuilt,old.size),"Memory mappings must have unique names and disjoint extents");
            maps.add(new MemoryMap(name,a,b,(int)size,List.copyOf(fields),Boolean.TRUE.equals(map.get("allow_one_past"))));}
        Map<String,Object> enc=object(profile.getOrDefault("initial_register_encodings",Map.of()));for(var e:enc.entrySet()){require(Arrays.asList(REGS).contains(e.getKey())&&!e.getKey().equals("rsp"),"Invalid initial register encoding");initialEncodings.put(e.getKey(),encoding(e.getValue()));}
        for(Object row:list(profile.get("register_outputs"))){var out=object(row);keys(out,"register","encoding");String r=Objects.toString(out.get("register"));require(Arrays.asList(REGS).contains(r),"Unknown output register");require(outputs.putIfAbsent(r,encoding(out.get("encoding")))==null,"Duplicate output register");}
        require(!outputs.isEmpty()||!maps.isEmpty(),"Declare at least one functional output");
        List<?> aInputs=list(original.contract.get("inputs")),bInputs=list(rebuilt.contract.get("inputs"));Set<Integer> ai=new HashSet<>(),bi=new HashSet<>();
        for(Object row:list(profile.get("input_map"))){var input=object(row);keys(input,"original","rebuilt","encoding");long a=n(input,"original"),b=n(input,"rebuilt");
            require(a>=0&&a<aInputs.size()&&b>=0&&b<bInputs.size(),"Input mapping index outside profile");require(ai.add((int)a)&&bi.add((int)b),"Input mapping must be bijective");String type=encoding(input.get("encoding"));
            var x=object(aInputs.get((int)a));var y=object(bInputs.get((int)b));
            if(x.containsKey("register")||y.containsKey("register")){check(Objects.equals(x.get("register"),y.get("register")),"INPUT_ABI_REGISTER_MISMATCH","ABI input registers must match");String register=Objects.toString(x.get("register"));
                check(!initialEncodings.containsKey(register)||initialEncodings.get(register).equals(type),"INPUT_ENCODING_MISMATCH","Input and initial register encodings disagree");initialEncodings.put(register,type);}
            else{check(n(x,"width")==n(y,"width")&&normalize(original,n(x,"address"),"address").equals(normalize(rebuilt,n(y,"address"),"address")),"INPUT_MEMORY_MISMATCH","Memory input locations/widths must correspond");}
            check(domain(original,x,type).equals(domain(rebuilt,y,type)),"INPUT_VALUE_DOMAIN_MISMATCH","Original/rebuilt input values must have identical mapped domains");inputs.add(new InputMap((int)a,(int)b,type));}
        check(ai.size()==aInputs.size()&&bi.size()==bInputs.size(),"INPUT_DOMAIN_MISMATCH","Map every input dimension exactly once");
        original.runtime=runtime(original.binary);rebuilt.runtime=runtime(rebuilt.binary);
        check(Boolean.TRUE.equals(original.runtime.get("supported"))&&Boolean.TRUE.equals(rebuilt.runtime.get("supported")),"UNSUPPORTED_RUNTIME_DEPENDENCIES","Loader, callback, TLS, relocation or external symbol dependencies are present");
        for(var point:forward.entrySet())check(executable(original,point.getKey())&&executable(rebuilt,point.getValue()),"NONEXECUTABLE_CODE_MAPPING","Code anchors must belong to executable file-backed mappings");
    }
    private boolean executable(Context c,long address){return list(c.runtime.get("executable_ranges")).stream().map(BoundedCorrespondence::object).anyMatch(r->address>=n(r,"address")&&address-n(r,"address")<n(r,"size"));}
    private Set<Object> domain(Context c,Map<String,Object> input,String enc){Set<Object> result=new HashSet<>();int width=input.containsKey("register")?8:(int)n(input,"width");
        for(Object v:list(input.get("values"))){long bits=number(v);if(width!=8)bits&=(1L<<(8*width))-1;require(result.add(normalize(c,bits,enc)),"Mapped input values must be unique");}return result;}
    private Object normalize(Context c,long value,String enc){if(enc.equals("scalar"))return value;if(enc.equals("nullable-address")&&value==0)return "null";
        Set<String> possibilities=new HashSet<>();if(value==RETURN)possibilities.add("caller");
        Long code=c.isOriginal?(forward.containsKey(value)?value:null):reverse.get(value);if(code!=null)possibilities.add("code:"+Long.toHexString(code));
        if(value>=c.stackStart&&value<=c.stackStart+c.stackSize)possibilities.add("stack:"+(value-c.stackStart));
        for(MemoryMap map:maps){long start=c.address(map),end=start+map.size;if(value>=start&&(value<end||map.onePast&&value==end))possibilities.add("memory:"+map.name+":"+(value-start));}
        check(possibilities.size()==1,possibilities.isEmpty()?"UNMAPPED_ADDRESS_CORRESPONDENCE":"AMBIGUOUS_ADDRESS_CORRESPONDENCE","Address 0x"+Long.toHexString(value)+" lacks a unique mapping on "+(c.isOriginal?"original":"rebuilt"));return possibilities.iterator().next();}
    private List<BoundedReferences.ObservationWindow> windows(Context c){return maps.stream().map(m->new BoundedReferences.ObservationWindow(m.name,c.address(m),m.size)).toList();}

    private Map<String,Object> run()throws IOException {
        Map<String,Object> rejection=null;
        try {prepare();original.report=BoundedReferences.analyzeForCorrespondence(original.path,windows(original));rebuilt.report=BoundedReferences.analyzeForCorrespondence(rebuilt.path,windows(rebuilt));
            for(Context c:List.of(original,rebuilt))check(c.profileHash.equals(c.report.get("profile_sha256"))&&c.contract.equals(c.report.get("contract")),"INPUT_CHANGED_DURING_ANALYSIS","Input profiles must remain identical during checking");
            check(Boolean.TRUE.equals(original.report.get("exhaustive"))&&Boolean.TRUE.equals(rebuilt.report.get("exhaustive")),"INCOMPLETE_BOUNDED_EXECUTION","Both binaries must complete all declared executions within bounds");
            for(Context c:List.of(original,rebuilt))check(c.runtime.get("binary_sha256").equals(c.report.get("binary_sha256")),"INPUT_CHANGED_DURING_ANALYSIS","Runtime metadata and execution must bind identical binary snapshots");
            Map<String,Map<String,Object>> left=index(original),right=index(rebuilt);check(left.keySet().equals(right.keySet()),"CASE_DOMAIN_MISMATCH","No execution case may be omitted or duplicated");
            for(String key:new TreeSet<>(left.keySet()))compareCase(key,left.get(key),right.get(key));
        }catch(Problem e){rejection=Map.of("kind",e.kind,"detail",e.getMessage());}
        boolean complete=rejection==null&&differences==0;Map<String,Object> out=new LinkedHashMap<>();out.put("schema","bcl-bounded-correspondence-report-1");out.put("analyzer_version","1.3.0");
        out.put("status",rejection!=null?"REJECTED_CORRESPONDENCE_MODEL":differences>0?"CORRESPONDENCE_COUNTEREXAMPLE":"CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS");
        out.put("correspondence_established",complete);out.put("profile_sha256",profileHash);out.put("contract",profile);out.put("cases_compared",cases.size());out.put("cases",cases);out.put("difference_count",differences);out.put("witnesses",witnesses);
        if(original!=null)out.put("original_profile_sha256",original.profileHash);if(rebuilt!=null)out.put("rebuilt_profile_sha256",rebuilt.profileHash);
        if(rejection!=null)out.put("rejection",rejection);
        if(original!=null&&original.runtime!=null)out.put("original_runtime",original.runtime);if(rebuilt!=null&&rebuilt.runtime!=null)out.put("rebuilt_runtime",rebuilt.runtime);
        if(original!=null&&original.report!=null)out.put("original_analysis",original.report);if(rebuilt!=null&&rebuilt.report!=null)out.put("rebuilt_analysis",rebuilt.report);
        out.put("automatic_rewrite_allowed",false);out.put("general_linux_runtime_equivalence_proved",false);
        out.put("scope","Exhaustive declared input/entry pairs in the closed integer machine model; declared register/persistent-memory outputs, integer ABI preservation and explicitly mapped control-transfer traces");return out;
    }
    private Map<String,Map<String,Object>> index(Context c){Map<String,Map<String,Object>> out=new HashMap<>();for(Object item:list(c.report.get("executions"))){var execution=object(item);long entry=n(execution,"entry");
            Long canonical=c.isOriginal?(entryForward.containsKey(entry)?entry:null):reverse.get(entry);check(canonical!=null,"UNMAPPED_ENTRY","Execution entry is unmapped");List<Object> key=new ArrayList<>();key.add(canonical);
            List<?> choices=list(execution.get("inputs"));for(InputMap input:inputs){var choice=object(choices.get(c.isOriginal?input.original:input.rebuilt));key.add(normalize(c,n(choice,"value"),input.encoding));}
            check(out.putIfAbsent(Json.write(key),execution)==null,"DUPLICATE_EXECUTION_KEY","Multiple executions map to the same logical case");}return out;}
    private void difference(String key,String component,String kind,Object a,Object b){differences++;if(witnesses.size()<128){Map<String,Object> witness=new LinkedHashMap<>();witness.put("case",key);witness.put("component",component);witness.put("kind",kind);witness.put("original",a);witness.put("rebuilt",b);witnesses.add(witness);}}
    private void compareCase(String key,Map<String,Object> a,Map<String,Object> b){var ac=object(a.get("correspondence"));var bc=object(b.get("correspondence"));var ar=object(ac.get("initial_registers"));var br=object(bc.get("initial_registers"));
        for(String reg:REGS){String enc=reg.equals("rsp")?"address":initialEncodings.getOrDefault(reg,"scalar");check(normalize(original,n(ar,reg),enc).equals(normalize(rebuilt,n(br,reg),enc)),"INITIAL_REGISTER_RELATION_MISMATCH","Initial register "+reg+" differs for case "+key);}
        compareMemory(key,ac,bc,true);long before=differences;
        for(var output:outputs.entrySet()){Object x=normalize(original,n(object(a.get("final_registers")),output.getKey()),output.getValue()),y=normalize(rebuilt,n(object(b.get("final_registers")),output.getKey()),output.getValue());if(!x.equals(y))difference(key,"functional","REGISTER_OUTPUT_"+output.getKey(),x,y);}
        compareMemory(key,ac,bc,false);boolean functional=differences==before;before=differences;
        abi(key,original,a);abi(key,rebuilt,b);boolean abi=differences==before;before=differences;
        var at=control(original,ac);var bt=control(rebuilt,bc);if(!at.equals(bt)){int pos=0;while(pos<at.size()&&pos<bt.size()&&at.get(pos).equals(bt.get(pos)))pos++;
            difference(key,"control_flow","TRANSFER_SEQUENCE_AT_"+pos,pos<at.size()?at.get(pos):"end",pos<bt.size()?bt.get(pos):"end");}
        cases.add(Map.of("logical_input",key,"original_case",a.get("index"),"rebuilt_case",b.get("index"),"functional",functional,"abi",abi,"control_flow",differences==before));
    }
    private void compareMemory(String key,Map<String,Object> ac,Map<String,Object> bc,boolean initial){Map<String,byte[]> left=snapshots(ac,initial),right=snapshots(bc,initial);
        for(MemoryMap map:maps){byte[] a=left.get(map.name),b=right.get(map.name);check(a!=null&&b!=null&&a.length==map.size&&b.length==map.size,"MISSING_MEMORY_SNAPSHOT","Expected exact observation windows");
            Map<Integer,Field> fields=new HashMap<>();for(Field field:map.pointers)fields.put(field.offset,field);
            for(int offset=0;offset<map.size;){Field field=fields.get(offset);Object x,y;int width=field==null?1:field.width;
                if(field==null){x=a[offset]&255;y=b[offset]&255;}else{x=normalize(original,word(a,offset,width),field.encoding);y=normalize(rebuilt,word(b,offset,width),field.encoding);}
                if(!x.equals(y)){if(initial)throw new Problem("INITIAL_MEMORY_RELATION_MISMATCH","Mapped memory "+map.name+" offset "+offset+" differs for case "+key);difference(key,"functional","MEMORY_"+map.name+"_OFFSET_"+offset,x,y);break;}offset+=width;}}
    }
    private static Map<String,byte[]> snapshots(Map<String,Object> capture,boolean initial){Map<String,byte[]> out=new HashMap<>();for(Object row:list(capture.get(initial?"initial_memory":"final_memory"))){var item=object(row);out.put((String)item.get("name"),HexFormat.of().parseHex((String)item.get("bytes")));}return out;}
    private static long word(byte[] bytes,int offset,int size){long out=0;for(int i=0;i<size;i++)out|=(bytes[offset+i]&255L)<<(8*i);return out;}
    private void abi(String key,Context c,Map<String,Object> execution){String side=c.isOriginal?"original":"rebuilt";var capture=object(execution.get("correspondence"));var initial=object(capture.get("initial_registers"));var last=object(execution.get("final_registers"));
        if((n(initial,"rsp")+8)%16!=0)difference(key,"abi","ENTRY_STACK_ALIGNMENT_"+side,n(initial,"rsp"),"rsp+8 aligned to 16");
        for(String reg:SAVED)if(n(initial,reg)!=n(last,reg))difference(key,"abi","CALLEE_SAVED_"+side+"_"+reg,initial.get(reg),last.get(reg));
        ArrayDeque<Map<String,Object>> frames=new ArrayDeque<>();
        for(Object row:list(capture.get("transfers"))){var transfer=object(row);String kind=(String)transfer.get("kind");
            if(kind.equals("call")){if((n(transfer,"rsp")+8)%16!=0)difference(key,"abi","CALL_STACK_ALIGNMENT_"+side,transfer.get("from"),"rsp aligned before call");frames.addLast(transfer);}
            else if(kind.equals("return")){if(frames.isEmpty()){difference(key,"abi","RETURN_WITHOUT_CALL_"+side,transfer.get("from"),"ordinary call frame");continue;}var call=frames.removeLast();
                if(n(transfer,"to")!=n(call,"return_address")||n(transfer,"rsp")!=n(call,"rsp")+8)difference(key,"abi","CALL_RETURN_CONTINUATION_"+side,transfer,call);
                var saved=object(call.get("callee_saved"));var returned=object(transfer.get("callee_saved"));for(String reg:SAVED)if(n(saved,reg)!=n(returned,reg))difference(key,"abi","INTERNAL_CALLEE_SAVED_"+side+"_"+reg,saved.get(reg),returned.get(reg));}
            else if(kind.equals("entry-return")&&!frames.isEmpty())difference(key,"abi","UNCLOSED_CALL_FRAME_"+side,frames.size(),0);}
        for(Object row:list(execution.get("references"))){var access=object(row);if(!Boolean.TRUE.equals(access.get("write")))continue;long address=n(access,"address"),width=n(access,"width");
            if(address>=c.stackStart&&address+width<=c.stackStart+c.stackSize)continue;
            check(maps.stream().anyMatch(m->address>=c.address(m)&&address+width<=c.address(m)+m.size),"UNMAPPED_PERSISTENT_WRITE","All non-stack writes must belong to declared persistent outputs on "+side+" at IP "+access.get("ip"));}
    }
    private List<Map<String,Object>> control(Context c,Map<String,Object> capture){List<Map<String,Object>> out=new ArrayList<>();for(Object row:list(capture.get("transfers"))){var transfer=object(row);long from=n(transfer,"from"),to=n(transfer,"to");
            check(c.isOriginal?forward.containsKey(from):reverse.containsKey(from),"UNMAPPED_CONTROL_SITE","Map every reached non-fallthrough control source: "+Long.toHexString(from));
            if(!"entry-return".equals(transfer.get("kind")))check(c.isOriginal?forward.containsKey(to):reverse.containsKey(to),"UNMAPPED_CONTROL_TARGET","Map every reached control target: "+Long.toHexString(to));
            out.add(Map.of("from",normalize(c,from,"address"),"to",normalize(c,to,"address"),"kind",transfer.get("kind")));}return out;}

    /** Reject runtime binding metadata even when the bounded path never touches it. */
    private static Map<String,Object> runtime(Path path)throws IOException {
        byte[] raw;try(var in=Files.newInputStream(path)){raw=in.readNBytes(64*1024*1024+1);}require(raw.length>=64&&raw.length<=64*1024*1024,"Invalid runtime ELF size");ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        require(b.getInt(0)==0x464c457f&&raw[4]==2&&raw[5]==1,"Require ELF64 little endian");Hazards hazards=new Hazards();List<Map<String,Object>> executable=new ArrayList<>();
        long ph=b.getLong(32);int pn=Short.toUnsignedInt(b.getShort(56));require(ph>=64&&b.getShort(54)==56&&ph<=raw.length-56L*pn,"Invalid program headers");
        if(b.getShort(16)!=2)hazards.add(Map.of("kind","NON_FIXED_EXECUTABLE"));
        for(int i=0;i<pn;i++){int at=(int)ph+i*56,type=b.getInt(at);if(type==2||type==3||type==7)hazards.add(Map.of("kind",type==2?"DYNAMIC_LOADER":type==3?"INTERPRETER":"TLS_RUNTIME","program_header",i));
            if(type==1){long address=b.getLong(at+16),off=b.getLong(at+8),size=b.getLong(at+32);require(address>=0&&size>=0&&off>=0&&address<=Long.MAX_VALUE-size&&off<=raw.length-size,"Invalid runtime load extent");
                if((b.getInt(at+4)&1)!=0&&size>0)executable.add(Map.of("address",address,"size",size));}}
        long sh=b.getLong(40);int count=Short.toUnsignedInt(b.getShort(60));
        if(sh!=0||count!=0){require(sh>=64&&count>0&&count<0xff00&&b.getShort(58)==64&&sh<=raw.length-64L*count,"Invalid runtime section table");
            long strings=0,stringsSize=0;int names=Short.toUnsignedInt(b.getShort(62));
            if(names!=0){require(names<count,"Invalid section-name table index");int at=(int)sh+names*64;strings=b.getLong(at+24);stringsSize=b.getLong(at+32);
                require(b.getInt(at+4)==3&&strings>=0&&stringsSize>0&&strings<=raw.length-stringsSize,"Invalid section-name table");}
            for(int i=0;i<count;i++){int at=(int)sh+i*64;long type=Integer.toUnsignedLong(b.getInt(at+4)),flags=b.getLong(at+8),off=b.getLong(at+24),size=b.getLong(at+32);
                require(size>=0&&off>=0&&(type==8||off<=raw.length-size),"Invalid runtime section extent");if(size==0)continue;
                String name="";if(names!=0){long index=Integer.toUnsignedLong(b.getInt(at));require(index<stringsSize,"Invalid section-name offset");int begin=(int)(strings+index),end=begin;
                    while(end<strings+stringsSize&&raw[end]!=0){end++;require(end-begin<=4096,"Runtime section-name too long");}require(end<strings+stringsSize,"Unterminated section name");name=new String(raw,begin,end-begin,java.nio.charset.StandardCharsets.US_ASCII);}
                if(Set.of(".ctors",".dtors",".init",".fini").contains(name))hazards.add(Map.of("kind","LEGACY_INITIALIZATION_OR_CALLBACK","section",i,"name",name));
                if(type==14||type==15||type==16)hazards.add(Map.of("kind","CALLBACK_ARRAY","section",i,"section_type",type,"size",size));
                if(type==6||(flags&0x400)!=0||((type==4||type==9)&&(flags&2)!=0))hazards.add(Map.of("kind","RUNTIME_BINDING_SECTION","section",i,"section_type",type));
                if(type==2||type==11){require(b.getLong(at+56)==24&&size%24==0&&size/24<=1000000,"Invalid runtime symbol table");for(long j=1;j<size/24;j++){int p=(int)(off+j*24),info=raw[p+4]&255,section=Short.toUnsignedInt(b.getShort(p+6));
                    if((info&15)==10||(section==0&&(info>>>4)==1)||(section==0&&(info>>>4)==2))hazards.add(Map.of("kind",(info&15)==10?"IFUNC_RESOLVER":"UNDEFINED_EXTERNAL_SYMBOL","section",i,"symbol_index",j));}}
            }}
        return Map.of("supported",hazards.isEmpty(),"hazards",hazards,"hazard_count",hazards.count,"binary_sha256",GroupPlan.hash(raw),"executable_ranges",executable,"model","closed-static-x86-64; no loader, external libraries, TLS or callback execution");
    }
}
