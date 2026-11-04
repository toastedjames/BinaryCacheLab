package org.binarycachelab.analysis;

import java.io.IOException;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.*;
import static org.binarycachelab.analysis.ReferenceClosure.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Exhaustive concrete execution of a finite, explicitly initialized closed machine model. */
public final class BoundedReferences {
    private static final String[] REGS={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    private static final long LIMIT=0x800000000000L, RETURN=0x7ffffffffff0L;
    private record Region(String name,long address,long size){}
    private record Input(int register,long address,int width,List<Long> values){}
    private record Value(long bits,long tags){}
    private static final class Segment {
        final long address; final int flags; final byte[] bytes; final long[] tags;
        Segment(long address,int flags,byte[] bytes){this.address=address;this.flags=flags;this.bytes=bytes;tags=new long[bytes.length];}
        Segment copy(){Segment s=new Segment(address,flags,bytes.clone());System.arraycopy(tags,0,s.tags,0,tags.length);return s;}
    }
    private static final class Rejected extends RuntimeException {
        final String kind; Rejected(String kind,String message){super(message);this.kind=kind;}
    }
    private final Map<String,Object> profile;
    private final List<Segment> image=new ArrayList<>();
    private final List<Region> regions=new ArrayList<>();
    private final List<Input> inputs=new ArrayList<>();
    private final List<Long> entries=new ArrayList<>();
    private final Map<Long,Ins> decoded=new TreeMap<>();
    private final Map<Long,String> covered=new TreeMap<>();
    private final Map<String,Map<String,Object>> edges=new TreeMap<>();
    private final long[] initial=new long[16];
    private long stackStart,stackSize,initialRsp,maxSteps,maxTotal,maxCases,maxEvents,maxMemory,totalSteps,eventCount,caseCount;
    private String binaryHash,profileHash;
    record ObservationWindow(String name,long address,int size){}
    private List<ObservationWindow> observationWindows=List.of();
    private boolean correspondenceCapture;

    private BoundedReferences(Path path)throws IOException {
        byte[] raw;try(var stream=Files.newInputStream(path)){raw=stream.readNBytes(1024*1024+1);}require(raw.length<=1024*1024,"Bounded profile exceeds 1 MiB");
        profile=Json.object(new String(raw,java.nio.charset.StandardCharsets.UTF_8));profileHash=GroupPlan.hash(raw);
    }
    public static Map<String,Object> analyze(Path path)throws IOException {BoundedReferences a=new BoundedReferences(path);return a.run(path.toAbsolutePath().getParent());}
    /** Complete finite transfer capture for protection map proposal; no approval. */
    public static Map<String,Object> analyzeWithControl(Path path)throws IOException {
        return analyzeForCorrespondence(path,List.of());
    }
    static Map<String,Object> analyzeForCorrespondence(Path path,List<ObservationWindow> windows)throws IOException {
        BoundedReferences a=new BoundedReferences(path);a.correspondenceCapture=true;a.observationWindows=List.copyOf(windows);return a.run(path.toAbsolutePath().getParent());
    }
    private static long number(Object value){require(value instanceof Long||value instanceof Integer,"Expected integer (signed 64-bit bit pattern)");return ((Number)value).longValue();}
    private static long n(Map<String,Object> m,String key){return number(m.get(key));}
    private static Map<String,Object> obj(Object o){return MultiRegionPlan.object(o);}
    private static List<?> list(Object o){require(o instanceof List<?>,"Expected array");return (List<?>)o;}
    private static void keys(Map<String,Object> m,String... allowed){require(Set.of(allowed).containsAll(m.keySet()),"Unknown field(s): "+m.keySet().stream().filter(k->!Set.of(allowed).contains(k)).toList());}
    private static void reject(boolean okay,String kind,String detail){if(!okay)throw new Rejected(kind,detail);}
    private static int reg(String name){for(int i=0;i<16;i++)if(REGS[i].equals(name))return i;throw new IllegalArgumentException("Unknown register "+name);}
    private static long bound(Map<String,Object> b,String key,long cap){long value=n(b,key);require(value>=1&&value<=cap,key+" must be 1.."+cap);return value;}
    private static boolean overlap(long a,long size,long b,long length){return a<b+length&&b<a+size;}
    private static boolean extent(long a,long size){return a>=0&&size>0&&a<LIMIT&&size<=LIMIT-a;}

    private void prepare(Path base)throws IOException {
        keys(profile,"schema","binary","entries","regions","machine","inputs","bounds");
        require("bcl-bounded-references-1".equals(profile.get("schema")),"Expected bcl-bounded-references-1");
        var bounds=obj(profile.get("bounds"));keys(bounds,"max_steps_per_execution","max_total_steps","max_executions","max_memory_bytes","max_reference_events");
        maxSteps=bound(bounds,"max_steps_per_execution",1000000);maxTotal=bound(bounds,"max_total_steps",2000000);
        maxCases=bound(bounds,"max_executions",65536);maxMemory=bound(bounds,"max_memory_bytes",16*1024*1024);maxEvents=bound(bounds,"max_reference_events",200000);
        var machine=obj(profile.get("machine"));keys(machine,"runtime","instruction_set","register_defaults","initial_registers","flags","memory_initialization","stack");
        reject("closed-static-x86-64".equals(machine.get("runtime")),"UNSUPPORTED_RUNTIME","Only closed static x86-64 execution is modeled");
        reject("bcl-x86-64-integer-1".equals(machine.get("instruction_set")),"UNSUPPORTED_INSTRUCTION_MODEL","Explicit bcl-x86-64-integer-1 instruction model required");
        require("zero".equals(machine.get("register_defaults"))&&"zero".equals(machine.get("flags")),"Explicit zero register/flag defaults required");
        require("elf-file-bss-zero-stack-zero".equals(machine.get("memory_initialization")),"Explicit file/BSS/stack initialization required");
        var stack=obj(machine.get("stack"));keys(stack,"address","size");stackStart=n(stack,"address");stackSize=n(stack,"size");
        reject(extent(stackStart,stackSize)&&stackSize>=16&&stackSize<=maxMemory,"MEMORY_BOUND_EXCEEDED","Invalid stack extent or memory budget");
        initialRsp=stackStart+stackSize-8;initial[4]=initialRsp;
        for(var r:obj(machine.get("initial_registers")).entrySet()){int index=reg(r.getKey());require(index!=4,"RSP is set by the stack contract");initial[index]=number(r.getValue());}
        require(profile.get("binary") instanceof String,"Missing binary path");Path binary=Path.of((String)profile.get("binary"));if(!binary.isAbsolute())binary=base.resolve(binary);
        loadImage(binary);image.add(new Segment(stackStart,6,new byte[Math.toIntExact(stackSize)]));
        long bytes=0;for(int i=0;i<image.size();i++){Segment s=image.get(i);bytes+=s.bytes.length;
            reject(!overlap(s.address,s.bytes.length,RETURN,1),"RESERVED_RETURN_ADDRESS_MAPPED","Caller continuation is reserved");
            for(int j=0;j<i;j++){Segment other=image.get(j);
                reject(!overlap(s.address,s.bytes.length,other.address,other.bytes.length),"OVERLAPPING_MAPPINGS","ELF/stack mappings must be disjoint");
                reject((s.address+s.bytes.length-1)/4096<other.address/4096||(other.address+other.bytes.length-1)/4096<s.address/4096,"SHARED_MAPPING_PAGE","Mappings may not share a 4 KiB page in this model");}}
        reject(bytes<=maxMemory,"MEMORY_BOUND_EXCEEDED","Image plus stack exceeds max_memory_bytes");
        require(list(profile.get("entries")).size()<=128,"At most 128 entries");
        for(Object e:list(profile.get("entries"))){long entry=number(e);require(!entries.contains(entry),"Duplicate entry");entries.add(entry);}
        require(!entries.isEmpty()&&entries.size()<=128,"Declare 1..128 entries");
        require(list(profile.get("regions")).size()<=63,"At most 63 regions");
        for(Object item:list(profile.get("regions"))){var r=obj(item);keys(r,"name","address","size");require(r.get("name") instanceof String,"Region name required");
            Region region=new Region((String)r.get("name"),n(r,"address"),n(r,"size"));
            require(extent(region.address,region.size),"Invalid region extent");
            reject(!overlap(region.address,region.size,stackStart,stackSize),"REGION_STACK_OVERLAP","Regions must be disjoint from the modeled stack");
            segment(image,region.address,region.size,4);
            require(regions.stream().noneMatch(x->x.name.equals(region.name)),"Duplicate region name");regions.add(region);}
        require(!regions.isEmpty()&&regions.size()<=63,"Declare 1..63 regions");
        caseCount=entries.size();
        require(list(profile.get("inputs")).size()<=128,"At most 128 input dimensions");
        for(Object item:list(profile.get("inputs"))){var input=obj(item);keys(input,"register","address","width","values");
            int register=-1,width=8;long address=0;
            if(input.containsKey("register")){require(!input.containsKey("address")&&!input.containsKey("width"),"Input must select register OR memory");register=reg(Objects.toString(input.get("register")));require(register!=4,"RSP inputs are outside the entry contract");}
            else{address=n(input,"address");long w=n(input,"width");require(Set.of(1L,2L,4L,8L).contains(w),"Memory input width must be 1,2,4,8");width=(int)w;
                Segment segment=segment(image,address,width,2);reject((segment.flags&1)==0,"SELF_MODIFICATION_UNSUPPORTED","Inputs may not modify executable mappings");
                reject(!overlap(address,width,initialRsp,8),"CALLER_CONTINUATION_INPUT","Inputs may not replace caller continuation");}
            List<Long> values=new ArrayList<>();for(Object v:list(input.get("values"))){long bits=mask(number(v),width);require(!values.contains(bits),"Duplicate normalized input value");values.add(bits);}
            require(!values.isEmpty()&&values.size()<=65536,"Input values must be a nonempty finite list (max 65536)");
            for(Input old:inputs)require(register>=0?old.register!=register:old.register>=0||!overlap(address,width,old.address,old.width),"Duplicate or overlapping input dimensions");
            reject(caseCount<=maxCases/values.size(),"EXECUTION_BOUND_EXCEEDED","Full Cartesian input/entry product exceeds max_executions");caseCount*=values.size();inputs.add(new Input(register,address,width,List.copyOf(values)));
        }
        reject(caseCount<=maxCases,"EXECUTION_BOUND_EXCEEDED","Entry count exceeds max_executions");
        long observedBytes=0;
        for(ObservationWindow window:observationWindows){require(window.size>0,"Observation window must be nonempty");segment(image,window.address,window.size,4);observedBytes+=window.size;}
        reject(observedBytes<=4*1024*1024L/Math.max(1,caseCount),"CORRESPONDENCE_CAPTURE_BOUND","Memory observations across all executions exceed 4 MiB per snapshot side");
    }

    private void loadImage(Path path)throws IOException {
        byte[] raw;try(var stream=Files.newInputStream(path)){raw=stream.readNBytes(64*1024*1024+1);}
        require(raw.length>=64&&raw.length<=64*1024*1024,"ELF must be <=64 MiB");binaryHash=GroupPlan.hash(raw);
        ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        require(b.getInt(0)==0x464c457f&&raw[4]==2&&raw[5]==1&&raw[6]==1&&b.getShort(18)==62&&b.getInt(20)==1&&b.getShort(52)==64,"Require x86-64 little-endian ELF64");
        reject(b.getShort(16)==2,"UNSUPPORTED_RUNTIME","Require fixed-address ET_EXEC; PIE/dynamic rebasing is not modeled");
        long offset=b.getLong(32);int count=Short.toUnsignedInt(b.getShort(56));require(offset>=64&&count>0&&count<65535&&b.getShort(54)==56&&offset<=raw.length-56L*count,"Invalid program headers");
        long memory=stackSize;
        for(int j=0;j<count;j++){int at=(int)offset+j*56,type=b.getInt(at),flags=b.getInt(at+4);
            reject(type!=2&&type!=3&&type!=7,"UNSUPPORTED_RUNTIME","Dynamic loader, interpreter and TLS segments are excluded");
            if(type!=1)continue;long file=b.getLong(at+8),address=b.getLong(at+16),size=b.getLong(at+32),mem=b.getLong(at+40);
            require(file>=0&&size>=0&&mem>=size&&file<=raw.length-size,"Invalid PT_LOAD file range");if(mem==0)continue;
            reject((file&4095)==(address&4095),"MAPPING_ALIGNMENT","File/virtual offsets must be congruent modulo 4 KiB");
            reject(extent(address,mem)&&mem<=maxMemory-memory,"MEMORY_BOUND_EXCEEDED","Image mappings exceed address or allocation bounds");memory+=mem;
            byte[] bytes=new byte[(int)mem];System.arraycopy(raw,(int)file,bytes,0,(int)size);image.add(new Segment(address,flags,bytes));}
        require(!image.isEmpty(),"No loadable image");
    }
    private static Segment segment(List<Segment> memory,long address,long width,int permission){
        reject(extent(address,width),"MEMORY_OUT_OF_BOUNDS","Noncanonical/high-half/wrapping address");
        for(Segment s:memory)if(address>=s.address&&address-s.address<=s.bytes.length-width){reject((s.flags&permission)==permission,"MEMORY_PERMISSION","Mapping does not grant required permission");return s;}
        throw new Rejected("MEMORY_OUT_OF_BOUNDS","No single mapping contains access at 0x"+Long.toHexString(address));
    }
    private long tags(long bits){long result=0;for(int i=0;i<regions.size();i++){Region r=regions.get(i);if(bits>=r.address&&bits<=r.address+r.size)result|=1L<<i;}return result;}
    private List<String> names(long tags){List<String> result=new ArrayList<>();for(int i=0;i<regions.size();i++)if((tags&(1L<<i))!=0)result.add(regions.get(i).name);return result;}
    private static long mask(long value,int width){return width==8?value:value&((1L<<(width*8))-1);}
    private static long signed(long value,int width){return width==8?value:(value<<(64-width*8))>>(64-width*8);}

    private Map<String,Object> run(Path base)throws IOException {
        List<Map<String,Object>> executions=new ArrayList<>();Map<String,Object> rejection=null;
        try {prepare(base);
            for(long index=0;index<caseCount;index++){
                if(totalSteps>=maxTotal||eventCount>=maxEvents){rejection=Map.of("kind","GLOBAL_BOUND_EXCEEDED","detail","Remaining executions were not evaluated");break;}
                Machine m=new Machine(index);executions.add(m.execute());
            }
        }catch(Rejected e){rejection=Map.of("kind",e.kind,"detail",e.getMessage());}
        boolean complete=rejection==null&&executions.size()==caseCount&&executions.stream().allMatch(e->"RETURNED".equals(e.get("status")));
        Map<String,Object> result=new LinkedHashMap<>();result.put("schema","bcl-bounded-reference-report-1");result.put("analyzer_version","1.2.1");
        result.put("status",complete?"COMPLETE_WITHIN_DECLARED_BOUNDS":"REJECTED_MODEL_OR_BOUNDS");result.put("exhaustive",complete);
        result.put("binary_sha256",binaryHash==null?"unavailable":binaryHash);result.put("profile_sha256",profileHash);result.put("contract",profile);
        result.put("expected_executions",caseCount);result.put("evaluated_executions",executions.size());result.put("total_steps",totalSteps);result.put("reference_events",eventCount);
        result.put("executions",executions);result.put("instruction_coverage",covered.entrySet().stream().map(e->Map.of("ip",e.getKey(),"bytes",e.getValue())).toList());
        result.put("control_flow_edges",new ArrayList<>(edges.values()));if(rejection!=null)result.put("rejection",rejection);
        result.put("automatic_rewrite_allowed",false);result.put("whole_program_runtime_proved",false);
        result.put("scope","Every declared entry and Cartesian input combination in the explicit closed machine model; unsupported or over-bound executions reject the result");
        result.put("provenance_scope","Region numeric membership and conservatively propagated derivation tags; tags do not distinguish intentional pointers from equal-valued integers");return result;
    }
    private final class Machine {
        final List<Segment> memory=image.stream().map(Segment::copy).toList();final long[] regs=initial.clone(),provenance=new long[16];
        final List<Map<String,Object>> events=new ArrayList<>(),escapes=new ArrayList<>(),choices=new ArrayList<>();
        final List<Map<String,Object>> transfers=new ArrayList<>();
        List<Map<String,Object>> initialMemory;
        Map<String,Object> initialRegisters;
        final long index,entry;long ip,steps;Boolean cf=false,pf=false,zf=false,sf=false,of=false;boolean returned;
        Machine(long index){this.index=index;entry=entries.get((int)(index%entries.size()));ip=entry;long cursor=index/entries.size();
            rawStore(initialRsp,new Value(RETURN,0),8);
            for(Input input:inputs){long value=input.values.get((int)(cursor%input.values.size()));cursor/=input.values.size();
                if(input.register>=0){regs[input.register]=value;choices.add(Map.of("register",REGS[input.register],"value",value));}
                else{rawStore(input.address,new Value(value,tags(value)),input.width);choices.add(Map.of("address",input.address,"width",input.width,"value",value));}}
            for(int i=0;i<16;i++)provenance[i]=tags(regs[i]);
            if(correspondenceCapture){initialMemory=snapshotMemory();initialRegisters=snapshotRegisters();}
        }
        Map<String,Object> execute(){Map<String,Object> result=new LinkedHashMap<>();result.put("index",index);result.put("entry",entry);result.put("inputs",choices);
            try{while(!returned){reject(steps<maxSteps,"INSTRUCTION_BOUND_EXCEEDED","Execution has not returned within max_steps_per_execution");reject(totalSteps<maxTotal,"TOTAL_STEP_BOUND_EXCEEDED","Total instruction budget exhausted");
                    Ins i=instruction(ip);steps++;totalSteps++;step(i);}
                result.put("status","RETURNED");
                for(int r=0;r<16;r++)if(provenance[r]!=0)escapes.add(Map.of("kind","return-register","register",REGS[r],"value",regs[r],"regions",names(provenance[r])));
            }catch(Rejected e){result.put("status","REJECTED");result.put("failure",Map.of("kind",e.kind,"ip",ip,"detail",e.getMessage()));}
            result.put("steps",steps);result.put("references",events);result.put("escapes",escapes);
            Map<String,Object> flags=new LinkedHashMap<>();flags.put("cf",cf);flags.put("pf",pf);flags.put("zf",zf);flags.put("sf",sf);flags.put("of",of);result.put("final_flags",flags);
            Map<String,Object> registers=new LinkedHashMap<>();for(int r=0;r<16;r++)registers.put(REGS[r],regs[r]);result.put("final_registers",registers);
            if(correspondenceCapture)result.put("correspondence",Map.of("initial_registers",initialRegisters,"initial_memory",initialMemory,"final_memory",snapshotMemory(),"transfers",transfers));
            return result;
        }
        Map<String,Object> snapshotRegisters(){Map<String,Object> out=new LinkedHashMap<>();for(int r=0;r<16;r++)out.put(REGS[r],regs[r]);return out;}
        List<Map<String,Object>> snapshotMemory(){List<Map<String,Object>> out=new ArrayList<>();
            for(ObservationWindow w:observationWindows){Segment s=segment(memory,w.address,w.size,4);int at=(int)(w.address-s.address);
                out.add(Map.of("name",w.name,"address",w.address,"bytes",HexFormat.of().formatHex(Arrays.copyOfRange(s.bytes,at,at+w.size))));}return out;}
        Ins instruction(long address){Ins i=decoded.get(address);if(i!=null)return i;Segment s=segment(memory,address,1,1);int at=(int)(address-s.address);
            for(int size=1;size<=15&&at+size<=s.bytes.length;size++)try{
                byte[] bytes=Arrays.copyOfRange(s.bytes,at,at+size);i=decode(address,bytes);decoded.put(address,i);covered.put(address,HexFormat.of().formatHex(bytes));return i;
            }catch(IllegalArgumentException|ArithmeticException ignored){}
            throw new Rejected("UNSUPPORTED_INSTRUCTION","No supported instruction at 0x"+Long.toHexString(address));
        }
        Value rawLoad(long address,int width){Segment s=segment(memory,address,width,4);int at=(int)(address-s.address);long value=0,tag=0;
            for(int j=0;j<width;j++){value|=(s.bytes[at+j]&255L)<<(8*j);tag|=s.tags[at+j];}return new Value(value,tag|tags(value));}
        void rawStore(long address,Value value,int width){Segment s=segment(memory,address,width,2);reject((s.flags&1)==0,"SELF_MODIFICATION_UNSUPPORTED","Writes into executable mappings are excluded");int at=(int)(address-s.address);
            for(int j=0;j<width;j++){s.bytes[at+j]=(byte)(value.bits>>>(8*j));s.tags[at+j]=value.tags;}}
        void event(long address,Value value,int width,boolean write){reject(eventCount<maxEvents,"REFERENCE_EVENT_BOUND_EXCEEDED","Reference event budget exhausted");eventCount++;
            List<String> hits=new ArrayList<>();for(Region r:regions)if(overlap(address,width,r.address,r.size))hits.add(r.name);
            events.add(Map.of("ip",ip,"address",address,"width",width,"write",write,"value",value.bits,"overlapping_regions",hits,"value_provenance",names(value.tags)));
            if(write&&value.tags!=0)escapes.add(Map.of("kind","memory-store","ip",ip,"address",address,"width",width,"value",value.bits,"regions",names(value.tags),"stack",address>=stackStart&&address<stackStart+stackSize));}
        Value load(long address,int width){Value v=rawLoad(address,width);event(address,v,width,false);return v;}
        void store(long address,Value v,int width){rawStore(address,v,width);event(address,v,width,true);}
        Value address(Mem m,Ins i){long value=m.rip()?i.ip()+i.length():m.base()<0?0:regs[m.base()],tag=m.base()<0?0:provenance[m.base()];
            if(m.index()>=0){value+=regs[m.index()]*m.scale();tag|=provenance[m.index()];}value+=m.displacement();return new Value(value,tag|tags(value));}
        Value read(Arg a,int width,Ins i){if(a.memory()!=null)return load(address(a.memory(),i).bits,width);long value=mask(a.immediate()!=null?a.immediate():regs[a.reg()],width);
            return new Value(value,(a.immediate()!=null?0:provenance[a.reg()])|tags(value));}
        void write(Arg a,Value v,int width,Ins i){long value=mask(v.bits,width),tag=v.tags|tags(value);if(a.memory()!=null){store(address(a.memory(),i).bits,new Value(value,tag),width);return;}
            reject(width==4||width==8,"UNSUPPORTED_REGISTER_WIDTH","Partial register writes are excluded");regs[a.reg()]=value;provenance[a.reg()]=tag;}
        void edge(long target,String kind){edges.put(ip+":"+target+":"+kind,Map.of("from",ip,"to",target,"kind",kind));
            if(correspondenceCapture&&!kind.equals("fallthrough"))transfers.add(transfer(target,kind));ip=target;}
        Map<String,Object> transfer(long target,String kind){Map<String,Object> out=new LinkedHashMap<>();out.put("from",ip);out.put("to",target);out.put("kind",kind);out.put("rsp",regs[4]);
            Map<String,Object> saved=new LinkedHashMap<>();for(int r:new int[]{3,5,12,13,14,15})saved.put(REGS[r],regs[r]);out.put("callee_saved",saved);
            if(kind.equals("call"))out.put("return_address",ip+decoded.get(ip).length());return out;}
        void commonFlags(long value,int width){long v=mask(value,width);zf=v==0;sf=(v&(1L<<(width*8-1)))!=0;pf=(Integer.bitCount((int)v&255)&1)==0;}
        Value arithmetic(Value a,Value b,String op,int width,boolean same){long x=mask(a.bits,width),y=mask(b.bits,width),value,sign=1L<<(width*8-1);int shift=(int)(y&(width==8?63:31));
            switch(op){
                case "ADD" -> {value=mask(x+y,width);cf=Long.compareUnsigned(value,x)<0;of=((~(x^y)&(x^value))&sign)!=0;}
                case "SUB","CMP" -> {value=mask(x-y,width);cf=Long.compareUnsigned(x,y)<0;of=(((x^y)&(x^value))&sign)!=0;}
                case "AND","TEST" -> {value=x&y;cf=false;of=false;}
                case "OR" -> {value=x|y;cf=false;of=false;}
                case "XOR" -> {value=x^y;cf=false;of=false;}
                case "SHL","SHR","SAR" -> {
                    if(shift==0)return a;
                    value=op.equals("SHL")?mask(x<<shift,width):op.equals("SHR")?x>>>shift:mask(signed(x,width)>>shift,width);
                    cf=op.equals("SHL")?(x&(1L<<(width*8-shift)))!=0:(x&(1L<<(shift-1)))!=0;
                    of=shift!=1?null:op.equals("SHL")?((value&sign)!=0)^cf:op.equals("SHR")?(x&sign)!=0:false;
                }
                default -> throw new Rejected("UNSUPPORTED_INSTRUCTION","Arithmetic operation not modeled");
            }
            commonFlags(value,width);return new Value(value,(same&&op.equals("XOR")?0:a.tags|b.tags)|tags(value));
        }
        boolean flag(Boolean value){reject(value!=null,"UNDEFINED_FLAG_DEPENDENCY","Branch depends on an architecturally undefined flag");return value;}
        boolean condition(Ins i){Segment s=segment(memory,ip,i.length(),1);int at=(int)(ip-s.address),op=s.bytes[at++]&255;if((op&0xf0)==0x40)op=s.bytes[at++]&255;int c=(op==0x0f?s.bytes[at]&255:op)&15;
            return switch(c){case 0->flag(of);case 1->!flag(of);case 2->flag(cf);case 3->!flag(cf);case 4->flag(zf);case 5->!flag(zf);case 6->flag(cf)||flag(zf);case 7->!flag(cf)&&!flag(zf);case 8->flag(sf);case 9->!flag(sf);case 10->flag(pf);case 11->!flag(pf);case 12->flag(sf)!=flag(of);case 13->flag(sf)==flag(of);case 14->flag(zf)||(flag(sf)!=flag(of));case 15->!flag(zf)&&(flag(sf)==flag(of));default->throw new AssertionError();};}
        void step(Ins i){long next=ip+i.length();Value a,b;
            switch(i.op()){
                case "NOP" -> {}
                case "MOV" -> write(i.dst(),read(i.src(),i.width(),i),i.width(),i);
                case "LEA" -> write(i.dst(),address(i.src().memory(),i),i.width(),i);
                case "MOVZX" -> write(i.dst(),read(i.src(),i.width(),i),4,i);
                case "MOVZX64" -> write(i.dst(),read(i.src(),i.width(),i),8,i);
                case "MOVSXD" -> {a=read(i.src(),4,i);write(i.dst(),new Value((long)(int)a.bits,a.tags),8,i);}
                case "LEAVE" -> {regs[4]=regs[5];provenance[4]=provenance[5];a=load(regs[4],8);regs[4]+=8;regs[5]=a.bits;provenance[5]=a.tags;}
                case "PUSH" -> {a=read(i.src(),8,i);regs[4]-=8;store(regs[4],a,8);}
                case "POP" -> {a=load(regs[4],8);regs[4]+=8;write(i.dst(),a,8,i);}
                case "ADD","SUB","AND","OR","XOR","SHL","SHR","SAR","CMP","TEST" -> {
                    a=read(i.dst(),i.width(),i);b=read(i.src(),i.width(),i);Value value=arithmetic(a,b,i.op(),i.width(),i.dst().reg()>=0&&i.dst().reg()==i.src().reg());
                    if(!i.op().equals("CMP")&&!i.op().equals("TEST"))write(i.dst(),value,i.width(),i);}
                case "INC","DEC" -> {a=read(i.dst(),i.width(),i);Boolean carry=cf;Value value=arithmetic(a,new Value(1,0),i.op().equals("INC")?"ADD":"SUB",i.width(),false);cf=carry;write(i.dst(),value,i.width(),i);}
                case "JCC" -> {edge(condition(i)?i.target():next,"conditional");return;}
                case "JMP","CALL" -> {long target=i.src()==null?i.target():read(i.src(),8,i).bits;
                    if(i.op().equals("CALL")){regs[4]-=8;store(regs[4],new Value(next,0),8);}edge(target,i.op().toLowerCase(Locale.ROOT));return;}
                case "RET" -> {long target=load(regs[4],8).bits;regs[4]+=8;
                    if(target==RETURN){reject(regs[4]==initialRsp+8,"RETURN_STACK_CONTRACT","Caller continuation reached with a different stack position");
                        if(correspondenceCapture)transfers.add(transfer(RETURN,"entry-return"));returned=true;return;}
                    edge(target,"return");return;}
                default -> throw new Rejected("UNSUPPORTED_INSTRUCTION","Unmodeled operation "+i.op());
            }
            edge(next,"fallthrough");
        }
    }
}
