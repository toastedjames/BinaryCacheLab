package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.binarycachelab.workflow.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Restricted x86-64 byte decoder and monotone, context-sensitive pointer analysis. */
public final class ReferenceClosure {
    private static final String[] REGS={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    private record Atom(boolean stack,long value){}
    private record Value(Set<Atom> values,boolean derived){
        Value(Set<Atom> values){this(values,false);}
        Value tagged(){return derived?this:new Value(values,true);}
        static Value top(){return new Value(null);} static Value constant(long n){return new Value(Set.of(new Atom(false,n)));}
        static Value stack(long n){return new Value(Set.of(new Atom(true,n)));} boolean unknown(){return values==null;}
        Value join(Value b){if(unknown()||b.unknown())return new Value(null,derived||b.derived);Set<Atom> all=new HashSet<>(values);all.addAll(b.values);return new Value(all.size()>8?null:Set.copyOf(all),derived||b.derived);}
    }
    record Mem(int base,int index,int scale,long displacement,boolean rip){}
    record Arg(int reg,Long immediate,Mem memory){static Arg reg(int r){return new Arg(r,null,null);}static Arg imm(long n){return new Arg(-1,n,null);}static Arg mem(Mem m){return new Arg(-1,null,m);}}
    record Ins(long ip,int length,String op,int width,Arg dst,Arg src,long target){}
    private record Key(boolean stack,long address,int width){}
    private record Point(long ip,List<Long> returns){}
    private static final class State {
        final Value[] regs=new Value[16];final Map<Key,Value> memory=new HashMap<>();
        Boolean zero;
        State(){Arrays.fill(regs,Value.top());}State copy(){State s=new State();System.arraycopy(regs,0,s.regs,0,16);s.memory.putAll(memory);s.zero=zero;return s;}
        boolean merge(State other){boolean changed=false;Boolean z=Objects.equals(zero,other.zero)?zero:null;if(!Objects.equals(z,zero)){zero=z;changed=true;}
            for(int i=0;i<16;i++){Value v=regs[i].join(other.regs[i]);if(!v.equals(regs[i])){regs[i]=v;changed=true;}}
            for(Key k:new ArrayList<>(memory.keySet())){Value v=memory.get(k).join(other.memory.getOrDefault(k,Value.top()));if(v.unknown()){memory.remove(k);changed=true;}else if(!v.equals(memory.get(k))){memory.put(k,v);changed=true;}}
            return changed;}
    }
    private final Map<String,Object> profile;private final Image image;private final NavigableMap<Long,byte[]> rows=new TreeMap<>();
    private final Map<Long,Ins> decoded=new HashMap<>();private final Map<Long,Map<String,Object>> contracts=new HashMap<>();
    private final Map<String,Map<String,Object>> issues=new TreeMap<>(),accesses=new TreeMap<>(),edges=new TreeMap<>();
    private final Set<Long> visited=new TreeSet<>();private final List<Map<String,Object>> regions=new ArrayList<>();
    private final boolean stackDisjoint;private final int budget;
    private final Set<Integer> observedReturns=new TreeSet<>();
    private ReferenceClosure(Path file,Map<String,Object> profile)throws IOException{
        this.profile=profile;require("bcl-closure-1".equals(profile.get("schema")),"Expected bcl-closure-1 profile");
        Path base=file.toAbsolutePath().getParent(),binary=resolve(base,profile,"binary"),disassembly=resolve(base,profile,"disassembly");image=new Image(binary);
        String text=Files.readString(disassembly);require(text.length()<=32*1024*1024,"Closure disassembly exceeds 32 MiB");
        Pattern p=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");long end=-1;
        for(String line:text.split("\\R")){Matcher m=p.matcher(line);if(!m.matches())continue;long ip=Long.parseLong(m.group(1),16);byte[] code=HexFormat.of().parseHex(m.group(2).replaceAll("\\s",""));
            require(code.length>0&&code.length<=15&&ip>=end,"Overlapping/unordered instruction rows");end=Math.addExact(ip,code.length);
            require(Arrays.equals(code,image.bytes(ip,code.length,true)),"Disassembly/ELF byte disagreement at 0x"+Long.toHexString(ip));rows.put(ip,code);}
        require(!rows.isEmpty(),"No bound instruction rows");
        Object rs=profile.get("regions");require(rs instanceof List<?>&&!((List<?>)rs).isEmpty(),"Closure requires declared regions");
        for(Object r:(List<?>)rs){Map<String,Object> region=MultiRegionPlan.object(r);long a=num(region,"address"),size=num(region,"size");
            require(a>=0&&size>0&&a<=Long.MAX_VALUE-size,"Invalid closure region");image.bytes(a,Math.toIntExact(size),false);regions.add(region);}
        stackDisjoint=Boolean.TRUE.equals(profile.get("stack_disjoint_from_regions"));
        if(profile.get("observed_return_registers") instanceof List<?> names)for(Object name:names)observedReturns.add(reg(Objects.toString(name)));
        else for(int i=0;i<16;i++)observedReturns.add(i);
        budget=(int)optional(profile,"state_budget",100000);require(budget>=1&&budget<=1000000,"State budget must be 1..1000000");
        if(profile.get("external_contracts") instanceof List<?> list)for(Object c:list){var contract=MultiRegionPlan.object(c);long target=num(contract,"target");require(contracts.putIfAbsent(target,contract)==null,"Duplicate external contract target");}
    }
    public static Map<String,Object> analyze(Path file)throws IOException{return new ReferenceClosure(file,Json.object(Files.readString(file))).run();}
    private Map<String,Object> run(){
        require(profile.get("entries") instanceof List<?> list&&!list.isEmpty()&&list.size()<=128,"Declare 1..128 entries");
        Map<Point,State> states=new HashMap<>();ArrayDeque<Point> work=new ArrayDeque<>();
        for(Object root:(List<?>)profile.get("entries")){require(root instanceof Number,"Entry must be an integer");long ip=((Number)root).longValue();State initial=new State();
            if(profile.get("initial_registers") instanceof Map<?,?> regs)for(var e:regs.entrySet()){int index=reg(e.getKey().toString());Object value=e.getValue();
                initial.regs[index]=initialValue(value);}
            // An unforgeable symbolic caller continuation, distinct from concrete addresses.
            initial.memory.put(new Key(true,0,8),Value.stack(Long.MIN_VALUE));
            enqueue(new Point(ip,List.of()),initial,states,work);}
        int iterations=0;
        while(!work.isEmpty()&&iterations++<budget){Point point=work.removeFirst();State state=states.get(point).copy();visited.add(point.ip);
            Ins ins;try{ins=decoded.computeIfAbsent(point.ip,ip->{byte[] code=rows.get(ip);require(code!=null,"No supplied instruction boundary");return decode(ip,code);});}
            catch(IllegalArgumentException|ArithmeticException failure){issue(point.ip,"UNSUPPORTED_INSTRUCTION_OR_BOUNDARY",failure.getMessage());continue;}
            try{step(point,state,ins,states,work);}catch(IllegalArgumentException|ArithmeticException failure){issue(point.ip,"UNSUPPORTED_STATE",failure.getMessage());}
        }
        if(!work.isEmpty())issue(0,"FIXPOINT_BUDGET_EXHAUSTED","Pending abstract states remain");
        List<Map<String,Object>> gaps=new ArrayList<>();
        for(var section:image.metadata.executableSections()){long at=section.address(),stop=Math.addExact(at,section.size());
            for(var row:rows.subMap(at,true,stop,false).entrySet()){if(row.getKey()>at)gaps.add(Map.of("start",at,"end",row.getKey()));at=Math.max(at,row.getKey()+row.getValue().length);}
            if(at<stop)gaps.add(Map.of("start",at,"end",stop));}
        Map<String,Object> out=new LinkedHashMap<>();out.put("schema","bcl-reference-closure-1");out.put("binary_sha256",image.metadata.sha256());
        out.put("status",issues.isEmpty()?"CLOSED_UNDER_DECLARED_ENTRY_CONTRACT":"UNRESOLVED_REFERENCE_CLOSURE");
        out.put("entries",profile.get("entries"));out.put("reachable_instructions",visited.size());out.put("abstract_states",states.size());out.put("worklist_iterations",iterations);
        out.put("analyzed_entry_addresses",profile.get("entries"));
        out.put("unvisited_supplied_instruction_addresses",rows.keySet().stream().filter(ip->!visited.contains(ip)).toList());
        out.put("fixpoint_reached",work.isEmpty());
        out.put("accesses",new ArrayList<>(accesses.values()));out.put("control_flow_edges",new ArrayList<>(edges.values()));out.put("unresolved",new ArrayList<>(issues.values()));
        out.put("executable_section_byte_gaps",gaps);out.put("all_executable_section_bytes_have_supplied_rows",gaps.isEmpty());
        out.put("contract",Map.of("initial_registers",profile.getOrDefault("initial_registers",Map.of()),"stack_disjoint_from_regions",stackDisjoint,
            "observed_return_registers",observedReturns.stream().map(i->REGS[i]).toList(),
            "external_contracts",profile.getOrDefault("external_contracts",List.of()),"scope","Normal execution from declared entries; valid ordinary return stack; no asynchronous events, loader mutation, self-modification or concurrent writes"));
        out.put("whole_program_entries_and_runtime_contract_proved",false);out.put("automatic_rewrite_allowed",false);
        out.put("limitations",List.of("Restricted byte decoder; unsupported operations stop their paths","User entry/external contracts are assumptions, not verified facts",
            "Eight-value points-to sets widen to unknown; recursion/call contexts bounded at eight","Does not establish original/rebuilt functional equivalence or outside-object observation independence"));return out;
    }
    private void step(Point p,State s,Ins i,Map<Point,State> states,ArrayDeque<Point> work){long next=Math.addExact(i.ip,i.length);Value a,b;
        switch(i.op){
            case "NOP" -> {}
            case "MOV" -> {b=read(s,i.src,i.width,i);write(s,i.dst,b,i.width,i);}
            case "LEA" -> write(s,i.dst,address(s,i.src.memory,i),i.width,i);
            case "LEAVE" -> {s.regs[4]=s.regs[5];a=load(s,s.regs[4],8,i);s.regs[4]=calculate(s.regs[4],Value.constant(8),"ADD",8);s.regs[5]=a;}
            case "MOVSXD" -> {b=read(s,i.src,4,i);write(s,i.dst,signExtend32(b),8,i);}
            case "MOVZX" -> {b=read(s,i.src,i.width,i);write(s,i.dst,b,4,i);}
            case "MOVZX64" -> {b=read(s,i.src,i.width,i);write(s,i.dst,b,8,i);}
            case "PUSH" -> {b=read(s,i.src,8,i);s.regs[4]=calculate(s.regs[4],Value.constant(8),"SUB",8);store(s,s.regs[4],b,8,i);}
            case "POP" -> {a=load(s,s.regs[4],8,i);s.regs[4]=calculate(s.regs[4],Value.constant(8),"ADD",8);write(s,i.dst,a,8,i);}
            case "ADD","SUB","AND","OR","XOR","SHL","SHR","SAR" -> {
                a=read(s,i.dst,i.width,i);b=read(s,i.src,i.width,i);
                if(regionPointer(a)||regionPointer(b))issue(i.ip,"REGION_POINTER_ARITHMETIC_REQUIRES_RELOCATION_MODEL","Address-derived integer behavior is not treated as scalar arithmetic");
                Value value=i.op.equals("XOR")&&i.dst.reg>=0&&i.src.reg==i.dst.reg?Value.constant(0):calculate(a,b,i.op,i.width);
                s.zero=zero(value);
                if(Set.of("SHL","SHR","SAR").contains(i.op)&&(b.unknown()||b.values.stream().anyMatch(v->(v.value&(i.width==8?63:31))==0)))s.zero=null;
                write(s,i.dst,value,i.width,i);}
            case "INC","DEC" -> {a=read(s,i.dst,i.width,i);if(regionPointer(a))issue(i.ip,"REGION_POINTER_ARITHMETIC_REQUIRES_RELOCATION_MODEL","Increment/decrement of address-derived value");Value value=calculate(a,Value.constant(1),i.op.equals("INC")?"ADD":"SUB",i.width);s.zero=zero(value);write(s,i.dst,value,i.width,i);}
            case "CMP","TEST" -> {a=read(s,i.dst,i.width,i);b=read(s,i.src,i.width,i);s.zero=zero(calculate(a,b,i.op.equals("CMP")?"SUB":"AND",i.width));if(regionPointer(a)||regionPointer(b))issue(i.ip,"REGION_ADDRESS_IDENTITY_OBSERVED","Pointer comparison/test needs a relocation correspondence model");}
            case "JCC" -> {byte[] raw=rows.get(i.ip);int at=(raw[0]&0xf0)==0x40?1:0,condition=((raw[at]&255)==0x0f?raw[at+1]:raw[at])&15;
                Boolean taken=s.zero!=null&&condition==4?s.zero:s.zero!=null&&condition==5?!s.zero:null;
                if(!Boolean.FALSE.equals(taken))follow(p,i.target,s,states,work,"conditional");if(!Boolean.TRUE.equals(taken))follow(p,next,s,states,work,"fallthrough");return;}
            case "JMP","CALL" -> {
                Value targets=i.src==null?Value.constant(i.target):read(s,i.src,8,i);
                if(targets.unknown()){issue(i.ip,"INDIRECT_CONTROL_FLOW_UNRESOLVED","Unknown target value");return;}
                for(Atom target:targets.values){if(target.stack){issue(i.ip,"STACK_CONTROL_FLOW_TARGET","Stack-relative target");continue;}
                    State branch=s.copy();Map<String,Object> contract=contracts.get(target.value);
                    if(contract!=null&&i.op.equals("CALL")){
                        if(!"sysv-amd64".equals(contract.get("abi"))||!"none".equals(contract.get("memory"))||!"none".equals(contract.get("address_observation"))||!"normal_return".equals(contract.get("control"))){issue(i.ip,"UNSUPPORTED_EXTERNAL_CONTRACT","Only explicit SysV AMD64/no-memory/no-address-observation normal-return contracts are modeled");continue;}
                        branch.regs[4]=calculate(branch.regs[4],Value.constant(8),"SUB",8);store(branch,branch.regs[4],Value.constant(next),8,i);load(branch,branch.regs[4],8,i);branch.regs[4]=calculate(branch.regs[4],Value.constant(8),"ADD",8);
                        for(int r:new int[]{0,1,2,6,7,8,9,10,11})branch.regs[r]=Value.top();branch.zero=null;follow(p,next,branch,states,work,"external-contract-return");continue;}
                    if(i.op.equals("CALL")){if(p.returns.size()>=8){issue(i.ip,"CALL_CONTEXT_LIMIT","Recursion or call depth exceeds eight");continue;}
                        branch.regs[4]=calculate(branch.regs[4],Value.constant(8),"SUB",8);store(branch,branch.regs[4],Value.constant(next),8,i);
                        List<Long> returns=new ArrayList<>(p.returns);returns.add(next);edge(i.ip,target.value,"call");enqueue(new Point(target.value,List.copyOf(returns)),branch,states,work);
                    }else follow(p,target.value,branch,states,work,"jump");}
                return;
            }
            case "RET" -> {
                Value returned=load(s,s.regs[4],8,i);s.regs[4]=calculate(s.regs[4],Value.constant(8),"ADD",8);
                if(p.returns.isEmpty()){
                    if(!returned.equals(Value.stack(Long.MIN_VALUE))||!s.regs[4].equals(Value.stack(8)))issue(i.ip,"ENTRY_RETURN_STACK_UNRESOLVED","Entry return must restore the declared caller continuation and stack position");
                    for(int r:observedReturns){if(s.regs[r].unknown())issue(i.ip,"OBSERVED_RETURN_VALUE_PROVENANCE_UNRESOLVED",REGS[r]+" may retain an unclassified pointer");
                    if(regionPointer(s.regs[r]))issue(i.ip,"REGION_POINTER_LIVE_AT_ENTRY_RETURN",REGS[r]+" remains a region/boundary pointer");}return;}
                long expected=p.returns.get(p.returns.size()-1);
                if(!returned.equals(Value.constant(expected))){issue(i.ip,"RETURN_ADDRESS_OR_STACK_ALIAS_UNRESOLVED","Return does not match abstract call context");return;}
                edge(i.ip,expected,"return");enqueue(new Point(expected,p.returns.subList(0,p.returns.size()-1)),s,states,work);return;
            }
            default -> throw new IllegalArgumentException("Unmodeled operation");
        }
        follow(p,next,s,states,work,"fallthrough");
    }
    private void follow(Point p,long target,State s,Map<Point,State> states,ArrayDeque<Point> work,String kind){edge(p.ip,target,kind);enqueue(new Point(target,p.returns),s,states,work);}
    private void enqueue(Point p,State s,Map<Point,State> states,ArrayDeque<Point> work){if(!rows.containsKey(p.ip)){issue(p.ip,"CONTROL_FLOW_BOUNDARY_OR_EXTERNAL_CODE_UNRESOLVED","Target is not a supplied instruction entry");return;}
        State old=states.get(p);if(old==null){states.put(p,s.copy());work.addLast(p);}else if(old.merge(s))work.addLast(p);}
    private void edge(long from,long to,String kind){edges.put(from+":"+to+":"+kind,Map.of("from",from,"to",to,"kind",kind));}
    private void issue(long ip,String kind,String detail){issues.put(ip+":"+kind,Map.of("ip",ip,"kind",kind,"detail",detail));}
    private Value read(State s,Arg a,int width,Ins i){Value v=a.memory!=null?load(s,address(s,a.memory,i),width,i):a.immediate!=null?normalize(Value.constant(a.immediate),width):normalize(s.regs[a.reg],width);return regionPointer(v)?v.tagged():v;}
    private void write(State s,Arg a,Value v,int width,Ins i){if(a.memory!=null){store(s,address(s,a.memory,i),normalize(v,width),width,i);return;}
        require(a.reg>=0,"Write to immediate");if(width<4)s.regs[a.reg]=Value.top();else s.regs[a.reg]=normalize(v,width);}
    private Value address(State s,Mem m,Ins i){Value value=m.rip?Value.constant(i.ip+i.length):m.base<0?Value.constant(0):s.regs[m.base];
        if(m.index>=0)value=calculate(value,calculate(s.regs[m.index],Value.constant(m.scale),"MUL",8),"ADD",8);
        value=calculate(value,Value.constant(m.displacement),"ADD",8);return regionPointer(value)?value.tagged():value;}
    private Value load(State s,Value address,int width,Ins i){access(address,width,false,i.ip);if(address.unknown())return Value.top();Value out=null;
        for(Atom a:address.values){Value value=s.memory.get(new Key(a.stack,a.value,width));
            if(value==null)value=containedLoad(s,a,width);
            if(value==null&&!a.stack&&immutable(a.value,width)){try{byte[] raw=image.bytes(a.value,width,false);long n=0;for(int k=0;k<width;k++)n|=(raw[k]&255L)<<(8*k);value=Value.constant(n);}catch(IllegalArgumentException e){issue(i.ip,"UNMAPPED_IMMUTABLE_READ",e.getMessage());}}
            if(value==null)value=Value.top();out=out==null?value:out.join(value);}
        return out==null?Value.top():out;
    }
    private void store(State s,Value address,Value value,int width,Ins i){access(address,width,true,i.ip);
        if(value.unknown()&&(address.unknown()||address.values.stream().anyMatch(a->!a.stack)))issue(i.ip,"STORED_VALUE_PROVENANCE_UNRESOLVED","An unclassified value may escape through non-stack memory");
        if(regionPointer(value)&&(address.unknown()||address.values.stream().anyMatch(a->!a.stack)))issue(i.ip,"STORED_REGION_POINTER_LIFETIME_UNRESOLVED","Region-derived value escapes through memory");
        if(address.unknown()){s.memory.clear();return;}boolean singleton=address.values.size()==1;
        for(Atom a:address.values){if(!a.stack&&immutable(a.value,width))issue(i.ip,"IMMUTABLE_REGION_WRITE","Write violates declared immutable-region contract");
            s.memory.keySet().removeIf(k->k.stack==a.stack&&overlap(k.address,k.width,a.value,width));
            if(singleton&&!value.unknown())s.memory.put(new Key(a.stack,a.value,width),value);
            if(s.memory.size()>256){s.memory.clear();issue(i.ip,"MEMORY_STATE_BUDGET_EXCEEDED","Abstract memory widened to unknown");}
            if(regionPointer(value)&&!a.stack)issue(i.ip,"STORED_REGION_POINTER_LIFETIME_UNRESOLVED","Region pointer stored outside the modeled stack");}}
    private void access(Value addresses,int width,boolean write,long ip){if(addresses.unknown()){issue(ip,"MEMORY_ALIAS_UNRESOLVED","Unknown effective address may alias declared regions");return;}
        for(Atom a:addresses.values){if(a.stack){if(!stackDisjoint)issue(ip,"STACK_REGION_ALIAS_UNRESOLVED","Stack disjointness not declared");continue;}
            if(a.value<0||a.value>Long.MAX_VALUE-width){issue(ip,"ADDRESS_RANGE_UNSUPPORTED","High-half/wrapping memory address");continue;}
            try{image.checkMemory(a.value,width,write);}catch(IllegalArgumentException e){issue(ip,"STATIC_MAPPING_OR_PERMISSION_UNRESOLVED",e.getMessage());}
            if(addresses.derived&&regions.stream().noneMatch(r->a.value>=num(r,"address")&&a.value+width<=num(r,"address")+num(r,"size")))
                issue(ip,"REGION_DERIVED_OUTSIDE_ACCESS","Region-derived address accesses bytes outside the declared regions");
            for(Map<String,Object> r:regions){long start=num(r,"address"),size=num(r,"size");if(overlap(a.value,width,start,size)){
                accesses.put(ip+":"+a.value+":"+width+":"+write,Map.of("ip",ip,"address",a.value,"width",width,"write",write,"region",r.getOrDefault("name","region")));
                if(a.value<start||a.value+width>start+size)issue(ip,"REGION_BOUNDARY_CROSSING_ACCESS","Access crosses declared region boundary");}}}}
    private boolean immutable(long a,int width){for(var r:regions)if(Boolean.TRUE.equals(r.get("immutable"))&&a>=num(r,"address")&&a<=num(r,"address")+num(r,"size")-width)return true;return false;}
    private boolean regionPointer(Value value){if(value.derived)return true;if(value.unknown())return false;for(Atom a:value.values)if(!a.stack)for(var r:regions)if(a.value>=num(r,"address")&&a.value<=num(r,"address")+num(r,"size"))return true;return false;}
    private static boolean overlap(long a,long n,long b,long m){try{return a<Math.addExact(b,m)&&b<Math.addExact(a,n);}catch(ArithmeticException e){return true;}}
    private static Value normalize(Value v,int width){if(v.unknown()||width==8)return v;Set<Atom> out=new HashSet<>();long mask=width==4?0xffffffffL:(1L<<(width*8))-1;
        for(Atom a:v.values){if(a.stack)return new Value(null,v.derived);out.add(new Atom(false,a.value&mask));}return new Value(Set.copyOf(out),v.derived);}
    private static Boolean zero(Value value){if(value.unknown()||value.values.isEmpty())return null;Boolean result=null;
        for(Atom atom:value.values){if(atom.stack)return null;boolean z=atom.value==0;if(result!=null&&result!=z)return null;result=z;}return result;}
    private static Value calculate(Value a,Value b,String op,int width){Value result=calculateNumbers(a,b,op,width);return a.derived||b.derived?result.tagged():result;}
    private static Value calculateNumbers(Value a,Value b,String op,int width){if(a.unknown()||b.unknown())return Value.top();Set<Atom> out=new HashSet<>();
        for(Atom x:a.values)for(Atom y:b.values){Atom r;
            if(x.stack||y.stack){if(op.equals("ADD")&&x.stack!=y.stack)r=new Atom(true,x.value+y.value);
                else if(op.equals("SUB")&&x.stack)r=new Atom(!y.stack,x.value-y.value);else return Value.top();}
            else{long value=switch(op){case "ADD"->x.value+y.value;case "SUB"->x.value-y.value;case "MUL"->x.value*y.value;case "AND"->x.value&y.value;case "OR"->x.value|y.value;case "XOR"->x.value^y.value;case "SHL"->x.value<<(y.value&(width==8?63:31));case "SHR"->x.value>>>(y.value&(width==8?63:31));case "SAR"->(width==4?(long)(int)x.value:x.value)>>(y.value&(width==8?63:31));default->throw new IllegalArgumentException("Unknown arithmetic");};r=new Atom(false,value);}
            out.add(r);if(out.size()>8)return Value.top();}return normalize(new Value(Set.copyOf(out)),width);}
    private static int reg(String name){for(int i=0;i<16;i++)if(REGS[i].equals(name))return i;throw new IllegalArgumentException("Unknown register "+name);}
    private Value initialValue(Object raw){
        if("stack".equals(raw))return Value.stack(0);
        List<?> choices=raw instanceof List<?> list?list:Collections.singletonList(raw);
        require(!choices.isEmpty()&&choices.size()<=8,"Initial register sets require 1..8 integer values");
        Value result=null;
        for(Object choice:choices){require(choice instanceof Long||choice instanceof Integer,"Initial registers require integers, integer lists, or stack");
            Value v=Value.constant(((Number)choice).longValue());if(regionPointer(v))v=v.tagged();result=result==null?v:result.join(v);}
        return result;
    }
    private static Value signExtend32(Value v){
        if(v.unknown())return v;Set<Atom> values=new HashSet<>();
        for(Atom a:v.values){if(a.stack)return new Value(null,v.derived);values.add(new Atom(false,(long)(int)a.value));}
        return new Value(Set.copyOf(values),v.derived);
    }
    /** A contained sub-load retains provenance. Partial overlapping stores invalidate the cell. */
    private static Value containedLoad(State s,Atom address,int width){
        for(var entry:s.memory.entrySet()){Key k=entry.getKey();
            if(k.stack!=address.stack||width>k.width||address.value<k.address||address.value-k.address>k.width-width)continue;
            Value v=entry.getValue();if(v.unknown())return v;
            int shift=(int)(address.value-k.address)*8;Set<Atom> values=new HashSet<>();
            for(Atom a:v.values){if(a.stack)return new Value(null,v.derived);values.add(new Atom(false,a.value>>>shift));}
            return normalize(new Value(Set.copyOf(values),v.derived),width);
        }
        return null;
    }
    private static long num(Map<String,Object> m,String key){return MultiRegionPlan.number(m,key);}
    private static long optional(Map<String,Object> m,String key,long fallback){return m.containsKey(key)?num(m,key):fallback;}
    private static Path resolve(Path base,Map<String,Object> m,String key){require(m.get(key) instanceof String,"Missing path "+key);Path p=Path.of((String)m.get(key));return p.isAbsolute()?p:base.resolve(p);}
    private static final class Reader {final byte[] b;int p;int rex;Reader(byte[] b){this.b=b;}int u(){require(p<b.length,"Truncated instruction");return b[p++]&255;}long signed(int n){require(n==1||n==2||n==4||n==8,"Bad immediate width");long x=0;for(int i=0;i<n;i++)x|=(long)u()<<(8*i);return n==1?(byte)x:n==2?(short)x:n==4?(int)x:x;}}
    private record Mod(Arg rm,int reg,int group){}
    private static Mod modrm(Reader r){int m=r.u(),mod=m>>>6,group=(m>>>3)&7,reg=group+((r.rex&4)!=0?8:0),rm=m&7;
        if(mod==3)return new Mod(Arg.reg(rm+((r.rex&1)!=0?8:0)),reg,group);
        int base=rm+((r.rex&1)!=0?8:0),index=-1,scale=1;long disp=0;boolean rip=false;
        if(rm==4){int sib=r.u();scale=1<<(sib>>>6);int ix=(sib>>>3)&7;if(ix!=4||(r.rex&2)!=0)index=ix+((r.rex&2)!=0?8:0);base=(sib&7)+((r.rex&1)!=0?8:0);if(mod==0&&(sib&7)==5){base=-1;disp=r.signed(4);}}
        else if(mod==0&&rm==5){base=-1;rip=true;disp=r.signed(4);}
        if(mod==1)disp=r.signed(1);else if(mod==2)disp=r.signed(4);
        return new Mod(Arg.mem(new Mem(base,index,scale,disp,rip)),reg,group);
    }
    static Ins decode(long ip,byte[] bytes){Reader r=new Reader(bytes);int op=r.u();
        if(op==0xf3){require(Arrays.equals(bytes,HexFormat.of().parseHex("f30f1efa")),"Unsupported F3 instruction");return new Ins(ip,4,"NOP",0,null,null,0);}
        require(op!=0x66&&op!=0x67&&op!=0x64&&op!=0x65&&op!=0xf0,"Unsupported size/segment/lock prefix");
        if(op>=0x40&&op<=0x4f){r.rex=op;op=r.u();}int width=(r.rex&8)!=0?8:4;String kind;Arg dst=null,src=null;long target=0;
        if(op==0x90){kind="NOP";require(r.rex==0,"REX XCHG/NOP unsupported");}
        else if(op==0xc3){kind="RET";width=8;}
        else if(op==0xc9){kind="LEAVE";width=8;}
        else if(op==0x63){require(width==8,"MOVSXD requires REX.W");Mod m=modrm(r);kind="MOVSXD";dst=Arg.reg(m.reg);src=m.rm;}
        else if(op>=0x50&&op<=0x57){kind="PUSH";width=8;src=Arg.reg(op-0x50+((r.rex&1)!=0?8:0));}
        else if(op>=0x58&&op<=0x5f){kind="POP";width=8;dst=Arg.reg(op-0x58+((r.rex&1)!=0?8:0));}
        else if(op==0xe8||op==0xe9||op==0xeb||(op>=0x70&&op<=0x7f)){
            long disp=r.signed(op==0xe8||op==0xe9?4:1);kind=op==0xe8?"CALL":op==0xe9||op==0xeb?"JMP":"JCC";target=Math.addExact(ip+r.p,disp);
        }else if(op>=0xb8&&op<=0xbf){kind="MOV";dst=Arg.reg(op-0xb8+((r.rex&1)!=0?8:0));src=Arg.imm(r.signed(width));}
        else if(op==0x68||op==0x6a){kind="PUSH";width=8;src=Arg.imm(r.signed(op==0x68?4:1));}
        else if(op==0x0f){int second=r.u();if(second>=0x80&&second<=0x8f){kind="JCC";long disp=r.signed(4);target=Math.addExact(ip+r.p,disp);}
            else if(second==0xb6||second==0xb7){Mod m=modrm(r);kind=(r.rex&8)!=0?"MOVZX64":"MOVZX";width=second==0xb6?1:2;dst=Arg.reg(m.reg);src=m.rm;require(width==2||src.memory!=null,"Register byte MOVZX unsupported");}
            else if(second==0x1f){Mod m=modrm(r);require(m.group==0,"Invalid NOP extension");kind="NOP";}
            else throw new IllegalArgumentException("Unsupported 0F opcode");
        }else if(Set.of(0x8b,0x89,0x8d,0x31,0x33,0x01,0x03,0x29,0x2b,0x21,0x23,0x09,0x0b,0x39,0x3b,0x85,0xff,0x81,0x83,0xc7,0xc6,0xc1,0xd1).contains(op)){
            Mod m=modrm(r);boolean reverse=Set.of(0x8b,0x8d,0x33,0x03,0x2b,0x23,0x0b,0x3b).contains(op);dst=reverse?Arg.reg(m.reg):m.rm;src=reverse?m.rm:Arg.reg(m.reg);
            kind=switch(op){case 0x8b,0x89->"MOV";case 0x8d->"LEA";case 0x31,0x33->"XOR";case 0x01,0x03->"ADD";case 0x29,0x2b->"SUB";case 0x21,0x23->"AND";case 0x09,0x0b->"OR";case 0x39,0x3b->"CMP";case 0x85->"TEST";default->"";};
            if(op==0x8d)require(m.rm.memory!=null,"LEA requires memory form");
            if(op==0xff){require(m.group==0||m.group==1||m.group==2||m.group==4,"Unsupported FF extension");if(m.group<=1){kind=m.group==0?"INC":"DEC";dst=m.rm;src=Arg.imm(1);}else{kind=m.group==2?"CALL":"JMP";width=8;src=m.rm;dst=null;}}
            if(op==0x81||op==0x83){kind=switch(m.group){case 0->"ADD";case 1->"OR";case 4->"AND";case 5->"SUB";case 6->"XOR";case 7->"CMP";default->throw new IllegalArgumentException("Unsupported arithmetic extension");};src=Arg.imm(r.signed(op==0x83?1:4));}
            if(op==0xc7||op==0xc6){require(m.group==0,"Invalid immediate move");kind="MOV";if(op==0xc6){width=1;require(m.rm.memory!=null,"Byte register writes unsupported");}src=Arg.imm(r.signed(op==0xc6?1:4));}
            if(op==0xc1||op==0xd1){kind=switch(m.group){case 4->"SHL";case 5->"SHR";case 7->"SAR";default->throw new IllegalArgumentException("Unsupported shift extension");};src=Arg.imm(op==0xd1?1:r.u());}
        }else throw new IllegalArgumentException("Unsupported opcode 0x"+Integer.toHexString(op));
        require(r.p==bytes.length,"Instruction length/decoder disagreement");return new Ins(ip,r.p,kind,width,dst,src,target);
    }
    private static final class Image {
        record Load(long address,long offset,long files,long memory,int flags){}
        final byte[] raw;final List<Load> loads=new ArrayList<>();final ElfMetadata metadata;
        Image(Path path)throws IOException{try(var in=Files.newInputStream(path)){raw=in.readNBytes(64*1024*1024+1);}require(raw.length>=64&&raw.length<=64*1024*1024,"Invalid closure ELF size");metadata=ElfMetadata.read(raw);
            ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);long ph=b.getLong(32);int count=Short.toUnsignedInt(b.getShort(56));
            require(ph>=64&&Short.toUnsignedInt(b.getShort(54))==56&&count>0&&ph<=raw.length-56L*count,"Invalid ELF program headers");
            for(int i=0;i<count;i++){int p=(int)ph+56*i;if(b.getInt(p)!=1)continue;long a=b.getLong(p+16),off=b.getLong(p+8),file=b.getLong(p+32),mem=b.getLong(p+40);
                require(a>=0&&off>=0&&file>=0&&mem>=file&&a<=Long.MAX_VALUE-mem&&off<=raw.length-file,"Invalid load extent");loads.add(new Load(a,off,file,mem,b.getInt(p+4)));}}
        byte[] bytes(long a,int n,boolean executable){require(a>=0&&n>0&&a<=Long.MAX_VALUE-n,"Invalid memory extent");Load found=null;
            for(Load s:loads)if(a<s.address+s.memory&&s.address<a+n){require(found==null,"Overlapping image mappings");found=s;require(a>=s.address&&a+n<=s.address+s.files,"Read crosses file-backed mapping");}
            require(found!=null&&(!executable||(found.flags&1)!=0),"Unmapped/nonexecutable extent");int offset=(int)(found.offset+a-found.address);return Arrays.copyOfRange(raw,offset,offset+n);}
        void checkMemory(long a,int n,boolean write){require(a>=0&&n>0&&a<=Long.MAX_VALUE-n,"Invalid memory extent");Load found=null;
            for(Load s:loads)if(a<s.address+s.memory&&s.address<a+n){require(found==null,"Ambiguous static memory mapping");found=s;require(a>=s.address&&a+n<=s.address+s.memory,"Static access crosses mapped extent");}
            require(found!=null&&(found.flags&(write?2:4))!=0,"Static access is outside declared image mappings or lacks permissions");}
    }
}
