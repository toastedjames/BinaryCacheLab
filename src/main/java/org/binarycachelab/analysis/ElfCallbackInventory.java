package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.GroupPlan;
import static org.binarycachelab.workflow.LabConfig.require;

/** File-derived callback candidates, not a model of the executing dynamic loader. */
public final class ElfCallbackInventory {
    private record Load(long offset,long address,long files,long memory,long flags){}
    private record Rela(long site,long type,long symbol,long addend){}
    private final byte[] raw; private final ByteBuffer b;
    private final List<Load> loads=new ArrayList<>();
    private final Map<Long,Long> tags=new HashMap<>();
    private final List<Rela> relas=new ArrayList<>();
    private final List<String> issues=new ArrayList<>();
    private ElfCallbackInventory(byte[] raw){this.raw=raw;b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);}
    public static Map<String,Object> analyze(Path file)throws IOException{
        try(var input=Files.newInputStream(file)){return analyze(input.readNBytes(64*1024*1024+1));}
    }
    public static Map<String,Object> analyze(byte[] bytes){
        require(bytes.length<=64*1024*1024,"Callback ELF exceeds 64 MiB");return new ElfCallbackInventory(bytes.clone()).inspect();
    }
    public static Map<String,Object> compareSources(Map<String,Object> original,Map<String,Object> rebuilt){
        Map<String,Integer> left=sourceCounts(original),right=sourceCounts(rebuilt);
        Set<String> names=new TreeSet<>(left.keySet());names.addAll(right.keySet());List<Map<String,Object>> differences=new ArrayList<>();
        for(String name:names)if(!Objects.equals(left.getOrDefault(name,0),right.getOrDefault(name,0)))
            differences.add(Map.of("source",name,"original_count",left.getOrDefault(name,0),"rebuilt_count",right.getOrDefault(name,0)));
        return Map.of("status",differences.isEmpty()?"SOURCE_COUNTS_MATCH_SEMANTICS_UNPROVED":"CALLBACK_METADATA_DIFF_REVIEW_REQUIRED",
            "original_source_counts",left,"rebuilt_source_counts",right,"differences",differences,
            "startup_shutdown_equivalence_proved",false,"automatic_rewrite_allowed",false);
    }
    private static Map<String,Integer> sourceCounts(Map<String,Object> inventory){Map<String,Integer> result=new TreeMap<>();
        for(Object item:(List<?>)inventory.get("callbacks")){String source=(String)((Map<?,?>)item).get("source");result.merge(source,1,Integer::sum);}return result;}
    private static long end(long a,long n){require(a>=0&&n>=0&&a<=Long.MAX_VALUE-n,"Invalid callback ELF extent");return a+n;}
    private int bound(long a,long n){require(end(a,n)<=raw.length,"Truncated callback ELF");return (int)a;}
    private int u16(int p){return Short.toUnsignedInt(b.getShort(p));}
    private long q(int p){return b.getLong(p);}
    private int mapped(long a,long n,boolean executable){
        long stop=end(a,n);Load found=null;
        for(Load s:loads)if(a<end(s.address,s.memory)&&s.address<stop){
            require(found==null,"Overlapping callback PT_LOAD mappings");found=s;
            require(a>=s.address&&stop<=end(s.address,s.files),"Callback extent is not uniquely file backed");}
        require(found!=null&&(!executable||(found.flags&1)!=0),"Callback address lacks required PT_LOAD mapping");
        return bound(end(found.offset,a-found.address),n);
    }
    private Map<String,Object> inspect(){
        require(raw.length>=64&&b.getInt(0)==0x464c457f&&raw[4]==2&&raw[5]==1&&raw[6]==1,"Require little-endian ELF64");
        int kind=u16(16);require((kind==2||kind==3)&&u16(18)==62&&b.getInt(20)==1&&u16(52)==64&&u16(54)==56,"Require linked x86-64 ELF");
        long ph=q(32);int count=u16(56);require(ph>=64&&count>0&&count<65535,"Unsupported program headers");bound(ph,56L*count);
        Load dynamic=null;boolean interpreter=false;
        for(int i=0;i<count;i++){int p=(int)ph+56*i,type=b.getInt(p);if(type==3)interpreter=true;if(type!=1&&type!=2)continue;
            Load s=new Load(q(p+8),q(p+16),q(p+32),q(p+40),Integer.toUnsignedLong(b.getInt(p+4)));
            require(s.files<=s.memory,"Segment file size exceeds memory");bound(s.offset,s.files);end(s.address,s.memory);
            if(type==1)loads.add(s);else{require(dynamic==null,"Multiple PT_DYNAMIC segments");dynamic=s;}}
        List<Map<String,Object>> callbacks=new ArrayList<>();
        if(dynamic!=null){
            require(dynamic.files>0&&dynamic.files%16==0&&mapped(dynamic.address,dynamic.files,false)==dynamic.offset,"Invalid PT_DYNAMIC mapping");
            boolean terminated=false;
            Set<Long> singleton=Set.of(2L,6L,7L,8L,9L,11L,12L,13L,17L,18L,19L,20L,23L,25L,26L,27L,28L,32L,33L,35L,36L,37L);
            for(long j=0;j<dynamic.files;j+=16){int p=(int)(dynamic.offset+j);long tag=q(p);if(tag==0){terminated=true;break;}
                if(singleton.contains(tag))require(tags.putIfAbsent(tag,q(p+8))==null,"Duplicate callback/relocation dynamic tag");}
            require(terminated,"Unterminated PT_DYNAMIC");
            if(tags.keySet().stream().anyMatch(Set.of(17L,18L,19L,35L,36L,37L)::contains))issues.add("REL_OR_RELR_CALLBACK_RELOCATION_UNSUPPORTED");
            if(tags.containsKey(7L)||tags.containsKey(8L)||tags.containsKey(9L)){
                require(tags.keySet().containsAll(List.of(7L,8L,9L))&&tags.get(9L)==24,"Incomplete/unsupported DT_RELA");readRelas(tags.get(7L),tags.get(8L));}
            if(tags.containsKey(23L)||tags.containsKey(2L)||tags.containsKey(20L)){
                require(tags.keySet().containsAll(List.of(23L,2L,20L)),"Incomplete PLT relocations");
                if(tags.get(20L)==7)readRelas(tags.get(23L),tags.get(2L));else issues.add("PLT_CALLBACK_RELOCATION_UNSUPPORTED");}
            // Unknown relocation widths could overlap a callback slot: retain uncertainty globally.
            if(relas.stream().anyMatch(r->writeWidth(r)<0))issues.add("UNKNOWN_RELOCATION_WRITE_EXTENT");
            for(long tag:List.of(12L,13L))if(tags.containsKey(tag)&&tags.get(tag)!=0){long target=tags.get(tag);
                Map<String,Object> row=new LinkedHashMap<>();row.put("source",tag==12?"DT_INIT":"DT_FINI");row.put("target",target);
                row.put("resolution","DYNAMIC_POINTER_PLUS_LOAD_BIAS");executable(row,target);callbacks.add(row);}
            array(callbacks,32,33,"DT_PREINIT_ARRAY",kind);array(callbacks,25,27,"DT_INIT_ARRAY",kind);array(callbacks,26,28,"DT_FINI_ARRAY",kind);
        }else{
            // Absence of PT_DYNAMIC is normal for a fixed, standalone executable.
            // Do not infer an empty inventory for static PIE, an interpreter, or
            // a file whose section metadata cannot exclude callback containers.
            if(kind!=2||interpreter)issues.add("UNSUPPORTED_STATIC_CALLBACK_RUNTIME");
            else try{
                mapped(q(24),1,true);
                Set<String> names=Set.of(".init",".fini",".preinit_array",".init_array",".fini_array",".ctors",".dtors",".dynamic",".interp");
                for(ElfMetadata.Section section:ElfMetadata.read(raw).allSections())
                    if((section.flags()&2)!=0&&section.size()>0&&(names.contains(section.name())||Set.of(6L,14L,15L,16L).contains(section.type())))
                        issues.add("STATIC_CALLBACK_OR_LOADER_SECTION_REQUIRES_CONTRACT");
            }catch(IllegalArgumentException failure){issues.add("STATIC_CALLBACK_SECTION_OR_ENTRY_INVENTORY_UNAVAILABLE");}
        }
        return Map.ofEntries(Map.entry("schema","java-elf-callback-inventory-1"),Map.entry("binary_sha256",GroupPlan.hash(raw)),
            Map.entry("callbacks",callbacks),Map.entry("issues",issues.stream().distinct().toList()),
            Map.entry("linking_model",dynamic!=null?"DYNAMIC":issues.isEmpty()?"STATIC_NO_CALLBACK_SECTIONS":"STATIC_UNSUPPORTED"),
            Map.entry("scope","File-derived PT_DYNAMIC candidates, or verified absence of allocated static callback/loader sections in fixed ELF; loader execution, manual callbacks and external code unproved"),
            Map.entry("runtime_callback_contract_proved",false),Map.entry("automatic_rewrite_allowed",false));
    }
    private void readRelas(long address,long size){
        require(size>=0&&size%24==0&&size/24<=100000,"Invalid callback RELA size");if(size==0)return;int p=mapped(address,size,false);
        for(int i=0;i<size/24;i++){int at=p+i*24;long info=q(at+8),site=q(at);require(site>=0,"Invalid callback relocation site");
            relas.add(new Rela(site,info&0xffffffffL,info>>>32,q(at+16)));}
    }
    private static int width(long type){return switch((int)type){case 0->0;case 1,6,7,8,16,17,18,37->8;case 2,4,9,10,11->4;case 12,13->2;case 14,15->1;default->-1;};}
    private long writeWidth(Rela relocation){
        if(relocation.type!=5)return width(relocation.type);
        // Bound R_X86_64_COPY by the executable's destination st_size (the
        // x86-64 glibc loader copies min(source size, destination size)). This
        // does not prove the source DSO/loader contract or copied contents.
        if(relocation.symbol==0||!tags.containsKey(6L)||!Objects.equals(tags.get(11L),24L))return -1;
        try{
            int symbol=mapped(end(tags.get(6L),Math.multiplyExact(relocation.symbol,24L)),24,false);
            if((Byte.toUnsignedInt(raw[symbol+4])&15)!=1||u16(symbol+6)==0||u16(symbol+6)>=0xff00)return -1;
            long value=q(symbol+8),size=q(symbol+16);
            if(value!=relocation.site||size<=0||size>64L*1024*1024)return -1;
            long stop=end(value,size);Load owner=null;
            for(Load load:loads)if(value<end(load.address,load.memory)&&load.address<stop){
                if(owner!=null||value<load.address||stop>end(load.address,load.memory)||(load.flags&2)==0)return -1;
                owner=load;
            }
            return owner==null?-1:size;
        }catch(IllegalArgumentException|ArithmeticException failure){return -1;}
    }
    private void array(List<Map<String,Object>> out,long pointerTag,long sizeTag,String name,int kind){
        if(!tags.containsKey(pointerTag)&&!tags.containsKey(sizeTag))return;
        require(tags.containsKey(pointerTag)&&tags.containsKey(sizeTag),"Incomplete callback array tags");
        long address=tags.get(pointerTag),size=tags.get(sizeTag);require(size>=0&&size%8==0&&size/8<=4096,"Invalid callback array size");if(size==0)return;
        int offset=mapped(address,size,false);
        for(int i=0;i<size/8;i++){long site=address+8L*i,value=q(offset+8*i);Map<String,Object> row=new LinkedHashMap<>();
            row.put("source",name);row.put("index",i);row.put("slot",site);row.put("file_value",value);
            List<Rela> writes=relas.stream().filter(r->{long w=writeWidth(r);return w!=0&&r.site<site+8&&(w<0||end(r.site,w)>site);}).toList();
            if(!issues.isEmpty()){row.put("resolution","UNRESOLVED_RELOCATION_INVENTORY");}
            else if(writes.size()==1&&writes.get(0).site==site&&writes.get(0).type==8&&writes.get(0).symbol==0&&writes.get(0).addend>=0){
                long target=writes.get(0).addend;row.put("target",target);row.put("resolution","R_X86_64_RELATIVE_ADDEND_PLUS_LOAD_BIAS");executable(row,target);
            }else if(writes.isEmpty()&&kind==2&&value>0){row.put("target",value);row.put("resolution","ET_EXEC_FILE_POINTER");executable(row,value);}
            else row.put("resolution",writes.isEmpty()?"UNRELOCATED_SLOT_RUNTIME_MEANING_UNPROVED":"UNSUPPORTED_OR_OVERLAPPING_SLOT_RELOCATIONS");
            out.add(row);
        }
    }
    private void executable(Map<String,Object> row,long target){try{mapped(target,1,true);row.put("target_in_executable_file_mapping",true);}
        catch(IllegalArgumentException failure){row.put("target_in_executable_file_mapping",false);row.put("mapping_issue",failure.getMessage());}}
}
