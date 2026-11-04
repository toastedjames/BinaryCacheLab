package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.binarycachelab.workflow.Stage3Engine;
import static org.binarycachelab.workflow.LabConfig.require;

/** Independently checks the encodings of the declared direct reads; not a complete decoder. */
public final class LinkedReadVerification {
    private LinkedReadVerification(){}
    private record Load(long address,long offset,long bytes,int flags){}
    private record Row(long ip,byte[] bytes){}
    public static Map<String,Object> verify(Path binary,String disassembly,long start,long size)throws IOException{
        require(Files.size(binary)<=64*1024*1024,"ELF exceeds instruction verification budget");
        byte[] raw;try(var input=Files.newInputStream(binary)){raw=input.readNBytes(64*1024*1024+1);}
        require(raw.length>=64&&raw.length<=64*1024*1024,"Invalid instruction ELF size");
        ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        require(b.getInt(0)==0x464c457f&&raw[4]==2&&raw[5]==1&&b.getShort(18)==62,"Expected little-endian x86-64 ELF");
        require(b.getShort(16)==2||b.getShort(16)==3,"Expected linked executable/shared ELF");
        long table=b.getLong(32);int stride=Short.toUnsignedInt(b.getShort(54)),count=Short.toUnsignedInt(b.getShort(56));
        require(table>=64&&stride==56&&count>0&&count<65535&&table<=raw.length-(long)count*stride,"Invalid program headers");
        List<Load> loads=new ArrayList<>();
        for(int n=0;n<count;n++){int at=(int)(table+(long)n*stride);if(b.getInt(at)!=1)continue;
            long offset=b.getLong(at+8),address=b.getLong(at+16),bytes=b.getLong(at+32),memory=b.getLong(at+40);
            require(offset>=0&&bytes>=0&&offset<=raw.length-bytes&&address>=0&&memory>=bytes&&address<=Long.MAX_VALUE-memory,"Invalid load extent");
            loads.add(new Load(address,offset,bytes,b.getInt(at+4)));}
        Map<String,Object> inventory=DirectReadInventory.inspect(disassembly,start,size);
        require(DirectReadInventory.supported(inventory),"Unsupported direct-read inventory");
        Pattern pattern=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
        Map<Long,Row> rows=new TreeMap<>();long previousEnd=-1;
        for(String line:disassembly.split("\\R")){Matcher m=pattern.matcher(line);if(!m.matches())continue;
            long ip=Long.parseLong(m.group(1),16);String hex=m.group(2).replaceAll("\\s","");byte[] bytes=HexFormat.of().parseHex(hex);
            require(bytes.length>0&&bytes.length<=15&&ip<=Long.MAX_VALUE-bytes.length,"Invalid x86 instruction row");
            require(ip>=previousEnd,"Repeated, overlapping or unordered disassembly rows");previousEnd=ip+bytes.length;
            Load found=null;for(Load load:loads)if(ip>=load.address&&ip-load.address<=load.bytes-bytes.length){require(found==null,"Ambiguous instruction mapping");found=load;}
            require(found!=null&&(found.flags&1)!=0,"Instruction row outside executable file-backed segment");
            int offset=(int)(found.offset+ip-found.address);
            for(int n=0;n<bytes.length;n++)require(bytes[n]==raw[offset+n],"Disassembly bytes disagree with ELF at 0x"+Long.toHexString(ip));
            rows.put(ip,new Row(ip,bytes));
        }
        List<Map<String,Object>> checked=new ArrayList<>();
        for(Object value:(List<?>)inventory.get("reads")){Map<?,?> read=(Map<?,?>)value;long ip=((Number)read.get("ip")).longValue();Row row=rows.get(ip);
            require(row!=null,"Missing selected instruction row");byte[] code=row.bytes;int cursor=0;boolean word=false;int rex=0;
            if((code[cursor]&255)==0x66){word=true;cursor++;}
            require(cursor<code.length,"Truncated instruction prefix");
            if((code[cursor]&0xf0)==0x40){rex=code[cursor]&255;cursor++;}
            require(cursor<code.length,"Truncated opcode");int opcode=code[cursor++]&255,width;String mnemonic="mov";
            if(opcode==0x8a)width=1;
            else if(opcode==0x8b)width=(rex&8)!=0?8:word?2:4;
            else {require(opcode==0x0f&&cursor<code.length,"Unsupported selected read opcode");int second=code[cursor++]&255;
                require(second==0xb6||second==0xb7||second==0xbe||second==0xbf,"Unsupported extended read opcode");width=(second==0xb6||second==0xbe)?1:2;mnemonic=second<0xbe?"movzx":"movsx";}
            require(cursor<code.length,"Missing ModRM byte");int modrm=code[cursor++]&255;
            require((modrm&0xc7)==5&&(rex&3)==0,"Expected unindexed RIP-relative read encoding");
            int register=((modrm>>3)&7)+((rex&4)!=0?8:0),destinationWidth=opcode==0x8a?1:(rex&8)!=0?8:word?2:4;
            String[] names=destinationWidth==1?(rex==0?new String[]{"al","cl","dl","bl","ah","ch","dh","bh"}:new String[]{"al","cl","dl","bl","spl","bpl","sil","dil"}):destinationWidth==2?new String[]{"ax","cx","dx","bx","sp","bp","si","di"}:destinationWidth==4?new String[]{"eax","ecx","edx","ebx","esp","ebp","esi","edi"}:new String[]{"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
            String destination=register<8?names[register]:"r"+register+(destinationWidth==1?"b":destinationWidth==2?"w":destinationWidth==4?"d":"");
            require(((String)read.get("instruction")).matches("(?i)"+mnemonic+"\\s+"+destination+",.*"),"Decoded opcode/destination disagrees with disassembly");
            require(code.length-cursor==4,"Unexpected instruction length/trailing bytes");
            int displacement=ByteBuffer.wrap(code,cursor,4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            long target=Math.addExact(Math.addExact(ip,code.length),displacement);
            require(target==((Number)read.get("target")).longValue()&&width==((Number)read.get("width_bytes")).intValue(),"Decoded read target/width disagrees with inventory");
            checked.add(Map.of("ip",ip,"target",target,"offset",target-start,"width_bytes",width,"encoding",HexFormat.of().formatHex(code)));
        }
        return Map.of("schema","java-linked-reads-1","binary_sha256",Stage3Engine.digest(binary),"instruction_rows_bound_to_elf",rows.size(),
            "reads",checked,"reference_coverage","INCOMPLETE","automatic_rewrite_allowed",false,
            "limitations",List.of("Only declared direct-read encodings are independently decoded","Disassembly boundaries and complete code/alias coverage are not proved"));
    }
    public static Map<String,Object> correspond(Map<String,Object> original,Map<String,Object> rebuilt){
        Map<String,List<Map<?,?>>> left=group(original),right=group(rebuilt);
        require(left.keySet().equals(right.keySet()),"Original/rebuilt access offsets or widths differ");
        List<Map<String,Object>> sites=new ArrayList<>();boolean unique=true;
        for(String key:left.keySet()){List<Map<?,?>> a=left.get(key),b=right.get(key);require(a.size()==b.size(),"Original/rebuilt access multiplicity differs");
            boolean one=a.size()==1;unique&=one;
            sites.add(Map.of("offset_width",key,"unique_site_match",one,"original_ips",a.stream().map(r->r.get("ip")).toList(),"rebuilt_ips",b.stream().map(r->r.get("ip")).toList()));}
        return Map.of("schema","java-access-correspondence-1","sites",sites,"all_sites_unique",unique,
            "basis","Independently decoded region-relative offset and access width; duplicate sites remain ambiguous",
            "control_flow_equivalence_proved",false,"reference_coverage","INCOMPLETE");
    }
    /** Exact two-path machine-code contract. This establishes no whole-program reference closure. */
    public static Map<String,Object> lookupKernel(String disassembly,Map<String,Object> encodings){
        List<?> reads=(List<?>)encodings.get("reads");require(reads.size()==2,"Lookup kernel requires exactly two declared reads");
        Map<Long,byte[]> rows=new TreeMap<>();Pattern pattern=Pattern.compile("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)(\\S.*)$");
        for(String line:disassembly.split("\\R")){Matcher m=pattern.matcher(line);if(m.matches())rows.put(Long.parseLong(m.group(1),16),HexFormat.of().parseHex(m.group(2).replaceAll("\\s","")));}
        Map<?,?> first=(Map<?,?>)reads.get(0),second=(Map<?,?>)reads.get(1);long a=((Number)first.get("ip")).longValue(),b=((Number)second.get("ip")).longValue();
        require(b==a+7&&a>=4,"Lookup kernel read sites are not the supported two-path shape");
        require(Arrays.equals(rows.get(a-4),HexFormat.of().parseHex("85ff"))&&Arrays.equals(rows.get(a-2),HexFormat.of().parseHex("7407")),"Lookup kernel must test edi and branch to the zero read");
        require(Arrays.equals(rows.get(a+6),new byte[]{(byte)0xc3})&&Arrays.equals(rows.get(b+6),new byte[]{(byte)0xc3}),"Lookup kernel paths must return directly");
        for(Object item:reads){Map<?,?> read=(Map<?,?>)item;require(((Number)read.get("width_bytes")).intValue()==4&&((String)read.get("encoding")).startsWith("8b05"),"Lookup kernel requires DWORD reads into eax");}
        return Map.of("schema","java-lookup-kernel-contract-1","entry_at_test_edi",a-4,"nonzero_offset",first.get("offset"),"zero_offset",second.get("offset"),
            "nonzero_lines",lines(((Number)first.get("target")).longValue(),4),"zero_lines",lines(((Number)second.get("target")).longValue(),4),
            "all_selector_values_partitioned",true,"selector_domain","All 32-bit edi values: zero or nonzero",
            "contract","Enters at test edi with a valid return address, readable immutable declared bytes, ordinary x86-64 execution; excludes asynchronous events and instruction fetch");
    }
    public static Map<String,Object> compareKernels(Map<String,Object> original,Map<String,Object> rebuilt,boolean groupBytesEqual){
        require(groupBytesEqual,"Kernel group contents differ");
        require(original.get("zero_offset").equals(rebuilt.get("zero_offset"))&&original.get("nonzero_offset").equals(rebuilt.get("nonzero_offset")),"Kernel branch/read correspondence differs");
        boolean premise=original.get("zero_lines").equals(original.get("nonzero_lines"));
        boolean conclusion=rebuilt.get("zero_lines").equals(rebuilt.get("nonzero_lines"));
        return Map.of("schema","java-local-preservation-1","original_branch_observations_equal",premise,"rebuilt_branch_observations_equal",conclusion,
            "preservation_for_all_selector_pairs_under_contract",!premise||conclusion,"return_value_correspondence_under_contract",true,
            "abi_effects_under_contract","eax returns the corresponding unchanged DWORD; rsp advances by 8 on ret; callee-saved registers are unchanged; caller-saved flags may change",
            "return_stack_observation","Same fixed entry rsp gives one identical 8-byte return-address read on both branches",
            "scope","Exact lookup kernel only; no whole-program alias, entry reachability, CET, loader or semantic-equivalence proof",
            "automatic_rewrite_allowed",false);
    }
    private static List<Long> lines(long target,int bytes){List<Long> result=new ArrayList<>();for(long line=target/64;line<=(target+bytes-1)/64;line++)result.add(line);return result;}
    private static Map<String,List<Map<?,?>>> group(Map<String,Object> report){Map<String,List<Map<?,?>>> result=new TreeMap<>();
        for(Object value:(List<?>)report.get("reads")){Map<?,?> row=(Map<?,?>)value;String key=row.get("offset")+"/"+row.get("width_bytes");result.computeIfAbsent(key,k->new ArrayList<>()).add(row);}return result;}
}
