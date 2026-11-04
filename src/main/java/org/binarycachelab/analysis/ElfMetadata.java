package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.GroupPlan;
import static org.binarycachelab.workflow.LabConfig.require;

/** Section/symbol/relocation inventory, never exhaustive reference coverage. */
public final class ElfMetadata {
    public record Section(int index,String name,long type,long flags,long address,long offset,long size,long link,long info,long entrySize){}
    public record Symbol(String name,long value,long size,int section,int type,int binding,int table,int index){}
    private final byte[] raw;private final ByteBuffer b;
    private final List<Section> sections=new ArrayList<>();
    private final Map<Integer,List<Symbol>> tables=new HashMap<>();
    private final List<Symbol> symbols=new ArrayList<>();
    private ElfMetadata(byte[] raw){this.raw=raw;b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);parse();}
    public static ElfMetadata read(Path path)throws IOException{
        try(var input=Files.newInputStream(path)){return read(input.readNBytes(64*1024*1024+1));}
    }
    public static ElfMetadata read(byte[] bytes){require(bytes.length<=64*1024*1024,"ELF metadata exceeds 64 MiB");return new ElfMetadata(bytes.clone());}
    public String sha256(){return GroupPlan.hash(raw);}
    public List<Section> allSections(){return List.copyOf(sections);}
    public List<Section> executableSections(){return sections.stream().filter(s->s.type==1&&(s.flags&6)==6&&s.size>0).toList();}
    private static long end(long a,long n){require(a>=0&&n>=0&&a<=Long.MAX_VALUE-n,"Unsupported ELF extent");return a+n;}
    private int bound(long offset,long size){require(end(offset,size)<=raw.length,"Truncated ELF metadata");return (int)offset;}
    private int u16(int p){return Short.toUnsignedInt(b.getShort(p));}
    private long u32(int p){return Integer.toUnsignedLong(b.getInt(p));}
    private long q(int p){return b.getLong(p);}
    private String string(Section table,long offset){require(table.type==3&&offset>=0&&offset<table.size,"Invalid ELF string reference");
        int at=bound(end(table.offset,offset),1),stop=(int)end(table.offset,table.size),last=at;
        while(last<stop&&raw[last]!=0){last++;require(last-at<=4096,"ELF string length limit exceeded");}
        require(last<stop,"Unterminated ELF string");
        try{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw,at,last-at)).toString();}
        catch(CharacterCodingException e){throw new IllegalArgumentException("Unsupported ELF string encoding",e);}
    }
    private void parse(){
        require(raw.length>=64&&b.getInt(0)==0x464c457f&&raw[4]==2&&raw[5]==1&&raw[6]==1,"Require little-endian ELF64");
        require((u16(16)==2||u16(16)==3)&&u16(18)==62&&u32(20)==1&&u16(52)==64,"Require linked x86-64 ELF");
        long offset=q(40);int count=u16(60),names=u16(62);
        require(offset>=64&&count>0&&count<0xff00&&u16(58)==64&&names<count&&names>0,"Absent/extended section tables unsupported");bound(offset,64L*count);
        List<Long> nameOffsets=new ArrayList<>();
        for(int i=0;i<count;i++){int p=(int)offset+64*i;long type=u32(p+4),flags=q(p+8),address=q(p+16),file=q(p+24),size=q(p+32);
            end(address,size);if(type!=8)bound(file,size);nameOffsets.add(u32(p));
            sections.add(new Section(i,"",type,flags,address,file,size,u32(p+40),u32(p+44),q(p+56)));
        }
        Section strings=sections.get(names);require(strings.type==3,"Invalid section-name table");
        for(int i=0;i<count;i++){Section s=sections.get(i);sections.set(i,new Section(i,string(strings,nameOffsets.get(i)),s.type,s.flags,s.address,s.offset,s.size,s.link,s.info,s.entrySize));}
        for(Section table:sections)if(table.type==2||table.type==11){
            require(table.entrySize==24&&table.size%24==0&&table.size/24<=1000000,"Unsupported ELF symbol table");
            require(table.link>0&&table.link<sections.size(),"Invalid symbol string-table link");List<Symbol> entries=new ArrayList<>();
            for(int i=0;i<table.size/24;i++){int p=(int)table.offset+i*24;String name=string(sections.get((int)table.link),u32(p));
                long value=q(p+8),size=q(p+16);end(value,size);int info=Byte.toUnsignedInt(raw[p+4]),section=u16(p+6);
                require(section>=0xff00||section<sections.size(),"Invalid symbol section index");require(section!=0xffff,"Extended symbol section index unsupported");
                Symbol s=new Symbol(name,value,size,section,info&15,info>>>4,table.index,i);entries.add(s);if(!name.isEmpty())symbols.add(s);
            }tables.put(table.index,List.copyOf(entries));
        }
    }
    public Map<String,Long> executableSymbols(){
        Map<String,Long> result=new TreeMap<>();Set<String> ambiguous=new HashSet<>();
        for(Symbol s:symbols)if(s.section>0&&s.section<sections.size()){
            Section section=sections.get(s.section);
            if(section.type!=1||(section.flags&6)!=6||s.value<section.address||s.value>=end(section.address,section.size))continue;
            if(result.containsKey(s.name)&&result.get(s.name)!=s.value)ambiguous.add(s.name);else result.put(s.name,s.value);
        }
        ambiguous.forEach(result::remove);return result;
    }
    public Map<String,Long> selected(Set<String> names){
        Map<String,Long> result=new HashMap<>();Map<String,Set<Integer>> seenTables=new HashMap<>();
        for(Symbol s:symbols)if(names.contains(s.name)&&s.section!=0){
            require(s.section<sections.size(),"Selected label is not section-backed: "+s.name);Section section=sections.get(s.section);
            require(section.type==1&&(section.flags&2)!=0&&(section.flags&4)==0&&(section.flags&0x400)==0,"Selected label is not ordinary allocated file data: "+s.name);
            require(s.value>=section.address&&s.value<=end(section.address,section.size),"Selected label outside section");
            if(result.containsKey(s.name))require(result.get(s.name)==s.value&&!seenTables.get(s.name).contains(s.table),"Ambiguous selected ELF symbol: "+s.name);
            else{result.put(s.name,s.value);seenTables.put(s.name,new HashSet<>());}seenTables.get(s.name).add(s.table);
        }
        require(result.keySet().containsAll(names),"Missing selected ELF symbols: "+names.stream().filter(x->!result.containsKey(x)).toList());return result;
    }
    public Map<String,Object> audit(long address,long size){
        long stop=end(address,size);require(size>0,"Region size must be positive");
        List<Map<String,Object>> owners=new ArrayList<>(),references=new ArrayList<>(),pointers=new ArrayList<>();
        List<Map<String,Object>> exposed=new ArrayList<>();
        List<Map<String,Object>> boundarySymbols=new ArrayList<>();
        List<String> blockers=new ArrayList<>(List.of("COMPLETE_REFERENCE_COVERAGE_NOT_ESTABLISHED","COMPUTED_POINTERS_AND_CONTROL_FLOW_NOT_PROVED"));
        List<Section> containing=sections.stream().filter(s->(s.flags&2)!=0&&s.address<=address&&stop<=end(s.address,s.size)&&s.size>0).toList();
        require(containing.size()==1&&containing.get(0).type==1&&(containing.get(0).flags&4)==0&&(containing.get(0).flags&0x400)==0,"Region has no unique ordinary allocated file-data section");
        for(Symbol s:symbols)if(s.section!=0&&s.section<sections.size()&&s.value==stop)
            boundarySymbols.add(Map.of("name",s.name,"value",s.value,"size",s.size,"section",sections.get(s.section).name,"type",s.type,"binding",s.binding));
        for(Symbol s:symbols)if(s.section!=0&&s.section<sections.size()&&s.value<stop&&address<end(s.value,Math.max(1,s.size))){
            String relationship=s.value<address&&end(s.value,Math.max(1,s.size))>=stop?"ENCLOSING_SYMBOL":s.value==address?"AT_REGION_START":"OVERLAPPING_OR_INTERIOR_SYMBOL";
            owners.add(Map.of("name",s.name,"value",s.value,"size",s.size,"type",s.type,"symbol_table",s.table,"relationship",relationship,"binding",s.binding));
            int visibility=raw[(int)sections.get(s.table).offset+s.index*24+5]&3;
            if(sections.get(s.table).type==11&&s.binding!=0&&visibility!=1&&visibility!=2)
                exposed.add(Map.of("name",s.name,"value",s.value,"size",s.size,"visibility",visibility,"binding",s.binding));
        }
        long count=0;Set<Long> seen=new HashSet<>();
        if(sections.stream().anyMatch(s->s.type==19))blockers.add("SECTION_RELR_PACKING_UNSUPPORTED");
        for(Section section:sections)if(section.type==4||section.type==9){
            if(section.type==9){blockers.add("SECTION_REL_IMPLICIT_ADDENDS_UNSUPPORTED");continue;}
            require(section.entrySize==24&&section.size%24==0&&section.size/24<=100000,"Unsupported section RELA table");
            require(section.link<sections.size()&&section.info<sections.size(),"Invalid relocation section links");
            List<Symbol> syms=tables.get((int)section.link);require(syms!=null,"Relocation symbol table missing");
            if((section.flags&2)==0&&(section.info==0||(sections.get((int)section.info).flags&2)==0))continue;
            for(int i=0;i<section.size/24;i++){long pos=section.offset+24L*i;if(!seen.add(pos))continue;int p=(int)pos;
                long site=q(p),info=q(p+8),addend=q(p+16),kind=info&0xffffffffL,index=info>>>32;
                require(site>=0&&index<syms.size(),"Invalid section relocation");count++;Symbol symbol=syms.get((int)index);
                int width=width(kind);List<String> reasons=new ArrayList<>();
                if(width<0){blockers.add("UNSUPPORTED_SECTION_RELOCATION_TYPE");if(site>=address&&site<stop)reasons.add("UNKNOWN_WRITE_EXTENT_SITE_IN_REGION");}
                if(width>0&&site<stop&&address<end(site,width))reasons.add("RELOCATION_WRITE_OVERLAPS_REGION");
                if(kind==8&&index==0&&addend>=address&&addend<=stop)reasons.add(addend==stop?"RELATIVE_ADDEND_ONE_PAST_REGION":"RELATIVE_ADDEND_IN_REGION");
                if(index>0&&symbol.section!=0){
                    if(symbol.value<stop&&address<end(symbol.value,Math.max(1,symbol.size)))reasons.add("REFERENCED_SYMBOL_OVERLAPS_REGION");
                    try{long target=Math.addExact(symbol.value,addend);if(target>=address&&target<=stop)reasons.add(target==stop?"SYMBOL_PLUS_ADDEND_ONE_PAST_REGION":"SYMBOL_PLUS_ADDEND_IN_REGION");}
                    catch(ArithmeticException e){blockers.add("RELOCATION_EXPRESSION_OVERFLOW");}
                }else if(index>0)blockers.add("RUNTIME_SYMBOL_BINDING_UNRESOLVED");
                if(!reasons.isEmpty())references.add(Map.of("table",section.name,"site",site,"type",kind,"symbol",symbol.name,"addend",addend,
                    "write_width",width,"reasons",reasons,"loader_table",(section.flags&2)!=0));
            }
        }
        long scanned=0;
        for(Section section:sections)if(section.type==1&&(section.flags&2)!=0&&(section.flags&4)==0){
            require(section.size<=8*1024*1024-scanned,"File-data pointer scan exceeds 8 MiB budget");scanned+=section.size;
            for(int i=0;i+8<=section.size;i++){long value=q((int)section.offset+i);
                if(value>=address&&value<=stop){require(pointers.size()<1000,"Pointer candidate limit exceeded");
                    pointers.add(Map.of("section",section.name,"site",section.address+i,"value",value,"classification",value==stop?"POTENTIAL_ONE_PAST_POINTER_NOT_PROVEN_REFERENCE":"POTENTIAL_POINTER_BYTES_NOT_PROVEN_REFERENCE"));}}
        }
        if(!references.isEmpty())blockers.add("SECTION_RELOCATION_REGION_REFERENCES_REQUIRE_REVIEW");if(!pointers.isEmpty())blockers.add("STORED_POINTER_CANDIDATES_REQUIRE_REVIEW");
        return Map.ofEntries(Map.entry("schema","java-elf-metadata-1"),Map.entry("binary_sha256",sha256()),Map.entry("address",address),Map.entry("size",size),
            Map.entry("section",containing.get(0).name),Map.entry("symbol_owners_and_alias_candidates",owners),Map.entry("allocated_relocation_entries",count),
            Map.entry("region_relocation_references",references),Map.entry("stored_pointer_candidates",pointers),Map.entry("blockers",blockers.stream().distinct().toList()),
            Map.entry("dynamic_symbol_exposures",exposed),
            Map.entry("symbols_at_region_end",boundarySymbols),
            Map.entry("reference_coverage","INCOMPLETE"),Map.entry("automatic_rewrite_allowed",false),
            Map.entry("limitations",List.of("Metadata and byte-window candidates are not complete instruction/pointer analysis",
                "Section/dynamic relocation views may overlap; do not add counts","Pointer scans omit BSS, heap, stack and runtime-generated pointers")));
    }
    public static List<String> detectedHazards(Map<String,Object> report){List<String> out=new ArrayList<>();
        for(String key:List.of("region_relocation_references","stored_pointer_candidates","dynamic_symbol_exposures"))
            if(report.get(key) instanceof List<?> rows&&!rows.isEmpty())out.add(key.toUpperCase(Locale.ROOT)+"_REQUIRE_REVIEW");
        for(Object value:(List<?>)report.get("blockers"))if(Set.of("SECTION_REL_IMPLICIT_ADDENDS_UNSUPPORTED","UNSUPPORTED_SECTION_RELOCATION_TYPE",
                "RELOCATION_EXPRESSION_OVERFLOW","SECTION_RELR_PACKING_UNSUPPORTED").contains(value))out.add(value.toString());
        return List.copyOf(out);
    }
    private static int width(long type){if(type>Integer.MAX_VALUE)return -1;return switch((int)type){case 0->0;case 1,6,7,8,24,37->8;case 2,4,9,10,11->4;default->-1;};}
}
