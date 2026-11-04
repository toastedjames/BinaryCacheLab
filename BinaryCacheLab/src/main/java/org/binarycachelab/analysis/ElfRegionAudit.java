package org.binarycachelab.analysis;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Advisory PT_DYNAMIC/RELA inventory. Never certifies reference coverage. */
public final class ElfRegionAudit {
    private static final int LIMIT = 64 * 1024 * 1024;
    private record Segment(long offset, long address, long fileSize, long memorySize) {}
    public record Relocation(long site, long type, long symbol, long addend,
                             int width, boolean writeOverlap, boolean interiorTarget) {}
    public record Result(String sha256, int elfType, long address, long size,
                         String regionSha256, List<Relocation> relocations, List<String> blockers) {
        public String json() {
            StringBuilder out = new StringBuilder("{\n  \"schema\": \"java-elf-region-audit-1\",\n");
            out.append("  \"binary_sha256\": \"").append(sha256).append("\",\n")
                .append("  \"elf_type\": ").append(elfType).append(",\n")
                .append("  \"address\": \"").append(hex(address)).append("\",\n")
                .append("  \"size\": ").append(size).append(",\n")
                .append("  \"region_sha256\": \"").append(regionSha256).append("\",\n")
                .append("  \"reference_coverage\": \"INCOMPLETE\",\n")
                .append("  \"automatic_rewrite_allowed\": false,\n")
                .append("  \"preservation_verdict\": \"NOT_EVALUATED\",\n")
                .append("  \"relocations\": [");
            for (int i=0; i<relocations.size(); i++) {
                Relocation r=relocations.get(i);
                if (i>0) out.append(',');
                out.append("\n    {\"site\": \"").append(hex(r.site)).append("\", \"type\": ")
                    .append(r.type).append(", \"symbol_index\": ").append(r.symbol)
                    .append(", \"addend\": ").append(r.addend)
                    .append(", \"write_width\": ").append(r.width < 0 ? "null" : r.width)
                    .append(", \"write_overlaps_region\": ").append(r.writeOverlap)
                    .append(", \"relative_addend_in_region\": ").append(r.interiorTarget).append('}');
            }
            out.append("\n  ],\n  \"blockers\": [");
            for(int i=0;i<blockers.size();i++) {
                if(i>0) out.append(", ");
                out.append('"').append(blockers.get(i)).append('"');
            }
            return out.append("]\n}\n").toString();
        }
    }

    private final byte[] raw;
    private final ByteBuffer b;
    private final List<Segment> loads = new ArrayList<>();
    private ElfRegionAudit(byte[] raw) { this.raw=raw; b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN); }
    private static void require(boolean ok, String message) {
        if(!ok) throw new IllegalArgumentException(message);
    }
    private static String hex(long n) { return "0x"+Long.toHexString(n); }
    private static long end(long start,long size) {
        require(start>=0 && size>=0 && start<=Long.MAX_VALUE-size,
            "Unsupported negative/high-half address or overflowing extent");
        return start+size;
    }
    private int bounds(long offset,long size) {
        require(end(offset,size)<=raw.length,"Truncated ELF extent");
        return (int)offset;
    }
    private long q(int offset) { return b.getLong(offset); }
    private int u16(int offset) { return Short.toUnsignedInt(b.getShort(offset)); }
    private long u32(int offset) { return Integer.toUnsignedLong(b.getInt(offset)); }
    private int mapped(long address,long size) {
        long stop=end(address,size); Segment found=null;
        for(Segment s:loads) {
            if(address<end(s.address,s.memorySize) && s.address<stop) {
                require(found==null,"Ambiguous overlapping PT_LOAD mappings"); found=s;
                require(address>=s.address && stop<=end(s.address,s.fileSize),
                    "Region/table crosses a PT_LOAD boundary or contains zero-fill bytes");
            }
        }
        require(found!=null,"Region/table is not file-backed by PT_LOAD");
        return bounds(end(found.offset,address-found.address),size);
    }
    private static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch(java.security.NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    public static Result audit(Path file,long address,long size) throws IOException {
        require(Files.size(file)<=LIMIT,"ELF exceeds 64 MiB audit limit");
        try(var input=Files.newInputStream(file)) {
            byte[] raw=input.readNBytes(LIMIT+1);
            require(raw.length<=LIMIT,"ELF exceeds 64 MiB audit limit");
            return audit(raw,address,size);
        }
    }
    public static Result audit(byte[] bytes,long address,long size) {
        require(bytes.length<=LIMIT,"ELF exceeds 64 MiB audit limit");
        return new ElfRegionAudit(bytes.clone()).inspect(address,size);
    }
    private Result inspect(long address,long size) {
        require(size>0,"Region size must be positive"); long stop=end(address,size);
        require(raw.length>=64 && b.getInt(0)==0x464c457f,"Require ELF magic and complete ELF64 header");
        require(raw[4]==2 && raw[5]==1 && raw[6]==1,"Require little-endian ELF64 version 1");
        int kind=u16(16);
        require((kind==2 || kind==3) && u16(18)==62 && u32(20)==1,"Require linked x86-64 ET_EXEC or ET_DYN");
        require(u16(52)==64 && u16(54)==56,"Unsupported ELF/program header size");
        long phoff=q(32); int count=u16(56);
        require(phoff>=64 && count>0 && count<65535,"Missing/extended program headers unsupported");
        bounds(phoff,56L*count);
        Segment dynamic=null;
        for(int i=0;i<count;i++) {
            int p=(int)phoff+56*i; long type=u32(p);
            if(type!=1 && type!=2) continue;
            Segment s=new Segment(q(p+8),q(p+16),q(p+32),q(p+40));
            require(s.fileSize<=s.memorySize,"PT_LOAD/PT_DYNAMIC file size exceeds memory size");
            bounds(s.offset,s.fileSize); end(s.address,s.memorySize);
            if(type==1) loads.add(s);
            else { require(dynamic==null,"Multiple PT_DYNAMIC segments unsupported"); dynamic=s; }
        }
        int region=mapped(address,size);
        LinkedHashSet<String> blockers=new LinkedHashSet<>(List.of(
            "COMPLETE_REFERENCE_COVERAGE_NOT_ESTABLISHED", "CONTROL_FLOW_CORRESPONDENCE_NOT_ESTABLISHED",
            "SECTION_RELOCATIONS_AND_CODE_REFERENCES_NOT_AUDITED"));
        Map<Long,Long> tags=new HashMap<>();
        if(dynamic!=null) {
            require(dynamic.fileSize%16==0,"Malformed PT_DYNAMIC size");
            require(mapped(dynamic.address,dynamic.fileSize)==dynamic.offset,"PT_DYNAMIC file/virtual mapping disagrees");
            boolean terminated=false;
            for(long j=0;j<dynamic.fileSize;j+=16) {
                int p=(int)(dynamic.offset+j); long tag=q(p),value=q(p+8);
                if(tag==0) { terminated=true; break; }
                // Only singleton relocation tags matter here. DT_NEEDED may repeat.
                if(Set.of(2L,7L,8L,9L,17L,18L,19L,20L,23L,35L,36L,37L).contains(tag)) {
                    require(tags.putIfAbsent(tag,value)==null,"Duplicate dynamic relocation tag");
                }
            }
            require(terminated,"Unterminated PT_DYNAMIC");
        }
        if(tags.containsKey(17L)||tags.containsKey(18L)||tags.containsKey(19L)) blockers.add("DT_REL_UNSUPPORTED");
        if(tags.containsKey(35L)||tags.containsKey(36L)||tags.containsKey(37L)) blockers.add("DT_RELR_UNSUPPORTED");
        List<Relocation> rows=new ArrayList<>(); Set<Integer> entries=new HashSet<>();
        if(tags.containsKey(7L)||tags.containsKey(8L)||tags.containsKey(9L)) {
            require(tags.keySet().containsAll(List.of(7L,8L,9L)),"Incomplete DT_RELA tags");
            require(tags.get(9L)==24,"Unsupported DT_RELAENT");
            rela(tags.get(7L),tags.get(8L),address,stop,rows,entries,blockers);
        }
        if(tags.containsKey(23L)||tags.containsKey(2L)||tags.containsKey(20L)) {
            require(tags.keySet().containsAll(List.of(23L,2L,20L)),"Incomplete PLT relocation tags");
            if(tags.get(20L)==7) rela(tags.get(23L),tags.get(2L),address,stop,rows,entries,blockers);
            else if(tags.get(20L)==17) blockers.add("DT_REL_PLT_UNSUPPORTED");
            else throw new IllegalArgumentException("Invalid DT_PLTREL");
        }
        return new Result(hash(raw),kind,address,size,hash(Arrays.copyOfRange(raw,region,region+(int)size)),
            List.copyOf(rows),List.copyOf(blockers));
    }
    private void rela(long address,long size,long start,long stop,List<Relocation> rows,
                      Set<Integer> entries,Set<String> blockers) {
        require(size>=0 && size%24==0,"Malformed RELA table size");
        if(size==0) return;
        int table=mapped(address,size);
        require(size/24<=100000,"RELA entry limit exceeded");
        for(int i=0;i<size/24;i++) {
            int p=table+24*i;
            // Overlapping dynamic views are the same entries, not independent evidence.
            if(!entries.add(p)) continue;
            long site=q(p),info=q(p+8),addend=q(p+16),type=info&0xffffffffL,symbol=info>>>32;
            require(site>=0,"High-half relocation sites unsupported");
            int width=type==0 ? 0 : (type==1 || type==6 || type==7 || type==8 || type==37 ? 8 : -1);
            boolean overlap=width>0 && site<stop && start<end(site,width);
            boolean target=type==8 && symbol==0 && addend>=start && addend<stop;
            if(width<0) blockers.add("UNKNOWN_RELOCATION_WRITE_EXTENT");
            if(type!=0 && !(type==8 && symbol==0)) blockers.add("UNRESOLVED_SYMBOL_OR_RELOCATION_TARGET");
            if(overlap) blockers.add("RELOCATION_WRITE_OVERLAPS_REGION");
            if(target) blockers.add("RELATIVE_ADDEND_POINTS_INTO_REGION");
            if(width>0) {
                long last=end(site,width);
                long matches=loads.stream().filter(s->site>=s.address && last<=end(s.address,s.memorySize)).count();
                require(matches==1,"Relocation write is not uniquely within PT_LOAD memory");
            }
            rows.add(new Relocation(site,type,symbol,addend,width,overlap,target));
        }
    }
}
