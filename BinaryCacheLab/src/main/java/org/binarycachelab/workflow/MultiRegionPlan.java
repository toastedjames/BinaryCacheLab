package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.binarycachelab.analysis.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Preserves the cache-line equality partition of declared bytes across multiple regions. */
public final class MultiRegionPlan {
    public record Region(String name,String end,long address,long size,long alignment) {long stop(){return Math.addExact(address,size);}}
    private record Group(List<Region> regions,long first,long stop,long residue,long period,long placement){}
    private final Map<String,Object> profile;
    private final List<Region> regions=new ArrayList<>();
    private final List<Group> groups=new ArrayList<>();
    private final long line;
    private final Path base;
    public MultiRegionPlan(Path file)throws IOException{this(file,Json.object(Files.readString(file)));}
    public MultiRegionPlan(Path file,Map<String,Object> profile){
        this.profile=profile;this.base=file.toAbsolutePath().getParent();
        require("bcl-regions-1".equals(profile.get("schema")),"Expected bcl-regions-1 profile");
        line=number(profile,"line_bytes");require(line>=16&&line<=4096&&(line&(line-1))==0,"Line size must be a power of two in 16..4096");
        require(profile.get("regions") instanceof List<?> list&&!list.isEmpty()&&list.size()<=128,"Require 1..128 regions");
        Set<String> names=new HashSet<>();long total=0;
        for(Object item:(List<?>)profile.get("regions")){Map<String,Object> r=object(item);String name=label(r,"name"),end=label(r,"end_label");
            require(names.add(name)&&names.add(end),"Duplicate region labels");long a=number(r,"address"),size=number(r,"size"),align=number(r,"alignment");
            require(a>=0&&size>0&&size<=4*1024*1024&&a<=Long.MAX_VALUE-size,"Invalid region extent");
            require(align>0&&align<=1024*1024&&(align&(align-1))==0,"Alignment must be a power of two <= 1 MiB");
            total=Math.addExact(total,size);require(total<=16*1024*1024,"Declared data exceeds 16 MiB");regions.add(new Region(name,end,a,size,align));}
        regions.sort(Comparator.comparingLong(Region::address));
        for(int i=1;i<regions.size();i++)require(regions.get(i-1).stop()<=regions.get(i).address,"Overlapping regions require one enclosing declaration");
        long cursor=number(profile,"placement_base");require(cursor>=0,"Negative placement base");
        for(int at=0;at<regions.size();){List<Region> component=new ArrayList<>();Region first=regions.get(at++);component.add(first);long stop=first.stop();
            while(at<regions.size()&&regions.get(at).address/line<=(stop-1)/line){Region next=regions.get(at++);component.add(next);stop=Math.max(stop,next.stop());}
            require(stop-first.address<=4*1024*1024,"Shared-line group exceeds 4 MiB");
            long period=line;for(Region r:component)period=Math.max(period,r.alignment);
            Long residue=null;
            for(long candidate=first.address%line;candidate<period;candidate+=line){boolean okay=true;
                for(Region r:component)if((candidate+r.address-first.address)%r.alignment!=0){okay=false;break;}
                if(okay){residue=candidate;break;}}
            require(residue!=null,"UNSATISFIABLE_ALIGNMENT_AND_LINE_PARTITION: "+component.stream().map(Region::name).toList());
            long delta=Math.floorMod(residue-Math.floorMod(cursor,period),period),placement=Math.addExact(cursor,delta);
            groups.add(new Group(List.copyOf(component),first.address,stop,residue,period,placement));
            long after=Math.addExact(placement,stop-first.address);cursor=Math.addExact(after,Math.floorMod(-after,line));
        }
    }
    public Path path(String key){Object value=profile.get(key);require(value instanceof String&&!((String)value).isBlank(),"Missing profile path: "+key);
        Path p=Path.of((String)value);return p.isAbsolute()?p:base.resolve(p).normalize();}
    public Map<String,Object> report(){List<Map<String,Object>> components=new ArrayList<>();
        for(Group group:groups){List<Map<String,Object>> members=new ArrayList<>();for(Region r:group.regions)members.add(Map.of("name",r.name,"end_label",r.end,"original_address",r.address,"size",r.size,
            "relative_offset",r.address-group.first,"planned_address",group.placement+r.address-group.first,"alignment",r.alignment));
            components.add(Map.of("members",members,"original_first",group.first,"span_bytes",group.stop-group.first,"alignment",group.period,"residue",group.residue,"planned_first",group.placement));}
        return Map.of("schema","bcl-multi-region-plan-1","status","CONSTRAINTS_SATISFIABLE","policy","preserve-shared-line-components",
            "line_bytes",line,"groups",components,"automatic_rewrite_allowed",false,
            "scope","Declared bytes only; source padding is a candidate transformation; reference, ABI, loader and outside-object obligations remain",
            "final_link_verification_required",true);
    }
    public String apply(String assembly){
        require(!assembly.contains("BCL multi-region policy"),"Policy already applied");
        List<String> lines=new ArrayList<>(Arrays.asList(assembly.replace("\r\n","\n").split("\n",-1)));
        Map<String,Integer> positions=new HashMap<>();Map<String,String> sections=new HashMap<>();String section="";
        for(int i=0;i<lines.size();i++){String code=lines.get(i).split(";",2)[0].trim();
            require(!code.startsWith("%")&&!code.matches("(?i)^(org|absolute|struc)\\b.*"),"Unsupported assembly address/preprocessor context");
            if(code.matches("(?i)^(section|segment)\\s+.*"))section=code;
            for(Region r:regions)for(String name:List.of(r.name,r.end))if(code.equals(name+":")){require(positions.putIfAbsent(name,i)==null,"Duplicate source label: "+name);sections.put(name,section);}}
        for(Region r:regions){require(positions.containsKey(r.name)&&positions.containsKey(r.end),"Missing source labels: "+r.name);
            String s=sections.get(r.name);require(s.equals(sections.get(r.end))&&s.matches("(?i)^(section|segment)\\s+\\.data(?:\\s+.*)?$"),"Regions require the same ordinary .data section");
            require(literals(lines,positions.get(r.name),positions.get(r.end)).length==r.size,"Source span size mismatch: "+r.name);}
        Map<Integer,String> insertions=new TreeMap<>(Comparator.reverseOrder());
        for(Group g:groups){Region first=g.regions.get(0),last=g.regions.get(g.regions.size()-1);int from=positions.get(first.name),to=positions.get(last.end);
            require(from<to,"Source order differs from declared region order");
            for(Region r:g.regions)require(positions.get(r.name)>=from&&positions.get(r.end)<=to&&literals(lines,from,positions.get(r.name)).length==r.address-g.first,"Source relative spacing differs: "+r.name);
            require(literals(lines,from,to).length==g.stop-g.first,"Source group gap/span mismatch");
            insertions.put(from,"; BCL multi-region policy\nalign "+g.period+", db 0\ntimes "+g.residue+" db 0");}
        insertions.forEach((at,text)->lines.add(at,text));return String.join("\n",lines);
    }
    public Map<String,Object> verify(Path original,Path rebuilt)throws IOException{
        Map<String,Long> labels=ElfMetadata.read(rebuilt).selected(regions.stream().flatMap(r->java.util.stream.Stream.of(r.name,r.end)).collect(java.util.stream.Collectors.toSet()));
        Map<Long,Long> forward=new HashMap<>(),reverse=new HashMap<>();List<Map<String,Object>> checked=new ArrayList<>();
        for(Region r:regions){long a=labels.get(r.name),end=labels.get(r.end);require(end-a==r.size&&a%r.alignment==0,"Linked extent/alignment mismatch: "+r.name);
            require(a%line==r.address%line,"Linked line residue mismatch: "+r.name);
            var before=ElfRegionAudit.audit(original,r.address,r.size);var after=ElfRegionAudit.audit(rebuilt,a,r.size);
            require(before.regionSha256().equals(after.regionSha256()),"Linked region bytes changed: "+r.name);
            require(after.relocations().stream().noneMatch(x->x.writeOverlap()||x.width()<0),"Final relocation write/unknown extent in declared region");
            for(long off=0;off<r.size;){long oldLine=(r.address+off)/line,newLine=(a+off)/line;Long mapped=forward.putIfAbsent(oldLine,newLine),back=reverse.putIfAbsent(newLine,oldLine);
                require((mapped==null||mapped==newLine)&&(back==null||back==oldLine),"Cross-region cache-line equality partition changed");
                off+=Math.min(r.size-off,line-(r.address+off)%line);}
            checked.add(Map.of("name",r.name,"original_address",r.address,"rebuilt_address",a,"size",r.size,"sha256",before.regionSha256()));}
        return Map.of("schema","bcl-multi-region-link-check-1","status","DECLARED_LAYOUT_RELATION_CHECKED","regions",checked,
            "line_classes",forward.size(),"declared_byte_line_equality_preserved",true,"automatic_rewrite_allowed",false,
            "scope","Declared byte contents and line partition; not instruction/reference or whole-program preservation proof");
    }
    private static byte[] literals(List<String> lines,int start,int stop){require(start<=stop,"Reversed source span");ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        for(int i=start+1;i<stop;i++){String s=lines.get(i).split(";",2)[0].trim();if(s.isEmpty()||s.matches("[A-Za-z_][A-Za-z0-9_.$]*:"))continue;
            require(s.matches("(?i)db\\s+.*"),"Only literal DB bytes supported inside region groups: "+s);
            for(String item:s.substring(2).trim().split(",")){String v=item.trim();long value;
                if(v.matches("(?i)[0-9][0-9a-f]*h"))value=Long.parseLong(v.substring(0,v.length()-1),16);
                else if(v.matches("0x[0-9a-fA-F]+"))value=Long.parseLong(v.substring(2),16);
                else{require(v.matches("[0-9]+"),"Nonliteral DB expression");value=Long.parseLong(v);}
                require(value>=0&&value<=255,"DB byte outside 0..255");bytes.write((int)value);}}
        return bytes.toByteArray();
    }
    @SuppressWarnings("unchecked") public static Map<String,Object> object(Object v){require(v instanceof Map<?,?>,"Expected JSON object");return (Map<String,Object>)v;}
    public static long number(Map<String,Object> m,String key){Object v=m.get(key);require(v instanceof Number,"Missing integer: "+key);return ((Number)v).longValue();}
    private static String label(Map<String,Object> m,String key){Object v=m.get(key);require(v instanceof String&&((String)v).matches("[A-Za-z_][A-Za-z0-9_.$]*"),"Invalid label: "+key);return (String)v;}
}
