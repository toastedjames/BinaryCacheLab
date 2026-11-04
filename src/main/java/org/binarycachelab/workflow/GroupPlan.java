package org.binarycachelab.workflow;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Restricted two-adjacent-literal-span layout planner. Does not certify reference coverage. */
public final class GroupPlan {
    public final String first,second,end;
    public final long address,firstBytes,secondBytes,shift;
    public GroupPlan(LabConfig c) {
        first=c.string("region.first");second=c.string("region.second");end=c.string("region.end");
        address=c.number("region.address");firstBytes=c.number("region.first_bytes");secondBytes=c.number("region.second_bytes");shift=c.number("region.shift");
        require(List.of(first,second,end).stream().allMatch(s->s.matches("[A-Za-z_][A-Za-z0-9_.$]*")),"Unsupported label name");
        require(new HashSet<>(List.of(first,second,end)).size()==3,"Region labels must be distinct");
        require(firstBytes>0 && secondBytes>0 && firstBytes<=64 && secondBytes<=64,"Require spans of 1..64 bytes");
        require(address>=0 && address<=Long.MAX_VALUE-128,"Unsupported region address");
        require(address/64==(address+firstBytes+secondBytes-1)/64,"Original group must fit inside one 64-byte line");
        require(shift>0 && shift<64,"Shift must be 1..63 bytes");
        require((address+shift)/64!=(address+firstBytes+shift)/64,"Shift does not make the selected span starts cross a line");
    }
    public long size(){return firstBytes+secondBytes;}
    public String shifted(String text) {validateAssembly(text);return insert(text,"; BCL deliberate layout control\ntimes "+shift+" db 0\n");}
    public String protectedAssembly(String text) {return insert(shifted(text),
        "; BCL java-group-layout-v1\nalign 64, db 0\ntimes "+(address%64)+" db 0\n");}
    private String insert(String text,String prefix) {
        List<String> lines=new ArrayList<>(Arrays.asList(text.replace("\r\n","\n").split("\n",-1)));
        int at=-1;for(int i=0;i<lines.size();i++)if(lines.get(i).trim().equals(first+":"))at=i;
        require(at>=0,"Missing first label");lines.add(at,prefix.stripTrailing());return String.join("\n",lines);
    }
    public String regionHash(String text) {return hash(validateAssembly(text));}
    public byte[] validateAssembly(String text) {
        require(!text.contains("BCL java-group-layout-v1")&&!text.contains("BCL deliberate layout control"),"Policy already applied");
        String[] lines=text.replace("\r\n","\n").split("\n");int a=-1,b=-1,z=-1;String section="";String enclosing="";
        for(int i=0;i<lines.length;i++) {String s=lines[i].split(";",2)[0].trim();
            require(!s.startsWith("%")&&!s.matches("(?i)^(org|absolute|struc)\\b.*"),"Preprocessor/address context unsupported");
            if(s.matches("(?i)^(section|segment)\\s+.*"))section=s;
            if(lines[i].trim().equals(first+":")){require(a<0,"Duplicate first label");a=i;enclosing=section;}
            if(lines[i].trim().equals(second+":")){require(b<0,"Duplicate second label");b=i;}
            if(lines[i].trim().equals(end+":")){require(z<0,"Duplicate end label");z=i;}
        }
        require(a>=0 && b>a && z>b,"Require unique ordered standalone region labels");
        require(enclosing.matches("(?i)section\\s+\\.data\\s+align=([0-9]+)"),"Require explicit section .data align=N");
        long align=Long.parseLong(enclosing.substring(enclosing.indexOf('=')+1));
        require(align>=64 && (align&(align-1))==0,"Data section alignment must be power-of-two >=64");
        var bytes=new java.io.ByteArrayOutputStream();int split=-1;
        for(int i=a+1;i<z;i++){if(i==b){split=bytes.size();continue;}String code=lines[i].split(";",2)[0].trim();if(code.isEmpty())continue;
            require(code.matches("(?i)db\\s+[0-9a-f]{1,2}h"),"Group contains nonliteral bytes or undeclared labels");
            bytes.write(Integer.parseInt(code.replaceFirst("(?i)^db\\s+","").replaceFirst("(?i)h$",""),16));}
        require(split==firstBytes && bytes.size()==size(),"Declared group sizes disagree with assembly");
        references(text);return bytes.toByteArray();
    }
    public List<Map<String,Object>> references(String text){
        List<Map<String,Object>> rows=new ArrayList<>();String[] lines=text.split("\\R");
        for(int i=0;i<lines.length;i++){
            String code=lines[i].split(";",2)[0].trim();
            for(String label:List.of(first,second,end)){
                String quoted=java.util.regex.Pattern.quote(label);
                if(!java.util.regex.Pattern.compile("(?<![A-Za-z0-9_.$])"+quoted+"(?![A-Za-z0-9_.$])").matcher(code).find())continue;
                if(code.equals(label+":"))continue;
                require(!label.equals(end),"Region-end address-taking/reference is unsupported at assembly line "+(i+1));
                var match=java.util.regex.Pattern.compile("(?i)^(MOV|MOVZX|MOVSX)\\s+[A-Z][A-Z0-9]*\\s*,\\s*(byte|word|dword|qword)\\s*\\[\\s*"+quoted+"\\s*\\]$").matcher(code);
                require(match.matches(),"Unsupported named region reference at assembly line "+(i+1)+": "+code);
                int width=switch(match.group(2).toLowerCase(Locale.ROOT)){case "byte"->1;case "word"->2;case "dword"->4;default->8;};
                require(width<=(label.equals(first)?firstBytes:secondBytes),"Named region access crosses its declared span at assembly line "+(i+1));
                rows.add(Map.of("symbol",label,"assembly_line",i+1,"width_bytes",width,"instruction",code));
            }
        }return List.copyOf(rows);
    }
    public Map<String,Object> manifest(String assembly) {
        var m=new LinkedHashMap<String,Object>();m.put("schema","java-group-plan-1");m.put("policy","preserve-group-line-residue");
        m.put("region_symbols",List.of(first,second,end));m.put("original_address",address);m.put("region_bytes",size());
        m.put("required_line_residue",address%64);m.put("line_bytes",64);m.put("control_shift_bytes",shift);
        m.put("region_sha256",regionHash(assembly));m.put("reference_coverage","INCOMPLETE");m.put("automatic_rewrite_allowed",false);
        m.put("named_direct_read_inventory",references(assembly));
        m.put("reason","Keep the declared adjacent bytes and line partition together by alignment and original residue; validate final linked addresses.");
        m.put("assumptions",List.of("Explicit research fixture: only classified named direct reads; raw/computed pointers and complete reference coverage not proved",
            "64-byte ordered virtual data-line observer; not cache-set identity or physical-cache security",
            "Protected relationship verified only for declared region; outside-object interactions require empirical checks"));return m;
    }
    public static String hash(byte[] bytes) {try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(Exception e){throw new IllegalStateException(e);}}
}
