package org.binarycachelab.workflow;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Strict documented TOML subset: sections, strings, booleans and positive integers. */
public final class LabConfig {
    public static final Set<String> KEYS=Set.of("schema","project.output","input.original","input.assembly",
        "input.helper","tools.python","tools.backend","tools.pin","tools.tracer","tools.tracer_source",
        "region.first","region.second","region.end","region.address","region.first_bytes","region.second_bytes",
        "region.shift","experiment.repetitions","experiment.timeout","experiment.eager_binding",
        "experiment.research_mode","lift.enabled","lift.image","lift.timeout","observation.model","observation.line_bytes","tools.docker","tools.docker_sudo");
    public final Path file;
    public final Map<String,Object> values;
    private LabConfig(Path file,Map<String,Object> values) {this.file=file.toAbsolutePath().normalize();this.values=Map.copyOf(values);}
    public static LabConfig load(Path file) throws IOException {return parse(file,Files.readString(file));}
    public static LabConfig parse(Path file,String text) {
        Map<String,Object> values=new LinkedHashMap<>(); Set<String> tables=new HashSet<>(); String section=""; int row=0;
        for(String line:text.split("\\R")) { row++; String code=stripComment(line).trim(); if(code.isEmpty())continue;
            if(code.matches("\\[[a-z_]+\\]")) {require(tables.add(code),"Duplicate TOML table: "+code);section=code.substring(1,code.length()-1)+".";continue;}
            int eq=code.indexOf('='); require(eq>0,"Invalid TOML row "+row);
            String key=section+code.substring(0,eq).trim(), raw=code.substring(eq+1).trim();
            require(KEYS.contains(key),"Unknown configuration key: "+key);
            Object value;
            if(raw.startsWith("\"")) {value=Json.read(raw);require(value instanceof String,"Require a string");}
            else if(raw.equals("true")||raw.equals("false"))value=Boolean.valueOf(raw);
            else {require(raw.matches("(0x[0-9a-fA-F]+|[0-9]+)"),"Unsupported TOML value at row "+row);value=Long.decode(raw.startsWith("0x")?raw:stripZeroes(raw));}
            require(values.putIfAbsent(key,value)==null,"Duplicate configuration key: "+key);
        }
        values.putIfAbsent("tools.docker","docker");values.putIfAbsent("tools.docker_sudo",false);
        require(values.keySet().containsAll(KEYS),"Missing configuration keys: "+difference(KEYS,values.keySet()));
        LabConfig c=new LabConfig(file,values);
        require(c.number("schema")==1,"Unsupported configuration schema");
        for(String key:List.of("project.output","input.original","input.assembly","input.helper","tools.python",
                "tools.backend","tools.pin","tools.tracer","tools.tracer_source","region.first","region.second","region.end"))c.string(key);
        c.bool("experiment.eager_binding");c.bool("experiment.research_mode");c.bool("lift.enabled");c.string("lift.image");
        c.string("tools.docker");c.bool("tools.docker_sudo");
        require(c.number("lift.timeout")>=1 && c.number("lift.timeout")<=7200,"Lift timeout must be 1..7200 seconds");
        require(c.string("observation.model").equals("ordered-raw-virtual-lines")&&c.number("observation.line_bytes")==64,
            "Only ordered-raw-virtual-lines with 64-byte lines is supported by this policy");
        require(c.number("experiment.repetitions")>=2 && c.number("experiment.repetitions")<=20,"Repetitions must be 2..20");
        require(c.number("experiment.timeout")>=1 && c.number("experiment.timeout")<=3600,"Timeout must be 1..3600 seconds");
        new GroupPlan(c); return c;
    }
    private static String stripZeroes(String s) {return s.replaceFirst("^0+(?!$)","");}
    private static Set<String> difference(Set<String>a,Set<String>b) {var d=new TreeSet<>(a);d.removeAll(b);return d;}
    private static String stripComment(String s) {boolean quoted=false,escape=false;
        for(int i=0;i<s.length();i++){char c=s.charAt(i);if(escape){escape=false;continue;}
            if(quoted&&c=='\\'){escape=true;continue;}if(c=='"')quoted=!quoted;if(c=='#'&&!quoted)return s.substring(0,i);}
        return s;}
    public String string(String key) {Object v=values.get(key);require(v instanceof String && !((String)v).isBlank(),"Require nonempty string: "+key);return (String)v;}
    public long number(String key) {Object v=values.get(key);require(v instanceof Long,"Require integer: "+key);return (Long)v;}
    public boolean bool(String key) {Object v=values.get(key);require(v instanceof Boolean,"Require boolean: "+key);return (Boolean)v;}
    public Path path(String key) {String s=string(key);if(s.startsWith("~/"))s=System.getProperty("user.home")+s.substring(1);
        Path p=Paths.get(s);return (p.isAbsolute()?p:file.getParent().resolve(p)).normalize();}
    public LabConfig withAssembly(Path assembly){Map<String,Object> copy=new LinkedHashMap<>(values);
        copy.put("input.assembly",assembly.toAbsolutePath().normalize().toString());return new LabConfig(file,copy);}
    public void edit(String key,String literal) throws IOException {
        require(KEYS.contains(key),"Unknown key");String old=Files.readString(file); String section="";List<String> lines=new ArrayList<>();
        boolean edited=false;
        for(String line:old.split("\\R")) {String code=stripComment(line).trim();
            if(code.matches("\\[[a-z_]+\\]"))section=code.substring(1,code.length()-1)+".";
            int eq=code.indexOf('=');if(eq>0 && (section+code.substring(0,eq).trim()).equals(key)){
                line=code.substring(0,eq).trim()+" = "+literal;edited=true;}
            lines.add(line);
        }
        if(!edited){int dot=key.lastIndexOf('.');String table=dot<0?"":"["+key.substring(0,dot)+"]";
            for(int i=0;i<lines.size();i++)if(stripComment(lines.get(i)).trim().equals(table)){lines.add(i+1,key.substring(dot+1)+" = "+literal);edited=true;break;}
            if(!edited)lines.add(0,key+" = "+literal);
        }
        String next=String.join("\n",lines)+"\n";parse(file,next); // validate the whole result before saving
        Path backup=file.resolveSibling(file.getFileName()+".backup-"+UUID.randomUUID());Files.copy(file,backup);
        Files.writeString(file,next);
    }
    public static void require(boolean ok,String message) {if(!ok)throw new IllegalArgumentException(message);}
}
