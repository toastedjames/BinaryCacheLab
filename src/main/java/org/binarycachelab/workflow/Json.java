package org.binarycachelab.workflow;

import java.util.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.regex.Pattern;

/** Small strict JSON codec for versioned evidence; no third-party runtime dependency. */
public final class Json {
    private static final Pattern NUMBER=Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");
    private Json() {}
    public static String write(Object value) {
        if(value==null) return "null";
        if(value instanceof String s) {
            StringBuilder out=new StringBuilder("\"");
            for(char c:s.toCharArray()) switch(c) {
                case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n"); case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
                default -> { if(c<32) out.append(String.format("\\u%04x",(int)c)); else out.append(c); }
            }
            return out.append('"').toString();
        }
        if(value instanceof Double d && !Double.isFinite(d) || value instanceof Float f && !Float.isFinite(f))
            throw new IllegalArgumentException("Non-finite JSON number");
        if(value instanceof Boolean || value instanceof Number) return value.toString();
        if(value instanceof Map<?,?> m) return "{"+String.join(",",m.entrySet().stream()
            .map(e->write(e.getKey().toString())+":"+write(e.getValue())).toList())+"}";
        if(value instanceof Collection<?> a) return "["+String.join(",",a.stream().map(Json::write).toList())+"]";
        throw new IllegalArgumentException("Unsupported JSON value");
    }
    public static Object read(String text) { return parse(text,false); }
    /** Evidence viewers accept JSON timing decimals without widening integer-only analysis inputs. */
    public static Object readEvidence(String text) { return parse(text,true); }
    private static Object parse(String text,boolean evidence) { Parser p=new Parser(text,evidence); Object v=p.value(0); p.space();
        if(p.i!=text.length()) throw new IllegalArgumentException("Trailing JSON content"); return v; }
    @SuppressWarnings("unchecked") public static Map<String,Object> object(String text) {
        Object v=read(text); if(!(v instanceof Map)) throw new IllegalArgumentException("Expected JSON object");
        return (Map<String,Object>)v;
    }
    @SuppressWarnings("unchecked") public static Map<String,Object> evidenceObject(String text) {
        Object v=readEvidence(text);if(!(v instanceof Map))throw new IllegalArgumentException("Expected JSON object");
        return (Map<String,Object>)v;
    }
    private static final class Parser {
        final String s;final boolean evidence; int i; Parser(String s,boolean evidence) { this.s=s;this.evidence=evidence; }
        void space() { while(i<s.length() && " \n\r\t".indexOf(s.charAt(i))>=0) i++; }
        char next() { if(i>=s.length()) throw new IllegalArgumentException("Truncated JSON"); return s.charAt(i++); }
        void expect(char c) { space(); if(next()!=c) throw new IllegalArgumentException("Expected JSON '"+c+"'"); }
        Object value(int depth) {
            if(depth>64) throw new IllegalArgumentException("JSON nesting too deep"); space();
            if(i>=s.length()) throw new IllegalArgumentException("Missing JSON value"); char c=s.charAt(i);
            if(c=='"') return string();
            if(c=='{') { i++; Map<String,Object> m=new LinkedHashMap<>(); space();
                if(i<s.length() && s.charAt(i)=='}') {i++;return m;}
                do { space(); String key=string(); expect(':');
                    if(m.containsKey(key)) throw new IllegalArgumentException("Duplicate JSON key");
                    m.put(key,value(depth+1)); space(); c=next(); if(c=='}') return m;
                    if(c!=',') throw new IllegalArgumentException("Expected JSON comma"); } while(true);
            }
            if(c=='[') { i++; List<Object> a=new ArrayList<>(); space();
                if(i<s.length() && s.charAt(i)==']') {i++;return a;}
                do { a.add(value(depth+1)); space(); c=next(); if(c==']')return a;
                    if(c!=',')throw new IllegalArgumentException("Expected JSON comma"); }while(true);
            }
            for(String lit:List.of("true","false","null")) if(s.startsWith(lit,i)) {
                i+=lit.length(); return lit.equals("null")?null:lit.equals("true"); }
            var number=NUMBER.matcher(s);number.region(i,s.length());
            if(!number.lookingAt())throw new IllegalArgumentException("Invalid JSON number");
            String n=number.group();i=number.end();
            if(n.indexOf('.')>=0||n.indexOf('e')>=0||n.indexOf('E')>=0){
                if(!evidence)throw new IllegalArgumentException("Unsupported JSON number");return new BigDecimal(n);
            }
            try{return Long.parseLong(n);}catch(NumberFormatException overflow){if(!evidence)throw overflow;return new BigInteger(n);}
        }
        String string() {
            expect('"'); StringBuilder out=new StringBuilder();
            while(true) { char c=next(); if(c=='"')return out.toString();
                if(c<32)throw new IllegalArgumentException("Control character in JSON");
                if(c=='\\') { c=next(); switch(c) {
                    case '"','\\','/' -> out.append(c); case 'b' -> out.append('\b'); case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n'); case 'r' -> out.append('\r'); case 't' -> out.append('\t');
                    case 'u' -> { if(i+4>s.length())throw new IllegalArgumentException("Short JSON escape");
                        out.append((char)Integer.parseInt(s.substring(i,i+4),16));i+=4; }
                    default -> throw new IllegalArgumentException("Bad JSON escape");
                }} else out.append(c);
            }
        }
    }
}
