package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.binarycachelab.analysis.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Required callback roots and link metadata; never asserts callback semantic equivalence. */
public final class CallbackLiftPlan {
    private final Map<String,Object> inventory;
    private final Map<String,Long> symbols;
    private final Map<Long,String> roots=new TreeMap<>();
    public CallbackLiftPlan(Path original)throws IOException{this(ElfCallbackInventory.analyze(original),ElfMetadata.read(original).executableSymbols());}
    CallbackLiftPlan(Map<String,Object> inventory,Map<String,Long> symbols){
        this.inventory=inventory;this.symbols=Map.copyOf(symbols);
        require(((List<?>)inventory.get("issues")).isEmpty(),"Unsupported callback inventory: "+inventory.get("issues"));
        for(Object item:(List<?>)inventory.get("callbacks")){Map<?,?> callback=(Map<?,?>)item;
            require(callback.get("target") instanceof Number&&Boolean.TRUE.equals(callback.get("target_in_executable_file_mapping")),"Unresolved callback root: "+callback);
            long target=((Number)callback.get("target")).longValue();String source=(String)callback.get("source");
            String preferred=source.equals("DT_INIT")?"_init":source.equals("DT_FINI")?"_fini":null;
            List<String> names=symbols.entrySet().stream().filter(e->e.getValue()==target&&e.getKey().matches("[A-Za-z_][A-Za-z0-9_.$]*")).map(Map.Entry::getKey).sorted().toList();
            require(!names.isEmpty(),"Callback root lacks a supported executable symbol at 0x"+Long.toHexString(target));
            if(preferred!=null)require(Objects.equals(symbols.get(preferred),target),"Callback entry requires explicit symbol mapping: "+source);
            String chosen=preferred!=null?preferred:names.get(0);
            require(!roots.containsKey(target)||roots.get(target).equals(chosen),"Shared callback entry has conflicting symbol mappings");
            roots.put(target,chosen);
        }
    }
    public String entries(){StringBuilder out=new StringBuilder();for(long root:roots.keySet())out.append("0x").append(Long.toHexString(root)).append('\n');return out.toString();}
    public void validateAssembly(String assembly){
        for(String name:roots.values()){
            Matcher definition=Pattern.compile("(?m)^\\s*"+Pattern.quote(name)+":\\s*(?:;[^\\r\\n]*)?$").matcher(assembly);
            int count=0;while(definition.find())count++;
            require(count==1,"Missing/duplicate lifted callback definition: "+name+"; a global declaration alone is insufficient");
        }
    }
    public List<String> linkerArguments(){List<String> args=new ArrayList<>();
        for(Object item:(List<?>)inventory.get("callbacks")){String source=(String)((Map<?,?>)item).get("source");
            if(source.equals("DT_INIT"))args.add("-Wl,-init,_init");if(source.equals("DT_FINI"))args.add("-Wl,-fini,_fini");}
        return List.copyOf(args);
    }
    public Map<String,Object> manifest(){List<Map<String,Object>> entries=new ArrayList<>();roots.forEach((ip,name)->entries.add(Map.of("original_entry",ip,"symbol",name)));
        List<Map<String,Object>> slots=new ArrayList<>();
        for(Object item:(List<?>)inventory.get("callbacks")){Map<?,?> callback=(Map<?,?>)item;
            if(callback.get("slot") instanceof Number slot){long target=((Number)callback.get("target")).longValue();
                slots.add(Map.of("source",callback.get("source"),"index",callback.get("index"),"slot",slot.longValue(),
                    "original_target",target,"symbol",roots.get(target)));}}
        return Map.of("schema","java-callback-lift-plan-1","original_binary_sha256",inventory.get("binary_sha256"),"required_roots",entries,
            "array_slots",slots,"linker_arguments",linkerArguments(),"callback_semantics_proved",false,"automatic_rewrite_allowed",false);
    }
    public Map<String,Object> verifyLinked(Path rebuilt)throws IOException{
        return verifyInventory(ElfCallbackInventory.analyze(rebuilt),ElfMetadata.read(rebuilt).executableSymbols());
    }
    Map<String,Object> verifyInventory(Map<String,Object> rebuilt,Map<String,Long> linkedSymbols){
        require(((List<?>)rebuilt.get("issues")).isEmpty(),"Unsupported final callback inventory");
        var comparison=ElfCallbackInventory.compareSources(inventory,rebuilt);
        require(((List<?>)comparison.get("differences")).isEmpty(),"Final callback source counts differ from original");
        List<Map<String,Object>> mappings=new ArrayList<>();List<?> actual=(List<?>)rebuilt.get("callbacks");
        for(Object item:(List<?>)inventory.get("callbacks")){Map<?,?> original=(Map<?,?>)item;String source=(String)original.get("source");
            long target=((Number)original.get("target")).longValue();String name=roots.get(target);Long expected=linkedSymbols.get(name);
            require(expected!=null,"Missing final callback code symbol: "+name);
            List<?> candidates=actual.stream().filter(x->{Map<?,?> row=(Map<?,?>)x;return source.equals(row.get("source"))&&Objects.equals(original.get("index"),row.get("index"));}).toList();
            require(candidates.size()==1,"Ambiguous final callback slot");Map<?,?> row=(Map<?,?>)candidates.get(0);
            require(row.get("target") instanceof Number&&((Number)row.get("target")).longValue()==expected&&Boolean.TRUE.equals(row.get("target_in_executable_file_mapping")),"Final callback does not point to expected executable symbol: "+name);
            mappings.add(Map.of("source",source,"original_entry",target,"rebuilt_entry",expected,"symbol",name));
        }
        return Map.of("schema","java-callback-link-check-1","status","CALLBACK_ENTRY_MAPPING_CHECKED","mappings",mappings,
            "callback_semantics_proved",false,"automatic_rewrite_allowed",false);
    }
}
