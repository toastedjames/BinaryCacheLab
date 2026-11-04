package org.binarycachelab.workflow;

import java.util.*;

public final class CallbackLiftPlanTest {
    private static int checks;
    private static Map<String,Object> row(String source,long address){return Map.of("source",source,"target",address,"target_in_executable_file_mapping",true);}
    private static Map<String,Object> inventory(List<Map<String,Object>> rows){return Map.of("callbacks",rows,"issues",List.of(),"binary_sha256","fixture");}
    public static void main(String[] args){
        var original=inventory(List.of(row("DT_INIT",0x1000),row("DT_FINI",0x1100)));
        var plan=new CallbackLiftPlan(original,Map.of("_init",0x1000L,"_fini",0x1100L));
        check(plan.entries().equals("0x1000\n0x1100\n"),"Callback roots require explicit hexadecimal prefixes");
        var wirePlan=new CallbackLiftPlan(inventory(List.of(row("DT_INIT",0x1000),row("DT_FINI",0x11b8),row("DT_INIT_ARRAY",0x1140))),Map.of("_init",0x1000L,"_fini",0x11b8L,"frame_dummy",0x1140L));
        var parsed=wirePlan.entries().lines().map(line->Long.parseLong(line.substring(2),16)).toList();
        check(parsed.equals(List.of(0x1000L,0x1140L,0x11b8L)),"Prefix-consuming reader changes callback addresses");
        check(plan.linkerArguments().equals(List.of("-Wl,-init,_init","-Wl,-fini,_fini")),"Missing explicit linker entry arguments");
        plan.validateAssembly("global _init\nglobal _fini\n_init:\n ret\n_fini:\n ret\n");checks++;
        reject(()->plan.validateAssembly("global _init\nglobal _fini\n"));
        reject(()->plan.validateAssembly("_init:\n ret\n; _fini:\n"));
        reject(()->plan.validateAssembly("_init:\n_init:\n_fini:\n"));
        reject(()->plan.validateAssembly("_init_other:\n_fini:\n"));
        var linked=inventory(List.of(row("DT_INIT",0x2000),row("DT_FINI",0x2100)));
        var checked=plan.verifyInventory(linked,Map.of("_init",0x2000L,"_fini",0x2100L));
        check(checked.get("status").equals("CALLBACK_ENTRY_MAPPING_CHECKED"),"Valid final mapping rejected");
        check(Boolean.FALSE.equals(checked.get("callback_semantics_proved"))&&Boolean.FALSE.equals(checked.get("automatic_rewrite_allowed")),"Entry mapping asserted semantic safety");
        reject(()->plan.verifyInventory(inventory(List.of(row("DT_INIT",0x2000))),Map.of("_init",0x2000L,"_fini",0x2100L)));
        reject(()->plan.verifyInventory(linked,Map.of("_init",0x2001L,"_fini",0x2100L)));
        reject(()->plan.verifyInventory(linked,Map.of("_init",0x2000L)));
        reject(()->new CallbackLiftPlan(original,Map.of("wrong",0x1000L,"_fini",0x1100L)));
        reject(()->new CallbackLiftPlan(original,Map.of("_init",0x999L,"_fini",0x1100L)));
        reject(()->new CallbackLiftPlan(Map.of("callbacks",List.of(),"issues",List.of("REL_UNSUPPORTED")),Map.of()));
        reject(()->new CallbackLiftPlan(inventory(List.of(Map.of("source","DT_INIT","resolution","UNRESOLVED"))),Map.of()));
        reject(()->new CallbackLiftPlan(inventory(List.of(Map.of("source","DT_INIT","target",0x1000L,"target_in_executable_file_mapping",false))),Map.of("_init",0x1000L)));
        var array0=new LinkedHashMap<>(row("DT_INIT_ARRAY",0x1200));array0.put("index",0);array0.put("slot",0x3000L);
        var array1=new LinkedHashMap<>(row("DT_INIT_ARRAY",0x1300));array1.put("index",1);array1.put("slot",0x3008L);
        var arrays=new CallbackLiftPlan(inventory(List.of(array0,array1)),Map.of("first",0x1200L,"second",0x1300L));
        check(arrays.linkerArguments().isEmpty(),"Invented DT_INIT/FINI for array-only input");
        var slots=(List<?>)arrays.manifest().get("array_slots");
        check(slots.size()==2,"Callback plan lost array slots");
        check(((Map<?,?>)slots.get(0)).get("slot").equals(0x3000L)&&((Map<?,?>)slots.get(0)).get("symbol").equals("first"),"Wrong first slot mapping");
        check(((Map<?,?>)slots.get(1)).get("original_target").equals(0x1300L),"Wrong original callback target");
        var swapped0=new LinkedHashMap<>(row("DT_INIT_ARRAY",0x2300));swapped0.put("index",0);
        var swapped1=new LinkedHashMap<>(row("DT_INIT_ARRAY",0x2200));swapped1.put("index",1);
        reject(()->arrays.verifyInventory(inventory(List.of(swapped0,swapped1)),Map.of("first",0x2200L,"second",0x2300L)));
        var empty=new CallbackLiftPlan(inventory(List.of()),Map.of());
        check(empty.entries().isEmpty()&&empty.linkerArguments().isEmpty(),"Empty callback inventory invented roots");
        System.out.println("All "+checks+" callback lift/link plan checks passed.");
    }
    private interface Checked{void run();}
    private static void reject(Checked action){try{action.run();}catch(IllegalArgumentException expected){checks++;return;}throw new AssertionError("Expected rejection");}
    private static void check(boolean value,String label){if(!value)throw new AssertionError(label);checks++;}
}
