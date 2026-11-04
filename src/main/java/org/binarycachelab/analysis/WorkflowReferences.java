package org.binarycachelab.analysis;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;
import static org.binarycachelab.workflow.LabConfig.require;

/** Reuses byte-verified direct reads and the exact existing two-path local contract. */
public final class WorkflowReferences {
    private WorkflowReferences(){}
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Object value){require(value instanceof Map,"Expected object");return (Map<String,Object>)value;}
    private static long number(Map<String,Object> row,String key){require(row.get(key) instanceof Long,"Require integer "+key);return ((Long)row.get(key));}
    public static Map<String,Object> analyze(Path profile)throws IOException {
        var doc=Json.object(Files.readString(profile));
        require(doc.keySet().equals(Set.of("schema","contract","variants")),"Invalid declared-kernel profile fields");
        require("bcl-workflow-kernel-references-1".equals(doc.get("schema")),"Unsupported declared-kernel profile");
        var contract=object(doc.get("contract"));
        require(contract.equals(Map.of("immutable_region",true,"entry_stack","fixed-valid-return","execution","ordinary-x86-64")),"Declare the complete local entry contract");
        Map<String,Object> checked=new LinkedHashMap<>();List<Map<String,Object>> pairs=new ArrayList<>();
        Map<String,Object> result=new LinkedHashMap<>();result.put("schema","bcl-workflow-kernel-reference-report-1");
        result.put("reference_coverage","INCOMPLETE");result.put("automatic_rewrite_allowed",false);result.put("contract",contract);
        result.put("variants",checked);result.put("pairs",pairs);
        result.put("scope","Declared two-path lookup kernel only: byte-verified reads, local integer ABI/return relation and all zero/nonzero selector classes. No complete aliases, caller reachability, loader, external-code or whole-program proof.");
        try {
            var variants=object(doc.get("variants"));require(variants.keySet().equals(Set.of("original","baseline","transformed")),"Require all three variants");
            for(String name:List.of("original","baseline","transformed")){
                var row=object(variants.get(name));require(row.keySet().equals(Set.of("binary","disassembly","address","size","entry")),"Invalid variant fields");
                Path binary=profile.toAbsolutePath().getParent().resolve((String)row.get("binary"));
                Path disassembly=profile.toAbsolutePath().getParent().resolve((String)row.get("disassembly"));
                require(Files.size(disassembly)<=32*1024*1024,"Disassembly exceeds local analysis bound");
                long address=number(row,"address"),size=number(row,"size");require(size==8,"This exact local contract supports one 8-byte group");
                var audit=ElfRegionAudit.audit(binary,address,size);
                require(audit.relocations().stream().noneMatch(r->r.writeOverlap()||r.width()<0),"Region relocation writes are unsupported");
                String text=Files.readString(disassembly);var reads=LinkedReadVerification.verify(binary,text,address,size);
                require(audit.sha256().equals(reads.get("binary_sha256")),"Executable changed during reference verification");
                var kernel=LinkedReadVerification.lookupKernel(text,reads);
                require(number(kernel,"entry_at_test_edi")==number(row,"entry"),"Verified kernel is not the declared function entry");
                require(Set.of(number(kernel,"zero_offset"),number(kernel,"nonzero_offset")).equals(Set.of(0L,4L)),"Expected the two distinct declared DWORDs");
                checked.put(name,Map.of("binary_sha256",audit.sha256(),"region_sha256",audit.regionSha256(),"reads",reads,"kernel",kernel));
            }
            for(String[] pair:List.of(new String[]{"original","baseline"},new String[]{"baseline","transformed"},new String[]{"original","transformed"})){
                var a=object(checked.get(pair[0]));var b=object(checked.get(pair[1]));
                var sites=LinkedReadVerification.correspond(object(a.get("reads")),object(b.get("reads")));
                require(Boolean.TRUE.equals(sites.get("all_sites_unique")),"Ambiguous direct-read correspondence");
                var kernel=LinkedReadVerification.compareKernels(object(a.get("kernel")),object(b.get("kernel")),a.get("region_sha256").equals(b.get("region_sha256")));
                pairs.add(Map.of("left",pair[0],"right",pair[1],"access_correspondence",sites,"local_contract",kernel));
            }
            result.put("status","DECLARED_KERNEL_REFERENCES_VERIFIED");result.put("verified",true);
        }catch(IllegalArgumentException error){result.put("status","UNSUPPORTED");result.put("verified",false);result.put("reason",error.getMessage());}
        return result;
    }
}
