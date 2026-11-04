package org.binarycachelab.analysis;

import java.nio.*;
import java.util.*;
import org.binarycachelab.workflow.*;

public final class ReferenceCoverageTest {
    private static int checks;
    public static void main(String[] args)throws Exception{
        var direct=inspect("1150: 8b 05 22 2f 00 00 mov eax,DWORD PTR [rip+0x2f22]");
        check(((List<?>)direct.get("region_reference_candidates")).size()==1,"Direct region read missing");
        check(((List<?>)direct.get("hazards")).isEmpty(),"Ordinary direct read spuriously hazardous");
        check(Boolean.FALSE.equals(direct.get("safe_to_transform"))&&"INCONCLUSIVE_REFERENCE_COVERAGE".equals(direct.get("decision")),"A clean inventory incorrectly authorizes rewriting");
        hazard("1150: 48 8d 05 21 2f 00 00 lea rax,[rip+0x2f21]","REGION_ADDRESS_TAKEN_REQUIRES_REVIEW");
        hazard("1150: 48 8d 05 29 2f 00 00 lea rax,[rip+0x2f29]","REGION_END_ADDRESS_IDENTITY_UNRESOLVED");
        hazard("1150: b8 78 40 00 00 mov eax,0x4078","REGION_ADDRESS_IMMEDIATE_REQUIRES_REVIEW");
        hazard("1150: 48 b8 80 40 00 00 00 00 00 00 movabs rax,0x4080","REGION_ADDRESS_IMMEDIATE_REQUIRES_REVIEW");
        hazard("1150: 8b 04 25 78 40 00 00 mov eax,DWORD PTR [0x4078]","ABSOLUTE_REGION_REFERENCE_NOT_REBOUND");
        hazard("1150: 8b 04 85 78 40 00 00 mov eax,DWORD PTR [rax*4+0x4078]","INDEXED_REGION_ADDRESS_REQUIRES_REVIEW");
        hazard("1150: 8b 05 27 2f 00 00 mov eax,DWORD PTR [rip+0x2f27]","ACCESS_CROSSES_REGION_BOUNDARY");
        hazard("1150: 89 05 22 2f 00 00 mov DWORD PTR [rip+0x2f22],eax","UNSUPPORTED_OR_CROSSING_DIRECT_REGION_REFERENCE");
        hazard("1150: 0f ff (bad)","UNSUPPORTED_INSTRUCTION_DECODING");
        hazard("1150: ?? unknown","UNSUPPORTED_INSTRUCTION_DECODING");
        hazard("1150: e9 23 2f 00 00 jmp 4078 <data>","CONTROL_FLOW_INTO_DECLARED_DATA");
        unresolved("1150: 8b 00 mov eax,DWORD PTR [rax]","REGISTER_OR_INDEXED_MEMORY_ALIAS_UNRESOLVED");
        unresolved("1150: 64 8b 00 mov eax,DWORD PTR fs:[rax]","SEGMENT_BASE_ADDRESS_UNRESOLVED");
        unresolved("1150: ff d0 call rax","INDIRECT_CONTROL_FLOW_TARGET");
        unresolved("1150: c3 ret","IMPLICIT_STACK_ADDRESS_AND_ALIAS");
        unresolved("1150: f3 a4 rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]","IMPLICIT_OR_REPEATED_MEMORY_ACCESSES");
        unresolved("1150: 0f 05 syscall","KERNEL_OR_EXCEPTION_SIDE_EFFECTS");
        check(((List<?>)inspect("1150: b8 01 00 00 00 mov eax,0x1 # 0x4078").get("region_reference_candidates")).isEmpty(),"Comments treated as address operands");
        var negative=inspect("4100: 8b 05 72 ff ff ff mov eax,DWORD PTR [rip+0xffffffffffffff72]");
        check(((List<?>)negative.get("hazards")).isEmpty()&&((List<?>)negative.get("region_reference_candidates")).size()==1,"Signed RIP displacement mishandled");
        byte[] raw=ToolkitEvidenceTest.elf();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x301,0x400340);
        var metadata=ElfMetadata.read(raw).audit(0x400338,8);check(((List<?>)metadata.get("stored_pointer_candidates")).stream().anyMatch(x->((Map<?,?>)x).get("classification").toString().contains("ONE_PAST")),"One-past pointer omitted");
        raw=ToolkitEvidenceTest.elf();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putLong(0x390,0x400340);
        check(!((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("region_relocation_references")).isEmpty(),"One-past relocation omitted");
        raw=ToolkitEvidenceTest.elf();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(0x600+3*64+4,11);raw[0x200+24+4]=0x11;
        metadata=ElfMetadata.read(raw).audit(0x400338,8);check(ElfMetadata.detectedHazards(metadata).contains("DYNAMIC_SYMBOL_EXPOSURES_REQUIRE_REVIEW"),"Exported region symbol omitted");
        raw[0x200+24+5]=2;check(((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("dynamic_symbol_exposures")).isEmpty(),"Hidden symbol treated as externally exposed");
        var base=new LinkedHashMap<String,Object>();base.put("hazards",List.of());base.put("safe_to_transform",false);base.put("automatic_rewrite_allowed",false);
        var combined=EligibilityAssessment.withReferences(base,inspect("1150: b8 78 40 00 00 mov eax,0x4078"));
        check(Boolean.FALSE.equals(combined.get("research_fixture_checks_passed"))&&combined.get("decision").toString().startsWith("REJECTED"),"Known address hazard did not reject experiment");
        check(((List<?>)inspect("1150: c3 ret").get("hazards")).contains("NO_SUPPORTED_DECLARED_DIRECT_READS"),"Missing declared reads accepted");
        base.put("safe_to_transform",true);base.put("automatic_rewrite_allowed",true);
        combined=EligibilityAssessment.withReferences(base,direct);check(Boolean.FALSE.equals(combined.get("safe_to_transform"))&&Boolean.FALSE.equals(combined.get("automatic_rewrite_allowed")),"Reference merge retained unsupported safe authorization");
        check(!((List<?>)ElfMetadata.read(ToolkitEvidenceTest.elf()).audit(0x400338,8).get("symbols_at_region_end")).isEmpty(),"Boundary symbol identity omitted");
        System.out.println("All "+checks+" reference coverage/eligibility checks passed.");
    }
    private static Map<String,Object> inspect(String row){return ReferenceCoverage.inspect(row,0x4078,8);}
    private static void hazard(String row,String code){check(((List<?>)inspect(row).get("hazards")).contains(code),"Missing hazard: "+code);}
    private static void unresolved(String row,String code){check(((Map<?,?>)inspect(row).get("unresolved_counts")).containsKey(code),"Missing obligation: "+code);}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);checks++;}
}
