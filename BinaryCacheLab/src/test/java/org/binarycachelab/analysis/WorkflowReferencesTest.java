package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;

public final class WorkflowReferencesTest {
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("workflow-references-");Map<String,Object> variants=new LinkedHashMap<>();int n=0;
        for(String name:List.of("original","baseline","transformed")){
            int code=0x100+32*n,data=0x538+64*n;n++;
            byte[] raw=new byte[4096];ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;b.putShort(16,(short)3).putShort(18,(short)62).putInt(20,1).putLong(32,64).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)1);
            b.putInt(64,1).putInt(68,5).putLong(72,0).putLong(80,0x400000).putLong(96,4096).putLong(104,4096);
            byte[] bytes=HexFormat.of().parseHex("85ff74078b0500000000c38b0500000000c3");System.arraycopy(bytes,0,raw,code,bytes.length);
            b.putInt(code+6,data+4-(code+10));b.putInt(code+13,data-(code+17));b.putInt(data,7).putInt(data+4,7);
            Path binary=root.resolve(name);Files.write(binary,raw);StringBuilder dis=new StringBuilder();
            int[] offsets={0,2,4,10,11,17},sizes={2,2,6,1,6,1};
            for(int i=0;i<offsets.length;i++){int at=code+offsets[i];String instruction=switch(i){case 0->"test edi,edi";case 1->"je 0x"+Integer.toHexString(0x400000+code+11);case 2,4->"mov eax,DWORD PTR [rip+0x"+Integer.toHexString(b.getInt(at+2))+"]";default->"ret";};
                dis.append(Integer.toHexString(0x400000+at)).append(": ").append(HexFormat.ofDelimiter(" ").formatHex(Arrays.copyOfRange(raw,at,at+sizes[i]))).append("  ").append(instruction).append('\n');}
            Path assembly=root.resolve(name+".txt");Files.writeString(assembly,dis.toString());
            variants.put(name,new LinkedHashMap<>(Map.of("binary",name,"disassembly",name+".txt","address",0x400000L+data,"size",8L,"entry",0x400000L+code)));
        }
        Path profile=root.resolve("profile.json");Map<String,Object> doc=Map.of("schema","bcl-workflow-kernel-references-1","contract",Map.of("immutable_region",true,"entry_stack","fixed-valid-return","execution","ordinary-x86-64"),"variants",variants);
        Files.writeString(profile,Json.write(doc));var result=WorkflowReferences.analyze(profile);
        if(!Boolean.TRUE.equals(result.get("verified")))throw new AssertionError(result);
        if(!"INCOMPLETE".equals(result.get("reference_coverage")))throw new AssertionError("Whole-program coverage invented");
        if(((List<?>)result.get("pairs")).size()!=3)throw new AssertionError("Missing reference pair");
        @SuppressWarnings("unchecked") var variant=(Map<String,Object>)variants.get("transformed");variant.put("entry",0x400141L);Files.writeString(profile,Json.write(doc));
        if(Boolean.TRUE.equals(WorkflowReferences.analyze(profile).get("verified")))throw new AssertionError("Wrong entry accepted");
        variant.put("entry",0x400140L);Files.writeString(profile,Json.write(doc));byte[] bad=Files.readAllBytes(root.resolve("transformed"));bad[0x142]=0x75;Files.write(root.resolve("transformed"),bad);
        if(Boolean.TRUE.equals(WorkflowReferences.analyze(profile).get("verified")))throw new AssertionError("Forged disassembly accepted");
        System.out.println("All 5 declared-kernel reference integration checks passed.");
    }
}
