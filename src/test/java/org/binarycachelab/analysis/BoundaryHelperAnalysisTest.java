package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;

public final class BoundaryHelperAnalysisTest {
    private static int checks;
    private record Fixture(byte[] raw,String text,int branchOffset){}
    public static void main(String[] args)throws Exception{
        Path file=Files.createTempFile("bcl-boundary-helper-",".elf");Fixture fixture=fixture(false,false,false,false);Files.write(file,fixture.raw);
        var result=BoundaryHelperAnalysis.analyze(file,fixture.text,0x400538,8);
        check(Boolean.TRUE.equals(result.get("all_candidate_paths_checked")),"Equal boundary compare not resolved locally");
        Map<?,?> path=(Map<?,?>)((List<?>)result.get("paths")).get(0);
        check(((Map<?,?>)path.get("boundary_values_live_at_return")).keySet().equals(Set.of("rax","rdi")),"Live address registers lost");
        check(Boolean.FALSE.equals(path.get("selected_region_dereferenced_on_checked_path"))&&Boolean.FALSE.equals(path.get("external_call_or_jump_on_checked_path")),"Local path side effects incorrect");
        check(((List<?>)result.get("covered_lea_ips")).size()==2,"Boundary LEA coverage incomplete");
        check(Boolean.FALSE.equals(result.get("automatic_rewrite_allowed")),"Local path analysis authorized general rewriting");
        fixture=fixture(true,false,false,false);Files.write(file,fixture.raw);result=BoundaryHelperAnalysis.analyze(file,fixture.text,0x400538,8);
        check(Boolean.TRUE.equals(result.get("all_candidate_paths_checked")),"Zero-sized table arithmetic not resolved");
        path=(Map<?,?>)((List<?>)result.get("paths")).get(0);Map<?,?> returned=(Map<?,?>)path.get("known_registers_at_return");
        check(returned.get("rax").equals(0L)&&returned.get("rsi").equals(0L),"Shift/subtract/add arithmetic incorrect");
        check(((Map<?,?>)path.get("boundary_values_live_at_return")).keySet().equals(Set.of("rdi")),"Arithmetic helper live pointer omitted");
        for(int mode=0;mode<3;mode++){fixture=fixture(false,mode==0,mode==1,mode==2);Files.write(file,fixture.raw);
            result=BoundaryHelperAnalysis.analyze(file,fixture.text,0x400538,8);check(Boolean.FALSE.equals(result.get("all_candidate_paths_checked")),"Changed address/call/loop incorrectly approved");}
        fixture=fixture(false,false,false,false);Files.write(file,fixture.raw);
        String mislabeled=fixture.text.replace("# table_end","# unrelated_name");
        check(Boolean.TRUE.equals(BoundaryHelperAnalysis.analyze(file,mislabeled,0x400538,8).get("all_candidate_paths_checked")),"Analysis depends on untrusted symbol comments");
        final Fixture valid=fixture;byte[] changed=fixture.raw.clone();changed[0x200]=0x49;Files.write(file,changed);
        reject(()->BoundaryHelperAnalysis.analyze(file,valid.text,0x400538,8));
        Files.write(file,fixture.raw);String missing=fixture.text.replaceAll("(?m)^.* c3  ret\\n?","");
        check(Boolean.FALSE.equals(BoundaryHelperAnalysis.analyze(file,missing,0x400538,8).get("all_candidate_paths_checked")),"Missing return row incorrectly resolved");
        System.out.println("All "+checks+" boundary-helper byte-path checks passed.");
    }
    private static Fixture fixture(boolean arithmetic,boolean unequal,boolean external,boolean loop){
        byte[] raw=new byte[4096];ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;b.putShort(16,(short)3).putShort(18,(short)62).putInt(20,1).putLong(32,64).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)1);
        b.putInt(64,1).putInt(68,5).putLong(72,0).putLong(80,0x400000).putLong(96,raw.length).putLong(104,raw.length);
        StringBuilder text=new StringBuilder();byte[] read=HexFormat.of().parseHex("8b0500000000");ByteBuffer.wrap(read).order(ByteOrder.LITTLE_ENDIAN).putInt(2,0x400538-0x400106);
        emit(raw,text,0x100,read,"mov eax,DWORD PTR [rip+0x432]");
        byte[] first=lea(0x3d,0x400200,0x400540),second=lea(arithmetic?0x35:5,0x400207,unequal?0x400548:0x400540);
        emit(raw,text,0x200,first,"lea rdi,[rip+0x339] # table_end");
        emit(raw,text,0x207,second,"lea "+(arithmetic?"rsi":"rax")+",[rip+0x"+Long.toHexString((unequal?0x400548:0x400540)-0x40020e)+"] # table_end");
        int at=0x20e;String[] body=arithmetic?new String[]{"4829fe","4889f0","48c1ee3f","48c1f803","4801c6","48d1fe"}:new String[]{"4839f8"};
        for(String hex:body){byte[] code=HexFormat.of().parseHex(hex);emit(raw,text,at,code,"checked_register_operation");at+=code.length;}
        int branch=at;emit(raw,text,at,new byte[]{0x74,(byte)(loop?-2:1)},"je "+Long.toHexString(0x400000L+at+(loop?0:3)));at+=2;
        emit(raw,text,at++,new byte[]{(byte)0xcc},"int3");emit(raw,text,at,external?new byte[]{(byte)0xff,(byte)0xd0}:new byte[]{(byte)0xc3},external?"call rax":"ret");
        return new Fixture(raw,text.toString(),branch);
    }
    private static byte[] lea(int modrm,long ip,long target){byte[] code={0x48,(byte)0x8d,(byte)modrm,0,0,0,0};ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN).putInt(3,(int)(target-ip-7));return code;}
    private static void emit(byte[] raw,StringBuilder text,int offset,byte[] code,String instruction){System.arraycopy(code,0,raw,offset,code.length);
        text.append(Long.toHexString(0x400000L+offset)).append(": ").append(HexFormat.ofDelimiter(" ").formatHex(code)).append("  ").append(instruction).append('\n');}
    private interface Checked{void run()throws Exception;}
    private static void reject(Checked task){try{task.run();}catch(Exception expected){checks++;return;}throw new AssertionError("Expected byte binding rejection");}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);checks++;}
}
