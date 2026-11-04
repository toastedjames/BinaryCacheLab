package org.binarycachelab.analysis;

import java.nio.*;
import java.util.*;

public final class ElfCallbackInventoryTest {
    private static int checks;
    static byte[] fixture(){
        byte[] raw=new byte[4096];ByteBuffer b=buffer(raw);b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;
        b.putShort(16,(short)3).putShort(18,(short)62).putInt(20,1).putLong(32,64).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)2);
        b.putInt(64,1).putInt(68,5).putLong(72,0).putLong(80,0x400000).putLong(96,raw.length).putLong(104,raw.length);
        b.putInt(120,2).putInt(124,6).putLong(128,0x200).putLong(136,0x400200).putLong(152,0x100).putLong(160,0x100);
        long[][] tags={{25,0x400500},{27,8},{26,0x400508},{28,8},{7,0x400400},{8,48},{9,24},{0,0}};
        for(int i=0;i<tags.length;i++)b.putLong(0x200+i*16,tags[i][0]).putLong(0x208+i*16,tags[i][1]);
        b.putLong(0x400,0x400500).putLong(0x408,8).putLong(0x410,0x400600);
        b.putLong(0x418,0x400508).putLong(0x420,8).putLong(0x428,0x400610);
        b.putLong(0x500,0xdead).putLong(0x508,0xbeef);raw[0x600]=(byte)0xc3;raw[0x610]=(byte)0xc3;return raw;
    }
    static ByteBuffer buffer(byte[] raw){return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);}
    static byte[] copyFixture(long site,long size){
        byte[] raw=fixture();ByteBuffer b=buffer(raw);b.putInt(68,7).putLong(0x258,72);
        b.putLong(0x270,6).putLong(0x278,0x400700).putLong(0x280,11).putLong(0x288,24);
        b.putLong(0x430,site).putLong(0x438,(1L<<32)|5).putLong(0x440,0);
        b.put(0x71c,(byte)0x11).putShort(0x71e,(short)1).putLong(0x720,site).putLong(0x728,size);
        return raw;
    }
    private static Map<?,?> first(byte[] raw){return (Map<?,?>)((List<?>)ElfCallbackInventory.analyze(raw).get("callbacks")).get(0);}
    public static void main(String[] args){
        byte[] raw=fixture();Map<String,Object> report=ElfCallbackInventory.analyze(raw);Map<?,?> row=first(raw);
        check(((List<?>)report.get("callbacks")).size()==2,"Missing callback array entries");
        check(row.get("target").equals(0x400600L),"Must use RELA addend, not stale file pointer");
        check(Boolean.TRUE.equals(row.get("target_in_executable_file_mapping")),"Executable target not mapped");
        check(Boolean.FALSE.equals(report.get("runtime_callback_contract_proved"))&&Boolean.FALSE.equals(report.get("automatic_rewrite_allowed")),"Callback inventory authorized rewrite");
        Map<String,Object> same=ElfCallbackInventory.compareSources(report,report);
        check(((List<?>)same.get("differences")).isEmpty()&&Boolean.FALSE.equals(same.get("startup_shutdown_equivalence_proved")),"Matching counts treated as semantic proof");
        raw=fixture();buffer(raw).putLong(0x270,12).putLong(0x278,0x400600);
        Map<String,Object> changed=ElfCallbackInventory.compareSources(ElfCallbackInventory.analyze(raw),report);
        check(changed.get("status").equals("CALLBACK_METADATA_DIFF_REVIEW_REQUIRED")&&((List<?>)changed.get("differences")).size()==1,"Missing DT_INIT not detected");
        raw=fixture();buffer(raw).putLong(0x408,6);check(!first(raw).containsKey("target"),"Symbol relocation assumed relative");
        raw=fixture();buffer(raw).putLong(0x408,(1L<<32)|8);check(!first(raw).containsKey("target"),"Relative relocation with symbol accepted");
        raw=fixture();buffer(raw).putLong(0x418,0x400504);check(!first(raw).containsKey("target"),"Overlapping slot relocation accepted");
        raw=fixture();buffer(raw).putLong(0x418,0x400500);check(!first(raw).containsKey("target"),"Duplicate slot writes accepted");
        raw=fixture();buffer(raw).putLong(0x420,0x1234);check(!first(raw).containsKey("target"),"Unknown relocation extent ignored");
        raw=copyFixture(0x400800,8);check(first(raw).get("target").equals(0x400600L),"Disjoint bounded COPY relocation blocked callbacks");
        check(((List<?>)ElfCallbackInventory.analyze(raw).get("issues")).isEmpty(),"Supported COPY retained unknown extent");
        raw=copyFixture(0x400800,32);check(first(raw).containsKey("target"),"COPY object extent incorrectly fixed at pointer width");
        raw=copyFixture(0x4004f0,32);check(!first(raw).containsKey("target"),"COPY beginning before callback slot overlapped it undetected");
        raw=copyFixture(0x400500,8);check(!first(raw).containsKey("target"),"COPY on callback slot accepted as RELATIVE");
        raw=copyFixture(0x400800,0);check(!first(raw).containsKey("target"),"Zero-size COPY treated as known extent");
        raw=copyFixture(0x400800,Long.MAX_VALUE);check(!first(raw).containsKey("target"),"Overflowing COPY extent accepted");
        raw=copyFixture(0x400800,8);buffer(raw).putLong(0x288,16);check(!first(raw).containsKey("target"),"Invalid dynamic symbol stride accepted");
        raw=copyFixture(0x400800,8);buffer(raw).putLong(0x720,0x400900);check(!first(raw).containsKey("target"),"COPY symbol value/site disagreement accepted");
        raw=copyFixture(0x400800,8);buffer(raw).putInt(68,5);check(!first(raw).containsKey("target"),"COPY into nonwritable mapping accepted");
        raw=copyFixture(0x400800,8);buffer(raw).putLong(0x438,5);check(!first(raw).containsKey("target"),"COPY with null symbol accepted");
        raw=copyFixture(0x400800,8);buffer(raw).putLong(0x278,0x900000);check(!first(raw).containsKey("target"),"Unmapped COPY symbol entry accepted");
        raw=fixture();buffer(raw).putLong(0x410,0x900000);check(Boolean.FALSE.equals(first(raw).get("target_in_executable_file_mapping")),"Unmapped target approved");
        raw=fixture();buffer(raw).putInt(68,4);check(Boolean.FALSE.equals(first(raw).get("target_in_executable_file_mapping")),"Nonexecutable target approved");
        raw=fixture();buffer(raw).putLong(0x270,36).putLong(0x278,0x400450);check(!first(raw).containsKey("target"),"RELR ignored");
        raw=fixture();buffer(raw).putLong(0x258,0);check(!first(raw).containsKey("target"),"Unrelocated PIE slot assumed linked target");
        raw=fixture();buffer(raw).putShort(16,(short)2).putLong(0x258,0).putLong(0x500,0x400600);check(first(raw).get("target").equals(0x400600L),"Fixed ET_EXEC file pointer missing");
        raw=fixture();buffer(raw).putLong(0x218,7);reject(raw,"Misaligned callback array size");
        raw=fixture();buffer(raw).putLong(0x208,0x400ffd);reject(raw,"Array extends beyond mapped file");
        raw=fixture();buffer(raw).putLong(0x210,25);reject(raw,"Duplicate dynamic callback tag");
        raw=fixture();buffer(raw).putLong(0x210,1);reject(raw,"Missing matching array-size tag");
        raw=fixture();buffer(raw).putLong(0x268,16);reject(raw,"Incorrect RELA entry size");
        raw=fixture();buffer(raw).putLong(136,0x400201);reject(raw,"Dynamic virtual/file mapping mismatch");
        raw=fixture();for(int at=0x270;at<0x300;at+=16)buffer(raw).putLong(at,1);reject(raw,"Unterminated dynamic table");
        raw=fixture();buffer(raw).putShort(56,(short)3).putInt(176,1).putInt(180,5).putLong(184,0).putLong(192,0x400000).putLong(208,4096).putLong(216,4096);reject(raw,"Ambiguous overlapping mappings");
        System.out.println("All "+checks+" callback ELF inventory checks passed.");
    }
    private static void reject(byte[] raw,String label){try{ElfCallbackInventory.analyze(raw);}catch(IllegalArgumentException expected){checks++;return;}throw new AssertionError(label);}
    private static void check(boolean value,String label){if(!value)throw new AssertionError(label);checks++;}
}
