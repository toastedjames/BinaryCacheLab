package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.CallbackLiftPlan;

/** Encoded metadata fixtures, never native execution attestation. */
public final class StaticCallbackInventoryTest {
    static int checks;
    static void check(boolean okay,String message){checks++;if(!okay)throw new AssertionError(message);}
    static byte[] fixture(){
        byte[] raw=new byte[1024];ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;
        b.putShort(16,(short)2).putShort(18,(short)62).putInt(20,1).putLong(24,0x401000).putLong(32,64).putLong(40,0x240);
        b.putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)2).putShort(58,(short)64).putShort(60,(short)6).putShort(62,(short)3);
        b.putInt(64,1).putInt(68,5).putLong(72,0x100).putLong(80,0x401000).putLong(96,32).putLong(104,32).putLong(112,1);
        b.putInt(120,1).putInt(124,6).putLong(128,0x140).putLong(136,0x402000).putLong(152,13).putLong(160,13).putLong(168,1);
        raw[0x100]=(byte)0xc3;
        String names="\0.text\0.data\0.shstrtab\0.strtab\0.symtab\0.ctors\0.dynamic\0";
        byte[] n=names.getBytes(StandardCharsets.US_ASCII);System.arraycopy(n,0,raw,0x160,n.length);
        byte[] symbols="\0_start\0".getBytes(StandardCharsets.US_ASCII);System.arraycopy(symbols,0,raw,0x1c0,symbols.length);
        section(b,1,names.indexOf(".text"),1,6,0x401000,0x100,32,0,0);
        section(b,2,names.indexOf(".data"),1,3,0x402000,0x140,13,0,0);
        section(b,3,names.indexOf(".shstrtab"),3,0,0,0x160,n.length,0,0);
        section(b,4,names.indexOf(".strtab"),3,0,0,0x1c0,symbols.length,0,0);
        section(b,5,names.indexOf(".symtab"),2,0,0,0x1d0,48,4,24);
        int s=0x1d0+24;b.putInt(s,1).put(s+4,(byte)0x10).putShort(s+6,(short)1).putLong(s+8,0x401000);
        return raw;
    }
    static void section(ByteBuffer b,int i,int name,int type,long flags,long address,long offset,long size,int link,long stride){
        int p=0x240+i*64;b.putInt(p,name).putInt(p+4,type).putLong(p+8,flags).putLong(p+16,address).putLong(p+24,offset).putLong(p+32,size).putInt(p+40,link).putLong(p+56,stride);
    }
    static List<?> issues(byte[] raw){return (List<?>)ElfCallbackInventory.analyze(raw).get("issues");}
    public static void main(String[] args)throws Exception {
        byte[] raw=fixture();var report=ElfCallbackInventory.analyze(raw);
        check(issues(raw).isEmpty(),"Standalone ELF was rejected");
        check("STATIC_NO_CALLBACK_SECTIONS".equals(report.get("linking_model")),"Static scope missing");
        check(((List<?>)report.get("callbacks")).isEmpty(),"Callbacks invented");
        check(Boolean.FALSE.equals(report.get("runtime_callback_contract_proved"))&&Boolean.FALSE.equals(report.get("automatic_rewrite_allowed")),"Static inventory asserted semantic safety");
        Path dir=Files.createTempDirectory("static-callbacks-");Path original=dir.resolve("original"),rebuilt=dir.resolve("rebuilt");Files.write(original,raw);Files.write(rebuilt,raw);
        CallbackLiftPlan plan=new CallbackLiftPlan(original);
        check(plan.entries().isEmpty()&&plan.linkerArguments().isEmpty(),"Static plan invented CRT callbacks");
        plan.validateAssembly("global _start\n_start:\n nop\n");checks++;
        check("CALLBACK_ENTRY_MAPPING_CHECKED".equals(plan.verifyLinked(rebuilt).get("status")),"Static no-callback mapping refused");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putShort(16,(short)3);check(!issues(raw).isEmpty(),"Static PIE accepted without contract");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putShort(56,(short)3).putInt(176,3);check(!issues(raw).isEmpty(),"Interpreter without dynamic segment accepted");
        for(int type:List.of(6,14,15,16)){
            raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(0x240+2*64+4,type);check(!issues(raw).isEmpty(),"Static callback section type ignored: "+type);
        }
        raw=fixture();String names=new String(raw,0x160,70,StandardCharsets.US_ASCII);ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(0x240+2*64,names.indexOf(".ctors"));check(!issues(raw).isEmpty(),"Legacy constructor section ignored");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putShort(60,(short)0);check(!issues(raw).isEmpty(),"Missing sections treated as absence of callbacks");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putLong(24,0x402000);check(!issues(raw).isEmpty(),"Non-executable entry accepted");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putLong(24,0x900000);check(!issues(raw).isEmpty(),"Unmapped entry accepted");
        raw=fixture();ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putShort(56,(short)3).putInt(176,1).putInt(180,5).putLong(184,0x100).putLong(192,0x401000).putLong(208,32).putLong(216,32);check(!issues(raw).isEmpty(),"Ambiguous entry mappings accepted");
        Files.write(rebuilt,raw);boolean rejected=false;try{plan.verifyLinked(rebuilt);}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"Unsupported rebuilt static mapping accepted");
        System.out.println("All "+checks+" static callback inventory checks passed.");
    }
}
