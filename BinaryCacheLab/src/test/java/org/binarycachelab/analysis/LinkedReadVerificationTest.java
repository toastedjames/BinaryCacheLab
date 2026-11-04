package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;

public final class LinkedReadVerificationTest {
    private static int checks;
    public static void main(String[] args)throws Exception{
        Path root=Files.createTempDirectory("bcl-linked-read-tests-");Path file=root.resolve("program");
        for(String opcode:List.of("8a05","668b05","8b05","488b05","0fb605","0fb705","480fbe05","480fbf05","440fb605")){
            int width=opcode.equals("8a05")||opcode.endsWith("b605")||opcode.endsWith("be05")?1:opcode.equals("668b05")||opcode.endsWith("b705")||opcode.endsWith("bf05")?2:opcode.equals("488b05")?8:4;
            byte[] code=instruction(opcode,0x400100,0x400538);Files.write(file,elf(code,0x100));String text=row(0x400100,code,width,0x400538);
            var checked=LinkedReadVerification.verify(file,text,0x400538,8);check(((List<?>)checked.get("reads")).size()==1,"Valid read encoding rejected");
        }
        byte[] code=instruction("0fb705",0x400600,0x400538);Files.write(file,elf(code,0x600));String negative=row(0x400600,code,2,0x400538);
        check(((List<?>)LinkedReadVerification.verify(file,negative,0x400538,8).get("reads")).size()==1,"Negative disp32 rejected");
        code=instruction("8b05",0x400100,0x400538);byte[] raw=elf(code,0x100);Files.write(file,raw);String good=row(0x400100,code,4,0x400538);
        reject(()->LinkedReadVerification.verify(file,good.replace("DWORD","WORD"),0x400538,8));
        reject(()->LinkedReadVerification.verify(file,good.replace("8b 05","89 05"),0x400538,8));
        reject(()->LinkedReadVerification.verify(file,good+"\n"+good,0x400538,8));
        raw[0x100]=(byte)0x89;Files.write(file,raw);String store=row(0x400100,Arrays.copyOfRange(raw,0x100,0x106),4,0x400538);
        reject(()->LinkedReadVerification.verify(file,store,0x400538,8));
        raw=elf(code,0x100);ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(68,4);Files.write(file,raw);
        reject(()->LinkedReadVerification.verify(file,good,0x400538,8));
        Files.write(file,elf(code,0x100));var a=LinkedReadVerification.verify(file,good,0x400538,8);
        check(Boolean.TRUE.equals(LinkedReadVerification.correspond(a,a).get("all_sites_unique")),"Unique site mapping missing");
        Map<String,Object> duplicate=new HashMap<>(a);List<?> reads=(List<?>)a.get("reads");duplicate.put("reads",List.of(reads.get(0),reads.get(0)));
        check(Boolean.FALSE.equals(LinkedReadVerification.correspond(duplicate,duplicate).get("all_sites_unique")),"Ambiguous sites falsely paired");
        reject(()->LinkedReadVerification.correspond(a,duplicate));
        reject(()->LinkedReadVerification.verify(file,good,0x40053a,8));
        byte[] extended=instruction("418b05",0x400100,0x400538);Files.write(file,elf(extended,0x100));String badRex=row(0x400100,extended,4,0x400538);
        reject(()->LinkedReadVerification.verify(file,badRex,0x400538,8));
        byte[] one=instruction("8b05",0x400100,0x40053c),two=instruction("8b05",0x400107,0x400538);raw=elf(one,0x100);
        System.arraycopy(two,0,raw,0x107,two.length);raw[0xfc]=(byte)0x85;raw[0xfd]=(byte)0xff;raw[0xfe]=0x74;raw[0xff]=7;raw[0x106]=(byte)0xc3;raw[0x10d]=(byte)0xc3;Files.write(file,raw);
        String kernelText="4000fc: 85 ff  test edi,edi\n4000fe: 74 07  je 400107\n"+row(0x400100,one,4,0x40053c)+"\n400106: c3  ret\n"+row(0x400107,two,4,0x400538)+"\n40010d: c3  ret";
        var encodings=LinkedReadVerification.verify(file,kernelText,0x400538,8);var contract=LinkedReadVerification.lookupKernel(kernelText,encodings);
        check(Boolean.TRUE.equals(LinkedReadVerification.compareKernels(contract,contract,true).get("preservation_for_all_selector_pairs_under_contract")),"Local kernel preservation rejected");
        var changed=new HashMap<>(contract);changed.put("zero_lines",List.of(999L));
        check(Boolean.FALSE.equals(LinkedReadVerification.compareKernels(contract,changed,true).get("preservation_for_all_selector_pairs_under_contract")),"Local kernel leakage not detected");
        reject(()->LinkedReadVerification.lookupKernel(kernelText.replace("74 07","75 07"),encodings));
        reject(()->LinkedReadVerification.lookupKernel(kernelText.replace("c3  ret","90  nop"),encodings));
        reject(()->LinkedReadVerification.compareKernels(contract,contract,false));
        var swapped=new HashMap<>(contract);swapped.put("zero_offset",99L);reject(()->LinkedReadVerification.compareKernels(contract,swapped,true));
        System.out.println("All "+checks+" linked instruction encoding/correspondence checks passed.");
    }
    private static byte[] elf(byte[] code,int position){byte[] raw=new byte[4096];ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;b.putShort(16,(short)3).putShort(18,(short)62).putInt(20,1).putLong(32,64).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)1);
        b.putInt(64,1).putInt(68,5).putLong(72,0).putLong(80,0x400000).putLong(96,raw.length).putLong(104,raw.length);
        System.arraycopy(code,0,raw,position,code.length);return raw;}
    private static byte[] instruction(String prefix,long ip,long target){byte[] op=HexFormat.of().parseHex(prefix),code=Arrays.copyOf(op,op.length+4);
        ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN).putInt(op.length,(int)(target-ip-code.length));return code;}
    private static String row(long ip,byte[] code,int width,long target){long disp=target-ip-code.length;
        String hex=HexFormat.of().formatHex(code),mnemonic=hex.contains("0fb6")||hex.contains("0fb7")?"movzx":hex.contains("0fbe")||hex.contains("0fbf")?"movsx":"mov";
        String register=hex.startsWith("44")?"r8d":hex.startsWith("48")?"rax":hex.startsWith("66")?"ax":hex.startsWith("8a")?"al":"eax";
        return Long.toHexString(ip)+": "+HexFormat.ofDelimiter(" ").formatHex(code)+"  "+mnemonic+" "+register+","+(width==1?"BYTE":width==2?"WORD":width==4?"DWORD":"QWORD")+" PTR [rip"+(disp<0?"-":"+")+"0x"+Long.toHexString(Math.abs(disp))+"]";}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);checks++;}
    private interface Checked{void run()throws Exception;}
    private static void reject(Checked task){try{task.run();}catch(Exception expected){checks++;return;}throw new AssertionError("Expected rejection");}
}
