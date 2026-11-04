package org.binarycachelab.analysis;

import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.*;

/** Synthetic metadata/trace controls: no native binaries or instrumentation are run. */
public final class ToolkitEvidenceTest {
    private static int checks;
    public static void main(String[] args)throws Exception{
        var elf=ElfMetadata.read(elf());check(elf.selected(Set.of("first","second","end")).get("first")==0x400338,"ELF selected symbols");
        var inventory=elf.audit(0x400338,8);check(((List<?>)inventory.get("symbol_owners_and_alias_candidates")).size()==3,"Owner/interior aliases not inventoried");
        check(((List<?>)inventory.get("region_relocation_references")).isEmpty(),"False region relocation hit");
        byte[] raw=elf();buf(raw).putLong(0x390,0x40033a);check(!((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("region_relocation_references")).isEmpty(),"Interior relative target missed");
        raw=elf();buf(raw).putLong(0x380,0x400334);check(!((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("region_relocation_references")).isEmpty(),"Crossing relocation write missed");
        raw=elf();buf(raw).putLong(0x301,0x400339);check(!((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("stored_pointer_candidates")).isEmpty(),"Unaligned stored pointer missed");
        raw=elf();buf(raw).putLong(0x388,0x100000001L);check(!((List<?>)ElfMetadata.read(raw).audit(0x400338,8).get("region_relocation_references")).isEmpty(),"Symbolic reference missed");
        reject(()->ElfMetadata.read(new byte[32]));
        bad(60,0,2);bad(58,32,2);bad(40,0x900,8);
        raw=elf();buf(raw).putInt(0x600+3*64+40,9);final byte[] badLink=raw;reject(()->ElfMetadata.read(badLink));
        raw=elf();buf(raw).putInt(0x200+2*24,1);final byte[] duplicate=raw;reject(()->ElfMetadata.read(duplicate).selected(Set.of("first")));
        raw=elf();buf(raw).putShort(0x200+24+6,(short)0);final byte[] undefined=raw;reject(()->ElfMetadata.read(undefined).selected(Set.of("first")));
        raw=elf();buf(raw).putLong(0x388,99L<<32|8);final byte[] badSymbol=raw;reject(()->ElfMetadata.read(badSymbol).audit(0x400338,8));
        Path temp=Files.createTempDirectory("bcl-evidence-tests-");
        Path positive=batch(temp,"positive",false,false);var result=WholeTraceAnalysis.evaluate(positive,2);
        check(result.exit()==0,"Positive observation equality");check(Boolean.TRUE.equals(result.report().get("functional_checks")),"Positive functionality");
        check(WholeTraceAnalysis.evaluate(batch(temp,"shifted",false,true),2).exit()==3,"Preservation negative control missed");
        check(WholeTraceAnalysis.evaluate(batch(temp,"dependent",true,true),2).exit()==5,"Secret-dependence control missed");
        Path output=batch(temp,"output",false,false);Files.writeString(output.resolve("repeat-1/rebuilt-0/native.stdout"),"different\n");seal(output);
        check(WholeTraceAnalysis.evaluate(output,2).exit()==2,"Unstable outputs should be inconclusive first");
        Path functionality=batch(temp,"functional",false,false);
        for(int r=0;r<2;r++)for(String mode:List.of("native","pin"))Files.writeString(functionality.resolve("repeat-"+r+"/rebuilt-0/"+mode+".stdout"),"different\n");seal(functionality);
        check(WholeTraceAnalysis.evaluate(functionality,2).exit()==4,"Stable functional mismatch missed");
        Path unstable=batch(temp,"unstable",false,false);Path trace=unstable.resolve("repeat-1/original-0/trace.csv");Files.writeString(trace,Files.readString(trace).replace("0x1000","0x1080"));seal(unstable);
        check(WholeTraceAnalysis.evaluate(unstable,2).exit()==2,"Nondeterministic trace accepted");
        Path corrupt=batch(temp,"corrupt",false,false);Files.writeString(corrupt.resolve("repeat-0/original-0/trace.csv"),"corrupt");reject(()->WholeTraceAnalysis.evaluate(corrupt,2));
        Path truncated=batch(temp,"truncated",false,false);trace=truncated.resolve("repeat-0/original-0/trace.csv");Files.writeString(trace,Files.readString(trace).split("\\R")[0]+"\n");seal(truncated);reject(()->WholeTraceAnalysis.evaluate(truncated,2));
        Path metadata=batch(temp,"metadata",false,false);Path properties=metadata.resolve("repeat-0/original-0/trace.properties");Files.writeString(properties,Files.readString(properties)+"events=1\n");seal(metadata);reject(()->WholeTraceAnalysis.evaluate(metadata,2));
        Path extra=batch(temp,"extra",false,false);Files.writeString(extra.resolve("unexpected"),"x");reject(()->WholeTraceAnalysis.evaluate(extra,2));
        Path incomplete=batch(temp,"incomplete",false,false);Files.writeString(incomplete.resolve("collection.json"),Json.write(Map.of("status","incomplete")));seal(incomplete);reject(()->WholeTraceAnalysis.evaluate(incomplete,2));
        Path wrapping=batch(temp,"wrap",false,false);trace=wrapping.resolve("repeat-0/original-0/trace.csv");Files.writeString(trace,Files.readString(trace).replace("0x1000,1","0xffffffffffffffff,2"));seal(wrapping);reject(()->WholeTraceAnalysis.evaluate(wrapping,2));
        Path cross=batch(temp,"cross",false,false);for(int r=0;r<2;r++)for(String role:List.of("original","rebuilt")){
            trace=cross.resolve("repeat-"+r+"/"+role+"-0/trace.csv");Files.writeString(trace,header()+"0,0,0x400000,0x103f,2,READ,PIN\n");
            Path folder=cross.resolve("repeat-"+r+"/"+role+"-1");Files.writeString(folder.resolve("trace.csv"),header()+"0,0,0x400000,0x103f,1,WRITE,PIN\n1,0,0x400001,0x1040,1,READ,PIN\n");
            Path prop=folder.resolve("trace.properties");Files.writeString(prop,Files.readString(prop).replace("events=1","events=2"));}
        seal(cross);check(WholeTraceAnalysis.evaluate(cross,2).exit()==0,"Event boundaries/access types entered observation equality");
        Path sequences=batch(temp,"sequence",false,false);for(int r=0;r<2;r++)for(int s=0;s<2;s++){
            Path folder=sequences.resolve("repeat-"+r+"/original-"+s);Files.writeString(folder.resolve("trace.properties"),Files.readString(folder.resolve("trace.properties")).replace("events=1","events=2"));
            String a=s==0?"0x1000":"0x1040",b=s==0?"0x1040":"0x1000";Files.writeString(folder.resolve("trace.csv"),header()+"0,0,0x400000,"+a+",1,READ,PIN\n1,0,0x400001,"+b+",1,READ,PIN\n");}
        seal(sequences);check(WholeTraceAnalysis.evaluate(sequences,2).exit()==5,"Equal aggregate/different ordered sequence not detected");
        var direct=DirectReadInventory.inspect("  1150: 8b 05 22 2f 00 00 mov eax,DWORD PTR [rip+0x2f22] # 4078 <table>\n",0x4078,8);
        check(DirectReadInventory.supported(direct)&&DirectReadInventory.signature(direct).get("0/4")==1,"RIP displacement inventory failed");
        check(!DirectReadInventory.supported(DirectReadInventory.inspect("  1150: 48 8d 05 21 2f 00 00 lea rax,[rip+0x2f21]\n",0x4078,8)),"Address-taking accepted as direct read");
        check(!DirectReadInventory.supported(DirectReadInventory.inspect("  1150: 8b 05 20 2f 00 00 mov eax,DWORD PTR [rip+0x2f20]\n",0x4078,8)),"Crossing reference accepted");
        check(!DirectReadInventory.supported(DirectReadInventory.inspect("  1150: 0f ff (bad)\n",0x4078,8)),"Undecoded instruction accepted");
        check(DirectReadInventory.supported(DirectReadInventory.inspect("  4100: 8b 05 72 ff ff ff mov eax,DWORD PTR [rip+0xffffffffffffff72]\n",0x4078,8)),"Sign-extended 64-bit printed RIP displacement rejected");
        check(DirectReadInventory.supported(DirectReadInventory.inspect("  4100: 8b 05 72 ff ff ff mov eax,DWORD PTR [rip+0xffffff72]\n",0x4078,8)),"Unsigned 32-bit printed RIP displacement rejected");
        System.out.println("All "+checks+" toolkit metadata/evidence checks passed; synthetic data only.");
    }
    private static String header(){return "sequence,thread_id,instruction_address,memory_address,access_size_bytes,access_type,source_backend\n";}
    static Path batch(Path root,String name,boolean originalDiff,boolean rebuiltDiff)throws Exception{
        Path batch=Files.createDirectory(root.resolve(name));
        for(int r=0;r<2;r++)for(String role:List.of("original","rebuilt"))for(int s=0;s<2;s++){
            Path run=batch.resolve("repeat-"+r+"/"+role+"-"+s);Files.createDirectories(run);
            long address=role.equals("original")?0x1000:0x2000;if(s==1&&(role.equals("original")?originalDiff:rebuiltDiff))address+=64;
            Files.writeString(run.resolve("trace.csv"),header()+"0,0,0x400000,0x"+Long.toHexString(address)+",1,READ,PIN\n");
            Files.writeString(run.resolve("trace.properties"),"status=complete\nreason=normal-exit\ntracer_version=whole-2\napplication_threads=1\nmain_images=1\napplication_exit=0\nbackend=PIN\naddress_space=raw-virtual\nobservation_filter=none\nnormalization=none\nscope=pin-instrumented-user-space\nevent_semantics=before-instruction-pin-predication\nread_modify_write=separate-read-then-write\nkernel_memory_accesses=excluded\ninstruction_fetches=excluded\nmapping_snapshots=1\nevents=1\n");
            for(String mode:List.of("native","pin")){Files.writeString(run.resolve(mode+".stdout"),"7\n");Files.writeString(run.resolve(mode+".stderr"),"");Files.writeString(run.resolve(mode+".exit"),"0\n");}
        }Files.writeString(batch.resolve("collection.json"),Json.write(Map.of("status","complete")));
        Files.writeString(batch.resolve("experiment.json"),Json.write(Map.of("schema","whole-collection-1","repetitions",2)));seal(batch);return batch;
    }
    static void seal(Path root)throws Exception{StringBuilder out=new StringBuilder();try(var files=Files.walk(root)){
        for(Path f:files.filter(Files::isRegularFile).sorted().toList())if(!f.equals(root.resolve("SHA256SUMS")))out.append(Stage3Engine.digest(f)).append("  ./").append(root.relativize(f).toString().replace('\\','/')).append('\n');}
        Files.writeString(root.resolve("SHA256SUMS"),out);}
    private static ByteBuffer buf(byte[] raw){return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);}
    static byte[] elf(){byte[] raw=new byte[0x800];ByteBuffer b=buf(raw);b.putInt(0,0x464c457f);raw[4]=2;raw[5]=1;raw[6]=1;
        b.putShort(16,(short)2).putShort(18,(short)62).putInt(20,1).putLong(32,64).putLong(40,0x600).putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)1).putShort(58,(short)64).putShort(60,(short)6).putShort(62,(short)1);
        b.putInt(64,1).putLong(72,0).putLong(80,0x400000).putLong(96,0x800).putLong(104,0x800);
        String names="\0.shstrtab\0.strtab\0.symtab\0.data\0.rela.data\0",strings="\0first\0second\0end\0owner\0";
        System.arraycopy(names.getBytes(java.nio.charset.StandardCharsets.UTF_8),0,raw,0x100,names.length());System.arraycopy(strings.getBytes(java.nio.charset.StandardCharsets.UTF_8),0,raw,0x180,strings.length());
        section(b,1,names.indexOf(".shstrtab"),3,0,0,0x100,names.length(),0,0,0);section(b,2,names.indexOf(".strtab"),3,0,0,0x180,strings.length(),0,0,0);
        section(b,3,names.indexOf(".symtab"),2,0,0,0x200,5*24,2,5,24);section(b,4,names.indexOf(".data"),1,3,0x400300,0x300,64,0,0,0);
        section(b,5,names.indexOf(".rela.data"),4,2,0x400380,0x380,24,3,4,24);
        String[] labels={"first","second","end","owner"};long[] values={0x400338,0x40033c,0x400340,0x400300};
        for(int i=1;i<5;i++){int p=0x200+i*24;b.putInt(p,strings.indexOf(labels[i-1])).putShort(p+6,(short)4).putLong(p+8,values[i-1]).putLong(p+16,i==4?64:0);}
        b.putInt(0x338,7).putInt(0x33c,7).putLong(0x380,0x400300).putLong(0x388,8);return raw;}
    private static void section(ByteBuffer b,int index,int name,int type,long flags,long address,long offset,long size,int link,int info,long entry){int p=0x600+index*64;
        b.putInt(p,name).putInt(p+4,type).putLong(p+8,flags).putLong(p+16,address).putLong(p+24,offset).putLong(p+32,size).putInt(p+40,link).putInt(p+44,info).putLong(p+56,entry);}
    private static void bad(int offset,long value,int size){byte[] raw=elf();if(size==2)buf(raw).putShort(offset,(short)value);else buf(raw).putLong(offset,value);reject(()->ElfMetadata.read(raw));}
    @FunctionalInterface private interface Checked{void run()throws Exception;}
    private static void reject(Checked task){try{task.run();}catch(Exception expected){checks++;return;}throw new AssertionError("Expected rejection");}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
}
