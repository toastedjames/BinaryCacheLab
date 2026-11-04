package org.binarycachelab.analysis;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.workflow.Json;
import static org.binarycachelab.analysis.BoundedReferencesTest.*;
public final class BoundedTransformationTest {
 static Path root;static int checks,count;
 static void verify(boolean b,String message){checks++;if(!b)throw new AssertionError(message);}
 static Program lookup(long base,String prefix){return new Program().code(prefix,"89f848c1e00248b9"+imm(base,8),"8b0401c3").input("rdi",0,1);}
 static void table(Program p,long base){ByteBuffer.wrap(p.raw).order(ByteOrder.LITTLE_ENDIAN).putInt((int)(base-0x400000),7).putInt((int)(base-0x400000)+4,7);}
 static BoundedCorrespondenceTest.Pair pair(long a,long b,String extra){var left=lookup(a,"");var right=lookup(b,extra);table(left,a);table(right,b);var p=new BoundedCorrespondenceTest.Pair(left,right);p.profile.put("memory_maps",List.of(Map.of("name","global","original",a,"rebuilt",b,"size",8)));return p;}
 static Map<String,Object> policy(Path pair){return new LinkedHashMap<>(Map.of("schema","bcl-bounded-transformation-1","correspondence",pair.toString(),"observer",Map.of("policy","ordered-raw-virtual-lines","line_bytes",64),"secret_inputs",List.of(0),"require_nonvacuous",true,"layout",Map.of("policy","preserve-byte-line-partition","regions",List.of(Map.of("name","global","alignment",4)))));}
 static Path save(Map<String,Object> policy)throws Exception{Path file=root.resolve("approval-"+(++count)+".json");Files.writeString(file,Json.write(policy));return file;}
 static Map<String,Object> run(BoundedCorrespondenceTest.Pair pair,String status)throws Exception{Path path=save(policy(pair.save()));var result=BoundedTransformation.analyze(path);verify(status.equals(result.get("status")),Json.write(result));verify(Boolean.FALSE.equals(result.get("automatic_rewrite_allowed")),"Unbounded rewriting enabled");return result;}
 public static void main(String[] args)throws Exception{
 root=args.length==0?Files.createTempDirectory("bcl-approval-"):Files.createDirectory(Path.of(args[0]));BoundedReferencesTest.root=root;BoundedCorrespondenceTest.root=root;
 for(int shift:new int[]{0,64,128,192}){var r=run(pair(DATA,DATA+shift,""),"APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS");verify(Boolean.TRUE.equals(r.get("bounded_transformation_approved")),"No scoped approval");verify(((Number)object(r.get("observation")).get("original_equal_secret_pairs")).intValue()==1,"Missing equal pair");}
 var r=run(pair(DATA+56,DATA+60,""),"PRESERVATION_COUNTEREXAMPLE");verify("REJECTED_LAYOUT".equals(object(r.get("linked_layout")).get("status")),"Invalid boundary layout accepted");verify(!((List<?>)object(r.get("observation")).get("witnesses")).isEmpty(),"Missing instruction witness");
 // A valid selected layout cannot hide a new secret-dependent read elsewhere.
 String extra="4889f848c1e00648b9"+imm(DATA+256,8)+"8b0401";
 r=run(pair(DATA,DATA+64,extra),"PRESERVATION_COUNTEREXAMPLE");verify("FINAL_LINKED_LAYOUT_VERIFIED".equals(object(r.get("linked_layout")).get("status")),"Outside-region negative did not reach full observation gate");
 run(pair(DATA,DATA+64,"48b9"+imm(DATA+256,8)+"8b01"),"APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS");
 r=run(pair(DATA,DATA+4,""),"TRANSFORMATION_REJECTED");verify(Boolean.TRUE.equals(object(r.get("observation")).get("preservation_holds")),"Residue negative unexpectedly leaked");
 var p=pair(DATA,DATA+64,"");p.b.raw[(int)(p.b.next-2-0x400000)]=0; // corrupt instruction: fail closed
 run(p,"TRANSFORMATION_REJECTED");
 p=pair(DATA,DATA+64,"");p.b.bound("max_steps_per_execution",1);run(p,"TRANSFORMATION_REJECTED");
 // Public inputs define separate equality contexts.
 p=pair(DATA,DATA+64,"");
 for(var program:List.of(p.a,p.b))program.profile.put("inputs",List.of(Map.of("register","rdi","values",List.of(0,1)),Map.of("register","rsi","values",List.of(11,12))));
 p.profile.put("input_map",List.of(Map.of("original",0,"rebuilt",0,"encoding","scalar"),Map.of("original",1,"rebuilt",1,"encoding","scalar")));
 r=run(p,"APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS");verify(((Number)object(r.get("observation")).get("public_contexts")).intValue()==2,"Public contexts merged");verify(((Number)object(r.get("observation")).get("original_equal_secret_pairs")).intValue()==2,"Pairs crossed public contexts");
 // Original already distinguishes every secret: implication is vacuous, approval refused.
 p=pair(DATA,DATA+128,"");p.a.raw[0x205]=6;p.b.raw[0x205]=6;
 table(p.a,DATA+64);table(p.b,DATA+192);
 p.profile.put("memory_maps",List.of(Map.of("name","global","original",DATA,"rebuilt",DATA+128,"size",68)));
 System.arraycopy(p.a.raw,0x1000,p.b.raw,0x1080,68);
 r=run(p,"TRANSFORMATION_REJECTED");verify("NO_ORIGINAL_EQUALITY_PAIR".equals(object(r.get("rejection")).get("kind")),"Vacuous approval allowed");
 // Two separately relocated maps must preserve cross-map line sharing.
 p=pair(DATA,DATA+64,"");
 p.profile.put("memory_maps",List.of(Map.of("name","global","original",DATA,"rebuilt",DATA+64,"size",8),Map.of("name","other","original",DATA+16,"rebuilt",DATA+144,"size",8)));
 var splitPolicy=policy(p.save());splitPolicy.put("layout",Map.of("policy","preserve-byte-line-partition","regions",List.of(Map.of("name","global","alignment",4),Map.of("name","other","alignment",4))));
 r=BoundedTransformation.analyze(save(splitPolicy));verify("CROSS_REGION_LINE_PARTITION_CHANGED".equals(object(r.get("rejection")).get("kind")),"Cross-map sharing split accepted");
 Path path=save(policy(pair(DATA,DATA+64,"").save()));r=BoundedTransformation.analyze(path);verify(Json.object(Json.write(r)).equals(Json.object(Json.write(BoundedTransformation.analyze(path)))),"Nondeterministic replay");
 Path output=root.resolve("published.elf");var published=BoundedTransformation.publish(path,output);verify(Files.exists(output),"Publication missing");verify(org.binarycachelab.workflow.GroupPlan.hash(Files.readAllBytes(output)).equals(published.get("candidate_sha256")),"Published wrong bytes");
 byte[] existing=Files.readAllBytes(output);try{BoundedTransformation.publish(path,output);throw new AssertionError("Overwrite allowed");}catch(IllegalArgumentException expected){checks++;}verify(Arrays.equals(existing,Files.readAllBytes(output)),"Existing publication changed");
 Path bad=save(policy(pair(DATA+56,DATA+60,"").save()));Path absent=root.resolve("rejected.elf");BoundedTransformation.publish(bad,absent);verify(!Files.exists(absent),"Rejected candidate published");
 var document=policy(pair(DATA,DATA+64,"").save());document.put("secret_inputs",List.of());try{BoundedTransformation.analyze(save(document));throw new AssertionError("No secret accepted");}catch(IllegalArgumentException expected){checks++;}
 document=policy(pair(DATA,DATA+64,"").save());document.put("observer",Map.of("policy","sets","line_bytes",64));verify("TRANSFORMATION_REJECTED".equals(BoundedTransformation.analyze(save(document)).get("status")),"Unsupported observer approved");
 document=policy(pair(DATA,DATA+64,"").save());document.put("layout",Map.of("policy","preserve-byte-line-partition","regions",List.of(Map.of("name","missing","alignment",4))));verify("TRANSFORMATION_REJECTED".equals(BoundedTransformation.analyze(save(document)).get("status")),"Unmapped layout approved");
 Files.writeString(root.resolve("summary.json"),Json.write(Map.of("status","APPROVAL_QUALIFICATION_EXPECTATIONS_MET","checks",checks,"scope","Exhaustive bounded encoded ELF pairs; exact publication, rejection, replay and observation checks")));System.out.println("Approval checks passed: "+checks);
 }
}
