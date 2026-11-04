package org.binarycachelab.analysis;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.binarycachelab.workflow.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Artifact-specific approval: exhaustive correspondence, final layout and observation equality. */
public final class BoundedTransformation {
    private static final int LINE=64;
    private record Document(Map<String,Object> data,String hash){}
    private record Token(long line,Map<String,Object> access){}
    private record Signature(String context,List<Long> original){}
    private record Representative(String input,List<Long> rebuilt,List<Token> tokens){}
    private static final class Group {final Representative first;long size=1;Group(Representative first){this.first=first;}}
    private static final class Problem extends RuntimeException {final String kind;Problem(String kind,String detail){super(detail);this.kind=kind;}}
    private final Path file;private final Map<String,Object> profile;private final String profileHash;
    private Path pairPath,originalPath,candidatePath;private String originalHash,candidateHash;
    private Map<String,Object> correspondence,layout,observation;
    private final Set<Integer> secrets=new TreeSet<>();
    private static Map<String,Object> object(Object value){return MultiRegionPlan.object(value);}
    private static List<?> list(Object value){require(value instanceof List<?>,"Expected array");return (List<?>)value;}
    private static long number(Object value){require(value instanceof Long||value instanceof Integer,"Expected integer");return ((Number)value).longValue();}
    private static long n(Map<String,Object> value,String key){return number(value.get(key));}
    private static void keys(Map<String,Object> value,String... names){require(Set.of(names).containsAll(value.keySet()),"Unknown approval fields: "+value.keySet().stream().filter(k->!Set.of(names).contains(k)).toList());}
    private static void check(boolean value,String kind,String detail){if(!value)throw new Problem(kind,detail);}
    private static Path resolve(Path base,Object value){require(value instanceof String&&!((String)value).isBlank(),"Expected nonempty path");return base.resolve((String)value).normalize();}
    private static Document read(Path path)throws IOException{byte[] bytes;try(var in=Files.newInputStream(path)){bytes=in.readNBytes(1024*1024+1);}require(bytes.length<=1024*1024,"Approval profile exceeds 1 MiB");return new Document(Json.object(new String(bytes,java.nio.charset.StandardCharsets.UTF_8)),GroupPlan.hash(bytes));}
    private BoundedTransformation(Path path)throws IOException{file=path.toAbsolutePath().normalize();Document doc=read(file);profile=doc.data;profileHash=doc.hash;}
    public static Map<String,Object> analyze(Path path)throws IOException{return new BoundedTransformation(path).run();}

    private Map<String,Object> run()throws IOException {
        Map<String,Object> rejection=null;
        try {
            keys(profile,"schema","correspondence","observer","secret_inputs","require_nonvacuous","layout");
            require("bcl-bounded-transformation-1".equals(profile.get("schema")),"Expected bcl-bounded-transformation-1");
            var observer=object(profile.get("observer"));keys(observer,"policy","line_bytes");
            check("ordered-raw-virtual-lines".equals(observer.get("policy"))&&n(observer,"line_bytes")==LINE,"UNSUPPORTED_OBSERVER","Only ordered 64-byte modeled virtual data lines are supported");
            require(Boolean.TRUE.equals(profile.get("require_nonvacuous")),"require_nonvacuous must explicitly be true");
            pairPath=resolve(file.getParent(),profile.get("correspondence"));correspondence=BoundedCorrespondence.analyze(pairPath);
            check(Boolean.TRUE.equals(correspondence.get("correspondence_established")),"CORRESPONDENCE_NOT_ESTABLISHED",Objects.toString(correspondence.get("status")));
            var pair=object(correspondence.get("contract"));int dimensions=list(pair.get("input_map")).size();
            for(Object value:list(profile.get("secret_inputs"))){long index=number(value);require(index>=0&&index<dimensions&&secrets.add((int)index),"Secret dimension indices must be unique and within input_map");}
            require(!secrets.isEmpty(),"Declare at least one secret input dimension");
            var a=object(correspondence.get("original_analysis"));var b=object(correspondence.get("rebuilt_analysis"));
            Path aProfile=resolve(pairPath.getParent(),pair.get("original")),bProfile=resolve(pairPath.getParent(),pair.get("rebuilt"));
            originalPath=resolve(aProfile.getParent(),object(a.get("contract")).get("binary"));candidatePath=resolve(bProfile.getParent(),object(b.get("contract")).get("binary"));
            originalHash=(String)a.get("binary_sha256");candidateHash=(String)b.get("binary_sha256");
            try{layout=linkedLayout(pair);}catch(Problem problem){layout=Map.of("status","REJECTED_LAYOUT","reason",Map.of("kind",problem.kind,"detail",problem.getMessage()));rejection=Map.of("kind",problem.kind,"detail",problem.getMessage());}
            observation=observations(a,b);
            if(!Boolean.TRUE.equals(observation.get("preservation_holds")))rejection=Map.of("kind","OBSERVATION_EQUALITY_NOT_PRESERVED","detail","An originally equal observation class splits in the candidate");
            else if(!Boolean.TRUE.equals(observation.get("nonvacuous")))rejection=Map.of("kind","NO_ORIGINAL_EQUALITY_PAIR","detail","The policy requires at least one pair of distinct secret assignments with equal original observations");
        }catch(Problem problem){rejection=Map.of("kind",problem.kind,"detail",problem.getMessage());}
        boolean approved=rejection==null;
        Map<String,Object> out=new LinkedHashMap<>();out.put("schema","bcl-bounded-transformation-report-1");out.put("analyzer_version","1.4.0");
        out.put("status",approved?"APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS":rejection.get("kind").equals("OBSERVATION_EQUALITY_NOT_PRESERVED")?"PRESERVATION_COUNTEREXAMPLE":"TRANSFORMATION_REJECTED");
        out.put("bounded_transformation_approved",approved);out.put("automatic_rewrite_allowed",false);out.put("profile_sha256",profileHash);out.put("contract",profile);
        if(correspondence!=null)out.put("correspondence",correspondence);if(layout!=null)out.put("linked_layout",layout);if(observation!=null)out.put("observation",observation);if(rejection!=null)out.put("rejection",rejection);
        if(originalHash!=null)out.put("original_sha256",originalHash);if(candidateHash!=null)out.put("candidate_sha256",candidateHash);
        out.put("authorization",Map.of("approved",approved,"scope","Exact candidate bytes, fixed original bytes, declared finite entry/input domain, closed integer runtime and 64-byte data-line observer","arbitrary_rewrites",false));
        out.put("scope","This result authorizes only publication of the exact checked candidate under the recorded bounded contract; no general Linux or physical-cache security claim");return out;
    }

    private Map<String,Object> linkedLayout(Map<String,Object> pair)throws IOException {
        var policy=object(profile.get("layout"));keys(policy,"policy","regions");
        check("preserve-byte-line-partition".equals(policy.get("policy")),"UNSUPPORTED_LAYOUT_POLICY","Only final linked literal-data byte/line-partition preservation is supported");
        List<?> selected=list(policy.get("regions"));require(!selected.isEmpty()&&selected.size()<=63,"Declare 1..63 layout regions");
        LinkedImage a=new LinkedImage(originalPath),b=new LinkedImage(candidatePath);
        check(originalHash.equals(a.hash)&&candidateHash.equals(b.hash),"BINARY_CHANGED_DURING_APPROVAL","Layout and execution must bind the same binary bytes");
        Map<String,Map<String,Object>> available=new HashMap<>();for(Object row:list(pair.get("memory_maps"))){var map=object(row);available.put((String)map.get("name"),map);}
        Set<String> seen=new HashSet<>();Map<Long,Long> forward=new HashMap<>(),reverse=new HashMap<>();List<Map<String,Object>> checked=new ArrayList<>();
        for(Object row:selected){var region=object(row);keys(region,"name","alignment");require(region.get("name") instanceof String,"Region name required");String name=(String)region.get("name");require(seen.add(name),"Duplicate selected layout region");
            var map=available.get(name);check(map!=null,"LAYOUT_REGION_NOT_MAPPED","Layout region has no persistent correspondence mapping: "+name);
            check(list(map.getOrDefault("pointer_fields",List.of())).isEmpty(),"POINTER_FIELDS_IN_LITERAL_LAYOUT","Selected literal-data regions cannot contain rebased pointer fields");
            long old=n(map,"original"),now=n(map,"rebuilt"),size=n(map,"size"),alignment=n(region,"alignment");
            require(alignment>0&&alignment<=1024*1024&&(alignment&(alignment-1))==0,"Alignment must be a power of two <=1 MiB");
            check(old%alignment==0&&now%alignment==0,"LINKED_ALIGNMENT_MISMATCH",name+" does not satisfy its declared linked alignment");
            check(old%LINE==now%LINE,"LINKED_LINE_RESIDUE_MISMATCH",name+": "+old%LINE+" -> "+now%LINE);
            byte[] before=a.bytes(old,Math.toIntExact(size)),after=b.bytes(now,Math.toIntExact(size));
            check(Arrays.equals(before,after),"LINKED_LITERAL_BYTES_CHANGED","Original/candidate file bytes differ in "+name);
            for(long offset=0;offset<size;){long x=(old+offset)/LINE,y=(now+offset)/LINE;Long f=forward.putIfAbsent(x,y),r=reverse.putIfAbsent(y,x);
                check((f==null||f==y)&&(r==null||r==x),"CROSS_REGION_LINE_PARTITION_CHANGED","Declared region bytes merge or split line classes");offset+=Math.min(size-offset,LINE-(old+offset)%LINE);}
            checked.add(Map.of("name",name,"original_address",old,"candidate_address",now,"size",size,"alignment",alignment,"sha256",GroupPlan.hash(before)));
        }
        return Map.of("status","FINAL_LINKED_LAYOUT_VERIFIED","regions",checked,"line_classes",forward.size(),"line_bytes",LINE,"literal_bytes_preserved",true,"declared_line_partition_preserved",true);
    }
    private static final class LinkedImage {
        final byte[] raw;final String hash;final ByteBuffer buffer;
        LinkedImage(Path path)throws IOException{try(var in=Files.newInputStream(path)){raw=in.readNBytes(64*1024*1024+1);}require(raw.length>=64&&raw.length<=64*1024*1024,"Invalid linked image size");hash=GroupPlan.hash(raw);buffer=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);}
        byte[] bytes(long address,int size){long ph=buffer.getLong(32);int count=Short.toUnsignedInt(buffer.getShort(56));require(ph>=64&&buffer.getShort(54)==56&&ph<=raw.length-56L*count,"Invalid linked program headers");
            byte[] found=null;for(int i=0;i<count;i++){int at=(int)ph+i*56;if(buffer.getInt(at)!=1)continue;long start=buffer.getLong(at+16),file=buffer.getLong(at+8),length=buffer.getLong(at+32);
                require(start>=0&&file>=0&&length>=0&&file<=raw.length-length,"Invalid linked load extent");
                if(address>=start&&size>0&&address-start<=length-size){check(found==null,"AMBIGUOUS_LINKED_REGION","Multiple file mappings contain the selected region");
                    check((buffer.getInt(at+4)&5)==4,"UNSUPPORTED_LINKED_REGION","Layout regions must be readable, nonexecutable, file-backed data");int offset=Math.toIntExact(file+address-start);found=Arrays.copyOfRange(raw,offset,offset+size);}}
            check(found!=null,"UNSUPPORTED_LINKED_REGION","Selected data must be fully file-backed in one readable data mapping");return found;
        }
    }

    private Map<String,Object> observations(Map<String,Object> a,Map<String,Object> b){
        List<?> left=list(a.get("executions")),right=list(b.get("executions"));Map<Signature,Group> classes=new HashMap<>();Set<String> contexts=new HashSet<>();List<Map<String,Object>> witnesses=new ArrayList<>(),caseReports=new ArrayList<>();long violations=0;
        for(Object row:list(correspondence.get("cases"))){var paired=object(row);String input=(String)paired.get("logical_input");List<?> values=list(Json.read(input));List<Object> context=new ArrayList<>();context.add(values.get(0));
            for(int i=1;i<values.size();i++)if(!secrets.contains(i-1))context.add(List.of(i-1,values.get(i)));String publicKey=Json.write(context);contexts.add(publicKey);
            var ae=object(left.get(Math.toIntExact(n(paired,"original_case"))));var be=object(right.get(Math.toIntExact(n(paired,"rebuilt_case"))));
            List<Token> at=project(ae),bt=project(be);List<Long> al=at.stream().map(Token::line).toList(),bl=bt.stream().map(Token::line).toList();
            Signature signature=new Signature(publicKey,al);Group group=classes.get(signature);
            if(group==null)classes.put(signature,new Group(new Representative(input,bl,bt)));
            else{group.size++;if(!group.first.rebuilt.equals(bl)){violations++;if(witnesses.size()<32)witnesses.add(divergence(group.first,new Representative(input,bl,bt),al,publicKey));}}
            caseReports.add(Map.of("logical_input",input,"public_context",publicKey,"original_observation_sha256",traceHash(al),"candidate_observation_sha256",traceHash(bl),"original_tokens",al.size(),"candidate_tokens",bl.size()));
        }
        long equalPairs=0;for(Group group:classes.values())equalPairs+=group.size*(group.size-1)/2;
        return Map.of("policy","ordered-raw-virtual-lines","line_bytes",LINE,"preservation_holds",violations==0,"nonvacuous",equalPairs>0,"original_equal_secret_pairs",equalPairs,"public_contexts",contexts.size(),"original_equality_classes",classes.size(),"split_witness_count",violations,"witnesses",witnesses,"cases",caseReports);
    }
    private static List<Token> project(Map<String,Object> execution){List<Token> out=new ArrayList<>();for(Object row:list(execution.get("references"))){var access=object(row);long address=n(access,"address"),width=n(access,"width");
            require(address>=0&&width>0&&width<=8&&address<=Long.MAX_VALUE-width,"Invalid bounded access extent");long last=(address+width-1)/LINE;
            for(long line=address/LINE;line<=last;line++)out.add(new Token(line,access));}return out;}
    private static String traceHash(List<Long> lines){try{MessageDigest hash=MessageDigest.getInstance("SHA-256");ByteBuffer word=ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);for(long line:lines){word.clear();word.putLong(line);hash.update(word.array());}return HexFormat.of().formatHex(hash.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
    private static Map<String,Object> divergence(Representative first,Representative next,List<Long> original,String context){int at=0;while(at<first.rebuilt.size()&&at<next.rebuilt.size()&&first.rebuilt.get(at).equals(next.rebuilt.get(at)))at++;
        return Map.of("public_context",context,"first_input",first.input,"second_input",next.input,"original_observations_equal",true,"original_observation_sha256",traceHash(original),"first_different_token",at,"first",token(first.tokens,at),"second",token(next.tokens,at));}
    private static Object token(List<Token> tokens,int index){if(index>=tokens.size())return "end";Token token=tokens.get(index);return Map.of("line",token.line,"responsible_ip",token.access.get("ip"),"address",token.access.get("address"),"width",token.access.get("width"),"write",token.access.get("write"));}

    /** Recompute approval, then publish only the exact checked bytes to a new path. */
    public static Map<String,Object> publish(Path profile,Path output)throws IOException {
        BoundedTransformation gate=new BoundedTransformation(profile);Map<String,Object> result=gate.run();
        if(!Boolean.TRUE.equals(result.get("bounded_transformation_approved")))return result;
        Path target=output.toAbsolutePath().normalize();for(Path at=target;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at),"Publish path contains a symbolic link");
        require(!Files.exists(target),"Publication never overwrites an existing file");byte[] bytes;try(var in=Files.newInputStream(gate.candidatePath)){bytes=in.readNBytes(64*1024*1024+1);}
        require(bytes.length<=64*1024*1024&&gate.candidateHash.equals(GroupPlan.hash(bytes)),"Candidate changed after approval");
        boolean created=false,complete=false;
        try{try(FileChannel channel=FileChannel.open(target,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){created=true;ByteBuffer data=ByteBuffer.wrap(bytes);while(data.hasRemaining())channel.write(data);channel.force(true);}complete=true;}
        finally{if(created&&!complete)Files.deleteIfExists(target);}
        try{Files.setPosixFilePermissions(target,Files.getPosixFilePermissions(gate.candidatePath));}catch(UnsupportedOperationException ignored){}
        result.put("publication",Map.of("status","EXACT_APPROVED_CANDIDATE_PUBLISHED","output",target.toString(),"sha256",gate.candidateHash));return result;
    }
}
