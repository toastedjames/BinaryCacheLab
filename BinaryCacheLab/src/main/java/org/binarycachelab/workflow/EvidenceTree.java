package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.binarycachelab.workflow.LabConfig.require;

/** Read-only checksummed evidence tree; hashes attest integrity, not publisher/execution authenticity. */
public final class EvidenceTree {
    public final Path root;public final Map<String,String> hashes=new LinkedHashMap<>();
    public EvidenceTree(Path root)throws IOException{
        require(!Files.isSymbolicLink(root),"Symlink evidence root unsupported");this.root=root.toRealPath();
        Path manifest=path("SHA256SUMS");
        for(String line:Files.readAllLines(manifest)){
            var match=java.util.regex.Pattern.compile("([0-9a-f]{64})  \\./(.+)").matcher(line);
            require(match.matches(),"Malformed SHA256SUMS row");String name=match.group(2);
            require(!name.equals("SHA256SUMS")&&!name.equals("completion.json"),"Self/finalization marker cannot be in evidence manifest");
            require(hashes.putIfAbsent(name,match.group(1))==null,"Duplicate evidence entry: "+name);
            require(Stage3Engine.digest(path(name)).equals(match.group(1)),"Checksum mismatch: "+name);
        }
        require(!hashes.isEmpty(),"Empty evidence manifest");
        try(var files=Files.walk(this.root)){
            for(Path file:files.toList()){
                require(!Files.isSymbolicLink(file),"Symlink inside evidence tree");
                if(Files.isRegularFile(file)){String name=this.root.relativize(file).toString().replace('\\','/');
                    require(name.equals("SHA256SUMS")||name.equals("completion.json")||hashes.containsKey(name),"Unmanifested evidence file: "+name);}
            }
        }
        if(Files.exists(this.root.resolve("completion.json"))){var seal=Json.object(Files.readString(path("completion.json")));
            require("bcl-evidence-seal-1".equals(seal.get("schema"))&&Stage3Engine.digest(manifest).equals(seal.get("manifest_sha256")),"Invalid evidence finalization marker");}
    }
    public Path path(String name)throws IOException{
        require(!name.isBlank()&&!name.contains("\\")&&!name.contains(":")&&!name.startsWith("/"),"Unsafe evidence path");
        Path result=root;
        for(String part:name.split("/",-1)){require(!part.isEmpty()&&!part.equals(".")&&!part.equals(".."),"Unsafe evidence path component");
            result=result.resolve(part);require(!Files.isSymbolicLink(result),"Symlink evidence artifact");}
        require(Files.isRegularFile(result)&&result.toRealPath().startsWith(root),"Missing/escaping evidence artifact: "+name);return result;
    }
    public Path covered(String name)throws IOException{require(hashes.containsKey(name),"Uncovered evidence artifact: "+name);return path(name);}
    public String text(String name)throws IOException{return Files.readString(covered(name));}
    public Map<String,Object> object(String name)throws IOException{return Json.object(text(name));}
}
