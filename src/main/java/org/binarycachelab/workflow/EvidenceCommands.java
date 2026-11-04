package org.binarycachelab.workflow;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.binarycachelab.analysis.*;
import static org.binarycachelab.workflow.LabConfig.require;

public final class EvidenceCommands {
    private EvidenceCommands(){}
    public static int run(String[] args)throws IOException{
        require(args.length>=2,"Expected input path");Path input=Path.of(args[1]),report=null;int repetitions=3;boolean seenRepetitions=false;
        for(int i=2;i<args.length;i++){
            if(args[i].equals("--report")&&i+1<args.length&&report==null)report=Path.of(args[++i]);
            else if(args[0].equals("pin-check-java")&&args[i].equals("--repetitions")&&i+1<args.length&&!seenRepetitions){repetitions=Integer.parseInt(args[++i]);seenRepetitions=true;}
            else throw new IllegalArgumentException("Unknown/incomplete option: "+args[i]);
        }
        Object value;int code=0;
        if(args[0].equals("verify"))value=ExperimentVerifier.verify(input);
        else if(args[0].equals("verify-references"))value=ExperimentVerifier.references(input);
        else if(args[0].equals("assess-references")){var assessment=ExperimentVerifier.assessReferences(input);value=assessment;code="INCONCLUSIVE_REFERENCE_COVERAGE".equals(assessment.get("decision"))?6:7;}
        else{var result=WholeTraceAnalysis.evaluate(input,repetitions);value=result.report();code=result.exit();}
        String json=Json.write(value)+"\n";
        if(report!=null){Path absolute=report.toAbsolutePath().normalize();
            for(Path p=absolute;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p),"Symlink report path");
            Path actual=absolute.getParent().toRealPath().resolve(absolute.getFileName());require(!actual.startsWith(input.toRealPath()),"Save report outside evidence tree");
            Files.writeString(absolute,json,StandardOpenOption.CREATE_NEW);}
        System.out.print(json);return code;
    }
}
