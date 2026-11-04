package org.binarycachelab.workflow;

import java.math.*;
import java.util.*;

/** Real Python workflow reports contain fractional command timings. */
public final class JsonNumbersTest {
    public static void main(String[] args){
        int checks=0;
        for(String number:List.of("0.453","-0.5","1e-9","2E+8","0.0","-2.3e-12")){
            Object value=Json.readEvidence(number);
            if(!(value instanceof BigDecimal)||new BigDecimal(number).compareTo((BigDecimal)value)!=0)throw new AssertionError(number);
            if(!Json.readEvidence(Json.write(value)).equals(value))throw new AssertionError("Round trip "+number);checks++;
        }
        for(String invalid:List.of("01","1.",".1","1e","1e+","--1","NaN","Infinity","[0.1.2]","{\"a\":1.0,\"a\":2}")){
            try{Json.readEvidence(invalid);throw new AssertionError("Accepted "+invalid);}catch(IllegalArgumentException expected){checks++;}
        }
        var report=Json.evidenceObject("{\"reproducibility\":{\"commands\":[{\"seconds\":0.453},{\"seconds\":1e-7}]},\"events\":222184,\"address\":18446744073709551615}");
        if(!(report.get("events") instanceof Long)||!(report.get("address") instanceof BigInteger))throw new AssertionError("Integer types/precision lost");checks++;
        if(!Json.readEvidence(Json.write(report)).equals(report))throw new AssertionError("Nested report round trip");checks++;
        for(Number value:List.of(Double.NaN,Double.POSITIVE_INFINITY,Float.NEGATIVE_INFINITY)){
            try{Json.write(value);throw new AssertionError("Wrote non-finite value");}catch(IllegalArgumentException expected){checks++;}
        }
        for(String input:List.of("0.453","18446744073709551615")){
            try{Json.read(input);throw new AssertionError("Analysis input parser widened");}catch(IllegalArgumentException expected){checks++;}
        }
        System.out.println("All "+checks+" JSON number checks passed.");
    }
}
