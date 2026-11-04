package org.binarycachelab.analysis;

import java.util.*;
import org.binarycachelab.core.MemoryAccess;

public final class PiePreservationCheckTest {
    private static MemoryAccess event(long address, int size) {
        return new MemoryAccess(0, 0, 0, address, size,
                MemoryAccess.AccessType.READ, MemoryAccess.SourceBackend.PIN);
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
    }
    public static void main(String[] args) {
        equal(Arrays.asList(257L), PiePreservationCheck.project(
                Arrays.asList(event(0x104044, 4)), 0x100000, 0x4040, 4096, 64));
        equal(Arrays.asList(257L, 258L), PiePreservationCheck.project(
                Arrays.asList(event(0x404f, 50)), 0, 0x4040, 4096, 64));
        equal(Arrays.asList(257L), PiePreservationCheck.project(
                Arrays.asList(event(0x403f, 2), event(0x700000, 8)), 0, 0x4040, 4096, 64));
        equal(Arrays.asList(257L, 257L), PiePreservationCheck.project(
                Arrays.asList(event(0x4040, 4), event(0x4044, 4)), 0, 0x4040, 4096, 64));
        try {
            PiePreservationCheck.project(Collections.emptyList(), 1, 0x4040, 4096, 64);
            throw new AssertionError("Accepted unaligned bias");
        } catch (IllegalArgumentException expected) { }
        List<Long> a = Arrays.asList(1L), b = Arrays.asList(9L), c = Arrays.asList(10L);
        equal("SATISFIED_FOR_TESTED_PAIR", PiePreservationCheck.classify(a, a, b, b));
        equal("CANDIDATE_PRESERVATION_VIOLATION", PiePreservationCheck.classify(a, a, b, c));
        equal("ORIGINAL_OBSERVATIONS_DIFFER", PiePreservationCheck.classify(a, b, b, b));
        MemoryAccess crossing = event(0x407f, 2);
        List<PiePreservationCheck.Token> tokens = PiePreservationCheck.projectTokens(
                Arrays.asList(crossing), 0, 0x4040, 128, 64);
        equal(2, tokens.size());
        if (tokens.get(0).event != crossing || tokens.get(1).event != crossing) {
            throw new AssertionError("Lost originating event for expanded access");
        }
        List<PiePreservationCheck.Token> one = tokens.subList(0, 1);
        equal(1, PiePreservationCheck.firstDifference(one, tokens));
        equal("END_OF_SEQUENCE (no event/instruction at this position)",
                PiePreservationCheck.witness(one, 1, 64));
        List<PiePreservationCheck.Token> relocated = PiePreservationCheck.projectTokens(
                Arrays.asList(event(0x10407f, 2)), 0x100000, 0x4040, 128, 64);
        equal(-1, PiePreservationCheck.firstDifference(tokens, relocated));
        List<PiePreservationCheck.Token> anotherLine = PiePreservationCheck.projectTokens(
                Arrays.asList(event(0x5040, 4)), 0, 0x5040, 128, 64);
        equal(0, PiePreservationCheck.firstDifference(one, anotherLine));
        MemoryAccess instructionEvent = new MemoryAccess(4, 0, 0x10115d, 0x104080, 4,
                MemoryAccess.AccessType.READ, MemoryAccess.SourceBackend.PIN);
        List<PiePreservationCheck.Token> located = PiePreservationCheck.projectTokens(
                Arrays.asList(instructionEvent), 0x100000, 0x4080, 128, 64);
        String witness = PiePreservationCheck.witness(located, 0, 64);
        if (!witness.contains("ip-link=0x115d") || !witness.contains("csv-row=6")
                || !witness.contains("line=258")) throw new AssertionError(witness);
        System.out.println("All 13 PIE preservation projection/verdict/witness tests passed.");
    }
}
