package org.binarycachelab.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;
import org.binarycachelab.analysis.PreservationChecker.Result;
import org.binarycachelab.analysis.PreservationChecker.Status;

public final class PreservationCheckerTest {

    private static final PreservationChecker CHECKER =
            new PreservationChecker(new CacheConfig(32768, 64, 8));

    public static void main(String[] args) {
        allowsChangedButEqualRecompiledObservations();
        detectsIntroducedDifference();
        detectsChangedOrderWithEqualCounts();
        detectsMissingObservation();
        rejectsFunctionalMismatch();
        distinguishesFalseAntecedent();
        handlesEmptyTraces();
        expandsCrossingAccesses();
        ignoresInstructionAddressesAndTags();
        handlesUnsignedAddresses();
        rejectsMultipleThreads();
        rejectsRealBackendForThisStage();
        rejectsDuplicateSequences();

        System.out.println("All 13 PreservationChecker tests passed.");
    }

    private static void allowsChangedButEqualRecompiledObservations() {
        Result result = check(
                trace(1, 3, 7),
                trace(1, 3, 7),
                trace(3, 10, 12),
                trace(3, 10, 12),
                true
        );

        expectStatus(result, Status.SATISFIED_FOR_TESTED_PAIR);
    }

    private static void detectsIntroducedDifference() {
        Result result = check(
                trace(1, 3, 7),
                trace(1, 3, 7),
                trace(3, 10, 12),
                trace(3, 20, 12),
                true
        );

        expectStatus(result, Status.CANDIDATE_PRESERVATION_VIOLATION);

        require(
                result.getRecompiledDifference().getIndex() == 1,
                "Expected difference at index 1."
        );
    }

    private static void detectsChangedOrderWithEqualCounts() {
        Result result = check(
                trace(0),
                trace(0),
                trace(1, 2, 1),
                trace(1, 1, 2),
                true
        );

        expectStatus(result, Status.CANDIDATE_PRESERVATION_VIOLATION);
    }

    private static void detectsMissingObservation() {
        Result result = check(
                trace(0),
                trace(0),
                trace(1, 2),
                trace(1),
                true
        );

        expectStatus(result, Status.CANDIDATE_PRESERVATION_VIOLATION);

        require(
                result.getRecompiledDifference().getIndex() == 1,
                "Expected missing observation at index 1."
        );
        require(
                result.getRecompiledDifference().toString().contains("<end of trace>"),
                "Expected an end-of-trace witness."
        );
    }

    private static void rejectsFunctionalMismatch() {
        // Functional mismatch takes precedence even when traces differ.
        Result result = check(
                trace(0),
                trace(0),
                trace(1),
                trace(2),
                false
        );

        expectStatus(result, Status.FUNCTIONAL_OUTPUT_MISMATCH);
    }

    private static void distinguishesFalseAntecedent() {
        Result result = check(
                trace(1),
                trace(2),
                trace(3),
                trace(4),
                true
        );

        expectStatus(result, Status.ORIGINAL_OBSERVATIONS_DIFFER);
    }

    private static void handlesEmptyTraces() {
        List<MemoryAccess> empty = Collections.emptyList();

        expectStatus(
                check(empty, empty, empty, empty, true),
                Status.SATISFIED_FOR_TESTED_PAIR
        );

        expectStatus(
                check(empty, empty, empty, trace(1), true),
                Status.CANDIDATE_PRESERVATION_VIOLATION
        );
    }

    private static void expandsCrossingAccesses() {
        List<MemoryAccess> crossing = Collections.singletonList(
                event(0, 0, 0x401120L, 0x103FL, 2, SourceBackend.SYNTHETIC)
        );

        // One two-line event equals two single-line events in this model.
        List<MemoryAccess> separate = trace(0, 1);

        expectStatus(
                check(crossing, separate, crossing, separate, true),
                Status.SATISFIED_FOR_TESTED_PAIR
        );
    }

    private static void ignoresInstructionAddressesAndTags() {
        List<MemoryAccess> a = Collections.singletonList(
                event(0, 0, 0x401120L, 0x1000L, 4, SourceBackend.SYNTHETIC)
        );

        List<MemoryAccess> b = Collections.singletonList(
                new MemoryAccess(
                        9, 5, 0x501990L, 0x2000L, 4,
                        AccessType.WRITE, SourceBackend.SYNTHETIC
                )
        );

        // Different lines, tags, instructions, access types and thread IDs,
        // but both emit set 0. Each individual trace has only one thread.
        expectStatus(
                check(a, b, a, b, true),
                Status.SATISFIED_FOR_TESTED_PAIR
        );
    }

    private static void handlesUnsignedAddresses() {
        List<MemoryAccess> finalByte = Collections.singletonList(
                event(0, 0, 0x401120L, -1L, 1, SourceBackend.SYNTHETIC)
        );

        expectStatus(
                check(finalByte, trace(63), finalByte, trace(63), true),
                Status.SATISFIED_FOR_TESTED_PAIR
        );
    }

    private static void rejectsMultipleThreads() {
        List<MemoryAccess> multiple = Arrays.asList(
                event(0, 0, 0, 0, 1, SourceBackend.SYNTHETIC),
                event(1, 1, 0, 64, 1, SourceBackend.SYNTHETIC)
        );

        expectRejected(() -> check(
                multiple, trace(0), trace(0), trace(0), true
        ));
    }

    private static void rejectsRealBackendForThisStage() {
        List<MemoryAccess> pin = Collections.singletonList(
                event(0, 0, 0, 0, 1, SourceBackend.PIN)
        );

        expectRejected(() -> check(
                pin, trace(0), trace(0), trace(0), true
        ));
    }

    private static void rejectsDuplicateSequences() {
        List<MemoryAccess> duplicate = Arrays.asList(
                event(0, 0, 0, 0, 1, SourceBackend.SYNTHETIC),
                event(0, 0, 0, 64, 1, SourceBackend.SYNTHETIC)
        );

        expectRejected(() -> check(
                duplicate, trace(0), trace(0), trace(0), true
        ));
    }

    private static Result check(
            List<MemoryAccess> p1,
            List<MemoryAccess> p2,
            List<MemoryAccess> pp1,
            List<MemoryAccess> pp2,
            boolean outputsMatch
    ) {
        return CHECKER.check(p1, p2, pp1, pp2, outputsMatch);
    }

    private static List<MemoryAccess> trace(int... sets) {
        List<MemoryAccess> result = new ArrayList<>();

        for (int i = 0; i < sets.length; i++) {
            result.add(event(
                    i,
                    0,
                    0x401000L + i * 4L,
                    sets[i] * 64L,
                    1,
                    SourceBackend.SYNTHETIC
            ));
        }

        return result;
    }

    private static MemoryAccess event(
            long sequence,
            long thread,
            long instruction,
            long address,
            int size,
            SourceBackend backend
    ) {
        return new MemoryAccess(
                sequence, thread, instruction, address, size,
                AccessType.READ, backend
        );
    }

    private static void expectStatus(Result result, Status expected) {
        require(
                result.getStatus() == expected,
                "Expected " + expected + " but got " + result.getStatus()
        );
    }

    private static void expectRejected(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }

        throw new AssertionError("Expected invalid trace to be rejected.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}