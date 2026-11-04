package org.binarycachelab.analysis;

import java.util.List;
import java.util.Objects;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class PreservationChecker {

    public enum Status {
        SATISFIED_FOR_TESTED_PAIR,
        CANDIDATE_PRESERVATION_VIOLATION,
        FUNCTIONAL_OUTPUT_MISMATCH,
        ORIGINAL_OBSERVATIONS_DIFFER
    }

    public static final class Difference {

        private final boolean equal;
        private final long index;
        private final String left;
        private final String right;

        private Difference(
                boolean equal,
                long index,
                String left,
                String right
        ) {
            this.equal = equal;
            this.index = index;
            this.left = left;
            this.right = right;
        }

        public boolean isEqual() {
            return equal;
        }

        public long getIndex() {
            return index;
        }

        @Override
        public String toString() {
            if (equal) {
                return "Equal ordered cache-set observations.";
            }

            return "First difference at observation index " + index
                    + " (zero-based)"
                    + "\n  s1: " + left
                    + "\n  s2: " + right;
        }
    }

    public static final class Result {

        private final Status status;
        private final boolean functionalOutputsMatch;
        private final Difference original;
        private final Difference recompiled;

        private Result(
                Status status,
                boolean functionalOutputsMatch,
                Difference original,
                Difference recompiled
        ) {
            this.status = status;
            this.functionalOutputsMatch = functionalOutputsMatch;
            this.original = original;
            this.recompiled = recompiled;
        }

        public Status getStatus() {
            return status;
        }

        public Difference getOriginalDifference() {
            return original;
        }

        public Difference getRecompiledDifference() {
            return recompiled;
        }

        @Override
        public String toString() {
            return "Status: " + status
                    + "\nCorresponding functional outputs match: "
                    + functionalOutputsMatch
                    + "\nOriginal P:\n" + original
                    + "\nRecompiled P':\n" + recompiled;
        }
    }

    private final CacheConfig cache;

    public PreservationChecker(CacheConfig cache) {
        this.cache = Objects.requireNonNull(cache, "Cache must not be null.");
    }

    public Result check(
            List<MemoryAccess> originalS1,
            List<MemoryAccess> originalS2,
            List<MemoryAccess> recompiledS1,
            List<MemoryAccess> recompiledS2,
            boolean functionalOutputsMatch
    ) {
        validate(originalS1);
        validate(originalS2);
        validate(recompiledS1);
        validate(recompiledS2);

        Difference original = compare(originalS1, originalS2);
        Difference recompiled = compare(recompiledS1, recompiledS2);

        Status status;

        if (!functionalOutputsMatch) {
            status = Status.FUNCTIONAL_OUTPUT_MISMATCH;
        } else if (!original.isEqual()) {
            // The implication's antecedent is false for this pair.
            // This is not reported as successful preservation evidence.
            status = Status.ORIGINAL_OBSERVATIONS_DIFFER;
        } else if (!recompiled.isEqual()) {
            status = Status.CANDIDATE_PRESERVATION_VIOLATION;
        } else {
            status = Status.SATISFIED_FOR_TESTED_PAIR;
        }

        return new Result(
                status,
                functionalOutputsMatch,
                original,
                recompiled
        );
    }

    private void validate(List<MemoryAccess> events) {
        Objects.requireNonNull(events, "Trace must not be null.");

        long previousSequence = -1;
        Long threadId = null;

        for (MemoryAccess event : events) {
            Objects.requireNonNull(event, "Event must not be null.");

            if (event.getSourceBackend() != SourceBackend.SYNTHETIC) {
                throw new IllegalArgumentException(
                        "This stage accepts SYNTHETIC traces only."
                );
            }

            if (event.getSequence() <= previousSequence) {
                throw new IllegalArgumentException(
                        "Trace sequences must increase strictly."
                );
            }

            if (threadId == null) {
                threadId = event.getThreadId();
            } else if (threadId.longValue() != event.getThreadId()) {
                throw new IllegalArgumentException(
                        "This stage accepts one thread per trace."
                );
            }

            previousSequence = event.getSequence();
        }
    }

    private Difference compare(
            List<MemoryAccess> left,
            List<MemoryAccess> right
    ) {
        Cursor a = new Cursor(left);
        Cursor b = new Cursor(right);
        long index = 0;

        while (a.hasNext() && b.hasNext()) {
            if (a.getSet() != b.getSet()) {
                return new Difference(
                        false,
                        index,
                        a.describe(),
                        b.describe()
                );
            }

            a.advance();
            b.advance();
            index++;
        }

        if (a.hasNext() || b.hasNext()) {
            return new Difference(
                    false,
                    index,
                    a.describe(),
                    b.describe()
            );
        }

        return new Difference(true, -1, "", "");
    }

    /**
     * Emits one set per touched cache line, in ascending address order
     * within each event. This is an abstract normalization convention,
     * not a claim about hardware transaction order.
     */
    private final class Cursor {

        private final List<MemoryAccess> events;
        private int eventIndex;
        private long line;
        private long lastLine;

        private Cursor(List<MemoryAccess> events) {
            this.events = events;

            if (!events.isEmpty()) {
                loadEvent();
            }
        }

        private boolean hasNext() {
            return eventIndex < events.size();
        }

        private void loadEvent() {
            MemoryAccess event = events.get(eventIndex);

            line = cache.getCacheLine(event.getMemoryAddress());

            long lastAddress = event.getMemoryAddress()
                    + event.getAccessSizeBytes() - 1L;

            lastLine = cache.getCacheLine(lastAddress);
        }

        private long getSet() {
            return Long.remainderUnsigned(line, cache.getNumberOfSets());
        }

        private void advance() {
            if (line != lastLine) {
                line++;
                return;
            }

            eventIndex++;

            if (hasNext()) {
                loadEvent();
            }
        }

        private String describe() {
            if (!hasNext()) {
                return "<end of trace>";
            }

            MemoryAccess event = events.get(eventIndex);

            return String.format(
                    "set=%s, line=%s, event=%d, instruction=0x%X, memory=0x%X",
                    Long.toUnsignedString(getSet()),
                    Long.toUnsignedString(line),
                    event.getSequence(),
                    event.getInstructionAddress(),
                    event.getMemoryAddress()
            );
        }
    }
}