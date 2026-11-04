package org.binarycachelab.core;

import org.binarycachelab.cache.CacheAddress;
import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class MemoryAccessTest {

    public static void main(String[] args) {
        preservesFields();
        classifiesAccessTypes();
        rejectsInvalidFields();
        handlesUnsignedAddresses();
        rejectsAddressWraparound();
        mapsMemoryAddressToCache();

        System.out.println("All 6 MemoryAccess tests passed.");
    }

    private static void preservesFields() {
        MemoryAccess access = new MemoryAccess(
                7,
                2,
                0x401120L,
                0x1040L,
                4,
                AccessType.READ,
                SourceBackend.SYNTHETIC
        );

        check(access.getSequence() == 7, "Incorrect sequence.");
        check(access.getThreadId() == 2, "Incorrect thread ID.");
        check(
                access.getInstructionAddress() == 0x401120L,
                "Incorrect instruction address."
        );
        check(
                access.getMemoryAddress() == 0x1040L,
                "Incorrect memory address."
        );
        check(access.getAccessSizeBytes() == 4, "Incorrect access size.");
        check(access.getAccessType() == AccessType.READ, "Incorrect type.");
        check(
                access.getSourceBackend() == SourceBackend.SYNTHETIC,
                "Incorrect backend."
        );
    }

    private static void classifiesAccessTypes() {
        MemoryAccess read = access(0x1000L, 4, AccessType.READ);
        MemoryAccess write = access(0x1000L, 4, AccessType.WRITE);
        MemoryAccess both = access(0x1000L, 4, AccessType.READ_WRITE);

        check(read.isRead() && !read.isWrite(), "Incorrect READ behavior.");
        check(!write.isRead() && write.isWrite(), "Incorrect WRITE behavior.");
        check(both.isRead() && both.isWrite(), "Incorrect READ_WRITE behavior.");
    }

    private static void rejectsInvalidFields() {
        expectThrows(
                IllegalArgumentException.class,
                () -> new MemoryAccess(
                        -1, 0, 0, 0, 4,
                        AccessType.READ, SourceBackend.PIN
                )
        );

        expectThrows(
                IllegalArgumentException.class,
                () -> new MemoryAccess(
                        0, -1, 0, 0, 4,
                        AccessType.READ, SourceBackend.PIN
                )
        );

        expectThrows(
                IllegalArgumentException.class,
                () -> access(0, 0, AccessType.READ)
        );

        expectThrows(
                IllegalArgumentException.class,
                () -> access(0, -4, AccessType.READ)
        );

        expectThrows(
                NullPointerException.class,
                () -> access(0, 4, null)
        );

        expectThrows(
                NullPointerException.class,
                () -> new MemoryAccess(
                        0, 0, 0, 0, 4,
                        AccessType.READ, null
                )
        );
    }

    private static void handlesUnsignedAddresses() {
        MemoryAccess highAddress = new MemoryAccess(
                0,
                0,
                0xFFFFFFFF80001000L,
                0xFFFFFFFFFFFFFFF8L,
                8,
                AccessType.READ,
                SourceBackend.GEM5
        );

        check(
                highAddress.getInstructionAddress() == 0xFFFFFFFF80001000L,
                "Instruction address bits changed."
        );
        check(
                highAddress.getMemoryAddress() == 0xFFFFFFFFFFFFFFF8L,
                "Memory address bits changed."
        );

        // Crossing the signed-long boundary is valid in unsigned space.
        MemoryAccess crossing = access(
                Long.MAX_VALUE,
                2,
                AccessType.READ
        );

        check(
                crossing.getMemoryAddress() == Long.MAX_VALUE,
                "Signed-boundary address changed."
        );
    }

    private static void rejectsAddressWraparound() {
        expectThrows(
                IllegalArgumentException.class,
                () -> access(0xFFFFFFFFFFFFFFFCL, 8, AccessType.READ)
        );

        // One byte at the final unsigned address is valid.
        MemoryAccess finalByte = access(-1L, 1, AccessType.READ);

        check(
                finalByte.getMemoryAddress() == -1L,
                "Final unsigned address changed."
        );
    }

    private static void mapsMemoryAddressToCache() {
        CacheConfig cache = new CacheConfig(32768, 64, 8);
        MemoryAccess access = access(0x1040L, 4, AccessType.READ);

        CacheAddress mapped = new CacheAddress(
                access.getMemoryAddress(),
                cache
        );

        check(mapped.getCacheLine() == 65, "Expected cache line 65.");
        check(mapped.getCacheSet() == 1, "Expected cache set 1.");
        check(mapped.getTag() == 1, "Expected tag 1.");
    }

    private static MemoryAccess access(
            long memoryAddress,
            int size,
            AccessType type
    ) {
        return new MemoryAccess(
                0,
                0,
                0x401120L,
                memoryAddress,
                size,
                type,
                SourceBackend.SYNTHETIC
        );
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void expectThrows(
            Class<? extends Throwable> expected,
            Runnable action
    ) {
        try {
            action.run();
        } catch (Throwable actual) {
            if (expected.isInstance(actual)) {
                return;
            }

            throw new AssertionError(
                    "Expected " + expected.getSimpleName()
                            + " but got " + actual.getClass().getSimpleName(),
                    actual
            );
        }

        throw new AssertionError(
                "Expected " + expected.getSimpleName()
                        + " but no exception was thrown."
        );
    }
}