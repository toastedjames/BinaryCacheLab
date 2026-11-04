package org.binarycachelab.analysis;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class TableTraceCheckTest {

    private static final CacheConfig CACHE =
            new CacheConfig(32768, 64, 8);

    public static void main(String[] args) {
        // One access inside the region.
        expect(0x1000L, 4096, events(access(0, 0x1040L, 4)), 65L);

        // Two-byte access crossing a cache-line boundary.
        expect(0x1000L, 4096, events(access(0, 0x103FL, 2)), 64L, 65L);

        // Exclude a stack access.
        expect(
                0x1000L, 4096,
                events(
                        access(0, 0x1000L, 4),
                        access(1, 0x7FFF00000000L, 8)
                ),
                64L
        );

        // Preserve repetitions and order.
        expect(
                0x1000L, 4096,
                events(
                        access(0, 0x1040L, 4),
                        access(1, 0x1000L, 4),
                        access(2, 0x1040L, 4)
                ),
                65L, 64L, 65L
        );

        // Include only the part intersecting the selected region.
        expect(0x1040L, 64, events(access(0, 0x103FL, 2)), 65L);

        // Addresses outside the region contribute no observations.
        expect(0x1000L, 64, events(access(0, 0x1040L, 4)));

        // Preserve distinct lines even when their cache sets are equal.
        expect(
                0x1000L, 8192,
                events(
                        access(0, 0x1000L, 4),
                        access(1, 0x2000L, 4)
                ),
                64L, 128L
        );

        // Final byte of the unsigned address space.
        expect(
                -64L, 64,
                events(access(0, -1L, 1)),
                0x3FFFFFFFFFFFFFFL
        );

        boolean rejected = false;

        try {
            TableTraceCheck.project(
                    Collections.<MemoryAccess>emptyList(),
                    -1L,
                    2,
                    CACHE
            );
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        if (!rejected) {
            throw new AssertionError("Wrapping region was accepted.");
        }

        System.out.println("All 9 TableTraceCheck projection tests passed.");
    }

    private static MemoryAccess access(long sequence, long address, int size) {
        return new MemoryAccess(
                sequence, 0, 0x40115FL, address, size,
                AccessType.READ, SourceBackend.PIN
        );
    }

    private static List<MemoryAccess> events(MemoryAccess... events) {
        return Arrays.asList(events);
    }

    private static void expect(
            long base,
            long bytes,
            List<MemoryAccess> events,
            Long... expected
    ) {
        List<Long> actual = TableTraceCheck.project(
                events, base, bytes, CACHE
        );

        if (!actual.equals(Arrays.asList(expected))) {
            throw new AssertionError(
                    "Expected " + Arrays.asList(expected) + " but got " + actual
            );
        }
    }
}