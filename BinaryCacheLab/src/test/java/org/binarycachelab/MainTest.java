package org.binarycachelab;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class MainTest {

    public static void main(String[] args) throws Exception {
        // Four bytes within one line.
        checkMapping(
                0x1000L,
                4,
                new long[][] {{64, 0, 1}}
        );

        // Exactly one full line: no extra line should be reported.
        checkMapping(
                0x1000L,
                64,
                new long[][] {{64, 0, 1}}
        );

        // Two bytes crossing a line boundary.
        checkMapping(
                0x103FL,
                2,
                new long[][] {{64, 0, 1}, {65, 1, 1}}
        );

        // Access spanning three lines.
        checkMapping(
                0x103FL,
                66,
                new long[][] {{64, 0, 1}, {65, 1, 1}, {66, 2, 1}}
        );

        // Set 63 wraps to set 0, and the tag changes.
        checkMapping(
                0x1FFFL,
                2,
                new long[][] {{127, 63, 1}, {128, 0, 2}}
        );

        // Final byte of the unsigned 64-bit address space.
        checkMapping(
                -1L,
                1,
                new long[][] {
                        {0x3FFFFFFFFFFFFFFL, 63, 0xFFFFFFFFFFFFFL}
                }
        );

        // Crossing Java's signed-long boundary is valid.
        checkMapping(
                Long.MAX_VALUE,
                2,
                new long[][] {
                        {0x1FFFFFFFFFFFFFFL, 63, 0x7FFFFFFFFFFFFL},
                        {0x200000000000000L, 0, 0x8000000000000L}
                }
        );

        System.out.println("All 7 Main mapping tests passed.");
    }

    private static void checkMapping(
            long address,
            int size,
            long[][] expected
    ) throws Exception {
        MemoryAccess event = new MemoryAccess(
                7,
                2,
                0x401120L,
                address,
                size,
                AccessType.READ,
                SourceBackend.SYNTHETIC
        );

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (PrintStream output = new PrintStream(buffer, true, "UTF-8")) {
            Main.printAccess(
                    event,
                    new CacheConfig(32768, 64, 8),
                    output
            );
        }

        String[] rows = buffer.toString("UTF-8")
                .trim()
                .split("\\r?\\n");

        check(
                rows.length == expected.length,
                "Wrong number of touched lines."
        );

        for (int i = 0; i < expected.length; i++) {
            String expectedRow = String.format(
                    "7,2,0x401120,0x%X,%d,READ,SYNTHETIC,%s,%s,%s",
                    address,
                    size,
                    Long.toUnsignedString(expected[i][0]),
                    Long.toUnsignedString(expected[i][1]),
                    Long.toUnsignedString(expected[i][2])
            );

            check(
                    rows[i].equals(expectedRow),
                    "Expected: " + expectedRow + " but got: " + rows[i]
            );
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}