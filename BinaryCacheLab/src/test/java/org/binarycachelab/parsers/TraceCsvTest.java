package org.binarycachelab.parsers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class TraceCsvTest {

    public static void main(String[] args) throws Exception {
        roundTripPreservesFields();
        emptyTraceRoundTrip();
        rejectsIncorrectHeader();
        rejectsMalformedRows();
        rejectsNonIncreasingSequences();
        preservesExistingFile();

        System.out.println("All 6 TraceCsv tests passed.");
    }

    private static void roundTripPreservesFields() throws Exception {
        List<MemoryAccess> expected = Arrays.asList(
                new MemoryAccess(
                        0, 0, 0x401120L, 0x1000L, 4,
                        AccessType.READ, SourceBackend.SYNTHETIC
                ),
                new MemoryAccess(
                        3, 2, 0x401128L, 0x1040L, 8,
                        AccessType.WRITE, SourceBackend.PIN
                ),
                new MemoryAccess(
                        9, 1, 0xFFFFFFFF80001000L,
                        0xFFFFFFFFFFFFFFF8L, 8,
                        AccessType.READ_WRITE, SourceBackend.GEM5
                )
        );

        Path directory = Files.createTempDirectory("binarycache-csv-");
        Path file = directory.resolve("trace.csv");

        try {
            new TraceCsvWriter().write(file, expected);

            List<MemoryAccess> actual = new TraceCsvReader().read(file);

            check(actual.size() == expected.size(), "Event count changed.");

            for (int i = 0; i < expected.size(); i++) {
                assertSameFields(expected.get(i), actual.get(i));
            }
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    private static void emptyTraceRoundTrip() throws Exception {
        Path directory = Files.createTempDirectory("binarycache-empty-");
        Path file = directory.resolve("empty.csv");

        try {
            new TraceCsvWriter().write(
                    file,
                    Collections.<MemoryAccess>emptyList()
            );

            check(
                    new TraceCsvReader().read(file).isEmpty(),
                    "Header-only trace should contain no events."
            );
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    private static void rejectsIncorrectHeader() throws Exception {
        expectReadFailure("", 1);
        expectReadFailure("incorrect,header\n", 1);
    }

    private static void rejectsMalformedRows() throws Exception {
        String[] invalidRows = {
                // Wrong field count.
                "0,0,0x401120,0x1000,4,READ",
                // Empty required field.
                "0,0,0x401120,,4,READ,SYNTHETIC",
                // Address missing its hexadecimal prefix.
                "0,0,401120,0x1000,4,READ,SYNTHETIC",
                // Address wider than 64 bits.
                "0,0,0x401120,0x10000000000000000,4,READ,SYNTHETIC",
                // Invalid size.
                "0,0,0x401120,0x1000,0,READ,SYNTHETIC",
                // Size too large for the model.
                "0,0,0x401120,0x1000,2147483648,READ,SYNTHETIC",
                // Unknown access type.
                "0,0,0x401120,0x1000,4,LOAD,SYNTHETIC",
                // Unknown backend.
                "0,0,0x401120,0x1000,4,READ,UNKNOWN",
                // Negative sequence.
                "-1,0,0x401120,0x1000,4,READ,SYNTHETIC",
                // Sequence exceeds signed-long range.
                "9223372036854775808,0,0x401120,0x1000,4,READ,SYNTHETIC",
                // Access wraps beyond the unsigned address space.
                "0,0,0x401120,0xffffffffffffffff,2,READ,SYNTHETIC"
        };

        for (String row : invalidRows) {
            expectReadFailure(TraceCsvReader.HEADER + "\n" + row + "\n", 2);
        }
    }

    private static void rejectsNonIncreasingSequences() throws Exception {
        String first = "1,0,0x401120,0x1000,4,READ,SYNTHETIC\n";
        String duplicate = "1,0,0x401128,0x1040,4,READ,SYNTHETIC\n";
        String decreasing = "0,0,0x401128,0x1040,4,READ,SYNTHETIC\n";

        expectReadFailure(
                TraceCsvReader.HEADER + "\n" + first + duplicate,
                3
        );
        expectReadFailure(
                TraceCsvReader.HEADER + "\n" + first + decreasing,
                3
        );

        Path directory = Files.createTempDirectory("binarycache-order-");
        Path file = directory.resolve("invalid.csv");

        try {
            MemoryAccess event = new MemoryAccess(
                    1, 0, 0x401120L, 0x1000L, 4,
                    AccessType.READ, SourceBackend.SYNTHETIC
            );

            boolean rejected = false;

            try {
                new TraceCsvWriter().write(
                        file,
                        Arrays.asList(event, event)
                );
            } catch (IllegalArgumentException expected) {
                rejected = true;
            }

            check(rejected, "Writer accepted duplicate sequences.");
            check(!Files.exists(file), "Invalid input created a file.");
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    private static void preservesExistingFile() throws Exception {
        Path file = Files.createTempFile("binarycache-existing-", ".csv");
        byte[] original = "existing content".getBytes(StandardCharsets.UTF_8);

        try {
            Files.write(file, original);
            boolean rejected = false;

            try {
                new TraceCsvWriter().write(
                        file,
                        Collections.<MemoryAccess>emptyList()
                );
            } catch (java.nio.file.FileAlreadyExistsException expected) {
                rejected = true;
            }

            check(rejected, "Writer should reject an existing file.");
            check(
                    Arrays.equals(original, Files.readAllBytes(file)),
                    "Existing file contents changed."
            );
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static void expectReadFailure(
            String content,
            int expectedLine
    ) throws Exception {
        Path file = Files.createTempFile("binarycache-invalid-", ".csv");

        try {
            Files.write(file, content.getBytes(StandardCharsets.UTF_8));

            try {
                new TraceCsvReader().read(file);
            } catch (IOException expected) {
                check(
                        expected.getMessage().startsWith(
                                file + ":" + expectedLine + ":"
                        ),
                        "Error did not identify the correct file and line."
                );
                return;
            }

            throw new AssertionError("Reader accepted invalid CSV.");
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static void assertSameFields(
            MemoryAccess expected,
            MemoryAccess actual
    ) {
        check(expected.getSequence() == actual.getSequence(), "Sequence changed.");
        check(expected.getThreadId() == actual.getThreadId(), "Thread changed.");
        check(
                expected.getInstructionAddress() == actual.getInstructionAddress(),
                "Instruction address changed."
        );
        check(
                expected.getMemoryAddress() == actual.getMemoryAddress(),
                "Memory address changed."
        );
        check(
                expected.getAccessSizeBytes() == actual.getAccessSizeBytes(),
                "Access size changed."
        );
        check(
                expected.getAccessType() == actual.getAccessType(),
                "Access type changed."
        );
        check(
                expected.getSourceBackend() == actual.getSourceBackend(),
                "Backend changed."
        );
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}