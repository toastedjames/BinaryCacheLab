package org.binarycachelab.parsers;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.binarycachelab.core.MemoryAccess;

public final class TraceCsvWriter {

    public void write(
            Path path,
            List<MemoryAccess> events
    ) throws IOException {
        Objects.requireNonNull(path, "Path must not be null.");
        Objects.requireNonNull(events, "Events must not be null.");

        // Validate before creating the output file.
        List<MemoryAccess> snapshot = new ArrayList<>(events);
        long previousSequence = -1;

        for (MemoryAccess event : snapshot) {
            Objects.requireNonNull(event, "Event must not be null.");

            if (event.getSequence() <= previousSequence) {
                throw new IllegalArgumentException(
                        "Sequence numbers must increase strictly."
                );
            }

            previousSequence = event.getSequence();
        }

        try (BufferedWriter writer = Files.newBufferedWriter(
                path,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        )) {
            writer.write(TraceCsvReader.HEADER);
            writer.newLine();

            for (MemoryAccess event : snapshot) {
                writer.write(Long.toString(event.getSequence()));
                writer.write(',');
                writer.write(Long.toString(event.getThreadId()));
                writer.write(',');
                writer.write(hex(event.getInstructionAddress()));
                writer.write(',');
                writer.write(hex(event.getMemoryAddress()));
                writer.write(',');
                writer.write(Integer.toString(event.getAccessSizeBytes()));
                writer.write(',');
                writer.write(event.getAccessType().name());
                writer.write(',');
                writer.write(event.getSourceBackend().name());
                writer.newLine();
            }
        }
    }

    private String hex(long address) {
        return "0x" + Long.toUnsignedString(address, 16);
    }
}