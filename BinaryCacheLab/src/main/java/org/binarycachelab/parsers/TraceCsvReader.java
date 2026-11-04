package org.binarycachelab.parsers;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.AccessType;
import org.binarycachelab.core.MemoryAccess.SourceBackend;

public final class TraceCsvReader {

    public static final String HEADER =
            "sequence,thread_id,instruction_address,memory_address,"
                    + "access_size_bytes,access_type,source_backend";

    public List<MemoryAccess> read(Path path) throws IOException {
        List<MemoryAccess> events = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(
                path,
                StandardCharsets.UTF_8
        )) {
            String header = reader.readLine();

            if (!HEADER.equals(header)) {
                throw new IOException(
                        path + ":1: Missing or incorrect CSV header. "
                                + "Expected: " + HEADER
                );
            }

            String row;
            long lineNumber = 1;
            long previousSequence = -1;

            while ((row = reader.readLine()) != null) {
                lineNumber++;

                try {
                    MemoryAccess event = parseRow(row);

                    if (event.getSequence() <= previousSequence) {
                        throw new IllegalArgumentException(
                                "Sequence numbers must increase strictly."
                        );
                    }

                    events.add(event);
                    previousSequence = event.getSequence();
                } catch (IllegalArgumentException exception) {
                    throw new IOException(
                            path + ":" + lineNumber + ": "
                                    + exception.getMessage(),
                            exception
                    );
                }
            }
        }

        return events;
    }

    private MemoryAccess parseRow(String row) {
        String[] fields = row.split(",", -1);

        if (fields.length != 7) {
            throw new IllegalArgumentException(
                    "Expected 7 fields, found " + fields.length + "."
            );
        }

        for (int i = 0; i < fields.length; i++) {
            fields[i] = fields[i].trim();

            if (fields[i].isEmpty()) {
                throw new IllegalArgumentException(
                        "Field " + (i + 1) + " must not be empty."
                );
            }
        }

        return new MemoryAccess(
                parseDecimal(fields[0], "sequence"),
                parseDecimal(fields[1], "thread_id"),
                parseAddress(fields[2], "instruction_address"),
                parseAddress(fields[3], "memory_address"),
                parseSize(fields[4]),
                AccessType.valueOf(fields[5]),
                SourceBackend.valueOf(fields[6])
        );
    }

    private long parseDecimal(String value, String field) {
        if (!value.matches("[0-9]+")) {
            throw new IllegalArgumentException(
                    field + " must be a non-negative decimal integer."
            );
        }

        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    field + " exceeds the supported integer range.",
                    exception
            );
        }
    }

    private int parseSize(String value) {
        long size = parseDecimal(value, "access_size_bytes");

        if (size == 0 || size > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "access_size_bytes must be between 1 and "
                            + Integer.MAX_VALUE + "."
            );
        }

        return (int) size;
    }

    private long parseAddress(String value, String field) {
        if (!value.matches("0[xX][0-9a-fA-F]{1,16}")) {
            throw new IllegalArgumentException(
                    field + " must be 0x followed by 1 to 16 hex digits."
            );
        }

        return Long.parseUnsignedLong(value.substring(2), 16);
    }
}