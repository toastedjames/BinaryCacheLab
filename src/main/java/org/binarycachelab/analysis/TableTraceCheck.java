package org.binarycachelab.analysis;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.core.MemoryAccess.SourceBackend;
import org.binarycachelab.parsers.TraceCsvReader;

public final class TableTraceCheck {

    private static final CacheConfig CACHE =
            new CacheConfig(32768, 64, 8);

    private static final long TABLE_BYTES = 4096;

    private static final Pattern TABLE_SYMBOL = Pattern.compile(
            "^([0-9a-fA-F]+)\\s+\\S\\s+table\\s*$"
    );

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println(
                    "Usage: java -cp build/classes "
                            + "org.binarycachelab.analysis.TableTraceCheck "
                            + "<batch-directory>"
            );
            System.exit(2);
            return;
        }

        try {
            checkBatch(Paths.get(args[0]));
        } catch (IOException | IllegalArgumentException exception) {
            System.err.println("INCONCLUSIVE: " + exception.getMessage());
            System.exit(2);
        }
    }

    private static void checkBatch(Path batch) throws IOException {
        List<List<Long>> secret0 = new ArrayList<>();
        List<List<Long>> secret1 = new ArrayList<>();

        byte[] firstHashes = null;
        Long firstBase = null;

        for (int repeat = 0; repeat < 3; repeat++) {
            Path experiment = batch.resolve("repeat-" + repeat);

            byte[] hashes = Files.readAllBytes(
                    experiment.resolve("hashes.txt")
            );

            if (hashes.length == 0) {
                throw new IOException("Empty artifact hash manifest.");
            }

            if (firstHashes == null) {
                firstHashes = hashes;
            } else if (!Arrays.equals(firstHashes, hashes)) {
                throw new IOException(
                        "Recorded artifact hashes differ across repetitions."
                );
            }

            long base = tableAddress(experiment.resolve("symbols.txt"));

            if (firstBase == null) {
                firstBase = base;
            } else if (firstBase.longValue() != base) {
                throw new IOException(
                        "Table address changed across repetitions."
                );
            }

            secret0.add(readObservation(
                    experiment.resolve("secret-0"), base
            ));

            secret1.add(readObservation(
                    experiment.resolve("secret-1"), base
            ));
        }

        boolean stable0 = allEqual(secret0);
        boolean stable1 = allEqual(secret1);

        System.out.println("Table-only observation experiment");
        System.out.println(CACHE);
        System.out.printf(
                "Region: base=0x%X, bytes=%d%n",
                firstBase.longValue(),
                TABLE_BYTES
        );
        System.out.println(
                "Observation: ordered absolute virtual cache-line numbers."
        );
        System.out.println(
                "Each event contributes its in-region touched lines; "
                        + "repeated accesses are retained."
        );
        System.out.println(
                "Excluded: accesses outside table, instruction addresses, "
                        + "access types, and event boundaries."
        );

        for (int repeat = 0; repeat < 3; repeat++) {
            System.out.println(
                    "repeat-" + repeat + " secret=0 lines="
                            + unsignedList(secret0.get(repeat))
                            + " sets=" + sets(secret0.get(repeat))
            );
            System.out.println(
                    "repeat-" + repeat + " secret=1 lines="
                            + unsignedList(secret1.get(repeat))
                            + " sets=" + sets(secret1.get(repeat))
            );
        }

        System.out.println("Secret 0 stable across repeats: " + stable0);
        System.out.println("Secret 1 stable across repeats: " + stable1);

        if (!stable0 || !stable1) {
            throw new IOException(
                    "Same-input observations are unstable; "
                            + "do not attribute differences to the secret."
            );
        }

        boolean sameLines = secret0.get(0).equals(secret1.get(0));
        boolean sameSets = sets(secret0.get(0)).equals(sets(secret1.get(0)));

        System.out.println("Across-secret line sequences equal: " + sameLines);
        System.out.println("Across-secret set sequences equal: " + sameSets);

        System.out.println(
                sameLines
                        ? "NO_TABLE_LINE_DIFFERENCE_OBSERVED"
                        : "INPUT_DEPENDENT_TABLE_LINE_BEHAVIOR"
        );

        System.out.println(
                "Scope: this benchmark and these six executions only. "
                        + "This is not a P/P' preservation result."
        );
    }

    private static List<Long> readObservation(Path run, long base)
            throws IOException {
        Properties metadata = new Properties();

        try (Reader reader = Files.newBufferedReader(
                run.resolve("trace.properties"),
                StandardCharsets.UTF_8
        )) {
            metadata.load(reader);
        }

        require(metadata, "status", "complete");
        require(metadata, "backend", "PIN");
        require(metadata, "scope", "main-executable-named-routine-only");
        require(metadata, "routine", "secret_lookup");
        require(metadata, "address_space", "virtual");
        require(metadata, "event_semantics", "before-instruction");
        require(metadata, "read_modify_write", "separate-read-then-write");
        require(metadata, "application_threads", "1");
        require(metadata, "routine_entries", "1");
        require(metadata, "return_instructions_reached", "1");
        require(metadata, "application_exit", "0");

        for (String mode : Arrays.asList("native", "pin")) {
            String exit = new String(
                    Files.readAllBytes(run.resolve(mode + ".exit")),
                    StandardCharsets.UTF_8
            ).trim();

            if (!exit.equals("0")) {
                throw new IOException("Nonzero execution status in " + run);
            }

            byte[] stdout = Files.readAllBytes(
                    run.resolve(mode + ".stdout")
            );

            if (!Arrays.equals(
                    stdout,
                    "7\n".getBytes(StandardCharsets.UTF_8)
            )) {
                throw new IOException("Unexpected functional output in " + run);
            }

            if (Files.size(run.resolve(mode + ".stderr")) != 0) {
                throw new IOException("Nonempty stderr in " + run);
            }
        }

        List<MemoryAccess> events =
                new TraceCsvReader().read(run.resolve("trace.csv"));

        long recordedCount = Long.parseLong(
                metadata.getProperty("events", "-1")
        );

        if (recordedCount != events.size()) {
            throw new IOException("CSV/metadata event-count mismatch in " + run);
        }

        Long thread = null;

        for (MemoryAccess event : events) {
            if (event.getSourceBackend() != SourceBackend.PIN) {
                throw new IOException("Non-PIN event in " + run);
            }

            if (thread == null) {
                thread = event.getThreadId();
            } else if (thread.longValue() != event.getThreadId()) {
                throw new IOException("Multiple trace threads in " + run);
            }
        }

        List<Long> observation = project(events, base, TABLE_BYTES, CACHE);

        if (observation.isEmpty()) {
            throw new IOException("No table accesses found in " + run);
        }

        return observation;
    }

    /**
     * Select bytes intersecting [base, base + bytes), then emit every
     * touched cache line in address order within each event.
     *
     * Addresses are unsigned long bit patterns.
     */
    public static List<Long> project(
            List<MemoryAccess> events,
            long base,
            long bytes,
            CacheConfig cache
    ) {
        if (bytes <= 0) {
            throw new IllegalArgumentException("Region size must be positive.");
        }

        long end = base + bytes - 1;

        if (Long.compareUnsigned(end, base) < 0) {
            throw new IllegalArgumentException("Region wraps address space.");
        }

        List<Long> lines = new ArrayList<>();

        for (MemoryAccess event : events) {
            long start = event.getMemoryAddress();
            long last = start + event.getAccessSizeBytes() - 1L;

            if (Long.compareUnsigned(last, base) < 0
                    || Long.compareUnsigned(start, end) > 0) {
                continue;
            }

            long firstInside =
                    Long.compareUnsigned(start, base) < 0 ? base : start;

            long lastInside =
                    Long.compareUnsigned(last, end) > 0 ? end : last;

            long firstLine = cache.getCacheLine(firstInside);
            long lastLine = cache.getCacheLine(lastInside);

            for (long line = firstLine; ; line++) {
                lines.add(line);

                if (line == lastLine) {
                    break;
                }
            }
        }

        return lines;
    }

    private static long tableAddress(Path symbols) throws IOException {
        Long address = null;

        for (String line : Files.readAllLines(symbols, StandardCharsets.UTF_8)) {
            Matcher match = TABLE_SYMBOL.matcher(line);

            if (match.matches()) {
                if (address != null) {
                    throw new IOException("Multiple table symbols in " + symbols);
                }

                address = Long.parseUnsignedLong(match.group(1), 16);
            }
        }

        if (address == null) {
            throw new IOException("Missing table symbol in " + symbols);
        }

        return address;
    }

    private static void require(
            Properties metadata,
            String key,
            String expected
    ) throws IOException {
        if (!expected.equals(metadata.getProperty(key))) {
            throw new IOException("Missing or unexpected trace field: " + key);
        }
    }

    private static boolean allEqual(List<List<Long>> observations) {
        for (List<Long> observation : observations) {
            if (!observations.get(0).equals(observation)) {
                return false;
            }
        }

        return true;
    }

    private static List<Long> sets(List<Long> lines) {
        List<Long> result = new ArrayList<>();

        for (long line : lines) {
            result.add(Long.remainderUnsigned(line, CACHE.getNumberOfSets()));
        }

        return result;
    }

    private static List<String> unsignedList(List<Long> values) {
        List<String> result = new ArrayList<>();

        for (long value : values) {
            result.add(Long.toUnsignedString(value));
        }

        return result;
    }
}