package org.binarycachelab;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.List;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.parsers.TraceCsvReader;

public final class Main {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println(
                    "Usage: java -cp build/classes "
                            + "org.binarycachelab.Main <trace.csv>"
            );
            System.exit(2);
            return;
        }

        try {
            List<MemoryAccess> events =
                    new TraceCsvReader().read(Paths.get(args[0]));

            CacheConfig cache = new CacheConfig(32768, 64, 8);

            System.out.println("BinaryCacheLab");
            System.out.println(cache);
            System.out.println("Memory events: " + events.size());
            System.out.println(
                    "One row per cache line touched; "
                            + "mappings only, no hit/miss simulation."
            );
            System.out.println(
                    "sequence,thread_id,instruction_address,memory_address,"
                            + "size,type,backend,cache_line,set,tag"
            );

            for (MemoryAccess event : events) {
                printAccess(event, cache, System.out);
            }
        } catch (IOException | InvalidPathException exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

    public static void printAccess(
            MemoryAccess event,
            CacheConfig cache,
            PrintStream output
    ) {
        long firstLine = cache.getCacheLine(event.getMemoryAddress());

        long lastAddress =
                event.getMemoryAddress() + event.getAccessSizeBytes() - 1L;

        long lastLine = cache.getCacheLine(lastAddress);

        // Equality termination also works for unsigned line numbers.
        // MemoryAccess has already rejected address-space wraparound.
        for (long line = firstLine; ; line++) {
            long set = Long.remainderUnsigned(
                    line,
                    cache.getNumberOfSets()
            );

            long tag = Long.divideUnsigned(
                    line,
                    cache.getNumberOfSets()
            );

            output.printf(
                    "%d,%d,0x%X,0x%X,%d,%s,%s,%s,%s,%s%n",
                    event.getSequence(),
                    event.getThreadId(),
                    event.getInstructionAddress(),
                    event.getMemoryAddress(),
                    event.getAccessSizeBytes(),
                    event.getAccessType(),
                    event.getSourceBackend(),
                    Long.toUnsignedString(line),
                    Long.toUnsignedString(set),
                    Long.toUnsignedString(tag)
            );

            if (line == lastLine) {
                break;
            }
        }
    }
}