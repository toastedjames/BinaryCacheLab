package org.binarycachelab.analysis;

import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.parsers.TraceCsvReader;
import org.binarycachelab.cache.CacheConfig;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Finite, table-only experiment checker; not a proof or a cache simulator. */
public final class PiePreservationCheck {
    private final Path root;
    private final Set<Path> verified = new HashSet<>();
    private final Map<Path, String> hashes = new HashMap<>();
    private final Map<String, List<Token>> observations = new HashMap<>();
    private Properties config;
    private CacheConfig cache;
    private final PrintStream output;

    private static final class FunctionalMismatch extends Exception {
        FunctionalMismatch(String message) { super(message); }
    }

    private PiePreservationCheck(Path root, PrintStream output) throws Exception {
        this.output = output;
        this.root = root.toAbsolutePath().normalize();
        require(Files.isDirectory(this.root), "Missing batch directory: " + root);
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream output, PrintStream errors) {
        int code;
        try {
            require(args.length == 1, "Usage: PiePreservationCheck <batch-directory>");
            code = new PiePreservationCheck(Paths.get(args[0]), output).run();
        } catch (FunctionalMismatch e) {
            errors.println("FUNCTIONAL_OUTPUT_MISMATCH: " + e.getMessage());
            code = 4;
        } catch (Exception e) {
            errors.println("INCONCLUSIVE: " + e.getMessage());
            code = 2;
        }
        return code;
    }

    private static void require(boolean ok, String message) {
        if (!ok) throw new IllegalArgumentException(message);
    }

    private Path safePath(String name) throws Exception {
        Path p = root.resolve(name).normalize();
        require(p.startsWith(root), "Path outside batch: " + name);
        require(Files.isRegularFile(p), "Missing file: " + name);
        for (Path part = p; part != null; part = part.getParent()) {
            require(!Files.isSymbolicLink(part), "Symbolic link in artifact path: " + name);
        }
        return p;
    }

    private void verifyManifest() throws Exception {
        for (String line : Files.readAllLines(safePath("SHA256SUMS"))) {
            require(line.matches("[0-9a-f]{64}  \\./.+"), "Invalid manifest entry");
            Path p = safePath(line.substring(66));
            require(verified.add(p), "Duplicate manifest path: " + p);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(p)) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count);
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : digest.digest()) hex.append(String.format("%02x", b & 255));
            require(hex.toString().equals(line.substring(0, 64)), "Hash mismatch: " + p);
            hashes.put(p, hex.toString());
        }
        require(!verified.isEmpty(), "Empty manifest");
    }

    private Path artifact(String name) throws Exception {
        Path p = safePath(name);
        require(verified.contains(p), "File missing from manifest: " + name);
        return p;
    }

    private byte[] bytes(String name) throws Exception {
        return Files.readAllBytes(artifact(name));
    }

    private Properties properties(String name) throws Exception {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(artifact(name))) { p.load(in); }
        return p;
    }

    private static String value(Properties p, String key) {
        String v = p.getProperty(key);
        require(v != null && !v.trim().isEmpty(), "Missing property: " + key);
        return v.trim();
    }

    private static void expect(Properties p, String key, String expected) {
        require(value(p, key).equals(expected), "Unexpected " + key + ": " + value(p, key));
    }

    private static long hex(Properties p, String key) {
        String v = value(p, key);
        require(v.matches("0[xX][0-9a-fA-F]{1,16}"), "Invalid address: " + key);
        long result = Long.parseUnsignedLong(v.substring(2), 16);
        // The current collector contract supports lower-half Linux addresses.
        require(result >= 0, "Unsupported upper-half address: " + key);
        return result;
    }

    private void exitZero(String name) throws Exception {
        require(new String(bytes(name), java.nio.charset.StandardCharsets.UTF_8).trim().equals("0"),
                "Nonzero or invalid exit: " + name);
    }

    private long tableBytes(String version) {
        String key = config.containsKey(version + ".table.bytes")
                ? version + ".table.bytes" : "table.bytes";
        long size = Long.parseLong(value(config, key));
        require(size > 0, "Table size must be positive: " + key);
        return size;
    }

    private static String runDirectory(int repeat, String version, int secret) {
        return "repeat-" + repeat + "/" + version + "-" + secret + "/";
    }

    private void compareOutput(String left, String right) throws Exception {
        if (!Arrays.equals(bytes(left), bytes(right))) {
            throw new FunctionalMismatch(left + " differs from " + right);
        }
    }

    private void checkFunctional(int repetitions) throws Exception {
        for (int repeat = 0; repeat < repetitions; repeat++) {
            for (int secret = 0; secret < 2; secret++) {
                for (String version : new String[]{"original", "recompiled"}) {
                    String dir = runDirectory(repeat, version, secret);
                    // Nonzero exits remain inconclusive, even when they match.
                    exitZero(dir + "native.exit");
                    exitZero(dir + "pin.exit");
                    for (String stream : new String[]{"stdout", "stderr"}) {
                        compareOutput(dir + "native." + stream, dir + "pin." + stream);
                        if (repeat > 0) {
                            require(Arrays.equals(bytes(dir + "native." + stream),
                                    bytes(runDirectory(0, version, secret) + "native." + stream)),
                                    "Unstable functional output: " + dir + stream);
                        }
                    }
                }
                for (String stream : new String[]{"stdout", "stderr"}) {
                    compareOutput(runDirectory(repeat, "original", secret) + "native." + stream,
                            runDirectory(repeat, "recompiled", secret) + "native." + stream);
                }
            }
        }
    }

    private static String digest(byte[] content) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(content)) {
            result.append(String.format("%02x", b & 255));
        }
        return result.toString();
    }

    private static String preview(byte[] content) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < Math.min(content.length, 80); i++) {
            int b = content[i] & 255;
            if (b == 10) result.append("\\n");
            else if (b == 13) result.append("\\r");
            else if (b == 9) result.append("\\t");
            else if (b == 34 || b == 92) result.append('\\').append((char) b);
            else if (b >= 32 && b <= 126) result.append((char) b);
            else result.append(String.format("\\x%02x", b));
        }
        result.append('"');
        if (content.length > 80) result.append(" (truncated preview)");
        return result.toString();
    }

    private void printFourRuns(int repetitions) throws Exception {
        output.println("FOUR-RUN DESIGN: P(s0), P(s1), Pprime(s0), Pprime(s1), repeated " + repetitions + " times.");
        output.println("Declared fixed public input: " + value(config, "public.input"));
        output.println("Input transport: argv; secret values are declarations from experiment.properties.");
        output.println("The collector establishes input correspondence; this checker does not infer argv semantics.");
        for (String version : new String[]{"original", "recompiled"}) {
            output.println(version + " binary SHA256=" + hashes.get(artifact("binaries/" + version)));
            output.printf("%s instruction range=[0x%x,0x%x), table link base=0x%x, table bytes=%d%n",
                    version, hex(config, version + ".range.start"), hex(config, version + ".range.end"),
                    hex(config, version + ".table.link"), tableBytes(version));
        }
        output.println("OBSERVATION MODEL: data-memory events from the selected instruction range, clipped to the table.");
        output.println("Each overlapping event emits all touched lines in order; repeated accesses are retained.");
        output.println("Normalized address = runtime address - main-image load offset; offset must be line-aligned.");
        output.println("line = floor(normalized address / line bytes); displayed set = line % number of sets.");
        output.println("Verdict uses ordered LINE sequences. Displayed sets are normalized model values, not measured physical sets.");
        output.println("Compare secrets WITHIN each binary; line values need not match ACROSS builds.");
        output.println("Table correspondence is declared per build, not automatically proved.");
        output.println("Excluded: out-of-table memory, instruction fetches, access types and event boundaries.");
        output.println("PIN records before-instruction effective addresses, not cache hits/misses or execution time.");
        output.println("FOUR-RUN OUTPUTS (byte equality is checked on full files, not previews):");
        for (int repeat = 0; repeat < repetitions; repeat++) {
            for (String version : new String[]{"original", "recompiled"}) {
                for (int secret = 0; secret < 2; secret++) {
                    String dir = runDirectory(repeat, version, secret);
                    output.println("RUN " + dir + " secret=" + value(config, "secret." + secret));
                    for (String mode : new String[]{"native", "pin"}) {
                        output.println("  " + mode + " exit=" + preview(bytes(dir + mode + ".exit")));
                        for (String stream : new String[]{"stdout", "stderr"}) {
                            byte[] content = bytes(dir + mode + "." + stream);
                            output.println("  " + mode + "." + stream + " bytes=" + content.length
                                    + " preview=" + preview(content) + " SHA256=" + digest(content));
                        }
                    }
                }
            }
        }
    }

    static final class Token {
        final long line;
        final MemoryAccess event;
        final long bias;
        Token(long line, MemoryAccess event, long bias) {
            this.line = line; this.event = event; this.bias = bias;
        }
    }

    static List<Token> projectTokens(List<MemoryAccess> events, long bias, long table,
                                    long size, long lineBytes) {
        require(bias >= 0 && table >= 0 && size > 0 && lineBytes > 0,
                "Invalid projection parameters");
        require(bias % lineBytes == 0, "Load offset is not cache-line aligned");
        long first = Math.addExact(bias, table);
        long last = Math.addExact(first, size - 1);
        List<Token> result = new ArrayList<>();
        for (MemoryAccess event : events) {
            long start = event.getMemoryAddress();
            require(start >= 0, "Unsupported upper-half memory address");
            long end = Math.addExact(start, event.getAccessSizeBytes() - 1L);
            if (end < first || start > last) continue;
            long a = (Math.max(start, first) - bias) / lineBytes;
            long b = (Math.min(end, last) - bias) / lineBytes;
            for (long line = a; ; line++) {
                result.add(new Token(line, event, bias));
                if (line == b) break;
            }
        }
        return result;
    }

    static List<Long> project(List<MemoryAccess> events, long bias, long table,
                              long size, long lineBytes) {
        List<Long> result = new ArrayList<>();
        for (Token token : projectTokens(events, bias, table, size, lineBytes)) result.add(token.line);
        return result;
    }

    static int firstDifference(List<Token> left, List<Token> right) {
        int count = Math.min(left.size(), right.size());
        for (int i = 0; i < count; i++) if (left.get(i).line != right.get(i).line) return i;
        return left.size() == right.size() ? -1 : count;
    }

    static String witness(List<Token> tokens, int index, long sets) {
        if (index >= tokens.size()) return "END_OF_SEQUENCE (no event/instruction at this position)";
        Token token = tokens.get(index);
        MemoryAccess e = token.event;
        return String.format("line=%d normalized-set=%d event=%d csv-row=%d thread=%d "
                        + "ip-runtime=0x%x ip-link=0x%x memory-runtime=0x%x access-bytes=%d type=%s load-offset=0x%x",
                token.line, token.line % sets, e.getSequence(), e.getSequence() + 2,
                e.getThreadId(), e.getInstructionAddress(), e.getInstructionAddress() - token.bias,
                e.getMemoryAddress(), e.getAccessSizeBytes(), e.getAccessType(), token.bias);
    }

    private boolean compareObservations(String label, String left, String right) {
        List<Token> a = observations.get(left), b = observations.get(right);
        int index = firstDifference(a, b);
        output.println(label + " equal=" + (index == -1) + " lengths=" + a.size() + "/" + b.size());
        if (index != -1) {
            output.println("FIRST_DIVERGENCE token-index=" + index + " (zero-based)");
            output.println("  " + left + "trace.csv: " + witness(a, index, cache.getNumberOfSets()));
            output.println("  " + right + "trace.csv: " + witness(b, index, cache.getNumberOfSets()));
            output.println("  Instructions identify the differing accesses, not necessarily the root cause.");
        }
        return index == -1;
    }

    private List<Long> readRun(int repeat, String version, int secret) throws Exception {
        String dir = runDirectory(repeat, version, secret);
        Properties meta = properties(dir + "trace.properties");
        String[][] required = {
            {"status", "complete"}, {"tracer_version", "range-1"}, {"backend", "PIN"},
            {"scope", "main-executable-instruction-range"}, {"address_space", "virtual"},
            {"event_semantics", "before-instruction"},
            {"read_modify_write", "separate-read-then-write"},
            {"range_entries", "1"}, {"return_instructions_reached", "1"},
            {"application_threads", "1"}, {"application_exit", "0"}
        };
        for (String[] pair : required) expect(meta, pair[0], pair[1]);
        long start = hex(config, version + ".range.start");
        long end = hex(config, version + ".range.end");
        require(end > start, "Invalid instruction range");
        require(hex(meta, "range_start_link") == start && hex(meta, "range_end_link") == end,
                "Instruction range mismatch: " + dir);
        long bias = hex(meta, "image_load_offset");
        long runtimeStart = Math.addExact(bias, start), runtimeEnd = Math.addExact(bias, end);
        List<MemoryAccess> events = new TraceCsvReader().read(artifact(dir + "trace.csv"));
        require(!events.isEmpty() && events.size() == Long.parseLong(value(meta, "events")),
                "Event count mismatch or empty trace: " + dir);
        long thread = events.get(0).getThreadId();
        for (int i = 0; i < events.size(); i++) {
            MemoryAccess event = events.get(i);
            require(event.getSequence() == i && event.getThreadId() == thread
                    && event.getSourceBackend() == MemoryAccess.SourceBackend.PIN,
                    "Invalid event sequence, thread, or backend: " + dir);
            require(event.getInstructionAddress() >= runtimeStart
                    && event.getInstructionAddress() < runtimeEnd, "Instruction outside range: " + dir);
        }
        List<Token> tokens = projectTokens(events, bias, hex(config, version + ".table.link"),
                tableBytes(version), cache.getCacheLineSizeBytes());
        observations.put(dir, tokens);
        List<Long> lines = new ArrayList<>();
        for (Token token : tokens) lines.add(token.line);
        require(!lines.isEmpty(), "No table observations: " + dir);
        output.println(dir + " normalized-lines=" + lines);
        return lines;
    }

    static String classify(List<Long> p0, List<Long> p1, List<Long> pp0, List<Long> pp1) {
        if (!p0.equals(p1)) return "ORIGINAL_OBSERVATIONS_DIFFER";
        return pp0.equals(pp1) ? "SATISFIED_FOR_TESTED_PAIR" : "CANDIDATE_PRESERVATION_VIOLATION";
    }

    private int run() throws Exception {
        verifyManifest();
        config = properties("experiment.properties");
        int repetitions = Integer.parseInt(value(config, "repetitions"));
        require(repetitions > 0, "Repetitions must be positive");
        require(!value(config, "secret.0").equals(value(config, "secret.1")),
                "The two configured secret inputs must differ");
        value(config, "public.input");
        cache = new CacheConfig(Integer.parseInt(value(config, "cache.size")),
                Integer.parseInt(value(config, "cache.line")),
                Integer.parseInt(value(config, "cache.ways")));
        for (String version : new String[]{"original", "recompiled"}) {
            require(hex(config, version + ".range.end") > hex(config, version + ".range.start"),
                    "Invalid instruction range: " + version);
            Math.addExact(hex(config, version + ".table.link"), tableBytes(version) - 1);
        }
        String[][] required = {
            {"input.transport", "argv"},
            {"functional.model", "stdout-stderr-exit"},
            {"observation", "ordered-relocation-normalized-table-cache-lines"},
            {"normalization", "subtract-main-image-load-offset"}
        };
        for (String[] pair : required) expect(config, pair[0], pair[1]);
        artifact("binaries/original"); artifact("binaries/recompiled");
        artifact("tool/RangeMemoryTracer.so"); artifact("tool/RangeMemoryTracer.cpp");
        output.println("Experiment: " + value(config, "experiment"));
        output.println(cache);
        output.println("Secret slots: 0=" + value(config, "secret.0")
                + ", 1=" + value(config, "secret.1") + "; repetitions=" + repetitions);
        printFourRuns(repetitions);
        checkFunctional(repetitions);
        output.println("Functional checks: passed (corresponding stdout, stderr and zero exits).");
        output.println("Different secrets are not required to produce equal outputs.");
        Map<String, List<Long>> stable = new HashMap<>();
        for (int repeat = 0; repeat < repetitions; repeat++) {
            for (String version : new String[]{"original", "recompiled"}) {
                for (int secret = 0; secret < 2; secret++) {
                    List<Long> lines = readRun(repeat, version, secret);
                    String key = version + secret;
                    stable.putIfAbsent(key, lines);
                }
            }
        }
        boolean stableAcrossRuns = true;
        for (String version : new String[]{"original", "recompiled"}) {
            for (int secret = 0; secret < 2; secret++) {
                boolean same = true;
                for (int repeat = 1; repeat < repetitions; repeat++) {
                    same &= compareObservations("REPEAT_CHECK " + version + " secret=" + secret
                                    + " repeat=0 vs repeat=" + repeat,
                            runDirectory(0, version, secret), runDirectory(repeat, version, secret));
                }
                output.println("STABILITY " + version + " secret=" + secret + "="
                        + (repetitions == 1 ? "NOT_ASSESSED" : same ? "STABLE" : "UNSTABLE"));
                stableAcrossRuns &= same;
            }
        }
        for (int repeat = 0; repeat < repetitions; repeat++) {
            compareObservations("ORIGINAL_EQUALITY repeat=" + repeat,
                    runDirectory(repeat, "original", 0), runDirectory(repeat, "original", 1));
            compareObservations("REBUILT_EQUALITY repeat=" + repeat,
                    runDirectory(repeat, "recompiled", 0), runDirectory(repeat, "recompiled", 1));
        }
        require(stableAcrossRuns, "Unstable observations: see repetition witnesses above");
        String status = classify(stable.get("original0"), stable.get("original1"),
                stable.get("recompiled0"), stable.get("recompiled1"));
        output.println(repetitions > 1 ? "Repeat stability: passed."
                : "Repeat stability: not assessed (one repetition).");
        output.println(status);
        if (status.equals("ORIGINAL_OBSERVATIONS_DIFFER")) {
            output.println("Antecedent false: a difference was detected in the original; this is not positive preservation evidence.");
        }
        output.println("Scope: these inputs and runs; ordered table-only normalized virtual cache lines.");
        output.println("Excludes other memory, instruction fetches, access types and event boundaries.");
        output.println("No cache hit/miss simulation or formal preservation proof.");
        return status.equals("SATISFIED_FOR_TESTED_PAIR") ? 0
                : status.equals("ORIGINAL_OBSERVATIONS_DIFFER") ? 5 : 3;
    }
}
