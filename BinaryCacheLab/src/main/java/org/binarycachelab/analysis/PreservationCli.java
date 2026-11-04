package org.binarycachelab.analysis;

import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.binarycachelab.cache.CacheConfig;
import org.binarycachelab.core.MemoryAccess;
import org.binarycachelab.parsers.TraceCsvReader;

public final class PreservationCli {

    private static final class Run {

        private final List<MemoryAccess> trace;
        private final byte[] stdout;
        private final byte[] stderr;
        private final int exitCode;

        private Run(
                List<MemoryAccess> trace,
                byte[] stdout,
                byte[] stderr,
                int exitCode
        ) {
            this.trace = trace;
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
        }

        private boolean hasSameOutput(Run other) {
            return exitCode == other.exitCode
                    && Arrays.equals(stdout, other.stdout)
                    && Arrays.equals(stderr, other.stderr);
        }
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(
            String[] args,
            PrintStream output,
            PrintStream errors
    ) {
        if (args.length != 1) {
            errors.println(
                    "Usage: java -cp build/classes "
                            + "org.binarycachelab.analysis.PreservationCli "
                            + "<experiment.properties>"
            );
            return 2;
        }

        try {
            Path manifest = Paths.get(args[0]).toAbsolutePath().normalize();
            Properties properties = new Properties();

            try (Reader reader = Files.newBufferedReader(
                    manifest,
                    StandardCharsets.UTF_8
            )) {
                properties.load(reader);
            }

            String publicInput = required(properties, "public.input");
            String secret1 = required(properties, "secret.s1");
            String secret2 = required(properties, "secret.s2");

            if (secret1.equals(secret2)) {
                throw new IllegalArgumentException(
                        "secret.s1 and secret.s2 must identify different secrets."
                );
            }

            CacheConfig cache = new CacheConfig(
                    integer(properties, "cache.size"),
                    integer(properties, "cache.line"),
                    integer(properties, "cache.ways")
            );

            StringBuilder artifacts = new StringBuilder();

            Run p1 = loadRun(properties, manifest, "p.s1", artifacts);
            Run p2 = loadRun(properties, manifest, "p.s2", artifacts);
            Run pp1 = loadRun(properties, manifest, "pp.s1", artifacts);
            Run pp2 = loadRun(properties, manifest, "pp.s2", artifacts);

            boolean s1OutputsMatch = p1.hasSameOutput(pp1);
            boolean s2OutputsMatch = p2.hasSameOutput(pp2);

            PreservationChecker.Result result =
                    new PreservationChecker(cache).check(
                            p1.trace,
                            p2.trace,
                            pp1.trace,
                            pp2.trace,
                            s1OutputsMatch && s2OutputsMatch
                    );

            output.println("BinaryCacheLab: synthetic preservation experiment");
            output.println("Time UTC: " + Instant.now());
            output.println("Manifest: " + manifest);
            output.println("Manifest SHA-256: " + sha256(Files.readAllBytes(manifest)));
            output.println("Public input label: " + publicInput);
            output.println("Secret labels: " + secret1 + ", " + secret2);
            output.println(cache);
            output.println(
                    "Observation: ordered cache sets; "
                            + "one token per touched line."
            );
            output.println(
                    "Excluded from observation equality: instruction addresses, "
                            + "tags, access types, thread IDs, and event boundaries."
            );
            output.println(
                    "Within-event order: ascending memory address."
            );
            output.println(
                    "Functional model: exact stdout bytes, stderr bytes, exit code."
            );
            output.println("Functional outputs match for s1: " + s1OutputsMatch);
            output.println("Functional outputs match for s2: " + s2OutputsMatch);
            output.println();
            output.println(result);
            output.println();
            output.println("Artifact fingerprints:");
            output.print(artifacts);
            output.println();
            output.println(
                    "Scope: supplied synthetic artifacts for one input/secret pair. "
                            + "No binaries were executed."
            );
            output.println(
                    "Input labels are declarations, not verified execution provenance."
            );
            output.println(
                    "This result is not a proof of semantic equivalence "
                            + "or preservation for all inputs."
            );

            switch (result.getStatus()) {
                case SATISFIED_FOR_TESTED_PAIR:
                    return 0;
                case CANDIDATE_PRESERVATION_VIOLATION:
                    return 3;
                case FUNCTIONAL_OUTPUT_MISMATCH:
                    return 4;
                case ORIGINAL_OBSERVATIONS_DIFFER:
                    return 5;
                default:
                    throw new IllegalStateException("Unhandled result.");
            }
        } catch (IOException | IllegalArgumentException exception) {
            errors.println("Error: " + exception.getMessage());
            return 2;
        }
    }

    private static Run loadRun(
            Properties properties,
            Path manifest,
            String prefix,
            StringBuilder artifacts
    ) throws IOException {
        Path tracePath = resolve(properties, manifest, prefix + ".trace");
        Path stdoutPath = resolve(properties, manifest, prefix + ".stdout");
        Path stderrPath = resolve(properties, manifest, prefix + ".stderr");

        int exitCode = integer(properties, prefix + ".exit");

        List<MemoryAccess> trace = new TraceCsvReader().read(tracePath);
        byte[] stdout = Files.readAllBytes(stdoutPath);
        byte[] stderr = Files.readAllBytes(stderrPath);

        fingerprint(artifacts, prefix + ".trace", tracePath, Files.readAllBytes(tracePath));
        fingerprint(artifacts, prefix + ".stdout", stdoutPath, stdout);
        fingerprint(artifacts, prefix + ".stderr", stderrPath, stderr);
        artifacts.append(prefix).append(".exit=").append(exitCode).append('\n');

        return new Run(trace, stdout, stderr, exitCode);
    }

    private static Path resolve(
            Properties properties,
            Path manifest,
            String key
    ) {
        return manifest.getParent()
                .resolve(required(properties, key))
                .normalize();
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key);

        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Missing required property: " + key
            );
        }

        return value.trim();
    }

    private static int integer(Properties properties, String key) {
        try {
            return Integer.parseInt(required(properties, key));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    key + " must be a valid 32-bit integer.",
                    exception
            );
        }
    }

    private static void fingerprint(
            StringBuilder result,
            String label,
            Path path,
            byte[] bytes
    ) {
        result.append(label)
                .append(": ")
                .append(path)
                .append(" | SHA-256=")
                .append(sha256(bytes))
                .append('\n');
    }

    private static String sha256(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder hex = new StringBuilder();

            for (byte value : digest) {
                hex.append(String.format("%02x", value & 0xff));
            }

            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }
}