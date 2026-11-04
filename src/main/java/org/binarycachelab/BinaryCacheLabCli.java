package org.binarycachelab;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.Arrays;
import org.binarycachelab.analysis.PiePreservationCheck;
import org.binarycachelab.analysis.PreservationCli;
import org.binarycachelab.analysis.TableTraceCheck;
import org.binarycachelab.analysis.ElfRegionAudit;
import org.binarycachelab.workflow.LabApp;
import org.binarycachelab.workflow.EvidenceCommands;

/** Command router for the analysis package. Collection remains a Linux task. */
public final class BinaryCacheLabCli {
    public static final String VERSION = "2.0.1";

    public static void main(String[] args) {
        try {
            if (args.length == 0 || (args.length == 1 && args[0].equals("--help"))) {
                help();
                return;
            }
            if (args.length == 1 && args[0].equals("--version")) {
                System.out.println("BinaryCacheLab " + VERSION);
                return;
            }
            if(org.binarycachelab.workflow.ToolkitCommands.COMMANDS.contains(args[0])){System.exit(org.binarycachelab.workflow.ToolkitCommands.run(args));return;}
            if(java.util.Set.of("verify","verify-references","assess-references","pin-check-java").contains(args[0])){System.exit(EvidenceCommands.run(args));return;}
            if (java.util.Set.of("tui","run","rebuild","demo-fixture","plan","assess","--doctor","--init","--last","history").contains(args[0]) || args[0].endsWith(".asm")) {
                System.exit(LabApp.run(args));
                return;
            }
            if (args[0].equals("check")) {
                System.exit(check(args));
                return;
            }
            if (args[0].equals("audit-region")) {
                auditRegion(args);
                return;
            }
            if (args.length != 2) throw new IllegalArgumentException("Expected a command and input path; use --help.");
            String[] input = Arrays.copyOfRange(args, 1, 2);
            switch (args[0]) {
                case "map": Main.main(input); break;
                case "check-synthetic": PreservationCli.main(input); break;
                case "table-control": TableTraceCheck.main(input); break;
                default: throw new IllegalArgumentException("Unknown command: " + args[0]);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void auditRegion(String[] args) throws Exception {
        if (!(args.length==4 || (args.length==6 && args[4].equals("--report"))))
            throw new IllegalArgumentException("Usage: audit-region <ELF> <link-address> <bytes> [--report <new.json>]");
        long address=Long.decode(args[2]), size=Long.decode(args[3]);
        Path input=Paths.get(args[1]).toAbsolutePath().normalize();
        String json=ElfRegionAudit.audit(input,address,size).json();
        if(args.length==6) {
            Path report=Paths.get(args[5]).toAbsolutePath().normalize();
            rejectLinks(report);
            Files.writeString(report,json,StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
        }
        System.out.print(json);
    }

    private static int check(String[] args) throws Exception {
        if (!(args.length == 2 || (args.length == 4 && args[2].equals("--report")))) {
            throw new IllegalArgumentException("Usage: check <batch-directory> [--report <new-file.txt>]");
        }
        Path batch = Paths.get(args[1]).toAbsolutePath().normalize();
        if (args.length == 2) return evaluate(batch, System.out, System.err);
        Path report = Paths.get(args[3]).toAbsolutePath().normalize();
        // Keep reports outside the collected evidence. Refuse symlink ancestors.
        rejectLinks(batch);
        rejectLinks(report);
        if (report.startsWith(batch)) throw new IllegalArgumentException("Save reports outside the batch directory.");
        // Parent directory must exist; CREATE_NEW never overwrites an earlier report.
        try (PrintStream out = new PrintStream(Files.newOutputStream(report,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), false, StandardCharsets.UTF_8)) {
            int code = evaluate(batch, out, out);
            out.flush();
            if (out.checkError()) throw new IOException("Report write failed: " + report);
            System.out.println("Report: " + report);
            System.out.println("Checker exit code: " + code);
            return code;
        }
    }

    private static void rejectLinks(Path path) {
        for (Path part = path; part != null; part = part.getParent()) {
            if (Files.isSymbolicLink(part)) throw new IllegalArgumentException("Symbolic link in path: " + path);
        }
    }

    private static int evaluate(Path batch, PrintStream output, PrintStream errors) {
        output.println("BinaryCacheLab " + VERSION);
        output.println("UTC: " + Instant.now());
        output.println("Batch: " + batch);
        int code = PiePreservationCheck.run(new String[]{batch.toString()}, output, errors);
        output.println("Exit code: " + code);
        return code;
    }

    private static void help() {
        System.out.println("BinaryCacheLab " + VERSION);
        System.out.println("Usage: java -jar binarycachelab.jar <command>");
        System.out.println("  check <batch-directory> [--report <new-file.txt>]");
        System.out.println("  map <trace.csv>");
        System.out.println("  check-synthetic <experiment.properties>");
        System.out.println("  table-control <legacy-table-repeat-directory>");
        System.out.println("  audit-region <ELF> <link-address> <bytes> [--report <new.json>]");
        System.out.println("audit-region inventories dynamic RELA hazards; exit 0 never authorizes rewriting.");
        System.out.println("  --help | --version");
        System.out.println("  --init | --doctor | plan | run | rebuild | tui | history | --last [--config bcl.toml]");
        System.out.println("  rebuild: baseline lift/link and metadata checks only; no native program execution");
        System.out.println("  demo-fixture: fresh three-layout experiment for the pinned bundled fixture only; safety remains unproved");
        System.out.println("  closure PROFILE [--report NEW_JSON] (restricted byte-level reference analysis)");
        System.out.println("  bounded-references PROFILE [--report NEW_JSON] (exhaustive finite machine model)");
        System.out.println("  bounded-control PROFILE [--report NEW_JSON] (finite transfer capture for protection)");
        System.out.println("  bounded-replay PROFILE --expected REPORT_JSON [--report NEW_JSON]");
        System.out.println("  correspondence PROFILE [--report NEW_JSON]");
        System.out.println("  ./bcl qualify-broad --output NEW_DIRECTORY [--native]");
        System.out.println("  ./bcl rewrite PROFILE --output NEW_DIRECTORY (automatic bounded rewriting)");
        System.out.println("  ./bcl protect INPUT --config FILE [--approval CONTRACT] (mandatory protected build)");
        System.out.println("  ./bcl rewrite verify EVIDENCE | rewrite qualify --output NEW_DIRECTORY");
        System.out.println("  approve-transform POLICY [--report NEW_JSON]");
        System.out.println("  approval-replay POLICY --expected REPORT_JSON");
        System.out.println("  publish-transform POLICY --output NEW_ELF [--report NEW_JSON]");
        System.out.println("  correspondence-replay PROFILE --expected REPORT_JSON [--report NEW_JSON]");
        System.out.println("  callback-plan ELF [--assembly NASM] [--report NEW_JSON]");
        System.out.println("  callback-check ORIGINAL --rebuilt ELF [--report NEW_JSON]");
        System.out.println("  ./bcl project init|discover|run|tui|verify (selected-program Python project driver)");
        System.out.println("  plan-regions PROFILE [--report NEW_JSON]");
        System.out.println("  apply-regions PROFILE --output NEW_ASM [--report NEW_JSON]");
        System.out.println("  verify-regions PROFILE --original ELF --rebuilt ELF [--report NEW_JSON]");
        System.out.println("  suite PROFILE [--list] (explicit native qualification jobs)");
        System.out.println("  validate-baseline EVIDENCE [--check-only] [--python python3]");
        System.out.println("  INPUT.asm [--check] [--config bcl.toml] (configured two-span fixture only)");
        System.out.println("  assess [--config bcl.toml] (safety assessment; inconclusive is exit 6, rejected is 7)");
        System.out.println("  pin-check-java <batch> [--repetitions N] [--report NEW_JSON]");
        System.out.println("  verify <stage3-experiment> [--report NEW_JSON] (offline, no native execution)");
        System.out.println("  verify-references <stage3-experiment> [--report NEW_JSON] (ELF read encodings/access sites)");
        System.out.println("  assess-references <stage3-experiment> [--report NEW_JSON] (exit 6 inconclusive; 7 rejected)");
        System.out.println("Stage 3 demo: explicit pre-lifted two-span fixture; Java transformation/build engine with Python PIN adapters.");
        System.out.println("check evaluates table-only normalized virtual cache-line preservation.");
        System.out.println("Report parent must exist. Existing report files are never overwritten.");
    }
}
