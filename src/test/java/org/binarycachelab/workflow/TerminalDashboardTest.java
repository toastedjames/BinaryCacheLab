package org.binarycachelab.workflow;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;

/** Presentation uses engine reports unchanged; no native analysis is simulated as qualification. */
public final class TerminalDashboardTest {
    static int checks;
    static void check(boolean yes,String why){if(!yes)throw new AssertionError(why);checks++;}
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("dashboard-test-");Path config=root.resolve("bcl.toml");
        Files.writeString(config,LabApp.sample());TerminalDashboard ui=new TerminalDashboard(config,null);
        String home=ui.render();check(home.contains("STATUS: IDLE"),"Initial state");
        check(home.contains(org.binarycachelab.BinaryCacheLabCli.VERSION),"Actual version absent");
        for(String label:List.of("[R] Run analysis","[P] Plan layout transformation","[V] View last report","[C] Configuration","[A] Advanced tools","[Q] Quit"))check(home.contains(label),"Primary action absent: "+label);
        check(!home.contains("[I] Instruction")&&!home.contains("[G] Reference"),"Research controls clutter home");
        check(home.lines().count()<=24,"Home requires scrolling");
        ui.command("unknown");check(ui.notice.contains("Invalid command"),"Invalid key ignored");
        ui.command("V");check(ui.notice.contains("No previous report"),"Empty history crashes");
        ui.command("C");check(ui.screen==TerminalDashboard.Screen.CONFIG,"Configuration navigation");
        String old=Files.readString(config);ui.command("E experiment.timeout=0");check(Files.readString(config).equals(old),"Invalid edit mutated configuration");
        ui.command("E experiment.timeout=76");check(LabConfig.load(config).number("experiment.timeout")==76,"Valid edit not applied");
        check(ui.notice.contains("Configuration validated"),"Edit feedback missing");
        try(var paths=Files.list(root)){check(paths.anyMatch(p->p.getFileName().toString().contains("backup-")),"Backup missing");}
        ui.command("I "+root.resolve("missing.asm"));check(ui.notice.contains("does not exist"),"Missing input accepted");
        ui.command("\033");check(ui.screen==TerminalDashboard.Screen.MAIN,"Esc does not go back");
        ui.command("R");check(!ui.running()&&ui.notice.contains("Input unavailable"),"Missing input starts worker");
        ui.command("A");check(ui.render().contains("[I] Instruction correspondence"),"Advanced actions absent");
        ui.command("O");check(ui.screen==TerminalDashboard.Screen.DETAIL&&ui.render().contains("64 B"),"Observer view");
        ui.command("B");check(ui.screen==TerminalDashboard.Screen.ADVANCED,"Detail back loses navigation");
        ui.command("J");check(ui.render().contains("Read-only"),"JSON help absent");ui.command("B");
        ui.command("B");check(ui.screen==TerminalDashboard.Screen.MAIN,"Advanced back");
        TerminalDashboard bad=new TerminalDashboard(root.resolve("missing.toml"),null);
        check(bad.render().contains("invalid/missing configuration"),"Missing configuration crashes launch");
        Files.writeString(root.resolve("bad.toml"),"not a configuration");
        check(new TerminalDashboard(root.resolve("bad.toml"),null).render().contains("UNAVAILABLE"),"Invalid configuration not shown");

        Path run=root.resolve("run");Files.createDirectories(run);
        Map<String,Object> data=report("FAIL","NOT_ASSESSED",7L);
        Files.writeString(run.resolve("report.json"),Json.write(data));ui.loadReport(run);ui.screen=TerminalDashboard.Screen.RESULTS;
        String result=ui.render();check(result.contains("VERDICT: FAIL"),"UI changed authoritative verdict");
        check(result.contains("NOT ASSESSED")&&!result.contains("COMPROMISED"),"Layout failure mislabeled compromise");
        check(result.contains("baseline events: 123")&&result.contains("transformed events: 456"),"Counts differ from report");
        check(result.contains("Policy violations: 7"),"Violation count differs");
        check(!result.contains("Change classifications:"),"Duplicate classification counts clutter summary");
        ui.command("V");check(ui.document.contains("First violation: TRACE-001"),"Violation details missing");
        ui.command("B");check(ui.screen==TerminalDashboard.Screen.RESULTS,"Report back starts a run");
        ui.command("D");check(ui.document.contains("UNAVAILABLE"),"Missing comparisons fabricated");ui.command("B");
        data=report("INCONCLUSIVE","NOT_ASSESSED",0L);Files.writeString(run.resolve("report.json"),Json.write(data));ui.loadReport(run);
        check(ui.resultText(false).contains("VERDICT: INCONCLUSIVE"),"Incomplete evidence promoted to pass");
        data=report("COMPROMISED","COMPROMISED",0L);Files.writeString(run.resolve("report.json"),Json.write(data));ui.loadReport(run);
        check(ui.resultText(false).contains("VERDICT: COMPROMISED"),"Engine compromise hidden");
        data=report("PASS","NOT_ASSESSED",0L);Files.writeString(run.resolve("report.json"),Json.write(data));ui.loadReport(run);
        check(ui.resultText(false).contains("VERDICT: PASS"),"Successful result hidden");
        Path comparisons=run.resolve("comparisons");Files.createDirectories(comparisons);
        data.put("presentation",Map.of("schema","bcl-readable-decisions-2"));
        String readable="SECRET INPUT DECISIONS\nG1: secret0 [key=0] versus secret1 [key=1]\nOriginal: SAME observed line sequence\nFINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED\n";
        Files.writeString(comparisons.resolve("trace_diff.txt"),readable);Files.writeString(run.resolve("report.json"),Json.write(data));ui.loadReport(run);
        ui.screen=TerminalDashboard.Screen.RESULTS;ui.command("D");
        check(ui.title.equals("Secret comparisons")&&ui.document.equals(readable),"TUI did not use grouped secret report");
        check(ui.document.contains("ADDRESS CHANGED; CACHE LINE CHANGED"),"TUI omitted combined findings");ui.command("B");

        ui.modern=true;ui.stageNames.addAll(List.of("Inspect input","Build original","Trace original"));ui.stages.clear();
        for(String stage:ui.stageNames)ui.stages.put(stage,"WAITING");
        ui.outputLine("[1/3] Inspect input ...");ui.outputLine("       PASS");ui.outputLine("[2/3] Build original ...");ui.outputLine("       FAIL: linker failed");
        check(ui.stages.get("Inspect input").equals("PASS")&&ui.stages.get("Build original").equals("FAIL")&&ui.stages.get("Trace original").equals("WAITING"),"Stage failure loses completed work");
        ui.outputLine("Run directory: "+run);check(ui.selected.equals(run),"Run ID not read from backend");
        ui.screen=TerminalDashboard.Screen.PROGRESS;ui.current="Build original";ui.state="RUNNING";
        check(ui.render().contains("[2/3]")&&ui.render().contains("Current stage: Build original"),"Progress does not reflect actual stages");
        CountDownLatch latch=new CountDownLatch(1);ui.worker=new Thread(()->{try{latch.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});ui.worker.start();
        ui.command("R");check(ui.notice.contains("already running"),"Duplicate start accepted");
        ui.screen=TerminalDashboard.Screen.MAIN;ui.command("Q");check(!ui.quit&&ui.worker.isAlive(),"Quit unexpectedly kills active run");
        ui.command("C");check(ui.state.equals("CANCELLING"),"Cancellation state missing");
        ui.screen=TerminalDashboard.Screen.CONFIG;old=Files.readString(config);ui.command("E experiment.timeout=77");check(Files.readString(config).equals(old),"Editing active run permitted");
        Path log=root.resolve("large.log");Files.writeString(log,"x".repeat(3*1024*1024)+"\nLAST LOG LINE\n");ui.transcript=log;
        ui.screen=TerminalDashboard.Screen.PROGRESS;ui.command("L");check(ui.document.length()<8500&&ui.document.contains("LAST LOG LINE"),"Large log read is unbounded");
        check(ui.render().contains("current stage: Build original"),"Log view loses progress context");
        ui.command("B");check(ui.screen==TerminalDashboard.Screen.PROGRESS,"Logs lose progress screen");
        latch.countDown();ui.worker.join(1000);ui.worker=null;ui.screen=TerminalDashboard.Screen.MAIN;ui.command("Q");check(ui.quit,"Clean idle exit failed");
        check(Files.readString(run.resolve("report.json")).equals(Json.write(data)),"Navigation damaged evidence");
        System.out.println("All "+checks+" terminal dashboard checks passed.");
    }
    static Map<String,Object> report(String verdict,String security,long violations) {
        Map<String,Object> report=new LinkedHashMap<>();report.put("overall_verdict",verdict);
        report.put("checks",Map.of("references",Map.of("status","NOT_ASSESSED"),"functional",Map.of("status","PASS"),"layout",Map.of("status","PASS"),"observations",Map.of("status",verdict.equals("FAIL")?"FAIL":"PASS")));
        report.put("security_assessment",Map.of("status",security));
        report.put("reproducibility",Map.of("commands",List.of(Map.of("seconds",new java.math.BigDecimal("0.453")))));
        report.put("event_statistics",Map.of("baseline",Map.of("events",123L,"incomplete_traces",0L),"transformed",Map.of("events",456L,"incomplete_traces",verdict.equals("INCONCLUSIVE")?1L:0L)));
        report.put("comparison",Map.of("policy_violations",violations,"preserved_observations",5L,"unmatched_events",0L,"classification_counts",Map.of("ADDRESS_CHANGED",9L,"PRESERVED",5L)));
        report.put("violations",violations==0?List.of():List.of(Map.of("rule_id","TRACE-001","baseline_lines",List.of(64L),"transformed_lines",List.of(128L))));return report;
    }
}
