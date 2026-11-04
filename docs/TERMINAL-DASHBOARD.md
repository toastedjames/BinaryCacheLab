# Terminal dashboard

From the toolkit root, launch the three-variant sample with:

```bash
./bcl tui --config examples/workflow/bcl.toml --input examples/workflow/sample1.asm
```

The existing schema-1 configuration remains supported:

```bash
./bcl tui --config bcl.toml
```

Use a letter followed by Enter. Input is case insensitive. `B` or `Esc` followed
by Enter goes back. No terminal framework, mouse support or dependency was added.
The TUI remains Java and uses the existing Stage3Engine for legacy configurations.
Schema-2 configurations run the same Python Workflow used by `bcl sample1.asm`,
through a small adapter. The UI does not compute an independent verdict.

## Screens

The dashboard shows only Run, Plan, View last report, Configuration, Advanced
tools and Quit. Its version comes from the application, observer settings come
from validated configuration, and input/configuration paths reflect the current
selection. Schema-2 global coverage starts UNVERIFIED: successful finite checks
do not imply complete reference coverage. Legacy coverage is INCOMPLETE because
the legacy engine explicitly declares that limitation.

Run opens a background progress screen. Its stages and statuses are taken from
the backend's actual execution events and finalized checks. Legacy stages are
listed as discovered, without inventing a total. Logs are accessible with L;
the log viewer retains the run and stage context and reads only the last 8 KiB.
The input thread remains responsive while analysis subprocesses run. Completed
stages survive later failures. Duplicate starts are rejected.

C on the progress screen requests cancellation. Legacy runs use Stage3Engine's
existing cancellation. Schema-2 runs signal the adapter, which lets the existing
Runner terminate process groups and Workflow finalize partial evidence. The
screen shows CANCELLING while cleanup runs. Q on the main screen does not kill an
active run: it returns to progress and explains how to cancel. EOF and process
shutdown request cleanup through the same engines.

The results screen displays the saved authoritative verdict, check statuses,
security assessment, event counts, incomplete-trace counts, preserved observations
and violations. V opens the report, D opens differences, and M returns home.
Legacy summaries retain their original workflow status; they are not converted
into a new PASS verdict. Optional and unsupported evidence remains visibly
unassessed or unavailable. Address changes alone never produce COMPROMISED.

Plan is read-only. Legacy configurations use the existing GroupPlan. Schema-2
configurations can inspect a derived saved region plan; before lifting resolves
its labels the screen explains why planning is unavailable and labels configured
constraints as unvalidated. Opening Plan never builds, transforms or replaces an
executable.

Configuration shows active paths. `E section.key=literal` validates the entire
candidate before saving and retains a backup. Invalid edits preserve the original.
The schema-2 editor supports existing scalar settings with unchanged value types;
array/recipe edits require editing TOML externally, then R to reload. `I path`
selects an existing input for the session. Configuration/input changes are blocked
during analysis. Editing a setting requires the explicit E command.

## Advanced Tools

* D: diagnostics/preflight, reporting actual configured path availability.
* T: saved trace comparisons and differences.
* I: available instruction-correspondence evidence.
* G: reference coverage/eligibility evidence.
* O: observer settings; supported edits use Configuration.
* M: run manifest/provenance.
* H: history; return to Advanced Tools and use `V N` to select a run.
* L: retained logs.
* S: existing safety/security assessment evidence.
* J: help for `J /path/to/evidence.json`, a read-only structured viewer.
* `F path`, `N path`, `U path`: existing closure, region-plan and suite descriptions.
* K/X: legacy-only baseline rebuild/controlled fixture workflow. Schema-2
  configurations clearly reject these inapplicable actions.

Instruction/reference evidence requires supplied contracts and actual report
files. Its absence is shown as UNAVAILABLE, not simulated. Security is NOT ASSESSED
when no configured test ran. Full closure and whole-program security are not
inferred from finite observations. The viewers paginate; large evidence beyond
their documented size limits remains available through its retained file path.
Trace differences show the first 100 rows and the full stream's location.

## Tests and affected files

The implementation changes `LabApp.java` and its command dispatch, factors its
screen handling into `TerminalDashboard.java`, and reuses its existing report
formatters and engines. `console.py` passes the application/Python locations to
Java. `dashboard_backend.py` adapts schema-2 configuration, validated editing and
execution. Workflow adds only a run-directory progress line; its observer,
transformation and report semantics are unchanged. Build packaging includes the
adapter and tests; no release ZIP is generated by this change.

`TerminalDashboardTest.java` and the updated `Stage3WorkflowTest.java` test idle,
invalid/missing configuration and input, navigation, actual-report rendering,
PASS/FAIL/COMPROMISED/INCONCLUSIVE labels, missing optional evidence, empty history,
duplicate starts, cancellation state, safe quit, edits and bounded large-log reads.
`test_dashboard_backend.py` tests configuration and dispatch, with real POSIX
process-group cancellation on Linux. `test_dashboard_native.py` drives the Java
TUI through its real eight-stage workflow and checks displayed counts/verdict
against the retained report. Run the native check with:

```bash
bash scripts/test-dashboard-wsl.sh
```

The native helper creates an isolated installation and preserves existing evidence.
Portable test doubles and report fixtures are never presented as native scientific
qualification. Exact results are recorded in `TUI-VALIDATION.json`.

## Verified native result

The user-provided WSL check passed all 9 adapter tests, including real Linux
process-group cancellation. The TUI launched a native run at
`examples/workflow/runs/20261022-095158-s_3vikqv`. Its first viewer attempt exposed
an integer-only JSON reader rejecting fractional command times. The evidence-viewer codec now
accepts exact JSON decimals/exponents and large integers, with strict invalid-number
checks. Default analysis-input parsing remains integer-only; no report or
observation schema changed.

The repaired viewer passed `NATIVE_TUI_SAVED_REPORT_EXPECTATIONS_MET` against that
retained native run without rerunning targets: 318 evidence files verified,
153008 original events, 222184 baseline events, 222184 transformed events,
20 comparison rows, zero policy violations, and authoritative verdict PASS.
Saved-report navigation, displayed counts/verdict, and clean exit were checked.
The sample's missing optional reference/security evidence remains unassessed.

The final JAR, including evidence-only decimal parsing and unchanged strict
analysis-input validation, also passed the native saved-report check against
`examples/workflow/runs/20261022-095739-8jy0p5cw`: 318 files, 20 comparison
rows, zero policy violations, and matching displayed verdict PASS. The final
regression passed all 23 Java test programs and 121 Python tests on Windows; the
one Linux-only test passed in the 9-test WSL adapter suite.
