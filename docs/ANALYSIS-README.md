# BinaryCacheLab analysis preview

BinaryCacheLab is a Java toolkit for experiments on preservation of cache-observable
behavior after binary lifting and recompilation. This package analyzes previously
collected traces. Version 0.2.0-preview is an analysis preview, not a complete
research release or an automated binary-lifting pipeline.

## Requirements and running

Use Java 17 or newer. Extract the ZIP, open a terminal in its BinaryCacheLab folder,
and run:

```
java -jar binarycachelab.jar --help
java -jar binarycachelab.jar --version
java -jar binarycachelab.jar check "/path/to/experiment-batch"
java -jar binarycachelab.jar check "/path/to/experiment-batch" --report "report.txt"
```

Replace the batch path with an actual collected experiment directory. It contains
experiment.properties, SHA256SUMS, binary/tool snapshots and repeat-N directories.
Supply batches separately alongside this package, preserving all files and bytes.
Do not run commands literally with the placeholder path.

The report contains tool version, UTC time, batch path, binary hashes, the fixed
public-input declaration, four-run output summaries for every repetition,
observations, per-run stability, separate original/rebuilt equality checks, verdict,
scope and exit code. Outputs include escaped byte previews, lengths and hashes;
full files, not previews, determine equality. Divergences show the first differing
line token, source CSV row, access size/type, runtime memory address and both
runtime and link instruction addresses. A sequence ending early is labelled
END_OF_SEQUENCE without inventing an instruction for the missing event.
With --report, detailed output goes to the report rather
than the terminal. Its parent must already exist. The report must be outside the
batch. Existing report files are never overwritten; choose a fresh filename.
Reports refer to the batch; retain its original manifest and evidence with them.

## Commands

* `check <batch> [--report <new-file>]`: current PIN range-trace preservation checker.
* `map <trace.csv>`: existing per-access line/set mapping with default 32 KiB,
  64-byte lines and eight ways. This is not hit/miss simulation.
* `check-synthetic <experiment.properties>`: earlier synthetic cache-set checker.
  It uses a different observation model from the real-trace `check` command.
* `table-control <directory>`: earlier, fixture-specific table-repeat experiment.

The original Java class entry points remain available for existing scripts.

## Interpretation of check

For a fixed public input and two secret inputs, the checker asks whether equal
original observations remain equal in the recompiled binary. It compares the
two secrets within each binary, not original line numbers against recompiled
line numbers. It first validates hashes, functional outputs and trace evidence.
Original/recompiled stdout and stderr must match for corresponding inputs;
native/instrumented outputs must match too. All executions must exit zero.
Both functional outputs and observations must be stable over configured repeats.

| Exit | Meaning |
| --- | --- |
| 0 | SATISFIED_FOR_TESTED_PAIR |
| 2 | Inconclusive evidence or CLI/report error |
| 3 | CANDIDATE_PRESERVATION_VIOLATION |
| 4 | FUNCTIONAL_OUTPUT_MISMATCH |
| 5 | ORIGINAL_OBSERVATIONS_DIFFER; antecedent is false |

The observation is an ordered sequence of virtual cache lines touched within
one selected table region, normalized by subtracting the main-image load offset.
Repeated accesses remain. Other memory, instruction fetches, access types and
event boundaries are excluded. No physical-cache or timing model is simulated.
Results apply only to the recorded inputs and executions, not all executions.

## Collection and remaining limitations

Intel PIN, the range tracer and FoxDec were used separately in Linux/WSL to collect
these experiments. This ZIP does not bundle or install them and does not collect
new traces. Windows is sufficient to analyze an existing portable batch.
Selecting corresponding regions still requires inspected disassembly. The current
collector supports one thread and a straight-line leaf range invoked once.
The checker supports two secret slots, one region per binary and lower-half Linux
virtual addresses. SHA256SUMS provides integrity relative to its manifest, not
proof that executions occurred as claimed.

Existing experiments reported matching observations [257] for the same-line
benchmark and [257, 258] for the two-line benchmark, with three repetitions per
binary/input. These are finite results. FoxDec build warnings and logs remain
part of their respective evidence directories.

## Rebuilding

Sources and plain Java test runners are included. On Windows with JDK 17 or newer:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-package.ps1
```

The script compiles with --release 17, runs six test runners, creates a runnable
JAR and ZIP in a fresh build/package-* directory, and prints both paths. It does
not include local experiment batches automatically. The build tests do not replace
the separate 17-case mutation suite or real-batch validation.
