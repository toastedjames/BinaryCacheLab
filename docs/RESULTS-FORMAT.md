# Readable results and single-run defaults

The workflow default executes each configured input once per build. Native and
PIN executions are still compared to check output consistency. Additional repeated
runs require an explicit `execution.repetitions` setting; their stability is never
claimed when this setting is 1.

The TXT report, its automatic desktop opening, and the TUI V/D views use the same
readable results. Each G group compares two declared secret values within Original,
Baseline and Transformed using the complete configured ordered line sequences.
The access section groups input cases within each build and shows instruction IP,
memory address and all touched cache-line bases. The C groups describe unique
cross-build access changes. Every applicable finding is displayed together, such
as `ADDRESS CHANGED; CACHE LINE CHANGED`. Duplicate display records are collapsed;
distinct states and ambiguous results remain visible. Ordered raw evidence remains
in CSV and JSONL. Display grouping does not change sequence comparisons.

There is no fixed number of comparisons or a 20-access report limit. With the
bundled two-secret, one-read example, there is one G decision group and six C
build-access groups. Up to 32 explicitly declared secret values are supported,
with all distinct secret pairs compared. Public arguments must be identical.

The default criterion is `configured_virtual_line_sequences`. A difference under
this criterion is an observation for the configured inputs. It does not establish
repeat stability. The earlier `stable_disjoint_virtual_line_sequences` criterion
still requires at least two runs and rejects a single run as inconclusive.

An ordinary program without a declared secret test gets build/trace results and
its observed accesses; the toolkit does not infer which inputs are secrets.
Arbitrary NASM is not universally supported by FoxDec. Unsupported instructions,
entry shapes, runtime dependencies, invalid executions and exhausted bounds are
reported explicitly; this presentation change does not remove those limitations.

Native gate: `bash scripts/test-programs-wsl.sh`.
Existing sealed runs can be exported into the new readable format with
`python3 -B scripts/export_differences.py RUN_DIRECTORY`; the export is outside the
sealed run. No program is rerun by that command.
