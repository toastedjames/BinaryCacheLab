# Three-variant command workflow

From a directory containing the input and its `bcl.toml` configuration, run:

```bash
/path/to/BinaryCacheLab/bcl sample1.asm
```

An existing ELF executable can be supplied instead. `--config PATH` selects an
explicit configuration. The assembly example is in `examples/workflow`.
Linux x86-64, Python 3.11+, Java 17+, GCC, NASM, binutils, PIN, the matching tracer,
and the configured FoxDec Docker image must be available. The existing setup
workflow installs/configures dependencies. The command records tool identities,
commands, target binaries, runtime controls, and retained evidence.

## Execution

The eight stages inspect the input, build the original, trace the original,
lift and rebuild the baseline, trace the baseline, transform and validate,
trace the transformed program, and compare all three pairs. Compiler and lifter
processes are build tools; PIN executes each actual target binary. Each input
case and repeat receives a native run and an instrumented run. Native/PIN stdout,
stderr and exit codes must agree before functional checks can pass.

The bundled sample uses PIE startup, a typed ELF `main`, and direct references to
two adjacent words. FoxDec must recover the declared region labels. Missing labels
stop the workflow; byte patterns or guessed addresses never replace a mapping.
A rebuilt binary missing an original `main` definition is rejected before use.
These checks do not establish complete startup or control-flow correspondence.

Both modes use identical fixed environment and input controls. Eager binding is
explicitly configured to avoid the dynamic loader lazy resolver's XSAVEC path,
which the current tracer does not support. Unsupported memory instructions stop
tracing. No unsupported accesses are silently excluded.

## Configuration and observation policies

The TOML schema version is `2.0`. Recipes are argv arrays rather than shell text.
The configuration declares logical regions, their per-variant symbols or
addresses, region sizes, layout constraints, instrumentation limits, cases,
repetitions, observation scope, policy and required checks. The example is the
complete configuration reference for the bundled program. Different programs
need their own justified region and build configuration.

* `strict_address`: matched accesses must preserve addresses, widths, operations
  and ordering.
* `region_relative`: preserve logical region/byte offsets, widths, operations and
  ordering; raw address changes alone are permitted.
* `cache_line_sequence`: compare the complete ordered line-token streams under
  the configured raw-virtual or logical-region line identity.
* `layout_only`: evaluate the configured linked layout constraints; traces remain
  diagnostic rather than an implicit security test.
* `security_evaluation`: evaluate ordered observations and an explicitly enabled
  finite secret-distinguishability criterion.

The tracer observes user-space data accesses before instructions. Read/modify/
write instructions produce separate read and write events. Repetitions remain in
the sequence; accesses crossing lines expand into all touched line bases.
Instruction fetches, kernel accesses, timing and physical-cache behavior are
outside this observer. Logical-region filtering is an explicit configured scope,
not a claim that unselected accesses are safe.

## Correspondence and verdicts

Correspondence uses verified code mappings where supplied, logical region offsets
and surrounding context, or identical-binary anchors. Ambiguous matches remain
inconclusive. Position in a line-token comparison does not establish instruction
correspondence. A changed address or line is not automatically a compromise.

`PASS` means all required configured checks passed for retained executions.
`FAIL` means a required check failed. `INCONCLUSIVE` includes missing, unsupported
or incomplete required evidence. `COMPROMISED` requires the explicit configured
security criterion to be demonstrated. It does not mean general secret recovery
or physical-cache compromise. Optional checks retain their actual status:
`NOT_ASSESSED` never becomes an implied proof. In particular, the sample does not
require a whole-program reference proof, and reports that limitation.

## Evidence

Every invocation creates a unique directory under the configured output path.
`summary.txt` gives the readable result, `report.json` retains structured checks,
`manifest.json` records hashes and runtime identities, and `SHA256SUMS` seals the
files. Configuration and inputs are retained. Per-variant `traces/*.jsonl` contain
versioned memory events with raw-source references. The `raw` directory retains
PIN CSV, metadata, images, maps, native/PIN outputs and execution records.

`comparisons/trace_diff.csv` and `.jsonl` stream classified differences and matches;
`violations.json` retains all policy violations. Report samples are bounded but
these streams retain complete results. `preserved_constraints.csv` records check
statuses. The `validation` directory contains actual layout, byte-audit,
functional and supplied reference-check evidence; unperformed proofs are not
fabricated. Logs retain build, transformation and instrumentation commands.

An incomplete trace is counted only after collection starts. A missing symbol
before collection is unsupported mapping evidence, not an incomplete trace.
If instrumentation aborts, differing instrumentation stderr alone does not prove
a target functional failure. Subsequent stages remain `NOT_RUN`.

## Native qualification

`scripts/test-workflow-wsl.sh` makes a fresh installation and runs the assembly
example through actual tools, retaining its console and all evidence. It does not
modify a previously distributed ZIP. Portable subprocess-double tests exercise
reporting and failure handling; they are not substitutes for this native gate.
The user-reported WSL integration run passed all eight stages on 2026-10-21.
See `THREE-VARIANT-NATIVE-VALIDATION.json` for its exact scope and counts.
Run `python3 -B scripts/verify_workflow_report.py RUN_DIRECTORY` for a read-only
hash and cross-format consistency check; this does not rerun target programs.

The passing native report also passed the read-only consistency verifier: 312
files, 597,376 exported trace events, 20 comparison rows, and zero policy
violations. These are raw trace population totals; the policy selected the
declared region, yielding 12 preserved pairwise observations.
