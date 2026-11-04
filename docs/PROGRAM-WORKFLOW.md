# Automatic program workflow and grouped TUI findings

The existing declared-lookup experiment remains available with its original
required reference and security checks. Its TXT, CSV and JSONL formats are
unchanged by the TUI finding-label update.

## Automatic ordinary-ASM path

From the toolkit root:

```bash
./bcl hello.asm
# or
./bcl tui --input /absolute/path/to/hello.asm
```

If the bundled lookup profile is selected but its lookup/region symbols are
absent from the input, the controller explicitly selects general program mode.
Custom profiles with declared contracts are not automatically replaced. You can
also select `examples/programs/bcl.toml` explicitly. It has `mode="program"`.

The source must have exactly one visible `main:` or `_start:` definition for
automatic entry selection. Macro/include-generated or ambiguous entries require
an explicit supported recipe; they are not guessed.

* `main`: NASM plus GCC with normal CRT startup (`-no-pie`). The executable main
  symbol is supplied as an explicit FoxDec root. A literal main pointer in the
  known lifted libc startup argument is rebound to the lifted main symbol.
* `_start`, no external imports: NASM plus `ld -e _start`, without an extra CRT.
* `_start`, external imports: NASM plus GCC `-nostartfiles` with an explicit entry.

Original and actual FoxDec baseline executions are compared for stdout, stderr
and zero exit status, natively and under PIN. Real traces are retained for both.
No transformed binary is invented when no transformation was requested. The two
transformation stages are marked NOT_REQUESTED and are not required checks.
This is trace capture and finite functional validation, not a correspondence or
security proof. Unsupported FoxDec/runtime/instruction cases stop explicitly.

The general-program tracer is compiled from source with the installed PIN kit,
then cached by source and PIN hashes. It accepts a zero-event trace only with an
explicit collector option and metadata flag, normal exit, single thread, one
main image and mapping snapshots. Existing lookup traces still require events.
For syscall-only Hello World the kernel reads the string; those accesses and
instruction fetches are excluded. Zero user-space data accesses are reported
plainly and are not classified as secure.

## Explicit security configuration

General program mode defaults to one case with no arguments and security
NOT_CONFIGURED. It does not infer that an argument is secret. Use an explicit
program profile to supply input cases, fixed public inputs, observation scope,
line identity and `[security]` configuration before requesting leakage testing.
The security target in this mode is original or baseline, since no transformed
binary exists. Empty selected observations cannot establish a security verdict.
General reference approval is not inferred; use the explicit supported bounded
or lookup experiment when reference approval is required.

## TUI finding cards

The TUI groups adjacent classification rows only when rule, build pair, input,
run, exact event references and recorded access fields all agree. It then lists
all reported findings, for example:

```
FINDINGS: ADDRESS CHANGED; CACHE LINE CHANGED
```

The two original JSONL findings remain intact. Different loop accesses, inputs,
repeated runs and line-sequence rule positions are not merged. Any recorded
violation or inconclusive finding remains visible in the grouped result. The
100-card display bound applies after grouping, not before the last finding.

## Qualification

Portable checks and status: `PROGRAM-WORKFLOW-VALIDATION.json`.
Native verification requires Linux x86-64, the real FoxDec Docker image and PIN:

```bash
bash scripts/test-programs-wsl.sh
```

This creates a fresh installation and checks both Hello World entry forms,
the existing lookup experiment, the deliberate leakage control, saved reports,
and grouped TUI findings. No release ZIP is replaced by this check.

## Static ELF callback inventory

Fixed ET_EXEC files without PT_DYNAMIC are accepted as having no loader callback
candidates only when the executable entry maps uniquely to file-backed executable
bytes and complete section metadata contains no nonempty allocated callback or
loader sections. Static PIE, PT_INTERP without PT_DYNAMIC, absent section tables,
legacy constructor sections, callback array section types and ambiguous entries
remain unsupported. This inventory does not prove the absence of manual function
pointer calls or runtime callback behavior.


## Direct Linux syscall entry points

The strict constant-buffer adapter remains as a fast path. Other static programs
use the program-independent interprocedural adapter described in
`GENERAL-CONTROL-FLOW.md`. It supports direct loops/branches, nested and recursive
calls, resolvable indirect targets and runtime-computed write buffers.
Unknown or unmodeled syscall effects remain explicit failures. Source patches are
hash-checked against the pinned FoxDec release and applied only inside the lift
container. The final linked inventory and actual runtime outputs are checked.

## Fixed-address callback arrays

For ET_EXEC inputs, FoxDec can emit init/fini array pointers as original numeric
bytes. Their code may move during linking. The callback plan now records each
verified loader callback slot, its original target and the selected executable
symbol. Before assembly, the general-program workflow checks the complete emitted
array against the original ELF bytes, preserves boundary labels, and emits `dq`
references to those verified symbols. Unsupported directives, unmatched bytes,
missing code definitions, incomplete inventories and ambiguous slots are rejected.
The existing final `callback-check` still verifies every linked callback target.
`validation/callback-array-bindings.json` records the repaired slots.
