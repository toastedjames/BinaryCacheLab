# Selected-program projects

Bounded correspondence can be requested with `"correspondence": "pair.json"`
in a project. Both bounded profiles are snapshotted and rebound to the final
binaries. Functional, ABI, control-flow or runtime rejection blocks the project
before native collection. `project verify` recomputes the sealed comparison.
See `BOUNDED-CORRESPONDENCE.md` and `examples/correspondence/project.json`.

The `project` workflow accepts Linux x86-64 ELF inputs without the bundled fixture's
fixed hash, region addresses or secret values. It connects build recipes, optional
fresh FoxDec lifting, declared multi-region transformations, final layout checks,
reference analysis and repeated four-run observation checking.

## Existing original and rebuilt binaries

Run setup once with `bash start.sh setup`, then:

```bash
./bcl project init --original /path/to/original --rebuilt /path/to/rebuilt --output project.json
./bcl project run project.json
./bcl project tui project.json
```

The two secrets default to `0` and `1`. All generated evidence goes into a new
`project-*` directory; previous evidence is retained. Discovery is readable:

```bash
./bcl project discover /path/to/original --report inventory.json
./bcl project discover /path/to/original --json
```

Discovery lists defined ELF object/function symbols. Missing symbols, aliases,
unidentified objects and pointer uses remain unproved. It does not silently select
every writable symbol for rewriting.

## Fresh FoxDec baseline

```bash
./bcl project init --original /path/to/program --lift --output project.json
./bcl project run project.json
```

This uses the configured compatible FoxDec image, adds callback roots, requires
successful lifting with required nonempty artifacts, validates callback definitions,
assembles the lifted NASM, links the helper and verifies final callback mappings.
Incomplete/unsupported lifting and linking stop the experiment. A successful lift
does not prove complete instruction coverage or semantic equivalence. The finite
functional/observation tests still run on the final linked binaries.

Optional `lift` fields are `image`, `timeout` (seconds) and `extra_link_args` (an
argv array, for example library options). Defaults use GCC `-nostartfiles -fgnu-tm`;
different applications may need additional link options. All four qualification-program lifts and rebuilds were confirmed through this
entry point on the user's WSL installation; arbitrary-program support is not implied.

## Inputs and build recipes

`examples/projects/equal-line.json` compiles a separate C fixture at two optimization
levels and compares them. It tests the project path, not FoxDec:

```bash
./bcl project run examples/projects/equal-line.json
```

`inputs` maps safe filenames to project-relative source paths. Sources are copied
into evidence before builds. In build-job argv tokens, `{input:filename}` expands
to that snapshot and `{work}` to the new evidence directory. Each job can specify
`cwd` and `timeout`; no shell parsing is performed. Build jobs are locally supplied
commands and run with your account's permissions. Build success alone does not
establish source correspondence or functional equivalence.

## Fixed public inputs

Project JSON supports `secrets`, `public_before`, `public_after`, and `stdin_file`.
For example, secrets `left/right`, `public_before: ["--secret"]`, and
`public_after: ["--size", "32"]` run:

```text
program --secret left  --size 32
program --secret right --size 32
```

The same argument lists and copied stdin bytes are used in both builds, native and
PIN runs, for every repeat. The secret occupies one argv token. Programs requiring
secret input over stdin, interactive input, nonzero successful exit conventions,
threads, or uncontrolled external files need further adapters.

## Multi-region transformations and reference contracts

For an existing rebuilt pair, `regions` names a `bcl-regions-1` profile; the workflow
checks final bytes and the declared byte-line partition. For candidate construction,
use `transform: {"regions": "regions.json", "link_argv": [...]}`. The planner applies
the supported literal-data policy, NASM assembles it, and link argv substitutes
`{object}` and `{output}`. With `lift`, set `link_argv` to `null` to use the generated
FoxDec link recipe and apply the policy to its fresh assembly. These are experimental
candidate transformations, never an automatic whole-program safety approval.

`contracts` maps `original` and/or `rebuilt` to `bcl-closure-1` profile paths. Entries,
region addresses and initial/external assumptions are declared separately for each
binary. The workflow supplies disassembly and binary paths from the actual snapshots.
Unsupported instructions or unresolved flow stay visible as unresolved reports;
reference closure is only under the declared entry contract. No contracts means no
reference-closure result, not a coverage pass.

For binaries retaining corresponding object/function names, `project init` can
generate contract addresses automatically with `--entry FUNCTION --region OBJECT`
(repeatable). This writes an `analysis` selection; each build's own ELF symbol table
resolves the addresses at run time. It assumes an ordinary valid function-return
stack, leaves region immutability and stack disjointness unasserted, observes all
return registers, and supplies no external-code contracts. Missing/ambiguous symbols
stop analysis. FoxDec-renamed symbols require explicit per-build contracts. Symbol
selection does not prove entry reachability or alias completeness.

```bash
./bcl project run project.json --check-only
```

This performs static checks on existing pairs; it refuses recipes, lifting or
transformation builds, and produces no observation verdict.

## Evidence and independent replay

Run the four-program selected-project qualification matrix with one command:

```bash
./bcl project qualify
./bcl project qualify --lift
```

The first compares independently compiled `-O1`/`-O2` binaries for equal-line,
multiple-region, secret-line and crossing-line examples. The second freshly lifts
and rebuilds each `-O1` original with FoxDec. Every case gets repeated four-run
collection and offline replay, and must match its stated expected verdict. A failed
case fails qualification and retains its evidence. Both matrices passed on the user's WSL installation. The source is user-pasted
terminal output, recorded in PROJECT-WSL-VALIDATION.json; the native evidence remains
on that machine. These matrices do not supply reference-closure contracts.

```bash
./bcl project verify /path/to/project-evidence
./bcl project verify /path/to/project-evidence --integrity-only
```

Default verification checks the complete file manifest, recomputes ELF inventories,
reruns declared reference/layout/callback checks, binds collection binaries to the
analyzed ELF files, and independently recomputes Python and Java trace results.
It does not rerun native programs. Replay logs are written outside sealed evidence.
The integrity-only option checks hashes, not analysis. Hashes detect changes relative
to the manifest; they are not signatures or execution attestation.

The supported observer remains ordered raw virtual 64-byte user-space data lines,
with crossing accesses expanded and repeated accesses retained. Equality is compared
between secrets within each build. Timing, instruction fetches, kernel accesses and
physical-cache behavior are excluded. General safety stays inconclusive: entry,
loader/external behavior, outside-object interactions and functional equivalence are
not proved by finite traces or restricted reference closure.

## Patch 1.1.1: COPY relocation bounds

The user completed all four compiler-matrix cases and their offline replays in WSL.
Fresh FoxDec qualification then stopped at the first callback plan because the
original uses `R_X86_64_COPY` for `stderr`. The callback audit now bounds COPY writes
by the defined object's dynamic symbol size, checks its value against the relocation
destination, and requires the whole extent to fit a unique writable load mapping.
Overlapping callback-slot writes still prevent resolution; missing/invalid size or
mapping data remains unknown. BSS destinations are supported through memory mappings.
This is a conservative destination extent under the x86-64 glibc loader's
[COPY implementation](https://github.com/bminor/glibc/blob/master/sysdeps/x86_64/dl-machine.h),
which copies the smaller source/destination symbol size. It does not prove external
object contents or loader behavior. The patched FoxDec matrix subsequently passed all four cases, including
callback checks and offline replay. Project failures now display the error and log path without a Python traceback.

## Reference-analysis qualification

Version 1.2.0 adds `./bcl project qualify --bounded-references` and accepts
bounded profiles through `contracts.original` / `contracts.rebuilt`. See
`BOUNDED-REFERENCES.md` for the exhaustive finite model and its completion
criterion. Static project checks can run without Linux target execution.

`./bcl project qualify --references` checks the pointer/alias/indirect-control
engine without running the native benchmarks. See `REFERENCE-ANALYSIS.md` for
supported semantics, input sets, evidence and remaining whole-program limits.



## Bounded transformation approval

For the closed bounded machine supported by items 1 and 2:

```sh
./bcl approve-transform examples/approval/approval.json --report approval-result.json
./bcl approval-replay examples/approval/approval.json --expected approval-result.json
./bcl publish-transform examples/approval/approval.json --output approved.elf
./bcl project qualify --approval
```

A project may set `"approval": "approval.json"` to gate its candidate. Run the
supplied `examples/approval/project.json` with `project run --check-only` for
exhaustive model checking without native collection. Use `project publish EVIDENCE
--output NEW_ELF` to replay and publish an approved evidence bundle. The finite
input/entry, instruction/runtime and observer contracts bound the approval;
arbitrary rewriting stays unauthorized. See docs/BOUNDED-APPROVAL.md (or
BOUNDED-APPROVAL.md from the docs directory) for the schema and result meanings.


## Automatic rewriting within the bounded model

```sh
./bcl rewrite examples/automatic/rewrite.json --output experiments/automatic-demo
./bcl rewrite verify experiments/automatic-demo
./bcl rewrite qualify --output experiments/automatic-qualification
```

This path generates the candidate and comparison contracts automatically, chooses
a supported placement and publishes `protected.elf` only after exhaustive approval
and executed-reference rebinding checks. Use new output directories. Unsupported
cases are rejected with retained evidence. See docs/AUTOMATIC-DECISIONS.md for the
policy schema and exact supported scope (AUTOMATIC-DECISIONS.md from docs).
