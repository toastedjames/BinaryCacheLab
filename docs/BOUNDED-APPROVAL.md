# Exact bounded transformation approval (item 3)

Item 3 is justified approval of a concrete layout-transformation candidate under the bounded model chosen for items 1 and 2. A passing result authorizes publication of that exact candidate. The candidate can come from the region planner, a compiler, FoxDec, or another explicit build recipe. Approval checks final ELF bytes, not an assembly promise.

## Run

From the toolkit root (Java 17+; the supplied launcher selects the included JAR):

```sh
./bcl approve-transform examples/approval/approval.json --report approval-result.json
./bcl approval-replay examples/approval/approval.json --expected approval-result.json
./bcl publish-transform examples/approval/approval.json --output approved.elf
./bcl project qualify --approval
```

Use new output/report names: existing files are never overwritten. Publication recomputes approval immediately, checks the copied bytes against the approved SHA-256, and creates only the exact checked candidate. A failed decision creates no output. No Docker, PIN or native target execution is required to run the bounded analyzer.

Project integration:

```sh
./bcl project run examples/approval/project.json --check-only
./bcl project verify PATH_PRINTED_BY_RUN
./bcl project publish PATH_PRINTED_BY_RUN --output approved-from-evidence.elf
```

`--check-only` skips native PIN collection; it still executes every declared case in the bounded machine and proves the scoped property if approval passes. `NO_OBSERVATION_VERDICT` in the ordinary project trace field refers to native trace collection; the separate bounded approval is authoritative for the model. Omit `--check-only` for the existing Linux trace workflow. Policy, pair profiles, binaries, results and toolkit are snapshotted and sealed; replay checks integrity and recomputes the approval. Project publication first replays that sealed evidence. Moving the evidence directory preserves relative bindings. A project with `approval` is stopped if correspondence, layout, or preservation is rejected.

## Policy

The supplied complete example is `examples/approval/approval.json`:

```json
{
  "schema": "bcl-bounded-transformation-1",
  "correspondence": "correspondence.json",
  "observer": {"policy": "ordered-raw-virtual-lines", "line_bytes": 64},
  "secret_inputs": [0],
  "require_nonvacuous": true,
  "layout": {
    "policy": "preserve-byte-line-partition",
    "regions": [{"name": "table", "alignment": 4}]
  }
}
```

Paths resolve relative to their owning JSON file. `secret_inputs` indexes the correspondence profile's `input_map`; remaining inputs and entry points are public context. At least one secret dimension is required. Region names identify `memory_maps` in the correspondence profile. Every selected region must be readable, nonexecutable, fully file-backed literal data; pointer fields are rejected. Unlisted machine data accesses are still observed.

The correspondence contract provides explicit finite entries and register/memory input domains, stack/memory bounds, instruction budgets, address mappings, output registers, persistent output windows and control anchors. See `BOUNDED-REFERENCES.md` and `BOUNDED-CORRESPONDENCE.md` for the complete machine and ABI contracts. Unsupported instructions, incomplete exploration, loader/library/callback/TLS dependencies or mismatched functionality/ABI/control flow reject approval.

## Approval conditions

1. Exhaustive original/candidate correspondence succeeds for all declared combinations, including modeled ABI effects and mapped non-fallthrough control transfers.
2. Final linked selected data has identical bytes, required power-of-two alignment and identical start modulo 64. Across the entire selected union, corresponding byte offsets preserve the equality partition of virtual cache lines: separately moved regions cannot split an originally shared line or merge distinct lines.
3. For each fixed public context and each pair of declared secrets, original observation equality implies candidate observation equality. There must be at least one distinct originally equal secret pair; an already distinguishing-only original domain cannot receive vacuous approval.

For condition 3, the observer includes **all modeled data reads and writes**, including implicit stack accesses and accesses outside selected regions. Each access expands to every 64-byte virtual line it spans, in increasing address order. Order and repeats are retained. Instruction fetch, values, read/write type and IP do not enter equality; IP and access metadata locate a difference. This is an ordered virtual-line observer, not cache-set, physical-cache, timing or speculative execution semantics.

Original and candidate raw addresses are never compared across builds. Instead, for each public context, original complete observation lists partition the secret assignments into equivalence classes. Each class must have one candidate observation list. Full sequence equality decides this property; hashes are diagnostic commitments, not a substitute for equality. This checks all pairs without quadratic pair enumeration. It allows an unconditional extra candidate access if it cannot split an original equality class.

## Results and publication

- `APPROVED_EXACT_CANDIDATE_WITHIN_BOUNDS` (exit 0): all three obligations hold, `bounded_transformation_approved=true`.
- `PRESERVATION_COUNTEREXAMPLE` (exit 3): an original equality class splits. Report includes both logical inputs, fixed public context, first differing candidate token, responsible IPs and addresses. Layout failure may also be present.
- `TRANSFORMATION_REJECTED` (exit 7): unsupported/incomplete correspondence, invalid layout, unsupported observer, or a vacuous domain. Malformed configuration, I/O and replay disagreement use exit 2.

Reports bind exact original/candidate bytes, approval and nested profile hashes, the complete finite contracts and interpreter results. `authorization` identifies the scope. `automatic_rewrite_allowed=false` continues to prohibit arbitrary rewriting; it does not negate a scoped candidate approval. No result proves arbitrary-program security or general Linux runtime equivalence. Native target execution and physical cache validation remain separate workflows.

## Regression and reproducibility

`./bcl project qualify --approval` compiles the bundled encoded-ELF test driver and two fixture helpers, snapshots its JAR and sources, runs positive/negative cases, and seals the result. Tests cover relocation, boundary crossing, cross-region sharing, new secret-dependent accesses outside the transformed region, unconditional added accesses, public-context separation, nonvacuity, runtime/budget rejection, replay, exact publication and refusal to overwrite. `scripts/make-approval-example.py NEW_DIRECTORY` regenerates the full portable example. The item acceptance record distinguishes host model verification from native WSL execution.
