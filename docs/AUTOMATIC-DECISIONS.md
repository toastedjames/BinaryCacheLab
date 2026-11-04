# Automatic transformation decisions (item 4)

This workflow joins items 1–3 to actual binary rewriting. It takes an original bounded program and permitted destination addresses, discovers supported executed address loads, selects a valid placement, generates the rewritten ELF and comparison contracts, and publishes only an exhaustively approved candidate. The caller does not supply a rebuilt binary or manually approve a result.

## Commands

From the toolkit root:

```sh
./bcl rewrite examples/automatic/rewrite.json --output experiments/automatic-demo
./bcl rewrite verify experiments/automatic-demo
./bcl rewrite qualify --output experiments/automatic-qualification
```

Use a new directory for each run or qualification. Original files and existing evidence are never overwritten. A passing run publishes `experiments/automatic-demo/protected.elf`. Rejected runs retain reasons, generated candidates and analysis logs, but do not publish `protected.elf`. Verification reconstructs every attempted decision and compares generated artifacts using the sealed original, profiles and toolkit. Copied evidence directories remain replayable. Integrity manifests are commitments to files, not signatures or execution attestations.

The examples are callable ELF routines for the closed interpreter model, not standalone Linux processes. Java 17+ and Python are sufficient for these commands; Docker, PIN, GCC and NASM are not required by this direct-ELF rewrite path. Native Linux process collection and FoxDec rebuilding remain available through the separate project workflow.

## Policy and automatic selection

```json
{
  "schema": "bcl-automatic-rewrite-1",
  "original": "original/lookup.json",
  "regions": [{"name": "table", "address": 4198400, "size": 8, "alignment": 4}],
  "destinations": [4198404, 4198464],
  "secret_inputs": [0],
  "register_outputs": [{"register": "rax", "encoding": "scalar"}]
}
```

`original` is an item-1 bounded profile, relative to this policy. It defines the finite entry/input/memory/runtime bounds. `secret_inputs` indexes that profile's input dimensions; remaining dimensions and entries are public context. Output registers are the functional output contract; selected region bytes are also persistent memory outputs. These are explicit research contracts, not inferred program specifications.

Regions must be disjoint readable/writable nonexecutable, entirely file-backed literal spans, with unique names and valid original power-of-two alignments. At most 32 regions and 4 MiB of selected data are supported. When section headers are present, each selected region must exactly occupy its allocated PROGBITS section; sectionless ELF is also supported. Symbol-table rebinding is rejected. Loader, library, TLS, relocation and callback restrictions from bounded correspondence still apply.

The destination list has 1–32 distinct candidate addresses for the lowest-addressed region. The engine evaluates them in order and chooses the first fully approved candidate. A candidate uses one common nonzero displacement for every region; it must be a multiple of 64 and all region alignments. Thus all selected relative offsets, line residues and shared-line relationships are preserved together. Every target byte must be zero storage in a suitable mapped data range, and destinations cannot overlap selected source ranges. This intentionally conservative policy rejects cases requiring independent region placement or overlapping moves.

The supplied example deliberately tries an invalid four-byte displacement first, records its rejection, then automatically chooses a valid 64-byte displacement. Destination bounds are the caller's permitted allocation locations; the engine determines which, if any, are safe within the declared contract.

## Analysis → rewrite → justified decision

1. Snapshot the original policy, bounded profile, binary and toolkit. Exhaustively interpret every declared original entry/input combination. Reject incomplete or unsupported execution.
2. Choose a candidate placement satisfying the common-displacement constraints.
3. Discover executed `MOVABS r64, imm64` and `MOV r32, imm32` region/interior-address loads from the byte-verified instruction inventory. Rebind their original-width encoded immediates; 32-bit replacements must fit without truncation. Reject missing supported loads or patch overlaps with alternate executed instruction decodings.
4. Move literal data, clear selected old bytes, and update corresponding data-section address/file-offset metadata. Preserve code sizes and addresses. Generate a transformation manifest containing the original/candidate hashes, each address patch, displacement, regions and selection rationale.
5. Generate the rebuilt bounded contract and identity code-anchor map automatically. Generate region memory correspondence, scalar input correspondence, output contract, and the item-3 approval policy.
6. Recompute exhaustive functionality, integer ABI and mapped control-flow correspondence. Verify final linked bytes/alignment/line partition and preservation of observation equality for **all** modeled data accesses.
7. Verify every executed reference: same instruction, width and read/write operation; selected-region accesses must move by the exact displacement and outside accesses must keep their addresses. Reject accesses crossing selected-region boundaries or stale references, even if an output-only test would miss them.
8. Recompute approval immediately before publishing the exact candidate bytes. Seal the report and evidence. No supported placement means a clear rejection.

No claim is made from a planner decision alone. A structural candidate, a semantic correspondence result, a preservation decision and final publication are separate recorded stages. Finite original equality classes must contain at least one distinct-secret pair; an already-distinguishing-only domain is rejected rather than approved vacuously.

## Supported boundary

This release automatically rewrites fixed-address x86-64 ELF literal-region loads using executed fixed-width `MOVABS r64, imm64` or zero-extending `MOV r32, imm32` encodings, scalar register inputs, zero initial register defaults and the closed integer machine selected for items 1 and 2. The complete modeled observer is ordered raw 64-byte virtual data lines, including stack reads/writes and crossing accesses; instruction fetch and physical cache behavior are excluded. All declared executions must terminate inside the configured budgets.

Other address encodings are not guessed. If a required reference is not rebound, final reference correspondence rejects it. Initial pointer-register contracts, memory inputs, unsupported runtime dependencies, instruction semantics, metadata, conflicting placements or incomplete exploration are rejected. General-purpose native binary rewriting remains outside this model. The approval is about exact generated bytes for the recorded finite contract, not arbitrary rewrites.

## Reports, exit codes and regression

- `AUTO_REWRITE_APPROVED_WITHIN_BOUNDS`, exit 0: an exact candidate was generated, justified and published; `bounded_transformation_approved=true`.
- `AUTO_REWRITE_REJECTED`, exit 7: no candidate met the complete checks; reasons and partial artifacts remain. Malformed policy, I/O before a snapshot can be created, integrity failure and replay disagreement use exit 2.
- `AUTOMATIC_QUALIFICATION_EXPECTATIONS_MET`, exit 0: the encoded-program qualification matrix met its expected positive and negative decisions.

`automatic_rewrite_allowed=false` is the existing global flag prohibiting arbitrary rewriting; the scoped approval and published-file hash identify the exact authorized result. `attempt-NN/approval-report.json` includes responsible instruction witnesses when preservation fails. `attempt-NN/transformation.json` documents the generated byte edits and executed-reference check.

Qualification performs real rewriting, exhaustive interpretation, approval, publication, replay, relocation of evidence and tamper rejection. It includes supported rewriting, invalid placement, occupied storage, budget exhaustion, unsupported opcodes and an already-distinguishing control. Portable unit tests additionally exercise section updates, instruction-overlap rejection, rebinding, metadata/runtime boundaries, invalid contracts and no-overwrite behavior. See `ITEM-4-ACCEPTANCE.json` for recorded platform and regression scope. No native WSL execution is inferred from host interpreter checks.
