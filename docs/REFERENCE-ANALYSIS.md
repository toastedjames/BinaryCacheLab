# Reference analysis in 1.1.2

This document describes the earlier abstract `closure` engine. Version 1.2.0
also provides the separately specified exhaustive bounded analyzer that
implements the revised item-1 criterion; see `BOUNDED-REFERENCES.md`.

Run the dedicated qualification with one command:

```sh
./bcl project qualify --references
```

This compiles the bundled Java test driver against a snapshot of the shipped JAR,
then analyzes encoded ELF fixtures. It requires Java and javac 17 or newer. It
does not run FoxDec, PIN, Docker, or the fixture machine code. Each case retains
its binary, byte-bound disassembly, profile and report; malformed input cases
intentionally have no completed report. The evidence directory also contains
the driver source, JAR, logs, summary and SHA256SUMS.

## Supported analysis

The engine explores declared instruction entries with a worklist and joins
register and memory states until they stabilize. It follows concrete direct and
indirect control-flow targets, including register targets and immutable indexed
jump tables. Multiple possible addresses are retained, up to eight per value.
Calls keep separate return contexts up to depth eight. Missing targets, excess
budgets, and unsupported instruction encodings produce unresolved results.

Addresses are checked against the ELF mappings. Disassembly bytes must match
the file; textual instruction mnemonics are not trusted as semantics. Memory
stores invalidate overlapping abstract cells. Contained sub-loads can extract
known scalar bytes while retaining region-derived provenance. Other partial
overlaps conservatively become unknown.

Region-derived provenance survives LEA, arithmetic, register copies, joins,
stack spills, truncation and widening. A pointer moved numerically outside a
region remains identifiable as region-derived. Escaping stores, live observed
return values and accesses outside the declared regions are reported. Unknown
values stored outside the stack are also unresolved. Root returns must restore
the symbolic caller continuation and entry stack position; internal returns
must match their call context.

Additional decoded forms in this release are REX register/memory indirect CALL
and JMP, 64-bit LEAVE, and REX.W MOVSXD. This remains a restricted x86-64 decoder.
An unsupported instruction stops that path and prevents a closed verdict.

## Entry contracts

Use `./bcl closure PROFILE --report NEW_REPORT` for an existing profile, or the
project workflow's `contracts` fields for original/rebuilt profiles. The schema
remains `bcl-closure-1`. Initial registers may contain an integer, `"stack"`, or
a list of one to eight integers. For example:

```json
{
  "initial_registers": {"rsp": "stack", "rdi": [16504, 16508]},
  "entries": [4425, 4430]
}
```

This fragment is illustrative: addresses must come from the actual binary,
and a full profile also needs schema, binary, disassembly and regions. A finite
input list is an assumption restricting the input domain, not a discovered fact.
Every declared entry is analyzed with the declared initial-register contract.
The report lists analyzed entries and supplied instruction rows not visited.
Unvisited rows are not automatically proved unreachable. Supplying all rows
does not prove that all runtime entries have been identified.

Immutable regions assume file-initialized contents without runtime relocation
or mutation for those bytes. Stack disjointness and external-call contracts
are explicit assumptions. External contracts only model the documented SysV
AMD64 no-memory/no-address-observation normal-return form. They are not inferred
library summaries. The entry contract excludes asynchronous events, concurrent
writes, loader changes and self-modifying execution.

## Meaning of completion

`CLOSED_UNDER_DECLARED_ENTRY_CONTRACT` means the supported abstract exploration
finished without an unresolved obligation under those declarations. It does
not prove termination, full instruction semantics, discovery of every possible
entry, runtime library/loader closure, or original/rebuilt equivalence.

The broader item “complete reference analysis for arbitrary binaries” remains
open. This release extends the implemented, conservative contract-based engine;
it does not turn unknown computed pointers or external behavior into approvals.
Automatic rewrite authorization remains false. Older reference reports can
change when reanalyzed because this release detects additional obligations;
keep their original evidence rather than replacing recorded reports.
