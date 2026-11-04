# Item 2: bounded original/rebuilt correspondence

The selected completion criterion is exhaustive comparison of original/rebuilt
functionality, integer ABI effects and mapped control flow in the same explicit
bounded machine model used by item 1. Unsupported runtime dependencies cause
rejection. This module implements that criterion; it does not establish general
Linux process equivalence.

## Commands

Run the included pair immediately, using Java 17+ and Python 3:

```sh
./bcl correspondence examples/correspondence/correspondence.json
```

The rebuilt fixture adds an instruction and relocates its table. Both declared
input values are exhaustively checked. The fixtures use callable entry contracts;
they are not standalone Linux processes. No native target execution, PIN, Docker
or sudo is needed for this check.

Save a new report and recompute the entire comparison:

```sh
./bcl correspondence examples/correspondence/correspondence.json --report pair-result.json
./bcl correspondence-replay examples/correspondence/correspondence.json --expected pair-result.json
./bcl report pair-result.json
```

Reports are never overwritten. Replay checks the complete recomputed report,
including profile and binary hashes, input pairing, execution outcomes, memory
snapshots, registers, ABI checks, transfer traces and witnesses. It uses the same
interpreter implementation; it is not execution attestation or a second,
independently implemented semantic proof.

Run the qualification suite with a JDK containing `javac` 17+:

```sh
./bcl project qualify --correspondence
```

The suite retains and seals the actual test JAR, both driver sources, encoded
ELF pairs, profiles, reports, logs and summary. The reproducible example builder
is `scripts/make-correspondence-example.py`; its CLI accepts a new output folder.

## What a successful result means

`CORRESPONDENCE_ESTABLISHED_WITHIN_BOUNDS` (exit 0) requires all of the following:

1. Both item-1 models complete every declared entry/input combination without
   unknown execution, unsupported instructions or exhausted bounds.
2. Entry and input mappings are bijective. Input domains agree after explicit
   value encoding, and cases are paired by logical values rather than run order.
3. Initial registers and mapped persistent memory satisfy their declared relation.
4. Declared register outputs and final mapped persistent memory agree. Pointer
   fields use explicit address mappings; ordinary integers and bytes remain exact.
5. All non-stack writes are contained in mapped persistent outputs. A missing
   output map cannot silently hide a write.
6. The integer ABI's preserved registers, ordinary call/return continuations,
   restored stack positions and 16-byte call alignment hold for both binaries.
7. Every reached non-fallthrough control source and target has an explicit
   mapping, and the ordered mapped transfer sequences agree for every case.
8. Runtime metadata has no unsupported loader, callback, TLS, resolver, allocated
   relocation or undefined-external-symbol dependencies. Metadata inspection and
   execution bind the same binary bytes, and profiles remain identical.

Functionality is the explicitly declared output projection of these fixed
machine models. All persistent writes must be represented, but caller-visible
state beyond this declared relation is not proved equivalent. The finite domain
is exhaustive within the profiles; it does not cover undeclared inputs/callers.

`CORRESPONDENCE_COUNTEREXAMPLE` (exit 3) gives a concrete logical input and a
functional, ABI or mapped-control-flow witness. A control-flow witness may occur
while functional outputs agree: all three components are requirements of this
contract. A rewrite that radically changes call/branch structure may require a
different relational proof and is not approved by this strict trace relation.

`REJECTED_CORRESPONDENCE_MODEL` (exit 7) means the declared relation cannot be
checked: for example a missing control mapping, mismatched input domain,
unsupported runtime dependency or an incomplete bounded execution. It does not
mean a functional difference was proved. Malformed profiles/ELF structure, I/O
errors and replay mismatches use exit 2.

All outcomes retain `automatic_rewrite_allowed: false`. This module does not
replace the separate observation-preservation checker or transformation policy.

## Pair profile

The schema is `bcl-bounded-correspondence-1`. Copy the included pair profile;
`original` and `rebuilt` name item-1 bounded profiles, relative to the pair file.
Each side retains its own binary, entry addresses, finite inputs and resource
bounds. See `BOUNDED-REFERENCES.md` for the instruction/runtime model and caps.

| Field | Meaning |
| --- | --- |
| `abi` | Required `sysv-amd64-integer` |
| `entries` | Complete bijection of declared original/rebuilt entry addresses |
| `control_map` | Additional original/rebuilt instruction-address pairs |
| `memory_maps` | Named persistent byte windows with original/rebuilt address and equal size |
| `input_map` | Original/rebuilt input-dimension indices and explicit value encoding |
| `initial_register_encodings` | Optional encodings for non-input initial register values |
| `register_outputs` | Explicit register names and output value encodings |

Entries also become code anchors. Address mappings must be bijective. Each
code anchor must be inside an executable file-backed mapping on its side. Each
reached conditional branch, jump, call, internal return and root return must
have mapped source/target anchors. The modeled caller continuation is handled
automatically. Ordinary fallthrough steps are omitted from transfer comparison,
allowing padding and other changes that preserve the declared transfer relation.
The instruction sequences themselves need not have identical bytes or lengths.

Input indices refer to the respective bounded profiles' `inputs` arrays.
Dimensions may be listed in different orders and values may be reordered, but
every dimension must be mapped once. Register-input locations must use the same
ABI register. Memory-input locations and widths must correspond. All fixed
initial general registers must also correspond; RSP uses the implicit stack
mapping. Stack sizes must agree, while stack bases may differ.

Encodings are:

* `scalar`: exact 64-bit value equality.
* `address`: a uniquely mapped code anchor, persistent-window offset, stack
  offset or modeled caller continuation.
* `nullable-address`: the same mapping, with zero explicitly representing null.

Pointer-valued inputs also establish the initial encoding for their register.
There is no automatic reinterpretation of an integer as a relocatable pointer.
An unmapped or ambiguous address rejects the relation.

`memory_maps` use `name`, `original`, `rebuilt` and `size`. They must be disjoint
on each side and cannot include stack scratch memory. Each map may contain
`pointer_fields`, whose entries give `offset`, `width` (4 or 8) and `encoding`
(`address` or `nullable-address`). These fields are decoded little-endian and
compared through address mappings in both initial and final snapshots. All other
bytes compare exactly. Pointer fields cannot overlap.

Optional `allow_one_past: true` permits an endpoint pointer for a memory map.
An endpoint that would have multiple meanings is rejected. Observation windows
across all executions are capped at 4 MiB of guest bytes per snapshot side;
original and rebuilt each retain initial and final snapshots. Larger projections
are rejected before execution rather than truncated.

## ABI and runtime boundary

The model checks preservation of RBX, RBP and R12–R15 at root returns and each
ordinary internal call return. It checks the saved return continuation, restored
RSP and 16-byte alignment immediately before calls, plus entry `RSP + 8`
alignment. It does not model vector, x87/MMX, variadic-vector or exception-unwind
ABIs. The instruction model cannot change the direction flag; execution uses
the closed machine's fixed ordinary state. The underlying convention is described
in the [System V AMD64 ABI source](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex).

The existing fixed-address ET_EXEC restrictions apply. Both binaries are audited
for PT_DYNAMIC/PT_INTERP/PT_TLS, callback arrays, legacy `.ctors`/`.dtors`,
`.init`/`.fini`, dynamic sections, TLS sections, allocated relocation sections,
IFUNC resolvers and undefined global/weak symbols. Known unsupported dependencies
reject the pair even if the chosen path never touches them. Hazard reports retain
the first 128 records and the total count. Sectionless images are supported;
this does not infer startup semantics from missing metadata. Closed callable
entries and absence of external runtime actions remain explicit model boundaries.

## Project integration

Add `"correspondence": "path/to/pair.json"` to a `bcl-project-1` project.
The driver snapshots the pair and both bounded profiles and binds their binary
paths to the final linked original/rebuilt artifacts in the experiment directory.
It runs correspondence before native observation collection. A counterexample or
rejected model makes the project fail while retaining its sealed diagnostic report.

```sh
./bcl project run examples/correspondence/project.json --check-only
./bcl project verify /path/to/completed/project-evidence
```

Static checks do not execute the target. Project replay recomputes correspondence
from the sealed binaries and profiles, checks the saved report and summary, and
works after moving the evidence directory. Other native observation workflows
still use Linux/PIN and their own finite observation criteria.
