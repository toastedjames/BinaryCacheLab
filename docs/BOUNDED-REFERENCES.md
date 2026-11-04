# Item 1: exhaustive bounded reference analysis

Version 1.2.0 implements the completion criterion selected for item 1: enumerate
every execution in an explicit finite machine model, and reject cases outside
that model or its resource bounds. It is a separate command from the older
abstract `closure` analysis. It does not silently approximate an unknown value
or sample a subset of the input domain.

## Run immediately

From the extracted toolkit directory, with Java 17+ and Python 3 installed:

```sh
./bcl bounded-references examples/bounded/lookup.json
```

The included callable ELF fixture has two input values, both of which are
exhaustively evaluated. No Docker, FoxDec, PIN, sudo, or target-native execution
is needed for this analysis. The generated ELF is an analysis fixture with a
function-entry contract; do not launch it as a standalone Linux process.

Save and independently recompute the result:

```sh
./bcl bounded-references examples/bounded/lookup.json --report bounded-result.json
./bcl bounded-replay examples/bounded/lookup.json --expected bounded-result.json
./bcl report bounded-result.json
```

Report creation refuses to overwrite an existing file. Replay checks the full
recomputed report, including binary/profile hashes, inputs, outcomes, ordered
accesses, control-flow edges, register values and flags. Editing the recorded
accesses or swapping the ELF fails replay. This is deterministic recomputation,
not an independently implemented second interpreter or execution attestation.

Qualification, requiring a JDK with `javac` 17+:

```sh
./bcl project qualify --bounded-references
```

The suite snapshots its JAR and Java driver, compiles the driver, evaluates the
encoded ELF cases, and seals binaries, profiles, reports, logs and summary in a
new evidence directory. The fixture generator is included as
`scripts/make-bounded-example.py`; it accepts a new output directory.

## Exact success criterion

Let E be the declared entry list and V_i the finite list of values for input
dimension i. The engine evaluates all `|E| * product(|V_i|)` initial states.
Each state fixes every modeled register, flag and memory byte. Inputs are
applied to registers or writable memory before the entry is executed. There
is no random sampling, abstract joining, widening or assumption of a missing
indirect target.

`COMPLETE_WITHIN_DECLARED_BOUNDS` (exit 0) requires every initial state to return
to the modeled caller, with every reached instruction decoded and every memory
access and control-flow target resolved inside the model and all bounds met.
Returning to the caller also checks the original stack position. Loops that do
not return within the instruction budget are rejected rather than counted as
complete. Success concerns reference enumeration; it does not assert safe
rewriting, program equivalence or cache-observation preservation.

`REJECTED_MODEL_OR_BOUNDS` (exit 7) means at least one execution or model check
failed. The report identifies the input case, instruction address and reason
where available. Exhaustiveness is false. Global-budget exhaustion explicitly
leaves expected and evaluated execution counts different when cases remain.
Malformed JSON/profiles, invalid ELF structure, I/O errors and replay mismatches
are errors (exit 2). None of these outcomes authorizes a transformation.

## Profile and bounds

Copy `examples/bounded/lookup.json` and replace its binary, entry addresses,
regions and input values for your closed routine. Binary paths are relative
to the profile. Register bit patterns are signed 64-bit JSON integers; negative
numbers represent high-bit patterns. Memory input widths are 1, 2, 4 or 8 bytes.
Memory values use the low width bits. Duplicate normalized values, duplicate
register dimensions and overlapping memory-input dimensions are rejected.

The profile explicitly selects `closed-static-x86-64` and
`bcl-x86-64-integer-1`. General registers default to zero, with explicit
overrides and input dimensions. RSP is fixed by the declared stack. CF, PF,
ZF, SF and OF initially contain zero. File bytes initialize mapped image
memory; BSS and stack bytes start at zero. A reserved caller continuation is
placed at the top of the stack; input dimensions cannot replace it.

| Bound | Required profile key | Implementation maximum |
| --- | --- | ---: |
| Instructions per execution | `max_steps_per_execution` | 1,000,000 |
| Instructions over all executions | `max_total_steps` | 2,000,000 |
| Entry/input combinations | `max_executions` | 65,536 |
| Guest image plus stack bytes | `max_memory_bytes` | 16 MiB |
| Recorded data accesses | `max_reference_events` | 200,000 |

Each bound must be positive. These are guest-model limits, not a wall-clock or
host-heap guarantee. Profiles are limited to 1 MiB, ELF files to 64 MiB, entries
and input dimensions to 128 each, and regions to 63. The complete Cartesian
product must fit before exploration starts. User bounds can be much smaller
than these caps, as in the bundled example.

## Memory, pointers, aliases and entries

Concrete byte-addressed memory resolves aliases directly, including partial
overlapping reads/writes and stack spills. Each execution records ordered data
accesses with responsible IP, address, width, read/write direction, value and
overlapping named regions. Implicit call/return/push/pop stack accesses are
included. Instruction fetches appear in instruction coverage rather than the
data-access list. This report is not a hardware cache trace.

Computed direct, register-indirect and memory-indirect control transfers follow
their concrete targets. All declared alternate entries are explored, including
entries inside a different instruction decoding. Decoding uses the actual ELF
bytes and does not rely on objdump rows or symbols; sectionless static ELF
inputs are supported. The tool does not claim to discover undeclared runtime
entries.

Numeric region/boundary values and conservatively propagated derivation tags
identify potential pointer escapes into memory or return registers. Tags survive
arithmetic, copies and partial memory accesses. The access addresses themselves
are exact for each modeled execution. Escape tags deliberately do not claim to
distinguish an intentional pointer from an integer with the same value.

## Supported instruction model

This is an explicitly restricted integer instruction set, not all x86-64.
Supported forms use 32/64-bit integer operands unless stated otherwise:

| Family | Supported encodings/forms |
| --- | --- |
| MOV | `89`, `8B`, `B8..BF`, `C7 /0`; `C6 /0` byte memory stores |
| LEA | `8D` memory-address form |
| Extensions | `0F B6` byte memory to 32-bit MOVZX; REX.W `63` MOVSXD |
| Arithmetic/logic | ADD, SUB, AND, OR, XOR, CMP register/memory forms and `81/83` immediate groups; `85` TEST |
| Shifts | `C1` immediate and `D1` count-one SHL/SHR/SAR |
| Stack | `50..5F` register PUSH/POP; `68/6A` immediate PUSH; `C9` LEAVE |
| Control | `E8` CALL, `E9/EB` JMP, `FF /2,/4` near indirect CALL/JMP, `C3` RET |
| Conditions | All sixteen short and near Jcc conditions |
| No operation | `90`, `0F 1F /0`, `F3 0F 1E FA` ENDBR64 with enforcement disabled |

Supported encodings accept one applicable REX prefix, RIP-relative addressing,
SIB indexing and displacements. Unlisted forms, 16-bit/address-size overrides,
segment/LOCK prefixes, SIMD, system calls, far transfers and external contracts
are rejected when reached. No missing instruction is treated as a no-op.
Branches that require an undefined modeled flag are rejected. Undefined flags
not consumed by execution are represented as null in the final flag report.
Arithmetic and shift semantics follow the integer operations in Intel's
[instruction-set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

## Runtime boundary

Inputs must be fixed-address, little-endian x86-64 ET_EXEC images. PT_DYNAMIC,
PT_INTERP and PT_TLS are rejected. Mappings and stack must not overlap or share
a 4 KiB page, and ELF file/virtual offsets must be congruent modulo 4 KiB.
Each access must fit within a single declared mapping with the appropriate
permission. High-half/noncanonical addresses, mapping gaps, self-modifying
writes and accesses outside the explicit memory bounds are rejected.

The model runs one thread from the declared callable entries. There are no
signals, interrupts, loader actions, external-library calls, kernel behavior,
concurrent mutation, CET enforcement or physical-cache semantics. Missing
external code is rejected through unmapped/unsupported execution. A successful
result covers this declared machine, not an ordinary dynamically linked Linux
process or every possible caller.

## Project integration

The project's existing `contracts.original` and `contracts.rebuilt` may point
to `bcl-bounded-references-1` profiles. Each profile must describe the appropriate
binary's entry/region addresses and finite inputs. The project binds each
contract to its snapshotted binary, runs the bounded analyzer, saves the result
and replays it during `./bcl project verify EVIDENCE`. Relative binary binding
keeps bounded evidence replayable after copying the evidence directory.

`./bcl project run PROJECT.json --check-only` performs static analysis without
executing the target binaries and is portable when its required tools are
available. Full native observation collection still requires Linux and the
existing PIN setup. Bounded reference completion does not change the project's
separate transformation-approval decision.


## Compiler coverage patch 1.6.1

The shared decoder and bounded interpreter now support FF /0 INC and FF /1 DEC
for 32- and 64-bit registers and memory. The operation updates the modeled
OF/SF/ZF/PF flags and preserves CF exactly; 32-bit register writes zero-extend.
Memory forms emit both a read and a write observation. Regression covers zero,
wrap, signed boundaries, both incoming carry values, memory forms and a branch
consuming preserved carry. Other unsupported FF extensions still reject.
