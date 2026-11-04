# General control-flow adapter

The static Linux x86-64 adapter is program-independent. It does not select an
implementation by example name or output. The same implementation handles:

- conditional jumps and counted loops, with loop-carried facts merged to a fixed point;
- direct and nested calls, standard returns, recursion and tail jumps;
- register-indirect calls/jumps when their possible targets are resolved;
- immutable function-pointer tables and bounded index sets;
- signed table entries and common integer/partial-register operations;
- write buffers and lengths constructed at runtime, including .bss buffers.

Objdump supplies instruction boundaries. Every decoded instruction's bytes must
match a unique executable mapping in the original ELF. Register facts are finite
sets (up to 64 values). Function-return summaries are propagated between callers
and callees; recursion shares fixed-point summaries. Stack-pointer values are
forgotten across call/return boundaries. This adapter assumes standard CALL/RET
structure; it is not a proof about arbitrary stack manipulation.

Unknown register effects erase facts. Writable pointer tables are not treated as
constants. Resolved function entries are supplied as FoxDec lifting roots. The
pinned FoxDec source extension still decodes and emits actual SYSCALL instructions.
No original binary or original ASM is copied as a substitute for a rebuilt binary.

Kernel models currently cover write (1), exit (60) and exit_group (231). Unknown
or ambiguous syscall numbers, unsupported kernel memory effects, unresolved
control transfers, writable executable code, overlapping mappings and exhausted
analysis bounds are rejected. Dynamic library programs continue through the
existing FoxDec path. This does not establish support for every instruction,
architecture, OS ABI, JIT or self-modifying program.

The original and final linked executables are executed under the configured
controls. Native and PIN stdout/stderr/exit results must agree for every input.
The prime regression requires all 168 primes from 2 to 997 exactly. A successful
ordinary-program run is a build/trace result; leakage testing requires explicit
secret inputs and an observer.

Native qualification:

    bash scripts/test-programs-wsl.sh

This checks seven programs (both Hello forms, a loop, nested calls, an indirect
call, recursion and prime printing), plus the declared lookup and leakage controls.
For a focused prime integration check only:

    bash scripts/test-programs-wsl.sh --prime-only

Direct CLI runs now authenticate configured Docker sudo access before entering
the workflow, with the same credential renewal used by the TUI. This prevents a
background password prompt from being mistaken for a program-analysis failure.


Writable globals are seeded into the initial FoxDec L0 memory structure using
validated allocated .data/.bss section boundaries. Each section must fit in a
unique writable PT_LOAD memory range; NOBITS sections use their allocated memory
size. The original global-memory write handler remains active. This addresses an
upstream missing-region failure for imprecise writes through computed .bss
pointers, without inventing buffer contents or suppressing memory effects.
