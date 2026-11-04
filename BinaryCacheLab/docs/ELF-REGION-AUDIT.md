# Java linked-region audit milestone (2026-10-20)

Run with JDK 17 or later:

```text
java -jar binarycachelab.jar audit-region program.elf 0x4078 8 --report new-audit.json
```

Addresses are link-time ELF virtual addresses, before load bias. Decimal and
`0x` numbers are accepted. Supply each build's own region address; this command
does not discover correspondence. It never executes the input. Report creation
uses CREATE_NEW, rejects symlink ancestors, and requires an existing parent.
Exit 0 means the advisory audit completed; exit 2 means malformed/unsupported
input, invalid arguments or I/O failure. Inspect blockers in the JSON.

The parser reads program headers and PT_DYNAMIC directly, so section names,
symbols and external binutils are not required. It reads DT_RELA and RELA PLT
tables through a unique file-backed PT_LOAD mapping and deduplicates entries
by file offset across overlapping views. RELATIVE (type 8, symbol index zero)
addends are compared with the declared half-open region. Eight-byte write
extents are classified for types 1, 6, 7, 8 and 37; NONE has no write. Symbol
indices are retained but not resolved. Type 37's resolver result is unresolved.
COPY and all other types have unknown write extent and add a blocker. A false
overlap flag with null width does not mean a write is disjoint.

REL and RELR metadata add explicit unsupported blockers. They are not decoded.
All reports say reference_coverage=INCOMPLETE, automatic_rewrite_allowed=false,
and preservation_verdict=NOT_EVALUATED, including empty relocation inventories.
There is no safe-movement conclusion from matching bytes or no region hits.

Scope is little-endian ELF64 x86-64 ET_EXEC/ET_DYN, up to 64 MiB, ordinary program
headers, nonnegative signed-long virtual extents, uniquely file-backed regions,
and at most 100,000 RELA entries per table. ET_DYN acceptance is metadata parsing,
not a claim of support for executing PIE or shared libraries. BSS, cross-segment
regions, overlapping mappings, malformed extents, incomplete/duplicate relevant
dynamic tags and extended program-header numbering are rejected. The region
and whole binary SHA-256 values describe the same in-memory snapshot.

This is not an ELF loader validator. Section relocation tables, code references,
stored/computed pointers without relocation records, aliases, disassembly,
symbol binding/interposition, TLS, IFUNC execution, dependency objects and
loader-written final bytes are not established. Stripping sections is not a
coverage proof. Code/data discovery and automatic protection remain unimplemented
in Java. No transformation, formal argument or new observer is added.

Metadata definitions follow the System V ABI relocation and dynamic-table
descriptions and AMD64 relocation numbering:

- https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch4.reloc.html
- https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html
- https://raw.githubusercontent.com/wiki/hjl-tools/x86-psabi/x86-64-psABI-1.0.pdf

Validation includes 26 synthetic checks and offline parsing of the original
and rebuilt binaries retained in region-assessment-dr80ud5z. The original has
nine dynamic RELA records; rebuilt has eight. Both expose unresolved symbolic
targets and remain ineligible. Region 0x4078..0x4080 has equal file-byte hashes;
this does not establish semantics or reference preservation. Live Linux,
FoxDec, PIN, loader and gem5 validation could not run: wsl.exe returns
Wsl/E_ACCESSDENIED. Existing Linux evidence was read without modification.
