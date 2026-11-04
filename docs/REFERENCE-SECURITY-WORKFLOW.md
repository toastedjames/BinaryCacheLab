# Required reference/security checks and automatic text results

Launch with `./bcl tui`, then R + Enter. Explicit --config remains available.

The three-variant sample configuration now requires reference validation and
enables the configured finite secret-input distinguishability test. Opening the
TUI and selecting R runs these through the existing workflow; there is no separate
manual reference command or text-export step for a new run.

## Reference contract

`reference_analysis.adapter = "declared_lookup_kernel"` names one 8-byte group
and the `lookup` function in each linked binary. The checker binds disassembly
bytes to each actual ELF, independently decodes both RIP-relative DWORD reads,
checks the exact TEST/conditional-branch/read/RET machine-code shape at the declared
entry, and compares group contents, offsets, return-value and local integer ABI
relations for all zero/nonzero selector classes. It checks all three build pairs.

The explicit contract assumes ordinary x86-64 execution, entry with a fixed valid
return stack, and immutable readable group bytes during the function. It does not
claim every whole-program alias/caller/loader path is proved. Program-wide coverage
remains INCOMPLETE. Unsupported shapes are rejected. Required validation failure
prevents transformed execution; it is never converted into PASS. Existing closed
static bounded-reference/correspondence profiles remain available separately.

## Security test

The configured test compares the two fixed-secret cases in original, baseline
and transformed executions, with the same public input controls and repetitions.
It checks repeat stability of the actual selected line sequences, separately from
ordinary policy stability. The report records results per build and distinguishes
a difference already present in the original from one introduced for the tested
pair. No line or address change alone establishes compromise.

`sample1.asm` puts both selected words in one line. `secret_line.asm` deliberately
puts them across a line boundary while returning the same output. Qualification
requires PASS for the equal-line sample and COMPROMISED under the explicitly
configured finite criterion for the control, with origin PRESENT_IN_ORIGINAL.
The security test is finite virtual-line distinguishability, not physical cache
measurement or a universal non-leakage guarantee.

## Text result and display

Every new run produces `comparisons/trace_diff.txt`. It streams every comparison
classification, with aligned before/after values, hexadecimal addresses/lines,
logical region offsets, policy decisions, rules and evidence locations, followed
by measured totals and the authoritative report verdict. If a run stops before
comparison, the text file gives the failed/not-run checks instead of invented data.

A completed TUI run automatically requests opening this file in Notepad on WSL,
then wslview/xdg-open where available. Without a desktop viewer it displays a bounded
preview of the same generated file inside the TUI. T opens it again from results.
No extra export command is needed. Older sealed runs can be exported separately
without altering their evidence. The JSON/CSV/JSONL data remains unchanged.

The D view uses one comparison card per page. It starts on the first changed
classification, uses hexadecimal values and aligned build columns, and keeps the
classification/rule/policy decision together. Advanced structured reports show
labeled fields instead of raw one-line JSON. The TXT report includes all rows;
the interactive view remains bounded to the first 100 rows.

## Docker and qualification

The TUI launcher handles configured sudo authentication before starting Java's
input reader and renews the existing credential timestamp while the TUI is open.
It never stores a password. Background Docker commands use noninteractive sudo,
and Docker preflight occurs before trace collection. Missing authentication or a
stopped daemon remains an explicit preflight failure.

Run `bash scripts/test-assessments-wsl.sh` to qualify a fresh installation. It
launches the sample through the TUI, checks the leakage control, verifies artifact
and TXT/CSV/JSONL consistency, and checks saved-report navigation. The existing
Windows session cannot execute this WSL integration gate directly. See
`REFERENCE-SECURITY-VALIDATION.json` for the exact verification state.
