# BinaryCacheLab

BinaryCacheLab (BCL) is a toolkit for lifting and rebuilding supported x86-64 binaries, comparing their memory-access observations, and producing protected builds under explicit finite contracts.

BCL combines **FoxDec**, **NASM/GCC**, **Intel PIN**, Java analysis components, and Python workflow orchestration. It provides a command-line interface, a terminal dashboard, readable reports, and inspectable execution evidence.

## What BCL does

- Builds supported NASM inputs or accepts native ELF inputs where configured.
- Lifts binaries with FoxDec and rebuilds the emitted assembly.
- Records runtime user-space data-memory operands with Intel PIN.
- Derives ordered virtual cache-line observations from effective addresses.
- Compares secret inputs within a build and selected accesses across builds.
- Applies supported protective data-layout transformations.
- Publishes a protected executable only after the required finite approval and configured native checks pass.

**Scope:** protected-build approval applies to the exact candidate bytes, declared finite inputs/state/outputs, supported instructions, declared data regions, and ordered 64-byte virtual data-line observations. It is not a universal secrecy, physical-cache timing, speculative-execution, or constant-time guarantee.

## Requirements

The native pipeline supports **Linux x86-64**, including **WSL2 Ubuntu on x86-64 Windows**. Ubuntu 24.04 supplies a suitable Python version. Native Windows, native macOS, ARM, and 32-bit x86 are outside this pipeline's supported setup.

| Dependency | Purpose |
| --- | --- |
| Git | Clone the repository |
| Python 3.11+ | Configuration, setup, orchestration, and reporting; standard library only |
| JDK 17+ | Build the Java application from source and run its analyzers/TUI |
| NASM | Assemble ELF64 objects |
| GCC, G++, make, GNU binutils | Link binaries, compile the tracer, and inspect ELF artifacts |
| Docker with an accessible daemon | Build/run the pinned FoxDec environment |
| Intel PIN 4.4 for Linux x86-64 | Runtime data-memory instrumentation |
| Bash and Linux utilities | Launchers, ASLR control, downloads, and extraction |

Internet access is needed for missing packages and the FoxDec/JDK downloads. Package installation may require administrator access. A desktop text viewer is optional.

## Installation

Install Git first if it is missing. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install git
```

Then run these commands inside Linux or your WSL2 Ubuntu terminal:

```bash
cd "$HOME"
git clone https://github.com/toastedjames/BinaryCacheLab.git
cd BinaryCacheLab
chmod +x setup.sh
./setup.sh
```

Keep the checkout in the Linux filesystem, such as `~/BinaryCacheLab`. No ZIP extraction is required.

### Interactive setup

`setup.sh` checks the platform and dependencies, reuses compatible installations, and asks before installing missing package groups, downloading dependencies, compiling local components, or changing configuration. Enter **Y** to continue or **N** to cancel. Invalid answers are requested again.

- A compatible JDK can be installed under `.deps/java` from a pinned official Temurin release, with SHA-256 verification before execution.
- Native compiler/assembler tools, Python bootstrap, utilities, and Docker use the supported apt installation path with explicit permission.
- FoxDec source/downloads are stored under `.deps/foxdec`. Its GHC/Cabal dependencies run inside Docker; host Haskell installation is not required. Docker manages image storage separately.
- The PIN tracer is built under `.deps/tracer` against the installed PIN kit.
- A missing application JAR is built from the Java sources after confirmation.
- Configuration changes are confirmed and backed up under `.deps/config-backups`.
- `./bcl` loads `.deps/environment.sh`, so normal operation does not require a separate PATH export.

Rerun `./setup.sh` to reuse compatible dependencies. Rerun it after relocating the checkout because generated tool paths may need updating. `start.sh` is the older fixture installer; use `setup.sh` for the interactive installation workflow.

### Intel PIN

Obtain **Linux x86-64 PIN 4.4** from Intel under its license. Setup accepts an existing compatible kit or a separately downloaded archive with a trusted SHA-256. It does not bypass Intel download restrictions or redistribute the PIN kit.

If a kit is already installed, select it during setup or provide its location:

```bash
export PIN_ROOT="/absolute/path/to/PIN/kit"
./setup.sh
```

`PIN_ROOT` must name the directory containing the `pin` executable. A version check does not establish download authenticity; use a kit from a trusted source.

### Docker

Start a Linux Docker daemon or enable Docker Desktop's WSL integration for your Ubuntu distribution before setup needs FoxDec. Check access with:

```bash
docker info
```

Setup asks before trying authenticated sudo access. It does not silently configure/start the daemon or change group membership.

## Quick start

All commands below run from the repository root after setup.

### Terminal dashboard

```bash
./bcl tui
```

The main actions are:

| Key | Action |
| --- | --- |
| `R` | Run analysis |
| `P` | View layout planning information |
| `V` | View the last report |
| `C` | Inspect/edit configuration |
| `A` | Open advanced tools |
| `Q` | Quit |

Commands are followed by Enter. During execution, `C` requests cancellation and `L` shows logs. Results and trace differences remain available on disk even when no external text viewer is available.

### Ordinary analysis

An ordinary run measures and checks configured behavior. It can include original, baseline, and transformed variants; it does not automatically publish an approved protected executable.

```bash
# Equal-line lookup example
./bcl examples/workflow/sample1.asm --config examples/workflow/bcl.toml

# Deliberately secret-dependent cache-line control
./bcl examples/workflow/secret_line.asm --config examples/workflow/bcl.toml

# General program: build, lift, rebuild, and trace without a secret contract
./bcl examples/programs/hello_start.asm --config examples/programs/bcl.toml
```

### Protected build

A protected run adds mandatory finite reference, functional/ABI, layout, preservation, trace-completeness, and repeated native/PIN checks. It publishes only the exact approved candidate.

```bash
./bcl protect examples/protection/tables.asm   --config examples/protection/bcl.toml
```

The loop/nested-call example uses its own finite contract:

```bash
./bcl protect examples/protection/tables_loop.asm   --config examples/protection/bcl.toml   --approval examples/protection/loop-contract.json
```

The same protected configuration can be used from the dashboard:

```bash
./bcl tui --input examples/protection/tables.asm   --config examples/protection/bcl.toml
```

Choose `R` to start. Approval is explicitly reported as `PROTECTED_BUILD_APPROVED_WITHIN_BOUNDS`. The published executable is `protected/program` inside the new run directory. Failed, unsupported, or incomplete required checks prevent protected publication.

## Executable variants

| Variant | Meaning |
| --- | --- |
| **Original** | Input executable, or the executable built from the input ASM |
| **Baseline** | FoxDec-lifted assembly rebuilt without the protective layout transformation |
| **Transformed** | Lifted assembly after the configured layout transformation, assembled and linked again |

Secret-pair decisions compare different secret inputs **within the same build**. Build-change comparisons compare the **same input across builds**. These answer different questions.

For preservation, if two secrets have equal selected observations in the original, their selected observations must remain equal in the checked rebuilt candidate. If the original already distinguishes them, that is not evidence that lifting introduced a new distinction.

## Reading results

The readable report groups secret-input decisions, observed accesses, build changes, and a summary. An access whose address and cache line both change lists both findings together.

| Label | Meaning |
| --- | --- |
| `PASS` | The configured workflow checks passed; this alone is not protected approval or proof of universal security |
| `FAIL` | A required check failed; inspect the responsible check and evidence |
| `COMPROMISED` | The configured finite distinguishability criterion demonstrated a secret-dependent observation |
| `INCONCLUSIVE` | Required evidence is incomplete, unsupported, ambiguous, or unavailable |
| `PROTECTED_BUILD_APPROVED_WITHIN_BOUNDS` | Exact-candidate protected publication passed within the declared contract |

### Policies and per-comparison outcomes

The header, for example `Policy: region_relative`, names the comparison policy:

| Policy | Main purpose |
| --- | --- |
| `strict_address` | Require matched accesses to preserve the configured address/access properties |
| `region_relative` | Permit relocation while checking mapped region/offset and required access properties |
| `cache_line_sequence` | Compare complete ordered configured line tokens across builds |
| `layout_only` | Treat access changes as informational and evaluate explicit layout obligations |
| `security_evaluation` | Use the configured within-build secret-input assessment rather than treating relocation itself as a security failure |

Within a build-change group, `Policy: PERMITTED` is an **outcome**, not another policy name:

- `PERMITTED`: the selected policy allows the reported changes.
- `VIOLATION`: at least one classification violates that policy.
- `INCONCLUSIVE`: correspondence/mapping is insufficient to decide and no definite violation takes precedence.

A run can have permitted cross-build relocations and still be compromised because different secrets select different lines within a build. Moving both secrets' accesses together to another line does not, by itself, demonstrate a new secret distinction.

## Outputs and evidence

The terminal prints the fresh run directory. `output = "runs"` is resolved relative to the active workflow configuration, so the supplied examples write under their own `examples/.../runs/` directories.

Typical artifacts include:

```text
RUN/
├── summary.txt
├── report.json
├── manifest.json
├── inputs/
├── build/
├── logs/
├── raw/
├── traces/
├── comparisons/
│   └── trace_diff.txt
├── validation/
└── protected/
    └── program           # successful protected publication only
```

Raw CSV/JSONL retain ordered event evidence, including repeated accesses. Readable grouping does not remove events from the sequences used for decisions. Reports and manifests link findings to instructions, memory addresses, source rows, and artifact hashes.

To check a saved modern workflow report:

```bash
python3 -B scripts/verify_workflow_report.py /absolute/path/to/RUN
```

This checks integrity and report consistency; it does not rerun the target or independently attest execution.

## Examples and source layout

```text
src/                     Java application and tests
scripts/                 Setup, workflows, protection, reporting, and tests
backend/                 PIN collection/comparison adapters
adapters/                Adapter source layout
fixtures/                Tracer source and required small test inputs
examples/
├── workflow/            Equal-line and deliberately leaking lookup controls
├── programs/            General ASM examples, including primes and recursion
├── protection/          Protected two-region and loop/call examples/contracts
├── benchmarks/          C source fixtures
└── ...                  Finite-analysis profiles and other supplied inputs
qualification/           Clean-environment qualification scripts
samples/README.md        Example-directory guide
docs/                    Detailed component documentation
setup.sh                 Interactive installation entry point
bcl                      CLI/TUI launcher
```

Configuration is explicit: select the intended TOML with `--config`. The root `bcl.toml` is a legacy fixture/setup profile; modern examples use `schema_version = "2.0"`. Protected examples additionally specify `[protection]` and an approval contract. General-program capture support is broader than protected finite-model support.

## Development and tests

To build the Java application separately:

```bash
sh scripts/build-linux.sh
```

The script prints the new JAR path under `build/`; it does not replace the root JAR. Use `java -jar` with that printed path. The GitHub-ready Windows `scripts/build-package.ps1` builds the root JAR and updates its checksum.

After installing native dependencies, run:

```bash
# Python regression suite
python3 -B -m unittest discover -s scripts -p 'test_*.py'

# General program, lookup/leakage, and dashboard integration gate
bash scripts/test-programs-wsl.sh

# Fresh protected-build, controlled-prevention, and rejection checks
mkdir -p experiments
python3 -B scripts/test_protection_native.py --pin /absolute/path/to/PIN/kit/pin
```

Native gates execute programs and create new evidence. Some optional interface/replay gates require previously accepted evidence and are not initial installation steps. The prevention fixture deliberately perturbs lifted data layout; it is not a claim of a naturally occurring default FoxDec vulnerability.

### Validation status

Recorded core acceptance includes 270 Linux Python tests, 27 Java test programs, 1,072 bounded-reference checks across 297 encoded ELF cases, and native protected/prevention/rejection and CLI/TUI checks. These results apply to the accepted core implementation and declared cases.

The new interactive installer has been implemented by source inspection but **has not been executed or clean-install validated**. Prior core acceptance does not establish that every fresh-clone environment will install successfully.

## Troubleshooting

| Problem | Action |
| --- | --- |
| `./bcl: No such file or directory` | Enter the repository root containing `bcl`, `setup.sh`, and `src` |
| Python/TOML error | Use Python 3.11+; rerun setup with a compatible interpreter |
| Java missing or class-version error | Use a JDK/runtime 17+ and rerun setup |
| Docker inaccessible | Start the daemon/WSL integration; inspect `docker info` and the approved sudo-access path |
| Intel download rejected | Obtain the licensed PIN 4.4 kit through Intel and supply its location to setup |
| Missing tracer | Rerun setup with the intended PIN kit and allow tracer compilation |
| `setarch -R` denied | Use an environment permitting the required ASLR control; do not disable checks to obtain PASS |
| Build/lift failure | Read the numbered command log named in the run report; inspect the exact assembler/linker/FoxDec error |
| Unsupported instruction or reference | Inspect the contract and failed analysis; unsupported coverage cannot be treated as approval |
| Incomplete trace | Inspect metadata and configured limits; rerun after addressing the cause |
| TXT viewer unavailable | Open `comparisons/trace_diff.txt` directly or use the dashboard preview |
| Setup lock remains after interruption | Confirm no installer is running before removing `.deps/setup.lock` |

Do not relabel incomplete evidence as complete or suppress required checks to obtain an approved protected build.

## Limits and licensing

PIN records instrumented **user-space data-memory operations**, not kernel buffer reads, instruction-fetch traces, hardware cache misses, physical-cache contention, or timing. Supported capture requires the configured single-threaded execution model and complete evidence. Arbitrary syscalls, dynamic behavior, indirect targets, instructions, and layouts are not universally supported.

Intel PIN, FoxDec, JDKs, system packages, and Docker images retain their own licenses and distribution conditions. The PIN kit is not included. Retain upstream notices in redistributed components. No standalone BCL license file is currently supplied; publication of the source alone does not grant an additional license for reuse or redistribution.

Do not commit credentials, local dependency installations, personal configuration paths, or experiment outputs. The supplied `.gitignore` excludes generated dependencies, build results, traces, and JAR assets while retaining required test fixtures and the FoxDec patch-source archive.
