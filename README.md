# BinaryCacheLab — GitHub installation

## Prerequisites

Git, internet connectivity, and x86-64 Linux or x86-64 WSL2 Ubuntu are required.
Ubuntu 24.04 is the recommended setup path (Python 3.12). Native macOS, native
Windows and ARM are not supported by this Linux/PIN pipeline. Install Git before
cloning, for example `sudo apt-get install git` on Ubuntu.

```bash
git clone https://github.com/toastedjames/BinaryCacheLab.git
cd BinaryCacheLab
chmod +x setup.sh
./setup.sh
```

This is the intended repository URL; this delivery does not create or publish
that GitHub repository. No ZIP extraction is needed by a GitHub user.

## What interactive setup does

- Detects Linux/WSL and x86-64; checks Python 3.11+ and Java JDK 17+.
- Reuses compatible installed tools or a local JDK/PIN installation.
- Offers a pinned Temurin JDK download to `.deps/java`, verified using the
  official release's SHA-256 before execution.
- Asks separately before each missing system package group. NASM, GCC/G++/make,
  binutils, util-linux, coreutils, curl, unzip and Docker use apt because they
  integrate with the distribution's native libraries/services. Python bootstrap
  also uses apt if needed. There is no silent sudo or global installation.
- Requires user-provided licensed PIN 4.4: an existing kit or a manually obtained
  archive plus a trusted SHA-256. It never bypasses Intel's download/license rules.
  An archive is extracted under `.deps/pin`; an existing kit is reused in place.
- Offers the existing checksum-pinned FoxDec Docker build. Source/downloads live
  under `.deps/foxdec`; GHC/Cabal run inside Docker. Docker manages image storage
  outside the toolkit; it is not a relocatable directory dependency.
- Asks before compiling the local tracer under `.deps/tracer` and before building
  a missing application JAR from the checked-in Java source.
- Asks before editing bundled configuration and backs it up under
  `.deps/config-backups`. Writes `.deps/environment.sh`, loaded by `./bcl`.

Answer **N** to any installation question to stop immediately. Invalid answers
are requested again. Rerun `./setup.sh` to reuse completed installations.
Interrupted downloads/extractions use temporary directories; an interrupted
process may leave `.deps/setup.lock`. Remove that file only after confirming
no setup is running. An incompatible existing `.deps/java` or `.deps/pin` is
not overwritten: move it aside yourself and rerun.

`setup.sh` is the recommended entry point. `start.sh` remains the legacy
noninteractive fixture installer and has different package-install behavior.
Do not use it as a substitute for interactive consent.

## Running BCL

```bash
./bcl tui
./bcl tui --input examples/protection/tables.asm --config examples/protection/bcl.toml
./bcl protect examples/protection/tables.asm --config examples/protection/bcl.toml
./bcl protect examples/protection/tables_loop.asm --config examples/protection/bcl.toml --approval examples/protection/loop-contract.json
```

Choose R in the TUI to run. Setup updates the example tool paths to your local
installation; no manual PATH export is required. Rerun setup after moving the
clone because generated configuration may contain local absolute tool paths.
Do not commit `.deps`, generated configurations with personal paths, or results.
The `.gitignore` excludes generated dependencies/builds/traces and JAR assets.
Keep required small ELF test inputs and `scripts/foxdec-syscall-base.zip` in Git.

## Manual dependencies and troubleshooting

Intel PIN: obtain Linux x86-64 PIN 4.4 from Intel under its license. HTTP 403 is
not bypassed; setup asks for your existing kit/manual archive. Do not redistribute
Intel's kit without authorization. If no official trusted checksum is available,
use a kit you have independently obtained and trust rather than an unverified
archive. The kit version check does not establish its authenticity.

Docker: install/start Docker Desktop with WSL integration or a Linux Docker daemon.
Setup never silently changes daemon configuration or group membership. If direct
`docker info` fails it asks before trying `sudo docker info`; if that also fails,
start/fix the daemon yourself and rerun. FoxDec downloads/builds can take a while;
inspect `.deps/foxdec/logs` on failure. No host GHC/Cabal installation is needed.

Java: setup needs a JDK, not just a runtime, for source clones. GitHub API rate
limits, unavailable pinned assets or checksum errors stop installation; no binary
is executed after a failed checksum. Use an independently installed JDK 17+ if
network access is blocked. The pinned version is a reproducibility baseline,
not a claim that it is the latest security release.

Python: use 3.11+ with the standard library. Ubuntu versions whose default Python
is older require a compatible Python or an OS upgrade; setup does not silently
add package repositories. There are no pip dependencies or virtual environments.

NASM/GCC/binutils: setup uses distribution versions with working version commands;
there is no claimed instruction-complete minimum-version matrix. The tested native
project environment is Linux x86-64, not every distribution/package combination.
A source clone without the runtime JAR is built only after explicit permission.
An existing JAR with a missing/mismatched checksum is rejected, never overwritten.

## Implementation versus validation

The interactive installer and environment integration were implemented by source
inspection only. **They have not been executed or tested.** No builds, benchmarks,
experiments, setup execution or test execution were performed for this change.
The following retained toolkit reference describes earlier accepted core behavior;
its prior Stage 3 validation does not validate this new installer.

---

# BinaryCacheLab â€” complete Stage 3 source distribution

Start here. This package contains the authoritative working Stage 3 implementation,
not an old v2.0.1 archive or a temporary native test installation.

## Supported environment and external dependencies

Use x86-64 Ubuntu Linux or Ubuntu under WSL2. Extract into the Linux filesystem,
for example `~/BinaryCacheLab`, rather than running instrumentation on `/mnt/c`.
Use Python 3.11+ (standard library; no pip environment required), Java 17+ runtime,
a JDK 17+ for development, NASM, GCC/G++, GNU ld/nm/readelf/objdump, make, Bash,
coreutils, util-linux, curl, unzip and a running Docker daemon.

Intel PIN 4.4 must be obtained separately under Intel's license. Neither the PIN
kit nor the generated PIN-linked tracer module is redistributed. The tracer C++
source is included; setup builds the module against your installed PIN kit.
If Intel returns HTTP 403, manually download the Linux PIN 4.4 archive from
Intel's PIN website into `~/Downloads` inside Linux and rerun setup. An existing
kit can be selected with `export PIN_ROOT=/absolute/path/to/the/kit`.

FoxDec is installed by setup from the official pinned release URL and checksum
in `scripts/easy.py`, using Docker. GHC/Cabal and FoxDec build dependencies live
inside that image; host Haskell installation is not required for this path.
The required syscall/control-flow extension scripts and base patch-source archive
are included. Network access is needed for apt, Docker and FoxDec downloads.
Retain upstream FoxDec notices/license terms. This distribution supplies no new
license grant for third-party components. The BCL project has no standalone
license file; obtain the owner's permission before further redistribution.

## Clean setup (run from the extracted BinaryCacheLab directory)

```bash
chmod +x bcl start.sh fixtures/group_lookup/original
sudo apt-get update
sudo apt-get install -y python3 openjdk-17-jdk nasm build-essential binutils docker.io util-linux curl unzip ca-certificates
bash start.sh setup
python3 scripts/configure-examples.py
```

Start Docker Desktop with WSL integration, or start the Linux Docker service as
appropriate to your host. Setup checks Docker access and configures sudo if
needed. If access fails, inspect `docker info` and `sudo docker info` in your
interactive terminal. Do not substitute another backend to obtain a pass.
`start.sh setup` performs dependency verification and may execute smoke checks;
these commands are instructions for the recipient, not actions performed while
packaging. Generated local absolute tool paths belong only to your installation.
Run configure-examples again if installed PIN/image locations change.

## Complete protected demonstration

After setup, use the supplied two-region finite contract:

```bash
./bcl protect examples/protection/tables.asm --config examples/protection/bcl.toml
```

The pipeline builds the original, lifts with FoxDec, rebuilds, plans protected
region layout, checks exact final bytes and finite references/ABI/observations,
executes native variants under PIN, and publishes only an approved candidate.
Look in the newly printed run directory under `examples/protection/runs/` for
`summary.txt`, `report.json`, and, on approval, `protected/program`.
For the loop/nested-call example use:

```bash
./bcl protect examples/protection/tables_loop.asm --config examples/protection/bcl.toml --approval examples/protection/loop-contract.json
```

Launch the same configured pipeline through the dashboard:

```bash
./bcl tui --input examples/protection/tables.asm --config examples/protection/bcl.toml
```

Choose R to run. General-program examples are in `examples/programs`; the
preserved/secret-dependent lookup controls are in `examples/workflow`.
General capture support does not imply protected-build support. Protected builds
require explicit finite static integer input/state/output contracts, declared
literal data regions and ordered 64-byte virtual data observations. Unsupported
instructions, references, layouts or incomplete evidence fail closed.

## Development build and tests (optional; not run during packaging)

The accepted prebuilt JAR is supplied so users can run without compiling.
To build Java sources on Linux, `sh scripts/build-linux.sh` prints the new JAR
path under `build/`; invoke it with `java -jar PRINTED_PATH`, or install it as the
root JAR and update `binarycachelab.jar.sha256` before using the launcher/setup.
Windows developers can use `powershell -File scripts/build-package.ps1` with a JDK;
this source-only build updates the root JAR and checksum without collecting history.

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py'
# Real native protection/prevention and rejection controls, after setup:
mkdir -p experiments
python3 -B scripts/test_protection_native.py --pin "$PIN_ROOT/pin"
```

Set PIN_ROOT to the actual kit directory before the second command. Native tests
need Docker, PIN and the built tracer, and deliberately create fresh evidence.
The controlled prevention test explicitly perturbs lifted data layout; it is
not evidence of a naturally occurring unmodified FoxDec defect.
The supplied test-protection-wsl.sh is a development gate; its optional replay
modes require accepted evidence and are not prerequisites for ordinary use.

## Results and troubleshooting

PASS means the configured checks passed. PROTECTED_BUILD_APPROVED_WITHIN_BOUNDS
means publication passed the finite protected contract and configured native gates.
COMPROMISED refers to the configured distinguishability criterion; a changed
address between builds alone is not a leakage proof. This is not a physical-cache
hit/miss, timing, speculative-execution or universal secrecy guarantee.

For errors inspect the numbered command log named in the report. Missing tracer:
rerun setup with the correct PIN_ROOT. Docker permission/timeout: verify the daemon
and interactive sudo access. Missing Java: install a JDK/runtime 17 or newer.
INCONCLUSIVE/UNSUPPORTED: inspect the first failed stage and contract; do not disable
required checks. Historical evidence/report commands naturally require a saved
experiment supplied by the user; no previous research runs are distributed.
The detailed docs describe individual existing subsystems; this README is the
current Stage 3 setup entry point. `bcl.toml` is the legacy fixture setup profile;
the Stage 3 demo uses `examples/protection/bcl.toml` explicitly.

## Packaging and prior validation

No builds, tests, benchmarks or demonstrations were run to make this archive.
Only archive paths, contents list/structure and SHA-256 were checked.
Prior acceptance evidence reported 270 Linux Python tests, 27 Java test programs,
1,072 bounded-reference checks across 297 encoded ELF cases, real PIN protected
runs, controlled prevention/rejection and CLI/TUI validation. Those are previous
working-source results, not fresh validation of distribution-only setup helpers.

Included: complete Java/Python/shell sources, tests, config/contract inputs,
small required executable fixtures, assembly/C examples, native tracer source,
FoxDec patch-source bundle, setup/build helpers, accepted runtime JAR, and docs.
Excluded: old results, reports, manifests, traces, logs, caches, build outputs,
research history, machine-local settings, PIN kit/module, Docker images and
regenerable toolchains. Small ELF fixtures are test inputs, not research datasets.
