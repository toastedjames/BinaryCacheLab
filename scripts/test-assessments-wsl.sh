#!/bin/bash
set -euo pipefail
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST=$(mktemp -d "$HOME/BinaryCacheLab-assessments-XXXXXXXX")
mkdir -p "$DEST/scripts" "$DEST/backend" "$DEST/fixtures/pin" "$DEST/examples/workflow"
cp "$SOURCE/binarycachelab.jar" "$SOURCE/binarycachelab.jar.sha256" "$SOURCE/bcl" "$DEST/"
cp "$SOURCE/scripts/"*.py "$DEST/scripts/"
cp "$SOURCE/backend/collect_whole.py" "$SOURCE/backend/whole_trace_check.py" "$DEST/backend/"
cp "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.so" "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.cpp" "$DEST/fixtures/pin/"
cp "$SOURCE/examples/workflow/"* "$DEST/examples/workflow/"
chmod +x "$DEST/bcl"
cd "$DEST"
exec > >(tee -a "$DEST/native-assessments.log") 2>&1
printf 'Assessment test installation: %s\n' "$DEST"
sha256sum -c binarycachelab.jar.sha256
sudo -v
export PYTHONDONTWRITEBYTECODE=1
export JAVA=$(command -v java)
python3 -B scripts/test_assessments_native.py "$@"
python3 -B scripts/test_dashboard_native.py --saved --expect COMPROMISED
printf '\nLaunch the updated TUI:\ncd "%s" && ./bcl tui --config examples/workflow/bcl.toml --input examples/workflow/sample1.asm\n' "$DEST"
