#!/bin/bash
# Fresh-copy native test of existing Java TUI navigation and its actual analysis engine.
set -euo pipefail
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST=$(mktemp -d "$HOME/BinaryCacheLab-dashboard-XXXXXXXX")
mkdir -p "$DEST/scripts" "$DEST/backend" "$DEST/fixtures/pin" "$DEST/examples/workflow"
cp "$SOURCE/binarycachelab.jar" "$SOURCE/binarycachelab.jar.sha256" "$SOURCE/bcl" "$DEST/"
cp "$SOURCE/scripts/"*.py "$DEST/scripts/"
cp "$SOURCE/backend/collect_whole.py" "$SOURCE/backend/whole_trace_check.py" "$DEST/backend/"
cp "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.so" "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.cpp" "$DEST/fixtures/pin/"
cp "$SOURCE/examples/workflow/"* "$DEST/examples/workflow/"
chmod +x "$DEST/bcl"
cd "$DEST"
exec > >(tee -a "$DEST/native-dashboard-test.log") 2>&1
sha256sum -c binarycachelab.jar.sha256
printf 'TUI test installation: %s\n' "$DEST"
sudo -v
export PYTHONDONTWRITEBYTECODE=1
export JAVA=$(command -v java)
python3 -B -m unittest discover -s scripts -p test_dashboard_backend.py
python3 -B scripts/test_dashboard_native.py
printf '\nLaunch the tested TUI:\ncd "%s" && ./bcl tui --config examples/workflow/bcl.toml --input examples/workflow/sample1.asm\n' "$DEST"
