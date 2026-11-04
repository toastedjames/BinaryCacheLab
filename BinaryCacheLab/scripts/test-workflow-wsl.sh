#!/bin/bash
# Exercise the new one-command assembly workflow using actual GCC/NASM, FoxDec and PIN.
set -euo pipefail
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST=$(mktemp -d "$HOME/BinaryCacheLab-workflow-XXXXXXXX")
mkdir -p "$DEST/scripts" "$DEST/backend" "$DEST/fixtures/pin" "$DEST/examples/workflow"
cp "$SOURCE/binarycachelab.jar" "$SOURCE/binarycachelab.jar.sha256" "$SOURCE/bcl" "$DEST/"
cp "$SOURCE/scripts/"*.py "$DEST/scripts/"
cp "$SOURCE/backend/collect_whole.py" "$SOURCE/backend/whole_trace_check.py" "$DEST/backend/"
cp "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.so" "$SOURCE/fixtures/pin/WholeProgramMemoryTracer.cpp" "$DEST/fixtures/pin/"
cp "$SOURCE/examples/workflow/"* "$DEST/examples/workflow/"
chmod +x "$DEST/bcl"
cd "$DEST"
exec > >(tee -a "$DEST/native-workflow.log") 2>&1
sha256sum -c binarycachelab.jar.sha256
printf 'One-command workflow installation: %s\n' "$DEST"
sudo -v
export PYTHONDONTWRITEBYTECODE=1
export JAVA=$(command -v java)
./bcl --version
cd "$DEST/examples/workflow"
status=0
"$DEST/bcl" sample1.asm || status=$?
if [ "$status" -eq 0 ]; then
  RUN=$(find "$DEST/examples/workflow/runs" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)
  python3 -B "$DEST/scripts/verify_workflow_report.py" "$RUN" || status=$?
fi
printf '\nWorkflow exit: %s\nInstallation: %s\n' "$status" "$DEST"
exit "$status"
