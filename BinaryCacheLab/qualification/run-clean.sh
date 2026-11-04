#!/bin/sh
set -eu
mkdir -p "$HOME"
java -version 2>&1
python3 --version
gcc --version
clang --version
strip --version
./bcl qualify-broad --native --output /evidence/run
python3 -B -c 'import json; from pathlib import Path; p=Path("/evidence/run/summary.json"); d=json.loads(p.read_text()); assert d["status"] == "BROADER_QUALIFICATION_EXPECTATIONS_MET"; Path("/evidence/CLEAN-INSTALL-PASSED.json").write_text(json.dumps({"status":"CLEAN_INSTALL_EXPECTATIONS_MET","base":"ubuntu:24.04","network_during_qualification":"disabled","report":"run/summary.json","scope":"Fresh dependency installation and exhaustive model qualification; no arbitrary-program/native-runtime proof"},indent=2)+"\n")'
