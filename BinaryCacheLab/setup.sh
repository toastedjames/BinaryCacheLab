#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ask() {
    local answer
    while true; do
        read -r -p "$1 [Y/N] " answer || { echo 'Setup cancelled: input closed.' >&2; exit 2; }
        case "$answer" in [Yy]) return;; [Nn]) echo 'Setup cancelled; installation is incomplete.'; exit 2;; *) echo 'Enter Y or N.';; esac
    done
}
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo 'BCL instrumentation requires x86-64 Linux or x86-64 WSL2. Native macOS/Windows/ARM are unsupported.' >&2
    exit 2
fi
PYTHON=''
for candidate in "$ROOT/.deps/python/bin/python3" python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys;sys.exit(sys.version_info < (3,11))'; then
        PYTHON=$candidate; break
    fi
done
if [[ -z "$PYTHON" ]]; then
    echo 'Python 3.11+ is required. Use Ubuntu 24.04 or install a compatible Python first.'
    echo 'Python uses system libraries; this bootstrap offers the supported apt system package, not an unverified standalone binary.'
    command -v apt-get >/dev/null || { echo 'Install Python 3.11+ manually, then rerun setup.'; exit 2; }
    ask 'Allow apt to install system Python 3 (sudo may be required)?'
    PRIV=(); if [[ $EUID != 0 ]]; then PRIV=(sudo); fi
    "${PRIV[@]}" apt-get update
    "${PRIV[@]}" apt-get install -y python3
    python3 -c 'import sys;sys.exit(sys.version_info < (3,11))' || { echo 'System Python is too old; use Ubuntu 24.04 or supply Python 3.11+.'; exit 2; }
    PYTHON=python3
fi
exec "$PYTHON" -B "$ROOT/scripts/interactive_setup.py"
